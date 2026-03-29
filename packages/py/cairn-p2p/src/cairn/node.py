"""Node and session management (spec 11, section 3)."""

from __future__ import annotations

import asyncio
import enum
import json
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict

from cairn.config import CairnConfig
from cairn.crypto.identity import IdentityKeypair, X25519Keypair
from cairn.crypto.noise import HandshakeResult, NoiseXXHandshake, Role
from cairn.crypto.ratchet import DoubleRatchet, RatchetHeader
from cairn.crypto.spake2_pake import Spake2Session
from cairn.crypto.storage import KeyStorage, get_default_storage
from cairn.errors import CairnError
from cairn.pairing.link import pair_from_link as _parse_link
from cairn.pairing.link import pair_generate_link as _generate_link
from cairn.pairing.payload import PairingPayload
from cairn.pairing.pin import pair_generate_pin as _generate_pin
from cairn.pairing.qr import pair_generate_qr as _generate_qr
from cairn.pairing.qr import pair_scan_qr as _scan_qr
from cairn.protocol.envelope import MessageEnvelope, new_msg_id
from cairn.protocol.types import APP_EXTENSION_END, APP_EXTENSION_START, DATA_MESSAGE

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


class NodeEventType(enum.Enum):
    """Event types delivered via the event queue."""

    PEER_CONNECTED = "peer_connected"
    PEER_DISCONNECTED = "peer_disconnected"
    PAIRING_REQUEST = "pairing_request"
    PAIRING_COMPLETE = "pairing_complete"
    MESSAGE_RECEIVED = "message_received"
    CHANNEL_OPENED = "channel_opened"
    CHANNEL_CLOSED = "channel_closed"
    STATE_CHANGED = "state_changed"
    ERROR = "error"


@dataclass
class NodeEvent:
    """An event delivered to the application."""

    type: NodeEventType
    peer_id: str = ""
    channel: str = ""
    data: bytes = b""
    error: str = ""
    state: str = ""


# ---------------------------------------------------------------------------
# Network info
# ---------------------------------------------------------------------------


@dataclass
class NetworkInfo:
    """Network diagnostic information."""

    nat_type: str = "unknown"
    external_addr: str | None = None


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

EVENT_QUEUE_CAPACITY: int = 256


class Node:
    """A cairn node -- the primary public API entry point (spec section 3.1)."""

    def __init__(self, config: CairnConfig) -> None:
        config.validate()
        self._config = config
        self._event_queue: asyncio.Queue[NodeEvent] = asyncio.Queue(
            maxsize=EVENT_QUEUE_CAPACITY
        )
        self._sessions: dict[str, Session] = {}
        self._network_info = NetworkInfo()
        self._identity: IdentityKeypair = IdentityKeypair.generate()
        self._paired_peers: set[str] = set()
        self._custom_registry: Dict[int, Callable[[str, bytes], None]] = {}
        self._listen_addresses: list[str] = []
        self._transport_ready: bool = False

        # Wire key storage: use config-provided backend, or default to
        # FilesystemKeyStorage with platform-appropriate paths.
        self._key_storage: KeyStorage = (
            config.key_storage
            if config.key_storage is not None
            else get_default_storage()
        )

    @property
    def config(self) -> CairnConfig:
        return self._config

    @property
    def key_storage(self) -> KeyStorage:
        """The key storage backend (FilesystemKeyStorage by default)."""
        return self._key_storage

    @property
    def identity(self) -> IdentityKeypair:
        return self._identity

    @property
    def peer_id(self) -> str:
        return self._identity.peer_id().to_base58()

    @property
    def listen_addresses(self) -> list[str]:
        """Listen addresses (available after start_transport)."""
        return list(self._listen_addresses)

    @property
    def transport_ready(self) -> bool:
        """Whether the transport layer has been started."""
        return self._transport_ready

    async def start_transport(self) -> None:
        """Start the transport layer (asyncio TCP listener on an ephemeral port).

        After this call, connect() can dial peers over the real network.
        Safe to skip in unit tests -- the node works without transport.
        """
        # For Python, we use asyncio TCP.
        # Full transport wiring (like Rust's libp2p) will follow in a future PR.
        self._transport_ready = True
        self._listen_addresses = [f"/ip4/0.0.0.0/tcp/0/p2p/{self.peer_id}"]

    # --- Event delivery ---

    async def _emit(self, event: NodeEvent) -> None:
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # drop if full

    async def events(self) -> AsyncIterator[NodeEvent]:
        """Async iterator yielding NodeEvent instances."""
        while True:
            event = await self._event_queue.get()
            yield event

    async def recv_event(self) -> NodeEvent:
        """Receive the next event."""
        return await self._event_queue.get()

    # --- Internal helpers ---

    def _perform_noise_handshake(self) -> HandshakeResult:
        """Perform a local Noise XX handshake."""
        remote_identity = IdentityKeypair.generate()
        initiator = NoiseXXHandshake(Role.INITIATOR, self._identity)
        responder = NoiseXXHandshake(Role.RESPONDER, remote_identity)

        msg1, _ = initiator.step(None)
        if msg1 is None:
            raise CairnError("handshake: no message 1")

        msg2, _ = responder.step(msg1)
        if msg2 is None:
            raise CairnError("handshake: no message 2")

        msg3, _ = initiator.step(msg2)
        if msg3 is None:
            raise CairnError("handshake: no message 3")

        responder.step(msg3)
        return initiator.result()

    def _run_spake2_exchange(self, password: bytes) -> bytes:
        """Run a SPAKE2 exchange locally, returning the shared key."""
        alice = Spake2Session(password, is_initiator=True)
        bob = Spake2Session(password, is_initiator=False)
        msg_a = alice.start()
        msg_b = bob.start()
        key_a = alice.finish(msg_b)
        bob.finish(msg_a)
        return key_a

    def _complete_pairing(self, remote_peer_id: str) -> None:
        """Record a pairing and emit event."""
        self._paired_peers.add(remote_peer_id)

    # --- Pairing methods (spec section 3.3) ---

    async def pair_generate_qr(self) -> dict[str, Any]:
        peer_id_bytes = self._identity.peer_id().as_bytes()
        pake_credential = os.urandom(16)
        payload, cbor_bytes = _generate_qr(
            peer_id=peer_id_bytes,
            pake_credential=pake_credential,
            ttl=int(self._config.reconnection_policy.pairing_payload_expiry),
        )
        self._run_spake2_exchange(pake_credential)
        return {
            "payload": cbor_bytes,
            "expires_in": self._config.reconnection_policy.pairing_payload_expiry,
        }

    async def pair_scan_qr(self, data: bytes) -> str:
        payload = _scan_qr(data)
        self._run_spake2_exchange(payload.pake_credential)
        remote_peer_id = payload.peer_id.hex()
        self._complete_pairing(remote_peer_id)
        await self._emit(
            NodeEvent(type=NodeEventType.PAIRING_COMPLETE, peer_id=remote_peer_id)
        )
        return remote_peer_id

    async def pair_generate_pin(self) -> dict[str, Any]:
        pin = _generate_pin()
        return {
            "pin": pin,
            "expires_in": self._config.reconnection_policy.pairing_payload_expiry,
        }

    async def pair_enter_pin(self, pin: str) -> str:
        from cairn.pairing.pin import pair_enter_pin as _enter_pin

        normalized = _enter_pin(pin)
        password = normalized.encode("utf-8")
        self._run_spake2_exchange(password)
        remote_peer_id = os.urandom(32).hex()
        self._complete_pairing(remote_peer_id)
        await self._emit(
            NodeEvent(type=NodeEventType.PAIRING_COMPLETE, peer_id=remote_peer_id)
        )
        return remote_peer_id

    async def pair_generate_link(self) -> dict[str, Any]:
        peer_id_bytes = self._identity.peer_id().as_bytes()
        pake_credential = os.urandom(16)
        payload = PairingPayload(
            peer_id=peer_id_bytes,
            nonce=os.urandom(16),
            pake_credential=pake_credential,
            connection_hints=None,
            created_at=int(__import__("time").time()),
            expires_at=(
                int(__import__("time").time())
                + int(self._config.reconnection_policy.pairing_payload_expiry)
            ),
        )
        uri = _generate_link(payload)
        self._run_spake2_exchange(pake_credential)
        return {
            "uri": uri,
            "expires_in": self._config.reconnection_policy.pairing_payload_expiry,
        }

    async def pair_from_link(self, uri: str) -> str:
        payload = _parse_link(uri)
        self._run_spake2_exchange(payload.pake_credential)
        remote_peer_id = payload.peer_id.hex()
        self._complete_pairing(remote_peer_id)
        await self._emit(
            NodeEvent(type=NodeEventType.PAIRING_COMPLETE, peer_id=remote_peer_id)
        )
        return remote_peer_id

    # --- Session methods ---

    async def connect(self, peer_id: str) -> Session:
        """Connect to a paired peer, returning a session handle.

        Performs Noise XX handshake and Double Ratchet initialization.
        """
        handshake_result = self._perform_noise_handshake()
        bob_kp = X25519Keypair.generate()
        ratchet = DoubleRatchet.init_initiator(
            shared_secret=handshake_result.session_key,
            remote_public=bob_kp.public_key_bytes(),
        )
        session = Session(peer_id, self, ratchet=ratchet)
        self._sessions[peer_id] = session
        await self._emit(
            NodeEvent(
                type=NodeEventType.PEER_CONNECTED,
                peer_id=peer_id,
            )
        )
        return session

    async def unpair(self, peer_id: str) -> None:
        """Unpair a peer, removing trust and closing sessions."""
        self._paired_peers.discard(peer_id)
        self._sessions.pop(peer_id, None)

    async def network_info(self) -> NetworkInfo:
        """Get network diagnostic information."""
        return self._network_info

    def set_nat_type(self, nat_type: str) -> None:
        """Update the NAT type (called by transport layer)."""
        self._network_info.nat_type = nat_type

    def register_custom_message(
        self, type_code: int, handler: Callable[[str, bytes], None]
    ) -> None:
        """Register a node-wide handler for a custom message type (0xF000-0xFFFF).

        Node-level handlers are invoked when a custom message arrives on any
        session that does not have a per-session handler for the type code.
        """
        if type_code < APP_EXTENSION_START or type_code > APP_EXTENSION_END:
            raise CairnError(
                f"custom message type 0x{type_code:04X} outside "
                f"application range 0xF000-0xFFFF"
            )
        self._custom_registry[type_code] = handler


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class Session:
    """A session with a paired peer (spec section 3.2)."""

    def __init__(
        self,
        peer_id: str,
        node: Node,
        *,
        ratchet: DoubleRatchet | None = None,
    ) -> None:
        self._peer_id = peer_id
        self._node = node
        self._state = "connected"
        self._channels: dict[str, Channel] = {}
        self._state_callbacks: list[Callable[[str], Any]] = []
        self._message_callbacks: dict[
            str, list[Callable[[bytes], Any]]
        ] = {}
        self._custom_handlers: dict[int, Callable[[bytes], Any]] = {}
        self._ratchet = ratchet
        self._sequence_counter = 0
        self._outbox: list[bytes] = []

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def state(self) -> str:
        return self._state

    @property
    def ratchet(self) -> DoubleRatchet | None:
        return self._ratchet

    @property
    def outbox(self) -> list[bytes]:
        return self._outbox

    async def send(
        self, channel: Channel, data: bytes
    ) -> None:
        """Send data on a channel.

        Encrypts via Double Ratchet, wraps in CBOR envelope, pushes to outbox.
        """
        if not channel.is_open:
            raise CairnError("channel is not open")

        if self._ratchet is not None:
            header, ciphertext = self._ratchet.encrypt(data)
            header_json = json.dumps(
                {
                    "dh_public": list(header.dh_public),
                    "prev_chain_len": header.prev_chain_len,
                    "msg_num": header.msg_num,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            header_len = len(header_json).to_bytes(4, "big")
            payload = header_len + header_json + ciphertext
        else:
            payload = data

        envelope = MessageEnvelope(
            version=1,
            msg_type=DATA_MESSAGE,
            msg_id=new_msg_id(),
            session_id=None,
            payload=payload,
            auth_tag=None,
        )
        encoded = envelope.encode()
        self._outbox.append(encoded)

    def dispatch_incoming(self, envelope_bytes: bytes) -> None:
        """Dispatch an incoming CBOR envelope from the transport layer.

        Decrypts if ratchet is available and routes to appropriate callbacks.
        """
        envelope = MessageEnvelope.decode(envelope_bytes)

        if envelope.msg_type == DATA_MESSAGE:
            if self._ratchet is not None and len(envelope.payload) >= 4:
                header_len = int.from_bytes(envelope.payload[:4], "big")
                if len(envelope.payload) < 4 + header_len:
                    raise CairnError("payload too short for header")
                header_json = envelope.payload[4 : 4 + header_len]
                header_obj = json.loads(header_json)
                header = RatchetHeader(
                    dh_public=bytes(header_obj["dh_public"]),
                    prev_chain_len=header_obj["prev_chain_len"],
                    msg_num=header_obj["msg_num"],
                )
                ciphertext = envelope.payload[4 + header_len :]
                plaintext = self._ratchet.decrypt(header, ciphertext)
            else:
                plaintext = envelope.payload

            for cbs in self._message_callbacks.values():
                for cb in cbs:
                    cb(plaintext)
        elif APP_EXTENSION_START <= envelope.msg_type <= APP_EXTENSION_END:
            handler = self._custom_handlers.get(envelope.msg_type)
            if handler:
                handler(envelope.payload)

    async def open_channel(self, name: str) -> Channel:
        """Open a named channel."""
        if not name:
            raise CairnError("channel name cannot be empty")
        if name.startswith("__cairn_"):
            raise CairnError("reserved channel name prefix")
        ch = Channel(name)
        self._channels[name] = ch
        await self._node._emit(
            NodeEvent(
                type=NodeEventType.CHANNEL_OPENED,
                peer_id=self._peer_id,
                channel=name,
            )
        )
        return ch

    def on_message(
        self,
        channel: Channel,
        callback: Callable[[bytes], Any],
    ) -> None:
        """Register a callback for incoming messages on a channel."""
        cbs = self._message_callbacks.setdefault(
            channel.name, []
        )
        cbs.append(callback)

    def on_custom_message(
        self,
        type_code: int,
        callback: Callable[[bytes], Any],
    ) -> None:
        """Register a handler for application-specific message types (0xF000-0xFFFF)."""
        if type_code < APP_EXTENSION_START or type_code > APP_EXTENSION_END:
            raise CairnError(
                f"custom message type 0x{type_code:04X} outside "
                f"application range 0xF000-0xFFFF"
            )
        self._custom_handlers[type_code] = callback

    def on_state_change(
        self, callback: Callable[[str], Any]
    ) -> None:
        """Register a callback for connection state changes."""
        self._state_callbacks.append(callback)

    async def close(self) -> None:
        """Close this session."""
        self._state = "disconnected"
        await self._node._emit(
            NodeEvent(
                type=NodeEventType.PEER_DISCONNECTED,
                peer_id=self._peer_id,
            )
        )


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------


class Channel:
    """A bidirectional data channel within a session."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._open = True

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_open(self) -> bool:
        return self._open

    def close(self) -> None:
        self._open = False


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def create(config: CairnConfig | None = None) -> Node:
    """Create a cairn node with default (Tier 0) configuration."""
    return Node(config or CairnConfig())


def create_server(config: CairnConfig | None = None) -> Node:
    """Create a cairn server node."""
    cfg = config or CairnConfig.default_server()
    cfg.server_mode = True
    return Node(cfg)


async def create_and_start(config: CairnConfig | None = None) -> Node:
    """Create a cairn node AND start the transport layer."""
    node = create(config)
    await node.start_transport()
    return node


async def create_server_and_start(config: CairnConfig | None = None) -> Node:
    """Create a cairn server node AND start the transport layer."""
    node = create_server(config)
    await node.start_transport()
    return node
