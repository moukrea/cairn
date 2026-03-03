"""Server-mode management: config, headless pairing, relay, sync, metrics, HTTP API."""

from __future__ import annotations

import asyncio
import hmac
import json
import math
import time
from dataclasses import dataclass, field
from http import HTTPStatus

from cairn.server.forward import RetentionPolicy

# ---------------------------------------------------------------------------
# Server config (spec 10.2)
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    """Server-mode configuration posture.

    Server mode is not a separate class or protocol -- it is a standard
    Node with adjusted defaults. ``create_server(config)`` applies these.
    """

    mesh_enabled: bool = True
    relay_willing: bool = True
    relay_capacity: int = 100
    store_forward_enabled: bool = True
    store_forward_max_per_peer: int = 1_000
    store_forward_max_age: float = 7 * 24 * 3600.0  # 7 days
    store_forward_max_total_size: int = 1_073_741_824  # 1 GB
    session_expiry: float = 7 * 24 * 3600.0  # 7 days
    heartbeat_interval: float = 60.0
    reconnect_max_duration: float | None = None  # indefinite
    headless: bool = True

    def retention_policy(self) -> RetentionPolicy:
        """Build a RetentionPolicy from this server config."""
        return RetentionPolicy(
            max_age=self.store_forward_max_age,
            max_messages=self.store_forward_max_per_peer,
        )


# ---------------------------------------------------------------------------
# Management API config
# ---------------------------------------------------------------------------


@dataclass
class ManagementConfig:
    """Management API configuration."""

    enabled: bool = False
    bind_address: str = "127.0.0.1"
    port: int = 9090
    auth_token: str = ""

    @property
    def is_loopback(self) -> bool:
        return self.bind_address in ("127.0.0.1", "::1", "localhost")


# ---------------------------------------------------------------------------
# Headless pairing
# ---------------------------------------------------------------------------

DEFAULT_VALIDITY_WINDOW: float = 300.0  # 5 minutes
PSK_ENV_VAR: str = "CAIRN_PSK"


class HeadlessPairingError(Exception):
    """Errors specific to headless pairing operations."""


class PskNotConfiguredError(HeadlessPairingError):
    """PSK not configured."""

    def __init__(self) -> None:
        super().__init__(
            f"PSK not configured (set {PSK_ENV_VAR} env var or "
            f"provide via config)"
        )


class PayloadExpiredError(HeadlessPairingError):
    """Pairing payload has expired."""

    def __init__(self) -> None:
        super().__init__("pairing payload has expired")


@dataclass
class HeadlessPairingMethod:
    """A generated headless pairing method with its payload and expiration."""

    kind: str  # "psk", "pin", "link", "qr"
    value: str | bytes = ""
    expires_at: float | None = None  # None = never expires

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() >= self.expires_at


class HeadlessPairing:
    """Headless pairing controller for server-mode peers (spec 10.5).

    SAS verification is excluded -- it requires a display.
    """

    def __init__(
        self, validity_window: float = DEFAULT_VALIDITY_WINDOW
    ) -> None:
        self.validity_window = validity_window

    def generate_psk(
        self, psk: bytes | None = None
    ) -> HeadlessPairingMethod:
        """Generate a PSK-based pairing method.

        Loads from provided bytes or CAIRN_PSK env var.
        Validates minimum 16 bytes (128 bits) entropy.
        """
        import os

        if psk is None:
            env_val = os.environ.get(PSK_ENV_VAR)
            if env_val is None:
                raise PskNotConfiguredError()
            psk = env_val.encode()

        if len(psk) < 16:
            raise HeadlessPairingError(
                f"PSK too short: {len(psk)} bytes (minimum 16)"
            )

        return HeadlessPairingMethod(kind="psk", value=psk)

    def generate_pin(self) -> HeadlessPairingMethod:
        """Generate a PIN code pairing method."""
        import os

        raw = os.urandom(4)
        num = int.from_bytes(raw, "big") % 100_000_000
        pin = f"{num:08d}"
        formatted = f"{pin[:4]}-{pin[4:]}"
        expires_at = time.monotonic() + self.validity_window

        return HeadlessPairingMethod(
            kind="pin", value=formatted, expires_at=expires_at
        )

    def generate_link(
        self, peer_id_hex: str
    ) -> HeadlessPairingMethod:
        """Generate a pairing link method."""
        import os

        nonce = os.urandom(16).hex()
        uri = f"cairn://pair?pid={peer_id_hex}&nonce={nonce}"
        expires_at = time.monotonic() + self.validity_window

        return HeadlessPairingMethod(
            kind="link", value=uri, expires_at=expires_at
        )

    @staticmethod
    def sas_available() -> bool:
        """SAS is not available in headless mode."""
        return False

    @staticmethod
    def supported_mechanisms() -> list[str]:
        return ["psk", "pin", "link", "qr"]


# ---------------------------------------------------------------------------
# Personal relay config (spec 10.4)
# ---------------------------------------------------------------------------


@dataclass
class PersonalRelayConfig:
    """Personal relay configuration for server-mode peers.

    Only serves paired peers, limiting abuse surface.
    """

    relay_willing: bool = True
    relay_capacity: int = 100
    allowed_peers: list[bytes] = field(default_factory=list)

    def is_peer_allowed(self, peer_id: bytes) -> bool:
        """Check whether a peer is allowed to use this relay."""
        if not self.allowed_peers:
            return True  # caller verifies pairing
        return peer_id in self.allowed_peers


# ---------------------------------------------------------------------------
# Peer sync state (spec 10.6)
# ---------------------------------------------------------------------------


@dataclass
class PeerSyncState:
    """Per-peer synchronization state tracked by the server node."""

    peer_id: bytes
    last_seen_sequence: int = 0
    pending_deliveries: int = 0
    last_connected: float | None = None

    def mark_connected(self) -> None:
        self.last_connected = time.time()

    def advance_sequence(self, seq: int) -> None:
        """Update the last-seen sequence number."""
        if seq > self.last_seen_sequence:
            delivered = seq - self.last_seen_sequence
            self.last_seen_sequence = seq
            self.pending_deliveries = max(
                0, self.pending_deliveries - delivered
            )

    def enqueue_delivery(self) -> None:
        self.pending_deliveries += 1

    def add_pending(self, count: int) -> None:
        self.pending_deliveries += count

    def acknowledge_delivery(self, count: int) -> None:
        self.pending_deliveries = max(
            0, self.pending_deliveries - count
        )


# ---------------------------------------------------------------------------
# Peer metrics (spec 10.7)
# ---------------------------------------------------------------------------


@dataclass
class PeerMetrics:
    """Per-peer resource metrics tracked by the server."""

    peer_id: bytes
    bytes_relayed: int = 0
    bytes_stored: int = 0

    def record_relay(self, nbytes: int) -> None:
        self.bytes_relayed += nbytes

    def record_store(self, nbytes: int) -> None:
        self.bytes_stored += nbytes

    def release_stored(self, nbytes: int) -> None:
        self.bytes_stored = max(0, self.bytes_stored - nbytes)


# ---------------------------------------------------------------------------
# Peer quota
# ---------------------------------------------------------------------------


@dataclass
class PeerQuota:
    """Per-peer resource quotas. Disabled (None) by default."""

    max_stored_messages: int | None = None
    max_relay_bandwidth_bps: int | None = None

    def check_store_quota(self, current_messages: int) -> bool:
        if self.max_stored_messages is None:
            return True
        return current_messages < self.max_stored_messages

    def check_relay_quota(self, current_bps: int) -> bool:
        if self.max_relay_bandwidth_bps is None:
            return True
        return current_bps <= self.max_relay_bandwidth_bps


# ---------------------------------------------------------------------------
# Management HTTP API (spec 10.5, 10.7)
# ---------------------------------------------------------------------------


@dataclass
class PeerInfo:
    """Information about a paired peer for the management API."""

    peer_id: str
    name: str
    connected: bool
    last_seen: str | None = None


@dataclass
class QueueInfo:
    """Per-peer store-and-forward queue info."""

    peer_id: str
    pending_messages: int
    oldest_message_age_secs: float | None = None
    total_bytes: int = 0


@dataclass
class PeerRelayStats:
    """Per-peer relay statistics."""

    peer_id: str
    bytes_relayed: int = 0
    active_streams: int = 0


@dataclass
class RelayStats:
    """Relay statistics overview."""

    active_connections: int = 0
    per_peer: list[PeerRelayStats] = field(default_factory=list)


class ManagementState:
    """Shared state accessible by all management API handlers."""

    def __init__(self, auth_token: str) -> None:
        self.auth_token = auth_token
        self.peers: list[PeerInfo] = []
        self.queues: list[QueueInfo] = []
        self.relay_stats = RelayStats()
        self.started_at = time.monotonic()


class ManagementServer:
    """Async HTTP management API server using asyncio.

    Serves 5 endpoints: /peers, /queues, /relay/stats, /health, /pairing/qr.
    Uses bearer token authentication with constant-time comparison.
    """

    def __init__(
        self, config: ManagementConfig, state: ManagementState
    ) -> None:
        if not config.auth_token:
            raise ValueError("management API auth token is empty")

        if not config.is_loopback:
            import warnings

            warnings.warn(
                f"Management API exposed on non-loopback interface "
                f"{config.bind_address} without TLS. This is insecure.",
                stacklevel=2,
            )

        self._config = config
        self._state = state
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the management API server."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._config.bind_address,
            self._config.port,
        )

    async def stop(self) -> None:
        """Stop the management API server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def port(self) -> int:
        """Return the actual port (useful when port=0)."""
        if self._server and self._server.sockets:
            return self._server.sockets[0].getsockname()[1]
        return self._config.port

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single HTTP connection."""
        try:
            # Read request line
            line = await asyncio.wait_for(
                reader.readline(), timeout=10.0
            )
            if not line:
                writer.close()
                return

            request_line = line.decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                await self._send_response(
                    writer, 400, {"error": "bad request"}
                )
                return

            method = parts[0]
            path = parts[1]

            # Read headers
            headers: dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(
                    reader.readline(), timeout=10.0
                )
                if not header_line or header_line == b"\r\n":
                    break
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    key, value = decoded.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Authentication
            auth = headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                await self._send_response(
                    writer, 401, {"error": "unauthorized"}
                )
                return

            provided = auth[7:]
            if not hmac.compare_digest(provided, self._state.auth_token):
                await self._send_response(
                    writer, 401, {"error": "unauthorized"}
                )
                return

            # Only GET is supported
            if method != "GET":
                await self._send_response(
                    writer, 405, {"error": "method not allowed"}
                )
                return

            # Route
            if path == "/peers":
                body = self._handle_peers()
            elif path == "/queues":
                body = self._handle_queues()
            elif path == "/relay/stats":
                body = self._handle_relay_stats()
            elif path == "/health":
                body = self._handle_health()
            elif path == "/pairing/qr":
                await self._send_response(
                    writer,
                    503,
                    {
                        "error": "pairing QR generation not yet available "
                        "(pending headless pairing integration)"
                    },
                )
                return
            else:
                await self._send_response(
                    writer, 404, {"error": "not found"}
                )
                return

            await self._send_response(writer, 200, body)

        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _handle_peers(self) -> dict:
        peers = [
            {
                "peer_id": p.peer_id,
                "name": p.name,
                "connected": p.connected,
                "last_seen": p.last_seen,
            }
            for p in self._state.peers
        ]
        return {"peers": peers}

    def _handle_queues(self) -> dict:
        queues = [
            {
                "peer_id": q.peer_id,
                "pending_messages": q.pending_messages,
                "oldest_message_age_secs": q.oldest_message_age_secs,
                "total_bytes": q.total_bytes,
            }
            for q in self._state.queues
        ]
        return {"queues": queues}

    def _handle_relay_stats(self) -> dict:
        stats = self._state.relay_stats
        return {
            "relay": {
                "active_connections": stats.active_connections,
                "per_peer": [
                    {
                        "peer_id": p.peer_id,
                        "bytes_relayed": p.bytes_relayed,
                        "active_streams": p.active_streams,
                    }
                    for p in stats.per_peer
                ],
            }
        }

    def _handle_health(self) -> dict:
        total_peers = len(self._state.peers)
        connected_peers = sum(
            1 for p in self._state.peers if p.connected
        )
        uptime_secs = math.floor(
            time.monotonic() - self._state.started_at
        )
        status = "healthy" if connected_peers > 0 else "degraded"

        return {
            "status": status,
            "uptime_secs": uptime_secs,
            "connected_peers": connected_peers,
            "total_peers": total_peers,
        }

    @staticmethod
    async def _send_response(
        writer: asyncio.StreamWriter,
        status_code: int,
        body: dict,
    ) -> None:
        """Send an HTTP response with JSON body."""
        status_phrase = HTTPStatus(status_code).phrase
        body_bytes = json.dumps(body).encode("utf-8")
        response = (
            f"HTTP/1.1 {status_code} {status_phrase}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8") + body_bytes
        writer.write(response)
        await writer.drain()
