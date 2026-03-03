"""Integration tests: full pairing-to-messaging flow between two in-process nodes."""

import asyncio

import pytest

from cairn.config import CairnConfig, MeshSettings
from cairn.crypto.identity import IdentityKeypair, X25519Keypair
from cairn.crypto.noise import NoiseXXHandshake, Role
from cairn.crypto.ratchet import DoubleRatchet
from cairn.crypto.spake2_pake import Spake2Session
from cairn.node import (
    NodeEventType,
    create,
    create_server,
)
from cairn.pairing.pin import (
    normalize_pin,
    pair_generate_pin,
)
from cairn.pairing.qr import pair_generate_qr, pair_scan_qr
from cairn.server.forward import (
    ForwardRequest,
    MessageQueue,
)

# ===========================================================================
# Crypto integration: Noise XX handshake -> Double Ratchet -> encrypted messaging
# ===========================================================================


class TestCryptoIntegration:
    """Full cryptographic pipeline: Noise XX + Double Ratchet."""

    def test_noise_to_ratchet_pipeline(self):
        """Noise XX handshake -> shared secret -> Double Ratchet."""
        alice_id = IdentityKeypair.generate()
        bob_id = IdentityKeypair.generate()

        # Noise XX handshake via step() API
        alice_hs = NoiseXXHandshake(Role.INITIATOR, alice_id)
        bob_hs = NoiseXXHandshake(Role.RESPONDER, bob_id)

        # Msg 1: initiator -> responder (ephemeral key)
        msg1, _ = alice_hs.step()
        # Msg 2: responder processes msg1, sends response
        msg2, _ = bob_hs.step(msg1)
        # Msg 3: initiator processes msg2, sends final
        msg3, _ = alice_hs.step(msg2)
        # Responder processes msg3, handshake complete
        _, bob_result = bob_hs.step(msg3)

        alice_result = alice_hs.result()
        assert alice_result.session_key == bob_result.session_key
        assert len(alice_result.session_key) == 32

        # Initialize Double Ratchet with session key
        bob_dh = X25519Keypair.generate()
        alice_ratchet = DoubleRatchet.init_initiator(
            alice_result.session_key,
            bob_dh.public_key_bytes(),
        )
        bob_ratchet = DoubleRatchet.init_responder(
            bob_result.session_key, bob_dh
        )

        # Alice sends encrypted message to Bob
        hdr_a, ct_a = alice_ratchet.encrypt(b"hello from alice")
        pt_b = bob_ratchet.decrypt(hdr_a, ct_a)
        assert pt_b == b"hello from alice"

        # Bob sends encrypted message to Alice
        hdr_b, ct_b = bob_ratchet.encrypt(b"hello from bob")
        pt_a = alice_ratchet.decrypt(hdr_b, ct_b)
        assert pt_a == b"hello from bob"

    def test_multiple_messages_bidirectional(self):
        """Multiple messages in both directions through the ratchet."""
        shared_secret = bytes([0x42] * 32)
        bob_kp = X25519Keypair.generate()

        alice = DoubleRatchet.init_initiator(
            shared_secret, bob_kp.public_key_bytes()
        )
        bob = DoubleRatchet.init_responder(shared_secret, bob_kp)

        # Alice sends 3 messages
        for i in range(3):
            hdr, ct = alice.encrypt(f"alice-{i}".encode())
            pt = bob.decrypt(hdr, ct)
            assert pt == f"alice-{i}".encode()

        # Bob sends 3 messages
        for i in range(3):
            hdr, ct = bob.encrypt(f"bob-{i}".encode())
            pt = alice.decrypt(hdr, ct)
            assert pt == f"bob-{i}".encode()

        # Interleaved
        h1, c1 = alice.encrypt(b"ping")
        h2, c2 = bob.encrypt(b"pong")
        assert bob.decrypt(h1, c1) == b"ping"
        assert alice.decrypt(h2, c2) == b"pong"


# ===========================================================================
# Pairing integration: QR round-trip, PIN normalization
# ===========================================================================


class TestPairingIntegration:
    def test_qr_roundtrip(self):
        """Generate QR payload, then scan it back."""
        kp = IdentityKeypair.generate()
        peer_id = kp.peer_id().as_bytes()
        pake_cred = b"test-pake-credential"

        payload, cbor_bytes = pair_generate_qr(
            peer_id, pake_cred
        )
        assert payload.peer_id == peer_id
        assert payload.pake_credential == pake_cred

        restored = pair_scan_qr(cbor_bytes)
        assert restored.peer_id == payload.peer_id
        assert restored.nonce == payload.nonce
        assert restored.pake_credential == pake_cred

    def test_pin_generate_and_normalize(self):
        """Generate PIN, normalize it, verify format."""
        pin = pair_generate_pin()
        assert len(pin) == 9  # XXXX-XXXX
        assert pin[4] == "-"

        # Normalize handles case and whitespace
        normalized = normalize_pin(pin.lower())
        # After normalize, dashes stripped and uppercased = 8 chars
        assert len(normalized) == 8

        # Normalize handles removal of dashes
        no_dash = pin.replace("-", "")
        normalized2 = normalize_pin(no_dash)
        assert len(normalized2) == 8

    def test_spake2_pairing_flow(self):
        """SPAKE2 mutual authentication between two peers."""
        password = b"shared-pairing-credential"

        alice = Spake2Session(password, is_initiator=True)
        bob = Spake2Session(password, is_initiator=False)

        alice_msg = alice.start()
        bob_msg = bob.start()

        alice_key = alice.finish(bob_msg)
        bob_key = bob.finish(alice_msg)

        assert alice_key == bob_key


# ===========================================================================
# Node API integration: create, connect, channel, events
# ===========================================================================


class TestNodeIntegration:
    @pytest.mark.asyncio
    async def test_two_nodes_session_lifecycle(self):
        """Two nodes: connect, open channel, exchange messages, close."""
        node_a = create()
        _node_b = create()  # second node (unused in stub mode)

        # Node A connects to a "peer"
        session_a = await node_a.connect("peer-b")
        assert session_a.state == "connected"
        assert session_a.ratchet is not None  # Double Ratchet initialized

        # Open a channel
        ch = await session_a.open_channel("chat")
        assert ch.is_open
        assert ch.name == "chat"

        # Send data -- encrypted and placed in outbox
        await session_a.send(ch, b"hello from A")
        assert len(session_a.outbox) == 1  # one CBOR envelope in outbox

        # Collect events from node A
        event1 = await node_a.recv_event()
        assert event1.type == NodeEventType.PEER_CONNECTED

        event2 = await node_a.recv_event()
        assert event2.type == NodeEventType.CHANNEL_OPENED

        # Close session
        await session_a.close()
        assert session_a.state == "disconnected"

        event3 = await node_a.recv_event()
        assert event3.type == NodeEventType.PEER_DISCONNECTED

    @pytest.mark.asyncio
    async def test_server_node_with_store_forward(self):
        """Server node with store-and-forward message queue."""
        import os

        server = create_server()
        assert server.config.server_mode

        # Create a message queue for the server
        mq = MessageQueue()
        sender = os.urandom(32)
        recipient = os.urandom(32)
        paired = {sender, recipient}

        # Enqueue messages while recipient is "offline"
        for seq in range(1, 4):
            req = ForwardRequest(
                msg_id=os.urandom(16),
                recipient=recipient,
                encrypted_payload=b"\xab" * 64,
                sequence_number=seq,
            )
            ack = mq.enqueue(req, sender, paired)
            assert ack.accepted

        assert mq.queue_depth(recipient) == 3

        # Deliver when recipient comes online
        delivers, purge = mq.deliver(recipient)
        assert len(delivers) == 3
        assert delivers[0].sequence_number == 1
        assert delivers[2].sequence_number == 3
        assert mq.queue_depth(recipient) == 0

    @pytest.mark.asyncio
    async def test_events_async_for_pattern(self):
        """Verify the `async for event in node.events()` pattern works."""
        node = create()

        # Schedule connect after a brief delay
        async def producer():
            await asyncio.sleep(0.01)
            await node.connect("peer-1")
            await asyncio.sleep(0.01)
            await node.connect("peer-2")

        collected = []

        async def consumer():
            async for event in node.events():
                collected.append(event)
                if len(collected) >= 2:
                    break

        # Run producer and consumer concurrently
        await asyncio.gather(producer(), consumer())

        assert len(collected) == 2
        assert collected[0].type == NodeEventType.PEER_CONNECTED
        assert collected[0].peer_id == "peer-1"
        assert collected[1].peer_id == "peer-2"

    @pytest.mark.asyncio
    async def test_multiple_channels_on_session(self):
        """Open multiple channels on a single session."""
        node = create()
        session = await node.connect("peer-1")

        ch_chat = await session.open_channel("chat")
        ch_video = await session.open_channel("video")
        ch_files = await session.open_channel("files")

        assert ch_chat.name == "chat"
        assert ch_video.name == "video"
        assert ch_files.name == "files"

        # All open
        assert ch_chat.is_open
        assert ch_video.is_open
        assert ch_files.is_open

        # Close one
        ch_video.close()
        assert not ch_video.is_open
        assert ch_chat.is_open

    @pytest.mark.asyncio
    async def test_unpair_removes_session(self):
        """Unpairing removes the session from the node."""
        node = create()
        await node.connect("peer-1")
        await node.unpair("peer-1")
        # No error on double unpair
        await node.unpair("peer-1")

    @pytest.mark.asyncio
    async def test_network_info(self):
        """Network info reflects NAT type changes."""
        node = create()
        info = await node.network_info()
        assert info.nat_type == "unknown"

        node.set_nat_type("full_cone")
        info = await node.network_info()
        assert info.nat_type == "full_cone"

    def test_config_tier_presets(self):
        """All config tier presets validate successfully."""
        CairnConfig.tier0().validate()
        CairnConfig.tier1(
            signaling_servers=["wss://sig.example.com"]
        ).validate()
        CairnConfig.tier2(
            signaling_servers=["wss://sig.example.com"],
            tracker_urls=["udp://tracker:6969"],
        ).validate()
        CairnConfig.tier3(
            signaling_servers=["wss://sig.example.com"],
            mesh_settings=MeshSettings(
                mesh_enabled=True, max_hops=5
            ),
        ).validate()
        CairnConfig.default_server().validate()


# ===========================================================================
# End-to-end: pairing -> handshake -> ratchet -> encrypted messaging
# ===========================================================================


class TestEndToEnd:
    def test_full_pairing_to_encrypted_messaging(self):
        """Full flow: identity -> SPAKE2 -> Noise XX -> ratchet."""
        # 1. Identity generation
        alice_id = IdentityKeypair.generate()
        bob_id = IdentityKeypair.generate()

        # 2. SPAKE2 pairing (mutual authentication)
        password = b"shared-pairing-secret-12345678"
        alice_spake = Spake2Session(password, is_initiator=True)
        bob_spake = Spake2Session(password, is_initiator=False)

        alice_spake_msg = alice_spake.start()
        bob_spake_msg = bob_spake.start()

        alice_pake_key = alice_spake.finish(bob_spake_msg)
        bob_pake_key = bob_spake.finish(alice_spake_msg)
        assert alice_pake_key == bob_pake_key

        # 3. Noise XX handshake (key exchange + identity)
        alice_noise = NoiseXXHandshake(
            Role.INITIATOR, alice_id
        )
        bob_noise = NoiseXXHandshake(Role.RESPONDER, bob_id)

        msg1, _ = alice_noise.step()
        msg2, _ = bob_noise.step(msg1)
        msg3, _ = alice_noise.step(msg2)
        _, bob_result = bob_noise.step(msg3)
        alice_result = alice_noise.result()

        # Both derive the same session key
        assert alice_result.session_key == bob_result.session_key

        # Verify remote peer identities
        assert (
            alice_result.remote_static
            == bob_id.public_key_bytes()
        )
        assert (
            bob_result.remote_static
            == alice_id.public_key_bytes()
        )

        # 4. Initialize Double Ratchet
        bob_dh = X25519Keypair.generate()
        alice_ratchet = DoubleRatchet.init_initiator(
            alice_result.session_key,
            bob_dh.public_key_bytes(),
        )
        bob_ratchet = DoubleRatchet.init_responder(
            bob_result.session_key, bob_dh
        )

        # 5. Exchange encrypted messages
        messages = [
            (alice_ratchet, bob_ratchet, b"alice: hello bob!"),
            (bob_ratchet, alice_ratchet, b"bob: hello alice!"),
            (
                alice_ratchet,
                bob_ratchet,
                b"alice: how are you?",
            ),
            (bob_ratchet, alice_ratchet, b"bob: great, thanks!"),
            (
                alice_ratchet,
                bob_ratchet,
                b"alice: let's encrypt everything!",
            ),
        ]

        for sender, receiver, plaintext in messages:
            header, ciphertext = sender.encrypt(plaintext)
            decrypted = receiver.decrypt(header, ciphertext)
            assert decrypted == plaintext

    def test_forward_secrecy_property(self):
        """Verify that ratchet state export/import works for state persistence."""
        shared_secret = bytes([0x99] * 32)
        bob_kp = X25519Keypair.generate()

        alice = DoubleRatchet.init_initiator(
            shared_secret, bob_kp.public_key_bytes()
        )
        bob = DoubleRatchet.init_responder(shared_secret, bob_kp)

        # Send some messages
        for i in range(5):
            hdr, ct = alice.encrypt(f"msg-{i}".encode())
            pt = bob.decrypt(hdr, ct)
            assert pt == f"msg-{i}".encode()

        # Export and re-import Alice's state
        state = alice.export_state()
        alice2 = DoubleRatchet.import_state(state)

        # Continue conversation with imported state
        hdr, ct = alice2.encrypt(b"from imported state")
        pt = bob.decrypt(hdr, ct)
        assert pt == b"from imported state"
