"""Tests for server mode: store-and-forward, management, headless pairing."""

import os
import time

import pytest

from cairn.server.forward import (
    FORWARD_CHANNEL,
    MAX_SKIP_THRESHOLD,
    DeduplicationTracker,
    ForwardAck,
    ForwardDeliver,
    ForwardPurge,
    ForwardRequest,
    MessageQueue,
    RetentionPolicy,
)
from cairn.server.management import (
    DEFAULT_VALIDITY_WINDOW,
    PSK_ENV_VAR,
    HeadlessPairing,
    HeadlessPairingError,
    ManagementConfig,
    ManagementServer,
    ManagementState,
    PeerMetrics,
    PeerQuota,
    PeerRelayStats,
    PeerSyncState,
    PersonalRelayConfig,
    PskNotConfiguredError,
    QueueInfo,
    RelayStats,
    ServerConfig,
)
from cairn.server.management import (
    PeerInfo as MgmtPeerInfo,
)


def _peer() -> bytes:
    return os.urandom(32)


def _msg_id() -> bytes:
    return os.urandom(16)


def _make_request(recipient: bytes, seq: int) -> ForwardRequest:
    return ForwardRequest(
        msg_id=_msg_id(),
        recipient=recipient,
        encrypted_payload=b"\xab" * 64,
        sequence_number=seq,
    )


# ===========================================================================
# ServerConfig
# ===========================================================================


class TestServerConfig:
    def test_defaults(self):
        cfg = ServerConfig()
        assert cfg.mesh_enabled
        assert cfg.relay_willing
        assert cfg.relay_capacity == 100
        assert cfg.store_forward_enabled
        assert cfg.store_forward_max_per_peer == 1_000
        assert cfg.store_forward_max_age == 7 * 24 * 3600.0
        assert cfg.store_forward_max_total_size == 1_073_741_824
        assert cfg.session_expiry == 7 * 24 * 3600.0
        assert cfg.heartbeat_interval == 60.0
        assert cfg.reconnect_max_duration is None
        assert cfg.headless

    def test_retention_policy(self):
        cfg = ServerConfig()
        policy = cfg.retention_policy()
        assert policy.max_age == cfg.store_forward_max_age
        assert policy.max_messages == cfg.store_forward_max_per_peer

    def test_custom(self):
        cfg = ServerConfig(
            relay_capacity=500,
            store_forward_max_per_peer=10_000,
            headless=False,
        )
        assert cfg.relay_capacity == 500
        assert cfg.store_forward_max_per_peer == 10_000
        assert not cfg.headless


# ===========================================================================
# Constants
# ===========================================================================


class TestConstants:
    def test_forward_channel(self):
        assert FORWARD_CHANNEL == "__cairn_forward"

    def test_max_skip_threshold(self):
        assert MAX_SKIP_THRESHOLD == 1_000

    def test_default_validity_window(self):
        assert DEFAULT_VALIDITY_WINDOW == 300.0


# ===========================================================================
# RetentionPolicy
# ===========================================================================


class TestRetentionPolicy:
    def test_defaults(self):
        policy = RetentionPolicy()
        assert policy.max_age == 7 * 24 * 3600.0
        assert policy.max_messages == 1_000


# ===========================================================================
# Forward message types
# ===========================================================================


class TestForwardTypes:
    def test_forward_request_fields(self):
        recipient = _peer()
        req = ForwardRequest(
            msg_id=_msg_id(),
            recipient=recipient,
            encrypted_payload=b"\x01\x02\x03",
            sequence_number=42,
        )
        assert req.recipient == recipient
        assert req.sequence_number == 42
        assert req.encrypted_payload == b"\x01\x02\x03"

    def test_forward_ack_accepted(self):
        ack = ForwardAck(msg_id=_msg_id(), accepted=True)
        assert ack.accepted
        assert ack.rejection_reason is None

    def test_forward_ack_rejected(self):
        ack = ForwardAck(
            msg_id=_msg_id(),
            accepted=False,
            rejection_reason="test reason",
        )
        assert not ack.accepted
        assert ack.rejection_reason == "test reason"

    def test_forward_deliver_fields(self):
        sender = _peer()
        deliver = ForwardDeliver(
            msg_id=_msg_id(),
            sender=sender,
            encrypted_payload=b"\xde\xad",
            sequence_number=99,
        )
        assert deliver.sender == sender
        assert deliver.sequence_number == 99

    def test_forward_purge_fields(self):
        ids = [_msg_id(), _msg_id()]
        purge = ForwardPurge(msg_ids=ids)
        assert len(purge.msg_ids) == 2


# ===========================================================================
# MessageQueue — enqueue
# ===========================================================================


class TestMessageQueueEnqueue:
    def test_enqueue_accepted(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}
        req = _make_request(recipient, 1)
        ack = mq.enqueue(req, sender, paired)
        assert ack.accepted
        assert ack.rejection_reason is None
        assert mq.queue_depth(recipient) == 1

    def test_rejects_unpaired_sender(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {recipient}  # sender not paired
        req = _make_request(recipient, 1)
        ack = mq.enqueue(req, sender, paired)
        assert not ack.accepted
        assert "sender" in ack.rejection_reason

    def test_rejects_unpaired_recipient(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender}  # recipient not paired
        req = _make_request(recipient, 1)
        ack = mq.enqueue(req, sender, paired)
        assert not ack.accepted
        assert "recipient" in ack.rejection_reason

    def test_rejects_duplicate_msg_id(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}
        req = _make_request(recipient, 1)
        mq.enqueue(req, sender, paired)
        ack2 = mq.enqueue(req, sender, paired)
        assert not ack2.accepted
        assert "duplicate" in ack2.rejection_reason

    def test_rejects_queue_full(self):
        policy = RetentionPolicy(max_age=86400.0, max_messages=3)
        mq = MessageQueue(default_policy=policy)
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        for seq in range(1, 4):
            ack = mq.enqueue(_make_request(recipient, seq), sender, paired)
            assert ack.accepted

        ack = mq.enqueue(_make_request(recipient, 4), sender, paired)
        assert not ack.accepted
        assert "queue full" in ack.rejection_reason

    def test_rejects_sequence_gap_exceeding_threshold(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        mq.enqueue(_make_request(recipient, 1), sender, paired)
        # Gap of 1001 exceeds MAX_SKIP_THRESHOLD (1000)
        req_far = _make_request(recipient, 1002)
        ack = mq.enqueue(req_far, sender, paired)
        assert not ack.accepted
        assert "skip threshold" in ack.rejection_reason

    def test_allows_sequence_gap_within_threshold(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        mq.enqueue(_make_request(recipient, 1), sender, paired)
        # Gap of exactly 1000 is within threshold
        ack = mq.enqueue(
            _make_request(recipient, 1001), sender, paired
        )
        assert ack.accepted


# ===========================================================================
# MessageQueue — deliver
# ===========================================================================


class TestMessageQueueDeliver:
    def test_deliver_returns_messages_in_order(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        for seq in range(1, 6):
            mq.enqueue(_make_request(recipient, seq), sender, paired)

        delivers, purge = mq.deliver(recipient)
        assert len(delivers) == 5
        assert len(purge.msg_ids) == 5
        for i, d in enumerate(delivers):
            assert d.sequence_number == i + 1
            assert d.sender == sender
        assert mq.queue_depth(recipient) == 0

    def test_deliver_empty_queue(self):
        mq = MessageQueue()
        delivers, purge = mq.deliver(_peer())
        assert delivers == []
        assert purge.msg_ids == []

    def test_deliver_clears_dedup_entries(self):
        mq = MessageQueue()
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        req = _make_request(recipient, 1)
        msg_id = req.msg_id
        mq.enqueue(req, sender, paired)
        mq.deliver(recipient)

        # Same msg_id should be accepted again after delivery purge
        req2 = ForwardRequest(
            msg_id=msg_id,
            recipient=recipient,
            encrypted_payload=b"\xcd" * 32,
            sequence_number=2,
        )
        ack = mq.enqueue(req2, sender, paired)
        assert ack.accepted


# ===========================================================================
# MessageQueue — retention
# ===========================================================================


class TestMessageQueueRetention:
    def test_expired_messages_pruned_on_enqueue(self):
        policy = RetentionPolicy(max_age=0.0, max_messages=1_000)
        mq = MessageQueue(default_policy=policy)
        sender = _peer()
        recipient = _peer()
        paired = {sender, recipient}

        mq.enqueue(_make_request(recipient, 1), sender, paired)
        time.sleep(0.01)
        mq.enqueue(_make_request(recipient, 2), sender, paired)
        # First should have been expired
        assert mq.queue_depth(recipient) == 1

    def test_per_peer_override(self):
        default_policy = RetentionPolicy(
            max_age=86400.0, max_messages=2
        )
        mq = MessageQueue(default_policy=default_policy)
        sender = _peer()
        priority = _peer()
        regular = _peer()
        paired = {sender, priority, regular}

        mq.set_peer_override(
            priority,
            RetentionPolicy(max_age=86400.0, max_messages=100),
        )

        # Regular peer should hit cap at 2
        for seq in range(1, 4):
            mq.enqueue(
                _make_request(regular, seq), sender, paired
            )
        assert mq.queue_depth(regular) == 2  # capped

        # Priority peer should accept all 3
        for seq in range(1, 4):
            mq.enqueue(
                _make_request(priority, seq), sender, paired
            )
        assert mq.queue_depth(priority) == 3


# ===========================================================================
# MessageQueue — stats
# ===========================================================================


class TestMessageQueueStats:
    def test_total_messages_across_peers(self):
        mq = MessageQueue()
        sender = _peer()
        r1 = _peer()
        r2 = _peer()
        paired = {sender, r1, r2}

        for seq in range(1, 4):
            mq.enqueue(_make_request(r1, seq), sender, paired)
        for seq in range(1, 3):
            mq.enqueue(_make_request(r2, seq), sender, paired)
        assert mq.total_messages() == 5

    def test_queue_stats(self):
        mq = MessageQueue()
        sender = _peer()
        r = _peer()
        paired = {sender, r}
        mq.enqueue(_make_request(r, 1), sender, paired)
        stats = mq.queue_stats()
        assert len(stats) == 1
        peer_id, pending, oldest_age, total_bytes = stats[0]
        assert peer_id == r
        assert pending == 1
        assert oldest_age is not None
        assert oldest_age >= 0
        assert total_bytes == 64  # 64 bytes payload


# ===========================================================================
# DeduplicationTracker
# ===========================================================================


class TestDeduplicationTracker:
    def test_new_message(self):
        tracker = DeduplicationTracker(100)
        assert tracker.check_and_insert(_msg_id())
        assert len(tracker) == 1

    def test_rejects_duplicate(self):
        tracker = DeduplicationTracker(100)
        mid = _msg_id()
        assert tracker.check_and_insert(mid)
        assert not tracker.check_and_insert(mid)
        assert len(tracker) == 1

    def test_evicts_oldest(self):
        tracker = DeduplicationTracker(3)
        id1 = _msg_id()
        id2 = _msg_id()
        id3 = _msg_id()
        id4 = _msg_id()

        tracker.check_and_insert(id1)
        tracker.check_and_insert(id2)
        tracker.check_and_insert(id3)
        assert len(tracker) == 3

        # Adding id4 should evict id1
        tracker.check_and_insert(id4)
        assert len(tracker) == 3

        # id1 should now be accepted again
        assert tracker.check_and_insert(id1)

    def test_is_empty(self):
        tracker = DeduplicationTracker(10)
        assert tracker.is_empty


# ===========================================================================
# ManagementConfig
# ===========================================================================


class TestManagementConfig:
    def test_defaults(self):
        cfg = ManagementConfig()
        assert not cfg.enabled
        assert cfg.is_loopback
        assert cfg.port == 9090
        assert cfg.auth_token == ""

    def test_non_loopback(self):
        cfg = ManagementConfig(bind_address="0.0.0.0")
        assert not cfg.is_loopback


# ===========================================================================
# HeadlessPairing
# ===========================================================================


class TestHeadlessPairing:
    def test_default_validity(self):
        hp = HeadlessPairing()
        assert hp.validity_window == DEFAULT_VALIDITY_WINDOW

    def test_custom_validity(self):
        hp = HeadlessPairing(validity_window=60.0)
        assert hp.validity_window == 60.0

    def test_sas_not_available(self):
        assert not HeadlessPairing.sas_available()

    def test_supported_mechanisms(self):
        mechs = HeadlessPairing.supported_mechanisms()
        assert len(mechs) == 4
        assert "psk" in mechs
        assert "pin" in mechs
        assert "link" in mechs
        assert "qr" in mechs
        assert "sas" not in mechs

    def test_generate_psk_valid(self):
        hp = HeadlessPairing()
        method = hp.generate_psk(b"\xab" * 16)
        assert method.kind == "psk"
        assert method.value == b"\xab" * 16
        assert not method.is_expired

    def test_generate_psk_too_short(self):
        hp = HeadlessPairing()
        with pytest.raises(HeadlessPairingError, match="too short"):
            hp.generate_psk(b"\xab" * 8)

    def test_generate_psk_env_var_not_set(self, monkeypatch):
        monkeypatch.delenv(PSK_ENV_VAR, raising=False)
        hp = HeadlessPairing()
        with pytest.raises(PskNotConfiguredError):
            hp.generate_psk(None)

    def test_generate_psk_from_env(self, monkeypatch):
        key = "A_VERY_LONG_SECRET_KEY_FOR_TESTING"
        monkeypatch.setenv(PSK_ENV_VAR, key)
        hp = HeadlessPairing()
        method = hp.generate_psk(None)
        assert method.kind == "psk"
        assert method.value == key.encode()

    def test_psk_never_expires(self):
        hp = HeadlessPairing()
        method = hp.generate_psk(b"\xab" * 16)
        assert not method.is_expired

    def test_generate_pin(self):
        hp = HeadlessPairing()
        method = hp.generate_pin()
        assert method.kind == "pin"
        pin = method.value
        assert len(pin) == 9  # XXXX-XXXX
        assert pin[4] == "-"
        assert not method.is_expired

    def test_generate_link(self):
        hp = HeadlessPairing()
        method = hp.generate_link("abcd1234")
        assert method.kind == "link"
        assert method.value.startswith("cairn://pair?")
        assert "pid=abcd1234" in method.value
        assert "nonce=" in method.value
        assert not method.is_expired


# ===========================================================================
# PersonalRelayConfig
# ===========================================================================


class TestPersonalRelayConfig:
    def test_defaults(self):
        cfg = PersonalRelayConfig()
        assert cfg.relay_willing
        assert cfg.relay_capacity == 100
        assert cfg.allowed_peers == []

    def test_allows_all_when_empty(self):
        cfg = PersonalRelayConfig()
        assert cfg.is_peer_allowed(_peer())

    def test_restricts_to_allowed(self):
        a = _peer()
        b = _peer()
        c = _peer()
        cfg = PersonalRelayConfig(allowed_peers=[a, b])
        assert cfg.is_peer_allowed(a)
        assert cfg.is_peer_allowed(b)
        assert not cfg.is_peer_allowed(c)


# ===========================================================================
# PeerSyncState
# ===========================================================================


class TestPeerSyncState:
    def test_new_is_zeroed(self):
        peer = _peer()
        state = PeerSyncState(peer_id=peer)
        assert state.peer_id == peer
        assert state.last_seen_sequence == 0
        assert state.pending_deliveries == 0
        assert state.last_connected is None

    def test_lifecycle(self):
        state = PeerSyncState(peer_id=_peer())
        state.mark_connected()
        assert state.last_connected is not None

        state.enqueue_delivery()
        state.enqueue_delivery()
        state.enqueue_delivery()
        assert state.pending_deliveries == 3

        state.advance_sequence(2)
        assert state.last_seen_sequence == 2
        assert state.pending_deliveries == 1

    def test_advance_does_not_go_backwards(self):
        state = PeerSyncState(peer_id=_peer())
        state.advance_sequence(42)
        assert state.last_seen_sequence == 42
        state.advance_sequence(10)
        assert state.last_seen_sequence == 42

    def test_add_pending_and_acknowledge(self):
        state = PeerSyncState(peer_id=_peer())
        state.add_pending(5)
        assert state.pending_deliveries == 5
        state.acknowledge_delivery(3)
        assert state.pending_deliveries == 2
        # Cannot go below zero
        state.acknowledge_delivery(10)
        assert state.pending_deliveries == 0


# ===========================================================================
# PeerMetrics
# ===========================================================================


class TestPeerMetrics:
    def test_new_is_zeroed(self):
        peer = _peer()
        m = PeerMetrics(peer_id=peer)
        assert m.bytes_relayed == 0
        assert m.bytes_stored == 0

    def test_accounting(self):
        m = PeerMetrics(peer_id=_peer())
        m.record_relay(1024)
        m.record_store(512)
        assert m.bytes_relayed == 1024
        assert m.bytes_stored == 512

    def test_release_stored(self):
        m = PeerMetrics(peer_id=_peer())
        m.record_store(2048)
        m.release_stored(1024)
        assert m.bytes_stored == 1024
        # Cannot go below zero
        m.release_stored(5000)
        assert m.bytes_stored == 0


# ===========================================================================
# PeerQuota
# ===========================================================================


class TestPeerQuota:
    def test_default_disabled(self):
        q = PeerQuota()
        assert q.max_stored_messages is None
        assert q.max_relay_bandwidth_bps is None

    def test_check_store_unlimited(self):
        assert PeerQuota().check_store_quota(1_000_000)

    def test_check_store_within_limit(self):
        q = PeerQuota(max_stored_messages=100)
        assert q.check_store_quota(99)
        assert not q.check_store_quota(100)
        assert not q.check_store_quota(101)

    def test_check_relay_unlimited(self):
        assert PeerQuota().check_relay_quota(2**63)

    def test_check_relay_within_limit(self):
        q = PeerQuota(max_relay_bandwidth_bps=1_000_000)
        assert q.check_relay_quota(999_999)
        assert q.check_relay_quota(1_000_000)
        assert not q.check_relay_quota(1_000_001)


# ===========================================================================
# ManagementServer
# ===========================================================================

AUTH_TOKEN = "test-secret-token-1234"


def _make_server(
    peers: list[MgmtPeerInfo] | None = None,
    queues: list[QueueInfo] | None = None,
    relay: RelayStats | None = None,
) -> tuple[ManagementServer, ManagementState]:
    """Create a ManagementServer with a ManagementState for testing."""
    cfg = ManagementConfig(enabled=True, port=0, auth_token=AUTH_TOKEN)
    state = ManagementState(auth_token=AUTH_TOKEN)
    if peers is not None:
        state.peers = peers
    if queues is not None:
        state.queues = queues
    if relay is not None:
        state.relay_stats = relay
    srv = ManagementServer(cfg, state)
    return srv, state


async def _request(
    srv: ManagementServer,
    path: str,
    token: str | None = AUTH_TOKEN,
    method: str = "GET",
) -> tuple[int, dict]:
    """Send a raw HTTP request to the management server and return (status, body)."""
    import asyncio
    import json as _json

    port = srv.port
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"{method} {path} HTTP/1.1\r\n"]
    lines.append(f"Host: 127.0.0.1:{port}\r\n")
    if token is not None:
        lines.append(f"Authorization: Bearer {token}\r\n")
    lines.append("\r\n")
    writer.write("".join(lines).encode())
    await writer.drain()

    # Read response
    data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
    writer.close()
    await writer.wait_closed()

    # Parse status line and body
    text = data.decode("utf-8", errors="replace")
    header_end = text.index("\r\n\r\n")
    status_line = text.split("\r\n", 1)[0]
    status_code = int(status_line.split(" ", 2)[1])
    body_str = text[header_end + 4 :]
    body = _json.loads(body_str) if body_str else {}
    return status_code, body


@pytest.mark.asyncio
class TestManagementServer:
    async def test_rejects_empty_token_config(self):
        with pytest.raises(ValueError, match="auth token is empty"):
            ManagementServer(
                ManagementConfig(enabled=True, auth_token=""),
                ManagementState(auth_token=""),
            )

    async def test_auth_missing_header(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/health", token=None)
            assert status == 401
            assert body["error"] == "unauthorized"
        finally:
            await srv.stop()

    async def test_auth_wrong_token(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/health", token="wrong-token")
            assert status == 401
            assert body["error"] == "unauthorized"
        finally:
            await srv.stop()

    async def test_auth_correct_token(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/health")
            assert status == 200
        finally:
            await srv.stop()

    async def test_method_not_allowed(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/health", method="POST")
            assert status == 405
            assert body["error"] == "method not allowed"
        finally:
            await srv.stop()

    async def test_not_found(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/nonexistent")
            assert status == 404
            assert body["error"] == "not found"
        finally:
            await srv.stop()

    async def test_health_degraded_no_peers(self):
        srv, _ = _make_server(peers=[])
        await srv.start()
        try:
            status, body = await _request(srv, "/health")
            assert status == 200
            assert body["status"] == "degraded"
            assert body["connected_peers"] == 0
            assert body["total_peers"] == 0
            assert "uptime_secs" in body
        finally:
            await srv.stop()

    async def test_health_healthy_with_connected_peer(self):
        peers = [
            MgmtPeerInfo(peer_id="aabb", name="phone", connected=True),
            MgmtPeerInfo(peer_id="ccdd", name="laptop", connected=False),
        ]
        srv, _ = _make_server(peers=peers)
        await srv.start()
        try:
            status, body = await _request(srv, "/health")
            assert status == 200
            assert body["status"] == "healthy"
            assert body["connected_peers"] == 1
            assert body["total_peers"] == 2
        finally:
            await srv.stop()

    async def test_peers_empty(self):
        srv, _ = _make_server(peers=[])
        await srv.start()
        try:
            status, body = await _request(srv, "/peers")
            assert status == 200
            assert body["peers"] == []
        finally:
            await srv.stop()

    async def test_peers_with_data(self):
        peers = [
            MgmtPeerInfo(
                peer_id="aabb",
                name="phone",
                connected=True,
                last_seen="2026-01-01T00:00:00Z",
            ),
        ]
        srv, _ = _make_server(peers=peers)
        await srv.start()
        try:
            status, body = await _request(srv, "/peers")
            assert status == 200
            assert len(body["peers"]) == 1
            p = body["peers"][0]
            assert p["peer_id"] == "aabb"
            assert p["name"] == "phone"
            assert p["connected"] is True
            assert p["last_seen"] == "2026-01-01T00:00:00Z"
        finally:
            await srv.stop()

    async def test_queues_empty(self):
        srv, _ = _make_server(queues=[])
        await srv.start()
        try:
            status, body = await _request(srv, "/queues")
            assert status == 200
            assert body["queues"] == []
        finally:
            await srv.stop()

    async def test_queues_with_data(self):
        queues = [
            QueueInfo(
                peer_id="aabb",
                pending_messages=5,
                oldest_message_age_secs=120.5,
                total_bytes=2048,
            ),
        ]
        srv, _ = _make_server(queues=queues)
        await srv.start()
        try:
            status, body = await _request(srv, "/queues")
            assert status == 200
            assert len(body["queues"]) == 1
            q = body["queues"][0]
            assert q["peer_id"] == "aabb"
            assert q["pending_messages"] == 5
            assert q["oldest_message_age_secs"] == 120.5
            assert q["total_bytes"] == 2048
        finally:
            await srv.stop()

    async def test_relay_stats_default(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/relay/stats")
            assert status == 200
            assert body["relay"]["active_connections"] == 0
            assert body["relay"]["per_peer"] == []
        finally:
            await srv.stop()

    async def test_relay_stats_with_data(self):
        relay = RelayStats(
            active_connections=3,
            per_peer=[
                PeerRelayStats(
                    peer_id="aabb", bytes_relayed=4096, active_streams=2
                ),
            ],
        )
        srv, _ = _make_server(relay=relay)
        await srv.start()
        try:
            status, body = await _request(srv, "/relay/stats")
            assert status == 200
            assert body["relay"]["active_connections"] == 3
            assert len(body["relay"]["per_peer"]) == 1
            ps = body["relay"]["per_peer"][0]
            assert ps["peer_id"] == "aabb"
            assert ps["bytes_relayed"] == 4096
            assert ps["active_streams"] == 2
        finally:
            await srv.stop()

    async def test_pairing_qr_placeholder(self):
        srv, _ = _make_server()
        await srv.start()
        try:
            status, body = await _request(srv, "/pairing/qr")
            assert status == 503
            assert "not yet available" in body["error"]
        finally:
            await srv.stop()
