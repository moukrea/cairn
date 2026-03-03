"""Tests for peer discovery: rendezvous IDs, backends, coordinator."""

import pytest

from cairn.discovery.mdns import (
    DhtBackend,
    DiscoveryBackend,
    DiscoveryCoordinator,
    MdnsBackend,
    PeerInfo,
    SignalingBackend,
    TrackerBackend,
)
from cairn.discovery.rendezvous import (
    RendezvousId,
    RotationConfig,
    _derive_epoch_offset,
    active_rendezvous_ids_at,
    compute_epoch,
    derive_pairing_rendezvous_id,
    derive_rendezvous_id,
)


class TestRendezvousId:
    def test_deterministic(self):
        secret = b"shared-pairing-secret"
        id1 = derive_rendezvous_id(secret, 42)
        id2 = derive_rendezvous_id(secret, 42)
        assert id1 == id2

    def test_different_epochs_differ(self):
        secret = b"shared-pairing-secret"
        id1 = derive_rendezvous_id(secret, 1)
        id2 = derive_rendezvous_id(secret, 2)
        assert id1 != id2

    def test_different_secrets_differ(self):
        id1 = derive_rendezvous_id(b"secret-a", 1)
        id2 = derive_rendezvous_id(b"secret-b", 1)
        assert id1 != id2

    def test_to_hex(self):
        rid = RendezvousId(bytes([0xAB] * 32))
        h = rid.to_hex()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_and_eq(self):
        rid1 = RendezvousId(bytes(32))
        rid2 = RendezvousId(bytes(32))
        assert rid1 == rid2
        assert hash(rid1) == hash(rid2)
        s = {rid1, rid2}
        assert len(s) == 1

    def test_repr(self):
        rid = RendezvousId(bytes([0xDE] * 32))
        assert "RendezvousId" in repr(rid)

    def test_invalid_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            RendezvousId(bytes(16))


class TestPairingRendezvousId:
    def test_deterministic(self):
        cred = b"pake-credential"
        nonce = b"nonce-123"
        id1 = derive_pairing_rendezvous_id(cred, nonce)
        id2 = derive_pairing_rendezvous_id(cred, nonce)
        assert id1 == id2

    def test_different_nonces_differ(self):
        cred = b"pake-credential"
        id1 = derive_pairing_rendezvous_id(cred, b"nonce-a")
        id2 = derive_pairing_rendezvous_id(cred, b"nonce-b")
        assert id1 != id2

    def test_differs_from_standard(self):
        secret = b"same-input"
        epoch_salt = (1).to_bytes(8, "big")
        standard = derive_rendezvous_id(secret, 1)
        pairing = derive_pairing_rendezvous_id(secret, epoch_salt)
        assert standard != pairing


class TestComputeEpoch:
    def test_consistent(self):
        secret = b"test-secret"
        ts = 1_700_000_000
        e1 = compute_epoch(secret, 3600.0, ts)
        e2 = compute_epoch(secret, 3600.0, ts)
        assert e1 == e2

    def test_advances_with_time(self):
        secret = b"test-secret"
        e1 = compute_epoch(secret, 3600.0, 1_700_000_000)
        e2 = compute_epoch(secret, 3600.0, 1_700_000_000 + 3600)
        assert e2 == e1 + 1

    def test_zero_interval_rejected(self):
        with pytest.raises(ValueError, match="must be > 0"):
            compute_epoch(b"secret", 0.0, 1_700_000_000)

    def test_different_secrets_different_offsets(self):
        ts = 1_700_000_000
        e1 = compute_epoch(b"secret-a", 3600.0, ts)
        e2 = compute_epoch(b"secret-b", 3600.0, ts)
        assert e1 != e2

    def test_both_peers_same_epoch(self):
        shared = b"shared-secret-alice-bob"
        ts = 1_700_000_000
        alice = compute_epoch(shared, 86400.0, ts)
        bob = compute_epoch(shared, 86400.0, ts)
        assert alice == bob


class TestActiveRendezvousIds:
    def test_single_outside_overlap(self):
        secret = b"test-secret"
        config = RotationConfig(
            rotation_interval=86400.0,
            overlap_window=3600.0,
            clock_tolerance=300.0,
        )
        offset = _derive_epoch_offset(secret)
        interval = 86400
        base_ts = 1_700_000_000
        adjusted = (base_ts + offset) & 0xFFFFFFFFFFFFFFFF
        position = adjusted % interval
        half_overlap = int(3600 / 2 + 300)

        # Find a timestamp in the middle of epoch
        mid_ts = base_ts + (interval // 2 - int(position))
        adjusted2 = (mid_ts + offset) & 0xFFFFFFFFFFFFFFFF
        pos2 = adjusted2 % interval

        if half_overlap <= pos2 <= interval - half_overlap:
            ids = active_rendezvous_ids_at(
                secret, config, mid_ts
            )
            assert len(ids) == 1

    def test_dual_near_boundary(self):
        secret = b"test-secret"
        config = RotationConfig(
            rotation_interval=86400.0,
            overlap_window=3600.0,
            clock_tolerance=300.0,
        )
        offset = _derive_epoch_offset(secret)
        interval = 86400
        n = ((1_700_000_000 + offset) & 0xFFFFFFFFFFFFFFFF) // interval + 1
        boundary_adjusted = n * interval
        boundary_ts = (
            boundary_adjusted - offset
        ) & 0xFFFFFFFFFFFFFFFF

        # Just after boundary
        ids = active_rendezvous_ids_at(
            secret, config, boundary_ts + 100
        )
        assert len(ids) == 2

        # Just before boundary
        ids = active_rendezvous_ids_at(
            secret, config, boundary_ts - 100
        )
        assert len(ids) == 2

    def test_includes_current_epoch_id(self):
        secret = b"test-secret"
        config = RotationConfig()
        ts = 1_700_000_000
        ids = active_rendezvous_ids_at(secret, config, ts)
        epoch = compute_epoch(
            secret, config.rotation_interval, ts
        )
        expected = derive_rendezvous_id(secret, epoch)
        assert expected in ids

    def test_zero_interval_rejected(self):
        config = RotationConfig(rotation_interval=0.0)
        with pytest.raises(ValueError):
            active_rendezvous_ids_at(b"s", config, 1_700_000_000)


class TestRotationConfig:
    def test_defaults(self):
        cfg = RotationConfig()
        assert cfg.rotation_interval == 86400.0
        assert cfg.overlap_window == 3600.0
        assert cfg.clock_tolerance == 300.0


class TestDiscoveryBackend:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            DiscoveryBackend()


class TestMdnsBackend:
    @pytest.mark.asyncio
    async def test_announce_and_query(self):
        backend = MdnsBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1
        assert results[0].peer_id == b"peer1"

    @pytest.mark.asyncio
    async def test_query_empty(self):
        backend = MdnsBackend()
        rid = RendezvousId(bytes(32))
        results = await backend.query(rid)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_stop_clears(self):
        backend = MdnsBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        await backend.stop()
        results = await backend.query(rid)
        assert len(results) == 0


class TestDhtBackend:
    @pytest.mark.asyncio
    async def test_announce_and_query(self):
        backend = DhtBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_multiple_announces(self):
        backend = DhtBackend()
        rid = RendezvousId(bytes(32))
        await backend.announce(
            rid, PeerInfo(peer_id=b"p1", addresses=[])
        )
        await backend.announce(
            rid, PeerInfo(peer_id=b"p2", addresses=[])
        )
        results = await backend.query(rid)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_with_bootstrap_no_network(self):
        """DHT with bootstrap nodes but no network falls back to in-memory."""
        backend = DhtBackend(
            bootstrap_nodes=[("127.0.0.1", 1)]
        )
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1
        assert results[0].peer_id == b"peer1"

    @pytest.mark.asyncio
    async def test_stop_clears_store(self):
        backend = DhtBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        await backend.stop()
        results = await backend.query(rid)
        assert len(results) == 0


class TestTrackerBackend:
    @pytest.mark.asyncio
    async def test_announce_and_query(self):
        backend = TrackerBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1

    def test_reannounce_interval(self):
        assert TrackerBackend.REANNOUNCE_INTERVAL == 900.0

    def test_info_hash_truncation(self):
        from cairn.discovery.mdns import _to_info_hash

        rid = RendezvousId(bytes(range(32)))
        ih = _to_info_hash(rid)
        assert len(ih) == 20
        assert ih == bytes(range(20))

    @pytest.mark.asyncio
    async def test_tracker_with_urls_no_network(self):
        """Tracker with URLs but no network falls back to in-memory."""
        backend = TrackerBackend(
            tracker_urls=["http://localhost:1/announce"]
        )
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1
        assert results[0].peer_id == b"peer1"

    @pytest.mark.asyncio
    async def test_stop_clears_store(self):
        backend = TrackerBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        await backend.stop()
        results = await backend.query(rid)
        assert len(results) == 0

    def test_parse_compact_peers_empty(self):
        result = TrackerBackend._parse_compact_peers(b"")
        assert result == []


class TestSignalingBackend:
    @pytest.mark.asyncio
    async def test_announce_and_query(self):
        backend = SignalingBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_with_urls_no_server(self):
        """Signaling with URLs but no server falls back to in-memory."""
        backend = SignalingBackend(
            server_urls=["ws://localhost:1/signal"]
        )
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await backend.announce(rid, info)
        results = await backend.query(rid)
        assert len(results) == 1
        assert results[0].peer_id == b"peer1"

    @pytest.mark.asyncio
    async def test_auth_token_stored(self):
        backend = SignalingBackend(
            server_urls=["wss://example.com"],
            auth_token="my-token",
        )
        assert backend._auth_token == "my-token"

    @pytest.mark.asyncio
    async def test_stop_clears_store(self):
        backend = SignalingBackend()
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await backend.announce(rid, info)
        await backend.stop()
        results = await backend.query(rid)
        assert len(results) == 0


class TestDiscoveryCoordinator:
    @pytest.mark.asyncio
    async def test_announce_to_all(self):
        mdns = MdnsBackend()
        dht = DhtBackend()
        coord = DiscoveryCoordinator([mdns, dht])
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=["1.2.3.4:5000"])
        await coord.announce(rid, info)

        r1 = await mdns.query(rid)
        r2 = await dht.query(rid)
        assert len(r1) == 1
        assert len(r2) == 1

    @pytest.mark.asyncio
    async def test_query_first_wins(self):
        mdns = MdnsBackend()
        dht = DhtBackend()
        coord = DiscoveryCoordinator([mdns, dht])
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await mdns.announce(rid, info)
        results = await coord.query(rid)
        assert len(results) >= 1
        assert results[0].peer_id == b"peer1"

    @pytest.mark.asyncio
    async def test_query_empty(self):
        coord = DiscoveryCoordinator()
        rid = RendezvousId(bytes(32))
        results = await coord.query(rid)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_stop_all(self):
        mdns = MdnsBackend()
        dht = DhtBackend()
        coord = DiscoveryCoordinator([mdns, dht])
        rid = RendezvousId(bytes(32))
        info = PeerInfo(peer_id=b"peer1", addresses=[])
        await coord.announce(rid, info)
        await coord.stop()
        assert await mdns.query(rid) == []
        assert await dht.query(rid) == []

    @pytest.mark.asyncio
    async def test_add_backend(self):
        coord = DiscoveryCoordinator()
        coord.add_backend(MdnsBackend())
        coord.add_backend(DhtBackend())
        rid = RendezvousId(bytes(32))
        results = await coord.query(rid)
        assert len(results) == 0
