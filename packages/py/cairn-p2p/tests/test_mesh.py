"""Tests for mesh routing and relay."""

import os

import pytest

from cairn.mesh.relay import RelayManager, RelaySession
from cairn.mesh.router import (
    MaxHopsExceededError,
    MeshConfig,
    MeshTopologyUpdate,
    NoRouteError,
    ReachabilityEntry,
    RelayCapacityFullError,
    RelayNotWillingError,
    Route,
    RoutingTable,
)


def _peer() -> bytes:
    return os.urandom(32)


class TestMeshConfig:
    def test_defaults(self):
        cfg = MeshConfig()
        assert not cfg.mesh_enabled
        assert cfg.max_hops == 3
        assert not cfg.relay_willing
        assert cfg.relay_capacity == 10

    def test_server_mode(self):
        cfg = MeshConfig.server_mode()
        assert cfg.mesh_enabled
        assert cfg.relay_willing
        assert cfg.relay_capacity == 100
        assert cfg.max_hops == 3


class TestRoute:
    def test_direct(self):
        r = Route.direct(10, 1_000_000)
        assert r.hop_count == 0
        assert r.latency_ms == 10
        assert r.bandwidth_bps == 1_000_000

    def test_relayed(self):
        relay = _peer()
        r = Route.relayed([relay], 50, 500_000)
        assert r.hop_count == 1
        assert r.hops == [relay]

    def test_selection_key_ordering(self):
        direct = Route.direct(100, 100_000)
        relayed = Route.relayed([_peer()], 5, 10_000_000)
        # Direct (0 hops) should sort before relayed (1 hop)
        assert direct.selection_key() < relayed.selection_key()


class TestRoutingTable:
    def test_add_and_select(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(dest, Route.direct(20, 1_000_000))
        best = rt.select_best_route(dest)
        assert best.hop_count == 0
        assert best.latency_ms == 20

    def test_max_hops_enforced(self):
        rt = RoutingTable(max_hops=2)
        dest = _peer()
        hops = [_peer() for _ in range(3)]
        with pytest.raises(MaxHopsExceededError) as exc_info:
            rt.add_route(dest, Route.relayed(hops, 100, 100_000))
        assert exc_info.value.got == 3
        assert exc_info.value.max_hops == 2

    def test_prefers_fewer_hops(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(
            dest,
            Route.relayed([_peer()], 5, 10_000_000),
        )
        rt.add_route(dest, Route.direct(100, 100_000))
        best = rt.select_best_route(dest)
        assert best.hop_count == 0  # direct wins

    def test_prefers_lower_latency(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(dest, Route.direct(100, 1_000_000))
        rt.add_route(dest, Route.direct(10, 1_000_000))
        best = rt.select_best_route(dest)
        assert best.latency_ms == 10

    def test_prefers_higher_bandwidth(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(dest, Route.direct(10, 100_000))
        rt.add_route(dest, Route.direct(10, 10_000_000))
        best = rt.select_best_route(dest)
        assert best.bandwidth_bps == 10_000_000

    def test_no_route_error(self):
        rt = RoutingTable(max_hops=3)
        with pytest.raises(NoRouteError):
            rt.select_best_route(_peer())

    def test_remove_routes(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(dest, Route.direct(10, 1_000_000))
        assert rt.peer_count == 1
        rt.remove_routes(dest)
        assert rt.peer_count == 0

    def test_peer_and_route_counts(self):
        rt = RoutingTable(max_hops=3)
        d1 = _peer()
        d2 = _peer()
        rt.add_route(d1, Route.direct(10, 1_000_000))
        rt.add_route(d1, Route.direct(20, 500_000))
        rt.add_route(d2, Route.direct(15, 800_000))
        assert rt.peer_count == 2
        assert rt.route_count == 3

    def test_destinations(self):
        rt = RoutingTable(max_hops=3)
        d1 = _peer()
        d2 = _peer()
        rt.add_route(d1, Route.direct(10, 1_000_000))
        rt.add_route(d2, Route.direct(20, 500_000))
        dests = rt.destinations()
        assert len(dests) == 2
        assert d1 in dests
        assert d2 in dests

    def test_get_routes(self):
        rt = RoutingTable(max_hops=3)
        dest = _peer()
        rt.add_route(dest, Route.direct(10, 1_000_000))
        rt.add_route(dest, Route.direct(20, 500_000))
        routes = rt.get_routes(dest)
        assert routes is not None
        assert len(routes) == 2

    def test_get_routes_none(self):
        rt = RoutingTable(max_hops=3)
        assert rt.get_routes(_peer()) is None

    def test_apply_topology_update(self):
        rt = RoutingTable(max_hops=3)
        neighbor = _peer()
        remote = _peer()
        update = MeshTopologyUpdate(
            reachable_peers=[
                ReachabilityEntry(
                    peer_id=remote,
                    via_hops=[],
                    latency_ms=30,
                    bandwidth_bps=500_000,
                )
            ]
        )
        added = rt.apply_topology_update(neighbor, update)
        assert added == 1
        best = rt.select_best_route(remote)
        assert best.hop_count == 1
        assert best.hops[0] == neighbor

    def test_topology_update_exceeding_max_hops(self):
        rt = RoutingTable(max_hops=1)
        neighbor = _peer()
        relay = _peer()
        remote = _peer()
        update = MeshTopologyUpdate(
            reachable_peers=[
                ReachabilityEntry(
                    peer_id=remote,
                    via_hops=[relay],
                    latency_ms=30,
                    bandwidth_bps=500_000,
                )
            ]
        )
        added = rt.apply_topology_update(neighbor, update)
        assert added == 0
        with pytest.raises(NoRouteError):
            rt.select_best_route(remote)

    def test_max_hops_property(self):
        rt = RoutingTable(max_hops=5)
        assert rt.max_hops == 5


class TestMeshErrors:
    def test_error_messages(self):
        from cairn.mesh.router import MeshDisabledError
        assert "disabled" in str(MeshDisabledError())
        assert "no route" in str(NoRouteError("abc"))
        assert "4 > 3" in str(MaxHopsExceededError(4, 3))
        assert "10/10" in str(RelayCapacityFullError(10, 10))
        assert "not willing" in str(RelayNotWillingError())


class TestRelayManager:
    def test_create_session(self):
        cfg = MeshConfig(relay_willing=True, relay_capacity=10)
        mgr = RelayManager(cfg)
        src = _peer()
        dst = _peer()
        sess = mgr.create_session(src, dst)
        assert isinstance(sess, RelaySession)
        assert sess.source == src
        assert sess.destination == dst
        assert sess.bytes_relayed == 0
        assert mgr.active_sessions == 1

    def test_not_willing_raises(self):
        cfg = MeshConfig(relay_willing=False)
        mgr = RelayManager(cfg)
        with pytest.raises(RelayNotWillingError):
            mgr.create_session(_peer(), _peer())

    def test_capacity_full_raises(self):
        cfg = MeshConfig(relay_willing=True, relay_capacity=2)
        mgr = RelayManager(cfg)
        mgr.create_session(_peer(), _peer())
        mgr.create_session(_peer(), _peer())
        with pytest.raises(RelayCapacityFullError) as exc_info:
            mgr.create_session(_peer(), _peer())
        assert exc_info.value.current == 2
        assert exc_info.value.capacity == 2

    def test_get_session(self):
        cfg = MeshConfig(relay_willing=True)
        mgr = RelayManager(cfg)
        sess = mgr.create_session(_peer(), _peer())
        found = mgr.get_session(sess.session_id)
        assert found is sess

    def test_get_session_not_found(self):
        mgr = RelayManager(MeshConfig(relay_willing=True))
        assert mgr.get_session(b"nonexistent") is None

    def test_close_session(self):
        cfg = MeshConfig(relay_willing=True)
        mgr = RelayManager(cfg)
        sess = mgr.create_session(_peer(), _peer())
        assert mgr.active_sessions == 1
        mgr.close_session(sess.session_id)
        assert mgr.active_sessions == 0

    def test_close_all(self):
        cfg = MeshConfig(relay_willing=True, relay_capacity=10)
        mgr = RelayManager(cfg)
        for _ in range(5):
            mgr.create_session(_peer(), _peer())
        assert mgr.active_sessions == 5
        mgr.close_all()
        assert mgr.active_sessions == 0

    def test_record_forwarded(self):
        cfg = MeshConfig(relay_willing=True)
        mgr = RelayManager(cfg)
        sess = mgr.create_session(_peer(), _peer())
        sess.record_forwarded(1024)
        sess.record_forwarded(2048)
        assert sess.bytes_relayed == 3072
