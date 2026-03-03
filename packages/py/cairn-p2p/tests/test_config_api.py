"""Tests for configuration, error types, and public API."""


import pytest

from cairn.config import (
    CairnConfig,
    MeshSettings,
    ReconnectionPolicy,
    TurnServer,
)
from cairn.errors import (
    AuthenticationFailedError,
    CairnError,
    ErrorBehavior,
    MeshRouteNotFoundError,
    PairingExpiredError,
    PairingRejectedError,
    PeerUnreachableError,
    SessionExpiredError,
    TransportExhaustedError,
    VersionMismatchError,
)
from cairn.node import (
    Channel,
    NetworkInfo,
    Node,
    NodeEvent,
    NodeEventType,
    create,
    create_server,
)

# ===========================================================================
# ErrorBehavior enum
# ===========================================================================


class TestErrorBehavior:
    def test_all_values(self):
        values = {e.value for e in ErrorBehavior}
        assert values == {
            "retry",
            "reconnect",
            "abort",
            "regenerate",
            "wait",
            "inform",
        }


# ===========================================================================
# Error types
# ===========================================================================


class TestCairnErrors:
    def test_base_error(self):
        err = CairnError("test")
        assert err.behavior == ErrorBehavior.ABORT
        assert "test" in str(err)

    def test_transport_exhausted(self):
        err = TransportExhaustedError(
            "QUIC: timeout", "deploy a TURN relay"
        )
        assert err.behavior == ErrorBehavior.RETRY
        assert "QUIC: timeout" in str(err)
        assert "deploy a TURN relay" in str(err)
        assert err.details == "QUIC: timeout"
        assert err.suggestion == "deploy a TURN relay"

    def test_session_expired(self):
        err = SessionExpiredError("sess-123", 86400.0)
        assert err.behavior == ErrorBehavior.RECONNECT
        assert "86400" in str(err)
        assert err.session_id == "sess-123"
        assert err.expiry_duration == 86400.0

    def test_peer_unreachable(self):
        err = PeerUnreachableError("peer-abc", 30.0)
        assert err.behavior == ErrorBehavior.WAIT
        assert "peer-abc" in str(err)
        assert err.peer_id == "peer-abc"
        assert err.timeout == 30.0

    def test_authentication_failed(self):
        err = AuthenticationFailedError("sess-456")
        assert err.behavior == ErrorBehavior.ABORT
        assert "authentication failed" in str(err)
        assert err.session_id == "sess-456"

    def test_pairing_rejected(self):
        err = PairingRejectedError("peer-xyz")
        assert err.behavior == ErrorBehavior.INFORM
        assert "peer-xyz" in str(err)
        assert err.peer_id == "peer-xyz"

    def test_pairing_expired(self):
        err = PairingExpiredError(300.0)
        assert err.behavior == ErrorBehavior.REGENERATE
        assert "300" in str(err)
        assert "Generate a new payload" in str(err)
        assert err.expiry == 300.0

    def test_mesh_route_not_found(self):
        err = MeshRouteNotFoundError("peer-mesh", "try direct")
        assert err.behavior == ErrorBehavior.WAIT
        assert "peer-mesh" in str(err)
        assert "try direct" in str(err)

    def test_version_mismatch(self):
        err = VersionMismatchError("1.0", "2.0", "update peer")
        assert err.behavior == ErrorBehavior.ABORT
        assert "1.0" in str(err)
        assert "2.0" in str(err)
        assert "update peer" in str(err)

    def test_transport_exhausted_default_suggestion(self):
        err = TransportExhaustedError("QUIC: timeout")
        assert err.suggestion == "deploy the cairn signaling server and/or TURN relay"
        assert "deploy the cairn signaling server" in str(err)

    def test_mesh_route_not_found_default_suggestion(self):
        err = MeshRouteNotFoundError("peer-mesh")
        expected = "try a direct connection or wait for mesh route discovery"
        assert err.suggestion == expected
        assert "try a direct connection" in str(err)

    def test_version_mismatch_default_suggestion(self):
        err = VersionMismatchError("1.0", "2.0")
        assert err.suggestion == "peer needs to update to a compatible cairn version"
        assert "peer needs to update" in str(err)

    def test_custom_suggestion_overrides_default(self):
        err = TransportExhaustedError("details", "custom suggestion")
        assert err.suggestion == "custom suggestion"

    def test_all_are_cairn_error_subclasses(self):
        errors = [
            TransportExhaustedError(),
            SessionExpiredError(),
            PeerUnreachableError(),
            AuthenticationFailedError(),
            PairingRejectedError(),
            PairingExpiredError(),
            MeshRouteNotFoundError(),
            VersionMismatchError(),
        ]
        for err in errors:
            assert isinstance(err, CairnError)
            assert isinstance(err, Exception)


# ===========================================================================
# ReconnectionPolicy
# ===========================================================================


class TestReconnectionPolicy:
    def test_defaults(self):
        p = ReconnectionPolicy()
        assert p.connect_timeout == 30.0
        assert p.transport_timeout == 10.0
        assert p.reconnect_max_duration == 3600.0
        assert p.reconnect_backoff_initial == 1.0
        assert p.reconnect_backoff_max == 60.0
        assert p.reconnect_backoff_factor == 2.0
        assert p.rendezvous_poll_interval == 30.0
        assert p.session_expiry == 86400.0
        assert p.pairing_payload_expiry == 300.0


# ===========================================================================
# MeshSettings
# ===========================================================================


class TestMeshSettings:
    def test_defaults(self):
        m = MeshSettings()
        assert not m.mesh_enabled
        assert m.max_hops == 3
        assert not m.relay_willing
        assert m.relay_capacity == 10


# ===========================================================================
# CairnConfig
# ===========================================================================


class TestCairnConfig:
    def test_defaults(self):
        cfg = CairnConfig()
        assert len(cfg.stun_servers) == 3
        assert "google.com" in cfg.stun_servers[0]
        assert "cloudflare.com" in cfg.stun_servers[2]
        assert cfg.turn_servers == []
        assert cfg.signaling_servers == []
        assert not cfg.server_mode

    def test_validates_ok(self):
        CairnConfig().validate()  # should not raise

    def test_tier0_is_default(self):
        t0 = CairnConfig.tier0()
        default = CairnConfig()
        assert t0.stun_servers == default.stun_servers
        assert t0.signaling_servers == []
        assert t0.turn_servers == []

    def test_tier1(self):
        t1 = CairnConfig.tier1(
            signaling_servers=["wss://signal.example.com"],
            turn_servers=[
                TurnServer(
                    url="turn:relay.example.com:3478",
                    username="u",
                    credential="p",
                )
            ],
        )
        assert len(t1.signaling_servers) == 1
        assert len(t1.turn_servers) == 1
        t1.validate()

    def test_tier2(self):
        t2 = CairnConfig.tier2(
            signaling_servers=["wss://signal.example.com"],
            tracker_urls=["udp://tracker.example.com:6969"],
            bootstrap_nodes=["/ip4/1.2.3.4/tcp/4001"],
        )
        assert len(t2.tracker_urls) == 1
        assert len(t2.bootstrap_nodes) == 1
        t2.validate()

    def test_tier3(self):
        t3 = CairnConfig.tier3(
            signaling_servers=["wss://signal.example.com"],
            mesh_settings=MeshSettings(
                mesh_enabled=True, max_hops=5
            ),
        )
        assert t3.mesh_settings.mesh_enabled
        assert t3.mesh_settings.max_hops == 5
        t3.validate()

    def test_default_server(self):
        cfg = CairnConfig.default_server()
        assert cfg.server_mode
        assert cfg.mesh_settings.relay_willing
        assert cfg.reconnection_policy.session_expiry == 7 * 86400.0
        cfg.validate()

    def test_validation_empty_stun_no_turn(self):
        cfg = CairnConfig(stun_servers=[])
        with pytest.raises(ValueError, match="stun_servers"):
            cfg.validate()

    def test_validation_empty_stun_with_turn_ok(self):
        cfg = CairnConfig(
            stun_servers=[],
            turn_servers=[TurnServer(url="turn:x", username="u", credential="p")],
        )
        cfg.validate()

    def test_validation_backoff_factor(self):
        cfg = CairnConfig(
            reconnection_policy=ReconnectionPolicy(
                reconnect_backoff_factor=1.0
            )
        )
        with pytest.raises(ValueError, match="backoff_factor"):
            cfg.validate()

    def test_validation_max_hops_zero(self):
        cfg = CairnConfig(
            mesh_settings=MeshSettings(max_hops=0)
        )
        with pytest.raises(ValueError, match="max_hops"):
            cfg.validate()

    def test_validation_max_hops_eleven(self):
        cfg = CairnConfig(
            mesh_settings=MeshSettings(max_hops=11)
        )
        with pytest.raises(ValueError, match="max_hops"):
            cfg.validate()


# ===========================================================================
# Node
# ===========================================================================


class TestNode:
    def test_create_default(self):
        node = create()
        assert not node.config.server_mode

    def test_create_server(self):
        node = create_server()
        assert node.config.server_mode

    def test_create_server_forces_server_mode(self):
        cfg = CairnConfig()
        cfg.server_mode = False
        node = create_server(config=cfg)
        assert node.config.server_mode

    def test_create_with_invalid_config_raises(self):
        cfg = CairnConfig(stun_servers=[])
        with pytest.raises(ValueError):
            Node(cfg)

    @pytest.mark.asyncio
    async def test_connect_creates_session(self):
        node = create()
        session = await node.connect("peer-abc")
        assert session.peer_id == "peer-abc"
        assert session.state == "connected"

    @pytest.mark.asyncio
    async def test_connect_emits_event(self):
        node = create()
        await node.connect("peer-1")
        event = await node.recv_event()
        assert event.type == NodeEventType.PEER_CONNECTED
        assert event.peer_id == "peer-1"

    @pytest.mark.asyncio
    async def test_unpair(self):
        node = create()
        await node.connect("peer-1")
        await node.unpair("peer-1")

    @pytest.mark.asyncio
    async def test_network_info(self):
        node = create()
        info = await node.network_info()
        assert info.nat_type == "unknown"
        assert info.external_addr is None

    @pytest.mark.asyncio
    async def test_set_nat_type(self):
        node = create()
        node.set_nat_type("full_cone")
        info = await node.network_info()
        assert info.nat_type == "full_cone"

    @pytest.mark.asyncio
    async def test_pair_generate_qr(self):
        node = create()
        data = await node.pair_generate_qr()
        assert "expires_in" in data
        assert data["expires_in"] == 300.0

    @pytest.mark.asyncio
    async def test_pair_generate_pin(self):
        node = create()
        data = await node.pair_generate_pin()
        # Real PIN is generated in XXXX-XXXX format
        assert len(data["pin"]) == 9
        assert data["pin"][4] == "-"

    @pytest.mark.asyncio
    async def test_pair_generate_link(self):
        node = create()
        data = await node.pair_generate_link()
        assert data["uri"].startswith("cairn://")

    @pytest.mark.asyncio
    async def test_pair_scan_qr_invalid_data(self):
        node = create()
        with pytest.raises((ValueError, Exception)):
            await node.pair_scan_qr(b"not-valid-cbor")

    @pytest.mark.asyncio
    async def test_pair_scan_qr_roundtrip(self):
        node = create()
        data = await node.pair_generate_qr()
        payload_bytes = data["payload"]
        peer_id = await node.pair_scan_qr(payload_bytes)
        assert isinstance(peer_id, str)
        assert len(peer_id) > 0

    @pytest.mark.asyncio
    async def test_pair_enter_pin(self):
        node = create()
        data = await node.pair_generate_pin()
        peer_id = await node.pair_enter_pin(data["pin"])
        assert isinstance(peer_id, str)
        assert len(peer_id) > 0

    @pytest.mark.asyncio
    async def test_pair_from_link_invalid(self):
        node = create()
        with pytest.raises(ValueError):
            await node.pair_from_link("http://invalid-scheme")

    @pytest.mark.asyncio
    async def test_events_async_iterator(self):
        node = create()
        await node.connect("peer-1")

        collected = []
        async for event in node.events():
            collected.append(event)
            if len(collected) >= 1:
                break

        assert collected[0].type == NodeEventType.PEER_CONNECTED


# ===========================================================================
# Session
# ===========================================================================


class TestSession:
    @pytest.mark.asyncio
    async def test_open_channel(self):
        node = create()
        session = await node.connect("peer-1")
        ch = await session.open_channel("data")
        assert ch.name == "data"
        assert ch.is_open

    @pytest.mark.asyncio
    async def test_open_channel_empty_name(self):
        node = create()
        session = await node.connect("peer-1")
        with pytest.raises(CairnError, match="empty"):
            await session.open_channel("")

    @pytest.mark.asyncio
    async def test_open_channel_reserved_prefix(self):
        node = create()
        session = await node.connect("peer-1")
        with pytest.raises(CairnError, match="reserved"):
            await session.open_channel("__cairn_internal")

    @pytest.mark.asyncio
    async def test_send_on_open_channel(self):
        node = create()
        session = await node.connect("peer-1")
        ch = await session.open_channel("data")
        await session.send(ch, b"hello")

    @pytest.mark.asyncio
    async def test_send_on_closed_channel(self):
        node = create()
        session = await node.connect("peer-1")
        ch = await session.open_channel("data")
        ch.close()
        with pytest.raises(CairnError, match="not open"):
            await session.send(ch, b"hello")

    @pytest.mark.asyncio
    async def test_close(self):
        node = create()
        session = await node.connect("peer-1")
        await session.close()
        assert session.state == "disconnected"

    @pytest.mark.asyncio
    async def test_on_message_callback(self):
        node = create()
        session = await node.connect("peer-1")
        ch = await session.open_channel("data")
        received = []
        session.on_message(ch, lambda d: received.append(d))
        # Callback stored but not invoked in stub

    @pytest.mark.asyncio
    async def test_on_state_change_callback(self):
        node = create()
        session = await node.connect("peer-1")
        states = []
        session.on_state_change(lambda s: states.append(s))


# ===========================================================================
# Channel
# ===========================================================================


class TestChannel:
    def test_lifecycle(self):
        ch = Channel("test")
        assert ch.is_open
        assert ch.name == "test"
        ch.close()
        assert not ch.is_open


# ===========================================================================
# NodeEvent
# ===========================================================================


class TestNodeEvent:
    def test_event_types(self):
        assert len(NodeEventType) == 9

    def test_event_fields(self):
        event = NodeEvent(
            type=NodeEventType.MESSAGE_RECEIVED,
            peer_id="peer-1",
            channel="data",
            data=b"hello",
        )
        assert event.type == NodeEventType.MESSAGE_RECEIVED
        assert event.peer_id == "peer-1"
        assert event.data == b"hello"


# ===========================================================================
# NetworkInfo
# ===========================================================================


class TestNetworkInfo:
    def test_defaults(self):
        info = NetworkInfo()
        assert info.nat_type == "unknown"
        assert info.external_addr is None
