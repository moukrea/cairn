"""Tests for transport layer: chain, NAT detection, TCP."""

import asyncio
import struct

import pytest

from cairn.transport.chain import (
    FallbackChain,
    Transport,
    TransportAttemptResult,
    TransportExhaustedError,
    TransportType,
)
from cairn.transport.nat import (
    STUN_BINDING_RESPONSE,
    STUN_MAGIC_COOKIE,
    NatDetector,
    NatType,
    NetworkInfo,
    build_binding_request,
    parse_binding_response,
)
from cairn.transport.tcp import TcpTransport


class TestTransportType:
    def test_nine_transport_types(self):
        all_types = TransportType.all_in_order()
        assert len(all_types) == 9

    def test_priorities_sequential(self):
        for i, tt in enumerate(TransportType.all_in_order()):
            assert tt.priority == i + 1

    def test_tier0_availability(self):
        assert TransportType.DIRECT_QUIC.tier0_available
        assert TransportType.STUN_HOLE_PUNCH.tier0_available
        assert TransportType.DIRECT_TCP.tier0_available
        assert not TransportType.TURN_UDP.tier0_available
        assert not TransportType.TURN_TCP.tier0_available
        assert not TransportType.WEBSOCKET_TLS.tier0_available
        assert not TransportType.WEBTRANSPORT_H3.tier0_available
        assert TransportType.CIRCUIT_RELAY_V2.tier0_available
        assert not TransportType.HTTPS_LONG_POLL.tier0_available

    def test_display_names(self):
        assert TransportType.DIRECT_QUIC.display_name == "Direct QUIC v1"
        assert (
            TransportType.HTTPS_LONG_POLL.display_name
            == "HTTPS long-polling"
        )


class TestTransportABC:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            Transport()

    def test_concrete_subclass(self):
        class MockTransport(Transport):
            async def connect(self, addr, timeout=10.0):
                pass

            async def send(self, data):
                pass

            async def receive(self):
                return b""

            async def close(self):
                pass

        t = MockTransport()
        assert isinstance(t, Transport)


class TestFallbackChain:
    def test_tier0_availability(self):
        chain = FallbackChain.tier0()
        transports = chain.transports
        assert len(transports) == 9

        assert transports[0].available  # QUIC
        assert transports[1].available  # STUN
        assert transports[2].available  # TCP
        assert not transports[3].available  # TURN UDP
        assert not transports[4].available  # TURN TCP
        assert not transports[5].available  # WebSocket
        assert not transports[6].available  # WebTransport
        assert transports[7].available  # Circuit Relay
        assert not transports[8].available  # HTTPS

    def test_full_chain_all_available(self):
        chain = FallbackChain(
            has_turn=True, has_relay_443=True
        )
        assert all(t.available for t in chain.transports)

    @pytest.mark.asyncio
    async def test_sequential_first_succeeds(self):
        chain = FallbackChain.tier0(per_transport_timeout=5.0)

        async def attempt(tt, timeout):
            if tt == TransportType.DIRECT_QUIC:
                return 42
            raise ConnectionError("not available")

        tt, value = await chain.execute(attempt)
        assert tt == TransportType.DIRECT_QUIC
        assert value == 42

    @pytest.mark.asyncio
    async def test_sequential_fallback_to_tcp(self):
        chain = FallbackChain.tier0(per_transport_timeout=5.0)

        async def attempt(tt, timeout):
            if tt == TransportType.DIRECT_TCP:
                return "tcp"
            raise ConnectionError(f"{tt} failed")

        tt, value = await chain.execute(attempt)
        assert tt == TransportType.DIRECT_TCP
        assert value == "tcp"

    @pytest.mark.asyncio
    async def test_sequential_all_fail(self):
        chain = FallbackChain.tier0(per_transport_timeout=1.0)

        async def attempt(tt, timeout):
            raise ConnectionError(f"{tt} failed")

        with pytest.raises(TransportExhaustedError) as exc_info:
            await chain.execute(attempt)

        err = exc_info.value
        assert "Direct QUIC v1" in err.details
        assert "Direct TCP" in err.details
        assert "skipped" in err.details
        assert "deploy companion infrastructure" in err.suggestion

    @pytest.mark.asyncio
    async def test_parallel_first_success_wins(self):
        chain = FallbackChain(parallel_mode=True)

        async def attempt(tt, timeout):
            if tt == TransportType.DIRECT_TCP:
                await asyncio.sleep(0.01)
                return "tcp"
            elif tt == TransportType.DIRECT_QUIC:
                await asyncio.sleep(0.1)
                return "quic"
            raise ConnectionError(f"{tt} failed")

        tt, value = await chain.execute(attempt)
        assert tt == TransportType.DIRECT_TCP
        assert value == "tcp"

    @pytest.mark.asyncio
    async def test_parallel_all_fail(self):
        chain = FallbackChain(parallel_mode=True)

        async def attempt(tt, timeout):
            raise ConnectionError(f"{tt} failed")

        with pytest.raises(TransportExhaustedError):
            await chain.execute(attempt)

    def test_parallel_mode_flag(self):
        chain = FallbackChain(parallel_mode=True)
        assert chain.parallel_mode

        chain2 = FallbackChain(parallel_mode=False)
        assert not chain2.parallel_mode


class TestTransportAttemptResult:
    def test_display_success(self):
        r = TransportAttemptResult(
            transport_type=TransportType.DIRECT_TCP,
            duration=0.5,
        )
        assert "success" in str(r)
        assert "Direct TCP" in str(r)

    def test_display_skipped(self):
        r = TransportAttemptResult(
            transport_type=TransportType.TURN_UDP,
            skipped=True,
        )
        assert "skipped" in str(r)

    def test_display_failed(self):
        r = TransportAttemptResult(
            transport_type=TransportType.DIRECT_QUIC,
            error="connection refused",
            duration=1.2,
        )
        assert "failed" in str(r)
        assert "connection refused" in str(r)


class TestNatType:
    def test_all_values(self):
        assert len(NatType) == 6

    def test_str_representation(self):
        assert str(NatType.OPEN) == "open"
        assert str(NatType.FULL_CONE) == "full_cone"
        assert str(NatType.RESTRICTED_CONE) == "restricted_cone"
        assert (
            str(NatType.PORT_RESTRICTED_CONE) == "port_restricted_cone"
        )
        assert str(NatType.SYMMETRIC) == "symmetric"
        assert str(NatType.UNKNOWN) == "unknown"


class TestNetworkInfo:
    def test_defaults(self):
        info = NetworkInfo()
        assert info.nat_type == NatType.UNKNOWN
        assert info.external_addr is None


class TestStunParsing:
    def test_build_binding_request(self):
        txn_id = bytes([1] * 12)
        req = build_binding_request(txn_id)
        assert len(req) == 20
        msg_type = struct.unpack(">H", req[0:2])[0]
        assert msg_type == 0x0001
        msg_len = struct.unpack(">H", req[2:4])[0]
        assert msg_len == 0
        magic = struct.unpack(">I", req[4:8])[0]
        assert magic == STUN_MAGIC_COOKIE
        assert req[8:20] == txn_id

    def test_parse_xor_mapped_ipv4(self):
        txn_id = bytes([0xAA] * 12)
        resp = bytearray()
        # Header
        resp.extend(struct.pack(">H", STUN_BINDING_RESPONSE))
        resp.extend(struct.pack(">H", 0))  # will fix later
        resp.extend(struct.pack(">I", STUN_MAGIC_COOKIE))
        resp.extend(txn_id)

        # XOR-MAPPED-ADDRESS attribute
        resp.extend(struct.pack(">H", 0x0020))  # type
        resp.extend(struct.pack(">H", 8))  # length
        resp.append(0x00)  # reserved
        resp.append(0x01)  # IPv4
        port = 12345
        xor_port = port ^ (STUN_MAGIC_COOKIE >> 16)
        resp.extend(struct.pack(">H", xor_port))
        ip_int = (192 << 24) | (168 << 16) | (1 << 8) | 100
        xor_ip = ip_int ^ STUN_MAGIC_COOKIE
        resp.extend(struct.pack(">I", xor_ip))

        # Fix message length
        msg_len = len(resp) - 20
        struct.pack_into(">H", resp, 2, msg_len)

        addr = parse_binding_response(bytes(resp), txn_id)
        assert addr == ("192.168.1.100", 12345)

    def test_rejects_short_response(self):
        with pytest.raises(ValueError, match="too short"):
            parse_binding_response(bytes(10), bytes(12))

    def test_rejects_wrong_message_type(self):
        txn_id = bytes(12)
        resp = bytearray(20)
        struct.pack_into(">H", resp, 0, 0x0111)
        struct.pack_into(">I", resp, 4, STUN_MAGIC_COOKIE)
        resp[8:20] = txn_id
        with pytest.raises(ValueError, match="unexpected"):
            parse_binding_response(bytes(resp), txn_id)

    def test_rejects_wrong_txn_id(self):
        txn_id = bytes([0xBB] * 12)
        wrong_id = bytes([0xCC] * 12)
        resp = bytearray(20)
        struct.pack_into(">H", resp, 0, STUN_BINDING_RESPONSE)
        struct.pack_into(">I", resp, 4, STUN_MAGIC_COOKIE)
        resp[8:20] = wrong_id
        with pytest.raises(ValueError, match="mismatch"):
            parse_binding_response(bytes(resp), txn_id)


class TestNatClassification:
    def test_empty_is_unknown(self):
        detector = NatDetector(stun_servers=[])
        assert detector._classify_nat([]) == NatType.UNKNOWN

    def test_single_server_is_unknown(self):
        detector = NatDetector(stun_servers=[])
        result = detector._classify_nat(
            [(("1.1.1.1", 3478), ("203.0.113.50", 54321))]
        )
        assert result == NatType.UNKNOWN

    def test_same_mapping_is_cone(self):
        detector = NatDetector(stun_servers=[])
        mapped = [
            (("1.1.1.1", 3478), ("203.0.113.50", 54321)),
            (("8.8.8.8", 3478), ("203.0.113.50", 54321)),
        ]
        assert (
            detector._classify_nat(mapped)
            == NatType.PORT_RESTRICTED_CONE
        )

    def test_different_ips_is_symmetric(self):
        detector = NatDetector(stun_servers=[])
        mapped = [
            (("1.1.1.1", 3478), ("203.0.113.50", 54321)),
            (("8.8.8.8", 3478), ("203.0.113.51", 54321)),
        ]
        assert detector._classify_nat(mapped) == NatType.SYMMETRIC

    def test_different_ports_is_symmetric(self):
        detector = NatDetector(stun_servers=[])
        mapped = [
            (("1.1.1.1", 3478), ("203.0.113.50", 54321)),
            (("8.8.8.8", 3478), ("203.0.113.50", 54322)),
        ]
        assert detector._classify_nat(mapped) == NatType.SYMMETRIC

    @pytest.mark.asyncio
    async def test_detect_with_no_servers(self):
        detector = NatDetector(stun_servers=[])
        info = await detector.detect()
        assert info.nat_type == NatType.UNKNOWN
        assert info.external_addr is None


class TestTcpTransport:
    @pytest.mark.asyncio
    async def test_roundtrip(self):
        """Test TCP transport with a local echo server."""
        received = []

        async def handle_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ):
            header = await reader.readexactly(4)
            length = struct.unpack(">I", header)[0]
            data = await reader.readexactly(length)
            received.append(data)
            # Echo back
            writer.write(struct.pack(">I", len(data)) + data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(
            handle_client, "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]

        try:
            transport = TcpTransport()
            await transport.connect(f"127.0.0.1:{port}")
            await transport.send(b"hello cairn")
            response = await transport.receive()
            assert response == b"hello cairn"
            assert received == [b"hello cairn"]
            await transport.close()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_send_before_connect_raises(self):
        transport = TcpTransport()
        with pytest.raises(ConnectionError, match="not connected"):
            await transport.send(b"data")

    @pytest.mark.asyncio
    async def test_receive_before_connect_raises(self):
        transport = TcpTransport()
        with pytest.raises(ConnectionError, match="not connected"):
            await transport.receive()

    @pytest.mark.asyncio
    async def test_close_before_connect(self):
        transport = TcpTransport()
        await transport.close()  # should not raise

    @pytest.mark.asyncio
    async def test_connect_timeout(self):
        transport = TcpTransport()
        # Use a non-routable address to trigger timeout
        with pytest.raises(
            (asyncio.TimeoutError, OSError, ConnectionRefusedError)
        ):
            await transport.connect(
                "192.0.2.1:9999", timeout=0.1
            )
