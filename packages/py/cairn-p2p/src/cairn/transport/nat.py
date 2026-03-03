"""NAT type detection via STUN (RFC 5389)."""

from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import dataclass
from enum import Enum, auto

# STUN constants (RFC 5389)
STUN_MAGIC_COOKIE: int = 0x2112_A442
STUN_BINDING_REQUEST: int = 0x0001
STUN_BINDING_RESPONSE: int = 0x0101
ATTR_XOR_MAPPED_ADDRESS: int = 0x0020
ATTR_MAPPED_ADDRESS: int = 0x0001

DEFAULT_STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

DEFAULT_STUN_TIMEOUT: float = 3.0


class NatType(Enum):
    """Detected NAT type (diagnostic only, not for application logic)."""

    OPEN = auto()
    FULL_CONE = auto()
    RESTRICTED_CONE = auto()
    PORT_RESTRICTED_CONE = auto()
    SYMMETRIC = auto()
    UNKNOWN = auto()

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class NetworkInfo:
    """Read-only network diagnostic info."""

    nat_type: NatType = NatType.UNKNOWN
    external_addr: tuple[str, int] | None = None


def build_binding_request(transaction_id: bytes) -> bytes:
    """Build a minimal STUN Binding Request (20 bytes)."""
    buf = bytearray(20)
    struct.pack_into(">HH", buf, 0, STUN_BINDING_REQUEST, 0)
    struct.pack_into(">I", buf, 4, STUN_MAGIC_COOKIE)
    buf[8:20] = transaction_id
    return bytes(buf)


def parse_xor_mapped_address(
    data: bytes, txn_id: bytes
) -> tuple[str, int] | None:
    """Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2)."""
    if len(data) < 8:
        return None
    family = data[1]
    xor_port = struct.unpack(">H", data[2:4])[0] ^ (
        STUN_MAGIC_COOKIE >> 16
    )

    if family == 0x01:  # IPv4
        xor_ip = struct.unpack(">I", data[4:8])[0] ^ STUN_MAGIC_COOKIE
        ip_bytes = struct.pack(">I", xor_ip)
        ip = ".".join(str(b) for b in ip_bytes)
        return (ip, xor_port)
    elif family == 0x02:  # IPv6
        if len(data) < 20:
            return None
        ip_raw = bytearray(data[4:20])
        xor_key = struct.pack(">I", STUN_MAGIC_COOKIE) + txn_id
        for i in range(16):
            ip_raw[i] ^= xor_key[i]
        parts = []
        for i in range(0, 16, 2):
            parts.append(f"{ip_raw[i]:02x}{ip_raw[i+1]:02x}")
        ip = ":".join(parts)
        return (ip, xor_port)
    return None


def parse_mapped_address(data: bytes) -> tuple[str, int] | None:
    """Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1)."""
    if len(data) < 8:
        return None
    family = data[1]
    port = struct.unpack(">H", data[2:4])[0]

    if family == 0x01:
        ip = ".".join(str(b) for b in data[4:8])
        return (ip, port)
    elif family == 0x02:
        if len(data) < 20:
            return None
        parts = []
        for i in range(4, 20, 2):
            parts.append(f"{data[i]:02x}{data[i+1]:02x}")
        ip = ":".join(parts)
        return (ip, port)
    return None


def parse_binding_response(
    data: bytes, expected_txn_id: bytes
) -> tuple[str, int]:
    """Parse a STUN Binding Response.

    Returns (ip, port) of the mapped address.
    Raises ValueError on invalid responses.
    """
    if len(data) < 20:
        raise ValueError("STUN response too short")

    msg_type = struct.unpack(">H", data[0:2])[0]
    if msg_type != STUN_BINDING_RESPONSE:
        raise ValueError(
            f"unexpected STUN message type: 0x{msg_type:04x}"
        )

    msg_len = struct.unpack(">H", data[2:4])[0]
    magic = struct.unpack(">I", data[4:8])[0]
    if magic != STUN_MAGIC_COOKIE:
        raise ValueError("invalid STUN magic cookie")

    if data[8:20] != expected_txn_id:
        raise ValueError("STUN transaction ID mismatch")

    # Parse attributes
    attrs = data[20 : 20 + min(msg_len, len(data) - 20)]
    offset = 0
    xor_mapped = None
    mapped = None

    while offset + 4 <= len(attrs):
        attr_type = struct.unpack(">H", attrs[offset : offset + 2])[0]
        attr_len = struct.unpack(
            ">H", attrs[offset + 2 : offset + 4]
        )[0]
        attr_start = offset + 4

        if attr_start + attr_len > len(attrs):
            break

        attr_data = attrs[attr_start : attr_start + attr_len]

        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            xor_mapped = parse_xor_mapped_address(
                attr_data, expected_txn_id
            )
        elif attr_type == ATTR_MAPPED_ADDRESS:
            mapped = parse_mapped_address(attr_data)

        padded_len = (attr_len + 3) & ~3
        offset = attr_start + padded_len

    result = xor_mapped or mapped
    if result is None:
        raise ValueError("no mapped address in STUN response")
    return result


class NatDetector:
    """STUN-based NAT type detector."""

    def __init__(
        self,
        stun_servers: list[tuple[str, int]] | None = None,
        timeout: float = DEFAULT_STUN_TIMEOUT,
    ) -> None:
        if stun_servers is None:
            self._stun_servers = list(DEFAULT_STUN_SERVERS)
        else:
            self._stun_servers = stun_servers
        self._timeout = timeout

    async def detect(self) -> NetworkInfo:
        """Detect NAT type by querying STUN servers.

        Returns NetworkInfo with UNKNOWN if detection fails.
        """
        if not self._stun_servers:
            return NetworkInfo()

        mapped: list[tuple[tuple[str, int], tuple[str, int]]] = []

        for server in self._stun_servers:
            try:
                addr = await self._stun_binding_request(server)
                mapped.append((server, addr))
            except Exception:
                continue

        if not mapped:
            return NetworkInfo()

        nat_type = self._classify_nat(mapped)
        return NetworkInfo(
            nat_type=nat_type,
            external_addr=mapped[0][1],
        )

    async def _stun_binding_request(
        self, server: tuple[str, int]
    ) -> tuple[str, int]:
        """Send a STUN Binding Request and return mapped address."""
        txn_id = os.urandom(12)
        request = build_binding_request(txn_id)

        loop = asyncio.get_event_loop()
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _StunProtocol(txn_id),
                remote_addr=server,
            ),
            timeout=self._timeout,
        )

        try:
            transport.sendto(request)
            result = await asyncio.wait_for(
                protocol.response_future, timeout=self._timeout
            )
            return result
        finally:
            transport.close()

    def _classify_nat(
        self,
        mapped: list[tuple[tuple[str, int], tuple[str, int]]],
    ) -> NatType:
        """Classify NAT type from mapped addresses."""
        if not mapped:
            return NatType.UNKNOWN

        if len(mapped) < 2:
            return NatType.UNKNOWN

        first_ip = mapped[0][1][0]
        first_port = mapped[0][1][1]

        all_same_ip = all(m[1][0] == first_ip for m in mapped)
        all_same_port = all(m[1][1] == first_port for m in mapped)

        if not all_same_ip or not all_same_port:
            return NatType.SYMMETRIC

        return NatType.PORT_RESTRICTED_CONE


class _StunProtocol(asyncio.DatagramProtocol):
    """Asyncio datagram protocol for STUN requests."""

    def __init__(self, txn_id: bytes) -> None:
        self._txn_id = txn_id
        self.response_future: asyncio.Future[tuple[str, int]] = (
            asyncio.get_event_loop().create_future()
        )

    def datagram_received(self, data: bytes, addr: object) -> None:
        if self.response_future.done():
            return
        try:
            result = parse_binding_response(data, self._txn_id)
            self.response_future.set_result(result)
        except Exception as e:
            self.response_future.set_exception(e)

    def error_received(self, exc: Exception) -> None:
        if not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.response_future.done():
            self.response_future.set_exception(
                ConnectionError("connection lost")
            )
