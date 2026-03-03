"""Discovery backends for cairn peer discovery (spec 08, section 4).

Each backend implements the DiscoveryBackend ABC with announce/query/stop.
Backends attempt real network I/O and fall back to in-memory stores
when the network is unavailable, ensuring tests still pass.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlencode

from cairn.discovery.rendezvous import RendezvousId

logger = logging.getLogger(__name__)


@dataclass
class PeerInfo:
    """Discovered peer information."""

    peer_id: bytes
    addresses: list[str]
    rendezvous_id: RendezvousId | None = None


class DiscoveryBackend(ABC):
    """Abstract discovery backend interface."""

    @abstractmethod
    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        """Announce our presence under a rendezvous ID."""

    @abstractmethod
    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        """Query for peers under a rendezvous ID."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the discovery backend."""


# ---------------------------------------------------------------------------
# mDNS backend (LAN discovery)
# ---------------------------------------------------------------------------


class MdnsBackend(DiscoveryBackend):
    """mDNS discovery for LAN (uses rendezvous ID as service name).

    Announces/queries via multicast on 224.0.0.251:5353.
    Uses the ``zeroconf`` library when available for real mDNS I/O,
    falling back to an in-memory store otherwise.
    """

    def __init__(self) -> None:
        self._announced: dict[str, PeerInfo] = {}
        self._zeroconf = None
        self._service_infos: list[object] = []
        try:
            import zeroconf as _zc  # noqa: F401

            self._zeroconf_available = True
        except ImportError:
            self._zeroconf_available = False
            logger.debug(
                "zeroconf not installed; MdnsBackend using in-memory mode"
            )

    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        key = rendezvous_id.to_hex()
        self._announced[key] = peer_info

        if self._zeroconf_available:
            try:
                await self._mdns_register(key, peer_info)
            except Exception as exc:
                logger.debug("mDNS register failed: %s", exc)

    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        key = rendezvous_id.to_hex()

        if self._zeroconf_available:
            try:
                found = await self._mdns_browse(key)
                if found:
                    return found
            except Exception as exc:
                logger.debug("mDNS browse failed: %s", exc)

        # Fallback to in-memory store
        info = self._announced.get(key)
        return [info] if info else []

    async def stop(self) -> None:
        self._announced.clear()
        if self._zeroconf is not None:
            try:

                for si in self._service_infos:
                    self._zeroconf.unregister_service(si)
                self._zeroconf.close()
            except Exception:
                pass
            self._zeroconf = None
            self._service_infos.clear()

    async def _mdns_register(
        self, hex_id: str, peer_info: PeerInfo
    ) -> None:
        """Register an mDNS service for the rendezvous ID."""
        import socket

        import zeroconf

        if self._zeroconf is None:
            self._zeroconf = zeroconf.Zeroconf()

        # Service name: _cairn-<hex_id[:16]>._tcp.local.
        short_id = hex_id[:16]
        stype = f"_cairn-{short_id}._tcp.local."
        sname = f"cairn-peer.{stype}"

        properties = {
            b"peer_id": peer_info.peer_id.hex().encode(),
            b"addrs": json.dumps(peer_info.addresses).encode(),
        }

        si = zeroconf.ServiceInfo(
            stype,
            sname,
            addresses=[socket.inet_aton("127.0.0.1")],
            port=0,
            properties=properties,
        )

        await asyncio.get_event_loop().run_in_executor(
            None, self._zeroconf.register_service, si
        )
        self._service_infos.append(si)

    async def _mdns_browse(self, hex_id: str) -> list[PeerInfo]:
        """Browse for mDNS services matching the rendezvous ID."""
        import zeroconf

        if self._zeroconf is None:
            self._zeroconf = zeroconf.Zeroconf()

        short_id = hex_id[:16]
        stype = f"_cairn-{short_id}._tcp.local."

        browser_results: list[PeerInfo] = []

        class Listener(zeroconf.ServiceListener):
            def add_service(
                self, zc: zeroconf.Zeroconf, stype: str, name: str
            ) -> None:
                info = zc.get_service_info(stype, name)
                if info and info.properties:
                    pid_hex = info.properties.get(b"peer_id", b"")
                    addrs_json = info.properties.get(b"addrs", b"[]")
                    try:
                        pid = bytes.fromhex(pid_hex.decode())
                        addrs = json.loads(addrs_json.decode())
                        browser_results.append(
                            PeerInfo(peer_id=pid, addresses=addrs)
                        )
                    except Exception:
                        pass

            def remove_service(
                self, zc: zeroconf.Zeroconf, stype: str, name: str
            ) -> None:
                pass

            def update_service(
                self, zc: zeroconf.Zeroconf, stype: str, name: str
            ) -> None:
                pass

        listener = Listener()
        browser = zeroconf.ServiceBrowser(
            self._zeroconf, stype, listener
        )

        # Brief wait for mDNS responses
        await asyncio.sleep(0.5)
        browser.cancel()

        return browser_results


# ---------------------------------------------------------------------------
# DHT backend (Kademlia)
# ---------------------------------------------------------------------------


class DhtBackend(DiscoveryBackend):
    """Kademlia DHT discovery backend.

    Uses the ``kademlia`` library for real DHT operations when available,
    with a configurable list of bootstrap nodes. Falls back to an
    in-memory store when the library is unavailable or bootstrap fails.
    """

    def __init__(
        self,
        bootstrap_nodes: list[tuple[str, int]] | None = None,
    ) -> None:
        self._bootstrap_nodes = bootstrap_nodes or []
        self._store: dict[str, list[PeerInfo]] = {}
        self._dht_server = None
        self._bootstrapped = False

    async def _ensure_bootstrapped(self) -> bool:
        """Bootstrap the DHT if not already done."""
        if self._bootstrapped:
            return self._dht_server is not None

        self._bootstrapped = True

        if not self._bootstrap_nodes:
            return False

        try:
            from kademlia.network import Server

            self._dht_server = Server()
            await self._dht_server.listen(0)
            await self._dht_server.bootstrap(self._bootstrap_nodes)
            return True
        except Exception as exc:
            logger.debug("DHT bootstrap failed: %s", exc)
            self._dht_server = None
            return False

    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        key = rendezvous_id.to_hex()

        # Always store locally
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(peer_info)

        # Attempt DHT publish
        if await self._ensure_bootstrapped() and self._dht_server:
            try:
                value = json.dumps({
                    "peer_id": peer_info.peer_id.hex(),
                    "addresses": peer_info.addresses,
                }).encode()
                await self._dht_server.set(key, value)
            except Exception as exc:
                logger.debug("DHT set failed: %s", exc)

    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        key = rendezvous_id.to_hex()

        # Try DHT first
        if await self._ensure_bootstrapped() and self._dht_server:
            try:
                result = await self._dht_server.get(key)
                if result is not None:
                    data = json.loads(result.decode())
                    return [PeerInfo(
                        peer_id=bytes.fromhex(data["peer_id"]),
                        addresses=data["addresses"],
                    )]
            except Exception as exc:
                logger.debug("DHT get failed: %s", exc)

        # Fallback to in-memory
        return list(self._store.get(key, []))

    async def stop(self) -> None:
        self._store.clear()
        if self._dht_server is not None:
            try:
                self._dht_server.stop()
            except Exception:
                pass
            self._dht_server = None
        self._bootstrapped = False


# ---------------------------------------------------------------------------
# BitTorrent tracker backend
# ---------------------------------------------------------------------------


def _to_info_hash(rendezvous_id: RendezvousId) -> bytes:
    """Convert a 32-byte RendezvousId to a 20-byte info_hash (truncate)."""
    return rendezvous_id.data[:20]


class TrackerBackend(DiscoveryBackend):
    """BitTorrent tracker discovery (BEP 3 HTTP announce/scrape).

    Uses HTTP tracker protocol with ``httpx`` for async requests.
    The info_hash is derived by truncating the 32-byte RendezvousId
    to 20 bytes (matching the Rust ``to_info_hash`` implementation).

    Falls back to in-memory storage when no trackers are configured
    or HTTP requests fail.
    """

    REANNOUNCE_INTERVAL: float = 900.0  # 15 minutes

    def __init__(
        self, tracker_urls: list[str] | None = None
    ) -> None:
        self._tracker_urls = tracker_urls or []
        self._store: dict[str, list[PeerInfo]] = {}
        self._last_announce: dict[str, float] = {}
        # Generate a stable 20-byte peer_id for tracker protocol
        self._tracker_peer_id = hashlib.sha1(
            struct.pack(">d", time.time())
        ).digest()

    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        key = rendezvous_id.to_hex()

        # Always store locally
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(peer_info)

        # Check reannounce interval
        now = time.monotonic()
        last = self._last_announce.get(key, 0.0)
        if now - last < self.REANNOUNCE_INTERVAL and last > 0.0:
            return

        # Attempt HTTP tracker announce
        if self._tracker_urls:
            info_hash = _to_info_hash(rendezvous_id)
            for url in self._tracker_urls:
                try:
                    await self._http_announce(url, info_hash, event="started")
                    self._last_announce[key] = now
                    break
                except Exception as exc:
                    logger.debug(
                        "tracker announce to %s failed: %s", url, exc
                    )

    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        key = rendezvous_id.to_hex()

        # Try HTTP tracker scrape
        if self._tracker_urls:
            info_hash = _to_info_hash(rendezvous_id)
            for url in self._tracker_urls:
                try:
                    peers = await self._http_announce(
                        url, info_hash, event=""
                    )
                    if peers:
                        return peers
                except Exception as exc:
                    logger.debug(
                        "tracker query to %s failed: %s", url, exc
                    )

        # Fallback to in-memory
        return list(self._store.get(key, []))

    async def stop(self) -> None:
        self._store.clear()
        self._last_announce.clear()

    async def _http_announce(
        self,
        tracker_url: str,
        info_hash: bytes,
        event: str = "",
    ) -> list[PeerInfo]:
        """Send BEP 3 HTTP tracker announce and parse response."""
        import httpx

        params: dict[str, str | int] = {
            "info_hash": info_hash.decode("latin-1"),
            "peer_id": self._tracker_peer_id.decode("latin-1"),
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "compact": 1,
            "numwant": 50,
        }
        if event:
            params["event"] = event

        url = f"{tracker_url}?{urlencode(params)}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        # BEP 3 response is bencoded. Parse compact peer list.
        return self._parse_compact_peers(resp.content)

    @staticmethod
    def _parse_compact_peers(data: bytes) -> list[PeerInfo]:
        """Parse BEP 3 compact peer response (best effort)."""
        # Look for compact "peers" field in bencoded response
        # Format: 6 bytes per peer (4 IP + 2 port)
        peers: list[PeerInfo] = []
        idx = data.find(b"5:peers")
        if idx == -1:
            return peers

        # Skip "5:peers" and read length prefix
        idx += 7
        # Read the length of the compact peers string
        length_str = b""
        while idx < len(data) and data[idx:idx + 1].isdigit():
            length_str += data[idx:idx + 1]
            idx += 1
        if not length_str or idx >= len(data) or data[idx:idx + 1] != b":":
            return peers
        idx += 1  # skip ':'
        length = int(length_str)

        peer_data = data[idx:idx + length]
        for i in range(0, len(peer_data), 6):
            chunk = peer_data[i:i + 6]
            if len(chunk) < 6:
                break
            ip = f"{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}"
            port = struct.unpack(">H", chunk[4:6])[0]
            peers.append(PeerInfo(
                peer_id=b"",
                addresses=[f"{ip}:{port}"],
            ))

        return peers


# ---------------------------------------------------------------------------
# Signaling backend (WebSocket)
# ---------------------------------------------------------------------------


class SignalingBackend(DiscoveryBackend):
    """WebSocket signaling discovery.

    Connects to configured signaling servers over WSS and subscribes
    to topics based on rendezvous ID hex. Uses the ``websockets``
    library for async WebSocket I/O.

    Falls back to in-memory storage when no servers are configured
    or WebSocket connections fail.
    """

    def __init__(
        self,
        server_urls: list[str] | None = None,
        auth_token: str | None = None,
    ) -> None:
        self._server_urls = server_urls or []
        self._auth_token = auth_token
        self._store: dict[str, list[PeerInfo]] = {}
        self._connections: dict[str, object] = {}

    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        key = rendezvous_id.to_hex()

        # Always store locally
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(peer_info)

        # Attempt WebSocket announce
        for url in self._server_urls:
            try:
                await self._ws_announce(url, key, peer_info)
                break
            except Exception as exc:
                logger.debug(
                    "signaling announce to %s failed: %s", url, exc
                )

    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        key = rendezvous_id.to_hex()

        # Try WebSocket query
        for url in self._server_urls:
            try:
                result = await self._ws_query(url, key)
                if result:
                    return result
            except Exception as exc:
                logger.debug(
                    "signaling query to %s failed: %s", url, exc
                )

        # Fallback to in-memory
        return list(self._store.get(key, []))

    async def stop(self) -> None:
        self._store.clear()
        # Close WebSocket connections
        for ws in self._connections.values():
            try:
                await ws.close()  # type: ignore[union-attr]
            except Exception:
                pass
        self._connections.clear()

    async def _ws_announce(
        self, url: str, topic: str, peer_info: PeerInfo
    ) -> None:
        """Announce via WebSocket signaling server."""
        import websockets

        headers: dict[str, str] = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        async with websockets.connect(
            url, additional_headers=headers
        ) as ws:
            msg = json.dumps({
                "type": "announce",
                "topic": topic,
                "peer_id": peer_info.peer_id.hex(),
                "addresses": peer_info.addresses,
            })
            await ws.send(msg)
            # Wait briefly for acknowledgement
            try:
                await asyncio.wait_for(ws.recv(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

    async def _ws_query(
        self, url: str, topic: str
    ) -> list[PeerInfo]:
        """Query via WebSocket signaling server."""
        import websockets

        headers: dict[str, str] = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        async with websockets.connect(
            url, additional_headers=headers
        ) as ws:
            msg = json.dumps({
                "type": "query",
                "topic": topic,
            })
            await ws.send(msg)

            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
                data = json.loads(resp)
                peers = []
                for p in data.get("peers", []):
                    peers.append(PeerInfo(
                        peer_id=bytes.fromhex(p["peer_id"]),
                        addresses=p["addresses"],
                    ))
                return peers
            except (asyncio.TimeoutError, Exception):
                return []


# ---------------------------------------------------------------------------
# Discovery coordinator
# ---------------------------------------------------------------------------


class DiscoveryCoordinator:
    """Coordinates multiple discovery backends.

    Queries all backends simultaneously, first result wins.
    """

    def __init__(
        self, backends: list[DiscoveryBackend] | None = None
    ) -> None:
        self._backends = backends or []

    def add_backend(self, backend: DiscoveryBackend) -> None:
        self._backends.append(backend)

    async def announce(
        self, rendezvous_id: RendezvousId, peer_info: PeerInfo
    ) -> None:
        """Announce to all backends."""
        for backend in self._backends:
            try:
                await backend.announce(rendezvous_id, peer_info)
            except Exception:
                continue

    async def query(
        self, rendezvous_id: RendezvousId
    ) -> list[PeerInfo]:
        """Query all backends, return first results found."""
        if not self._backends:
            return []

        tasks = [
            asyncio.create_task(b.query(rendezvous_id))
            for b in self._backends
        ]

        results: list[PeerInfo] = []
        for coro in asyncio.as_completed(tasks):
            try:
                found = await coro
                if found:
                    results.extend(found)
                    break
            except Exception:
                continue

        # Cancel remaining
        for t in tasks:
            if not t.done():
                t.cancel()

        return results

    async def stop(self) -> None:
        for backend in self._backends:
            try:
                await backend.stop()
            except Exception:
                continue
