"""Mesh routing table and route selection."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class MeshError(Exception):
    """Base error for mesh operations."""


class MeshDisabledError(MeshError):
    def __init__(self) -> None:
        super().__init__("mesh routing disabled")


class NoRouteError(MeshError):
    def __init__(self, peer_id: str) -> None:
        self.peer_id = peer_id
        super().__init__(f"no route to peer {peer_id}")


class MaxHopsExceededError(MeshError):
    def __init__(self, got: int, max_hops: int) -> None:
        self.got = got
        self.max_hops = max_hops
        super().__init__(
            f"max hops exceeded: {got} > {max_hops}"
        )


class RelayCapacityFullError(MeshError):
    def __init__(self, current: int, capacity: int) -> None:
        self.current = current
        self.capacity = capacity
        super().__init__(
            f"relay capacity full ({current}/{capacity})"
        )


class RelayNotWillingError(MeshError):
    def __init__(self) -> None:
        super().__init__("relay not willing")


@dataclass
class MeshConfig:
    """Mesh networking configuration."""

    mesh_enabled: bool = False
    max_hops: int = 3
    relay_willing: bool = False
    relay_capacity: int = 10

    @classmethod
    def server_mode(cls) -> MeshConfig:
        return cls(
            mesh_enabled=True,
            max_hops=3,
            relay_willing=True,
            relay_capacity=100,
        )


@dataclass
class Route:
    """A route to a destination peer."""

    hops: list[bytes] = field(default_factory=list)
    latency_ms: int = 0
    bandwidth_bps: int = 0
    last_seen: float = field(default_factory=time.monotonic)

    @classmethod
    def direct(
        cls, latency_ms: int = 0, bandwidth_bps: int = 0
    ) -> Route:
        return cls(
            hops=[],
            latency_ms=latency_ms,
            bandwidth_bps=bandwidth_bps,
        )

    @classmethod
    def relayed(
        cls,
        hops: list[bytes],
        latency_ms: int = 0,
        bandwidth_bps: int = 0,
    ) -> Route:
        return cls(
            hops=list(hops),
            latency_ms=latency_ms,
            bandwidth_bps=bandwidth_bps,
        )

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    def selection_key(self) -> tuple[int, int, int]:
        """Sort key: (hops ASC, latency ASC, -bandwidth ASC)."""
        return (self.hop_count, self.latency_ms, -self.bandwidth_bps)


@dataclass
class ReachabilityEntry:
    """A single reachability entry in a topology update."""

    peer_id: bytes
    via_hops: list[bytes] = field(default_factory=list)
    latency_ms: int = 0
    bandwidth_bps: int = 0


@dataclass
class MeshTopologyUpdate:
    """Topology update exchanged between mesh peers."""

    reachable_peers: list[ReachabilityEntry] = field(
        default_factory=list
    )


class RoutingTable:
    """Routing table maintaining peers and reachability."""

    def __init__(self, max_hops: int = 3) -> None:
        self._routes: dict[bytes, list[Route]] = {}
        self._max_hops = max_hops

    @property
    def max_hops(self) -> int:
        return self._max_hops

    def add_route(
        self, destination: bytes, route: Route
    ) -> None:
        """Add a route. Raises MaxHopsExceededError if too many hops."""
        if route.hop_count > self._max_hops:
            raise MaxHopsExceededError(
                route.hop_count, self._max_hops
            )
        if destination not in self._routes:
            self._routes[destination] = []
        self._routes[destination].append(route)

    def select_best_route(self, destination: bytes) -> Route:
        """Select best route. Raises NoRouteError if none exists."""
        routes = self._routes.get(destination)
        if not routes:
            raise NoRouteError(destination.hex())
        return min(routes, key=lambda r: r.selection_key())

    def get_routes(
        self, destination: bytes
    ) -> list[Route] | None:
        routes = self._routes.get(destination)
        return list(routes) if routes else None

    def remove_routes(self, destination: bytes) -> None:
        self._routes.pop(destination, None)

    def expire_routes(self, max_age: float) -> None:
        """Remove routes older than max_age seconds."""
        now = time.monotonic()
        for dest in list(self._routes.keys()):
            self._routes[dest] = [
                r
                for r in self._routes[dest]
                if now - r.last_seen < max_age
            ]
            if not self._routes[dest]:
                del self._routes[dest]

    @property
    def peer_count(self) -> int:
        return len(self._routes)

    @property
    def route_count(self) -> int:
        return sum(len(v) for v in self._routes.values())

    def destinations(self) -> list[bytes]:
        return list(self._routes.keys())

    def apply_topology_update(
        self,
        neighbor: bytes,
        update: MeshTopologyUpdate,
    ) -> int:
        """Apply a topology update from a neighbor. Returns count added."""
        added = 0
        for entry in update.reachable_peers:
            hops = [neighbor] + list(entry.via_hops)
            route = Route(
                hops=hops,
                latency_ms=entry.latency_ms,
                bandwidth_bps=entry.bandwidth_bps,
            )
            try:
                self.add_route(entry.peer_id, route)
                added += 1
            except MaxHopsExceededError:
                continue
        return added
