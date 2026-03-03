"""Transport abstraction and 9-level fallback chain."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Coroutine

DEFAULT_TIMEOUT: float = 10.0


class TransportType(Enum):
    """Transport type in the 9-level fallback chain."""

    DIRECT_QUIC = auto()
    STUN_HOLE_PUNCH = auto()
    DIRECT_TCP = auto()
    TURN_UDP = auto()
    TURN_TCP = auto()
    WEBSOCKET_TLS = auto()
    WEBTRANSPORT_H3 = auto()
    CIRCUIT_RELAY_V2 = auto()
    HTTPS_LONG_POLL = auto()

    @property
    def priority(self) -> int:
        """Priority number (1 = best, 9 = worst)."""
        return list(TransportType).index(self) + 1

    @property
    def tier0_available(self) -> bool:
        """Whether this transport is available in zero-config mode."""
        return self in (
            TransportType.DIRECT_QUIC,
            TransportType.STUN_HOLE_PUNCH,
            TransportType.DIRECT_TCP,
            TransportType.CIRCUIT_RELAY_V2,
        )

    @property
    def display_name(self) -> str:
        """Human-readable name."""
        names = {
            TransportType.DIRECT_QUIC: "Direct QUIC v1",
            TransportType.STUN_HOLE_PUNCH: "STUN-assisted UDP",
            TransportType.DIRECT_TCP: "Direct TCP",
            TransportType.TURN_UDP: "TURN relay (UDP)",
            TransportType.TURN_TCP: "TURN relay (TCP)",
            TransportType.WEBSOCKET_TLS: "WebSocket/TLS (443)",
            TransportType.WEBTRANSPORT_H3: "WebTransport/HTTP3",
            TransportType.CIRCUIT_RELAY_V2: "Circuit Relay v2",
            TransportType.HTTPS_LONG_POLL: "HTTPS long-polling",
        }
        return names[self]

    @classmethod
    def all_in_order(cls) -> list[TransportType]:
        """All transport types in priority order."""
        return list(cls)


class Transport(ABC):
    """Abstract base class for transport implementations."""

    @abstractmethod
    async def connect(
        self, addr: str, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        """Connect to a remote address."""

    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send data to the connected peer."""

    @abstractmethod
    async def receive(self) -> bytes:
        """Receive data from the connected peer."""

    @abstractmethod
    async def close(self) -> None:
        """Close the transport connection."""


@dataclass
class TransportAttempt:
    """Configuration for a single transport attempt."""

    transport_type: TransportType
    timeout: float = DEFAULT_TIMEOUT
    available: bool = True

    @property
    def priority(self) -> int:
        return self.transport_type.priority


@dataclass
class TransportAttemptResult:
    """Result of attempting a single transport."""

    transport_type: TransportType
    error: str | None = None
    skipped: bool = False
    duration: float = 0.0

    def __str__(self) -> str:
        if self.skipped:
            return (
                f"{self.transport_type.display_name}: "
                f"skipped (not configured)"
            )
        if self.error:
            return (
                f"{self.transport_type.display_name}: "
                f"failed ({self.error}) [{self.duration:.3f}s]"
            )
        return (
            f"{self.transport_type.display_name}: "
            f"success [{self.duration:.3f}s]"
        )


class TransportExhaustedError(Exception):
    """All transports in the fallback chain failed."""

    def __init__(
        self,
        details: str,
        suggestion: str,
        results: list[TransportAttemptResult],
    ) -> None:
        self.details = details
        self.suggestion = suggestion
        self.results = results
        super().__init__(
            f"all transports exhausted: {details}. {suggestion}"
        )


class FallbackChain:
    """Executes the 9-level transport priority chain.

    Supports both sequential and parallel (ICE-style) probing modes.
    """

    def __init__(
        self,
        per_transport_timeout: float = DEFAULT_TIMEOUT,
        has_turn: bool = False,
        has_relay_443: bool = False,
        parallel_mode: bool = False,
    ) -> None:
        self._parallel_mode = parallel_mode
        self._transports: list[TransportAttempt] = []

        for tt in TransportType.all_in_order():
            if tt in (TransportType.TURN_UDP, TransportType.TURN_TCP):
                available = has_turn
            elif tt in (
                TransportType.WEBSOCKET_TLS,
                TransportType.WEBTRANSPORT_H3,
                TransportType.HTTPS_LONG_POLL,
            ):
                available = has_relay_443
            else:
                available = True

            self._transports.append(
                TransportAttempt(
                    transport_type=tt,
                    timeout=per_transport_timeout,
                    available=available,
                )
            )

    @classmethod
    def tier0(
        cls, per_transport_timeout: float = DEFAULT_TIMEOUT
    ) -> FallbackChain:
        """Create a Tier 0 (zero-config) fallback chain."""
        return cls(per_transport_timeout, False, False, False)

    @property
    def transports(self) -> list[TransportAttempt]:
        return list(self._transports)

    @property
    def parallel_mode(self) -> bool:
        return self._parallel_mode

    async def execute(
        self,
        attempt_fn: Callable[
            [TransportType, float],
            Coroutine[Any, Any, Any],
        ],
    ) -> tuple[TransportType, Any]:
        """Execute the fallback chain.

        attempt_fn(transport_type, timeout) should return the result
        on success or raise an exception on failure.

        Returns (transport_type, result) for the first success.
        Raises TransportExhaustedError if all fail.
        """
        if self._parallel_mode:
            return await self._execute_parallel(attempt_fn)
        return await self._execute_sequential(attempt_fn)

    async def _execute_sequential(
        self,
        attempt_fn: Callable[
            [TransportType, float],
            Coroutine[Any, Any, Any],
        ],
    ) -> tuple[TransportType, Any]:
        results: list[TransportAttemptResult] = []

        for attempt in self._transports:
            if not attempt.available:
                results.append(
                    TransportAttemptResult(
                        transport_type=attempt.transport_type,
                        skipped=True,
                    )
                )
                continue

            loop = asyncio.get_event_loop()
            start = loop.time()
            try:
                value = await attempt_fn(
                    attempt.transport_type, attempt.timeout
                )
                return (attempt.transport_type, value)
            except Exception as e:
                elapsed = loop.time() - start
                results.append(
                    TransportAttemptResult(
                        transport_type=attempt.transport_type,
                        error=str(e),
                        duration=elapsed,
                    )
                )

        raise _build_exhausted_error(results)

    async def _execute_parallel(
        self,
        attempt_fn: Callable[
            [TransportType, float],
            Coroutine[Any, Any, Any],
        ],
    ) -> tuple[TransportType, Any]:
        results: list[TransportAttemptResult] = []
        tasks: dict[asyncio.Task[Any], TransportType] = {}

        for attempt in self._transports:
            if not attempt.available:
                results.append(
                    TransportAttemptResult(
                        transport_type=attempt.transport_type,
                        skipped=True,
                    )
                )
                continue

            task = asyncio.create_task(
                attempt_fn(attempt.transport_type, attempt.timeout)
            )
            tasks[task] = attempt.transport_type

        if not tasks:
            raise _build_exhausted_error(results)

        pending = set(tasks.keys())

        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                tt = tasks[task]
                exc = task.exception()
                if exc is None:
                    # Cancel remaining tasks
                    for p in pending:
                        p.cancel()
                    return (tt, task.result())
                else:
                    results.append(
                        TransportAttemptResult(
                            transport_type=tt,
                            error=str(exc),
                        )
                    )

        raise _build_exhausted_error(results)


def _build_exhausted_error(
    results: list[TransportAttemptResult],
) -> TransportExhaustedError:
    details = "; ".join(str(r) for r in results)
    has_skipped = any(r.skipped for r in results)
    suggestion = (
        "deploy companion infrastructure (TURN relay, "
        "WebSocket relay on port 443) to enable additional "
        "transport fallbacks"
        if has_skipped
        else "check network connectivity and firewall rules"
    )
    return TransportExhaustedError(details, suggestion, results)
