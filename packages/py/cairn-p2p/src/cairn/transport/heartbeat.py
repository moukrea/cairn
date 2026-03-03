"""Heartbeat/keepalive monitoring and message queuing."""

from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum, auto

# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

@dataclass
class HeartbeatConfig:
    """Heartbeat configuration (spec section 6)."""

    interval: float = 30.0
    timeout: float = 90.0

    @classmethod
    def aggressive(cls) -> HeartbeatConfig:
        """Real-time preset: 5s interval, 15s timeout."""
        return cls(interval=5.0, timeout=15.0)

    @classmethod
    def relaxed(cls) -> HeartbeatConfig:
        """Background sync preset: 60s interval, 180s timeout."""
        return cls(interval=60.0, timeout=180.0)


class HeartbeatMonitor:
    """Tracks heartbeat timing and determines connection liveness."""

    def __init__(self, config: HeartbeatConfig | None = None) -> None:
        self._config = config or HeartbeatConfig()
        now = time.monotonic()
        self._last_activity = now
        self._last_heartbeat_sent = now

    @property
    def config(self) -> HeartbeatConfig:
        return self._config

    @property
    def last_activity(self) -> float:
        return self._last_activity

    def record_activity(self) -> None:
        """Record data receipt (any data resets timeout counter)."""
        self._last_activity = time.monotonic()

    def record_heartbeat_sent(self) -> None:
        """Record that a heartbeat was sent."""
        self._last_heartbeat_sent = time.monotonic()

    def is_timed_out(self) -> bool:
        """Check if the connection has timed out."""
        return (
            time.monotonic() - self._last_activity
            >= self._config.timeout
        )

    def should_send_heartbeat(self) -> bool:
        """Check if it's time to send a heartbeat."""
        return (
            time.monotonic() - self._last_heartbeat_sent
            >= self._config.interval
        )

    def time_until_next_heartbeat(self) -> float:
        """Seconds until next heartbeat should be sent."""
        elapsed = time.monotonic() - self._last_heartbeat_sent
        return max(0.0, self._config.interval - elapsed)

    def time_until_timeout(self) -> float:
        """Seconds until connection times out."""
        elapsed = time.monotonic() - self._last_activity
        return max(0.0, self._config.timeout - elapsed)


# ---------------------------------------------------------------------------
# Exponential Backoff
# ---------------------------------------------------------------------------

@dataclass
class BackoffConfig:
    """Exponential backoff configuration (spec section 2)."""

    initial_delay: float = 1.0
    max_delay: float = 60.0
    factor: float = 2.0


class BackoffState:
    """Tracks exponential backoff state."""

    def __init__(
        self, config: BackoffConfig | None = None
    ) -> None:
        self._config = config or BackoffConfig()
        self._attempt: int = 0

    @property
    def attempt(self) -> int:
        return self._attempt

    @property
    def config(self) -> BackoffConfig:
        return self._config

    def next_delay(self) -> float:
        """Calculate next delay with jitter, advance attempt counter.

        Formula: min(initial * factor^attempt + jitter, max_delay)
        """
        base = self._config.initial_delay * (
            self._config.factor ** self._attempt
        )
        capped = min(base, self._config.max_delay)
        jitter = random.uniform(0, 0.5 * capped)
        self._attempt += 1
        return min(capped + jitter, self._config.max_delay)

    def next_delay_no_jitter(self) -> float:
        """Calculate next delay without jitter (for testing)."""
        base = self._config.initial_delay * (
            self._config.factor ** self._attempt
        )
        self._attempt += 1
        return min(base, self._config.max_delay)

    def reset(self) -> None:
        """Reset attempt counter (on successful reconnection)."""
        self._attempt = 0


# ---------------------------------------------------------------------------
# Message Queue
# ---------------------------------------------------------------------------

class QueueStrategy(Enum):
    """Queue overflow strategy."""

    FIFO = auto()
    LIFO = auto()

    def __str__(self) -> str:
        return self.name


@dataclass
class QueueConfig:
    """Message queue configuration (spec section 5)."""

    enabled: bool = True
    max_size: int = 1000
    max_age: float = 3600.0
    strategy: QueueStrategy = QueueStrategy.FIFO


class EnqueueResult(Enum):
    """Result of attempting to enqueue a message."""

    ENQUEUED = auto()
    DISABLED = auto()
    FULL = auto()
    ENQUEUED_WITH_EVICTION = auto()


@dataclass
class QueuedMessage:
    """A queued message with metadata for age tracking."""

    sequence: int
    payload: bytes
    enqueued_at: float


class MessageQueue:
    """Message queue for buffering during disconnection.

    FIFO: reject new messages when full.
    LIFO: discard oldest to make room.
    Messages exceeding max_age are discarded on access.
    """

    def __init__(
        self, config: QueueConfig | None = None
    ) -> None:
        self._config = config or QueueConfig()
        self._messages: deque[QueuedMessage] = deque()

    @property
    def config(self) -> QueueConfig:
        return self._config

    def enqueue(
        self, sequence: int, payload: bytes
    ) -> EnqueueResult:
        """Enqueue a message."""
        if not self._config.enabled:
            return EnqueueResult.DISABLED

        self._expire_stale()

        msg = QueuedMessage(
            sequence=sequence,
            payload=payload,
            enqueued_at=time.monotonic(),
        )

        if len(self._messages) >= self._config.max_size:
            if self._config.strategy == QueueStrategy.FIFO:
                return EnqueueResult.FULL
            else:
                self._messages.popleft()
                self._messages.append(msg)
                return EnqueueResult.ENQUEUED_WITH_EVICTION

        self._messages.append(msg)
        return EnqueueResult.ENQUEUED

    def drain(self) -> list[QueuedMessage]:
        """Drain all queued messages in sequence order."""
        self._expire_stale()
        msgs = list(self._messages)
        self._messages.clear()
        return msgs

    def clear(self) -> None:
        """Discard all queued messages."""
        self._messages.clear()

    def __len__(self) -> int:
        return len(self._messages)

    @property
    def is_empty(self) -> bool:
        return len(self._messages) == 0

    @property
    def remaining_capacity(self) -> int:
        return max(0, self._config.max_size - len(self._messages))

    def peek(self) -> QueuedMessage | None:
        """Peek at the next message without removing."""
        if self._messages:
            return self._messages[0]
        return None

    def _expire_stale(self) -> None:
        """Remove messages older than max_age."""
        now = time.monotonic()
        while self._messages and (
            now - self._messages[0].enqueued_at
            >= self._config.max_age
        ):
            self._messages.popleft()


# ---------------------------------------------------------------------------
# Network Change
# ---------------------------------------------------------------------------

class NetworkChangeType(Enum):
    """Types of network change events."""

    INTERFACE_UP = auto()
    INTERFACE_DOWN = auto()
    ADDRESS_CHANGED = auto()


@dataclass
class NetworkChange:
    """Network change event for proactive reconnection."""

    change_type: NetworkChangeType
    interface: str
    old_addr: str | None = None
    new_addr: str | None = None

    def __str__(self) -> str:
        if self.change_type == NetworkChangeType.INTERFACE_UP:
            return f"interface up: {self.interface}"
        elif self.change_type == NetworkChangeType.INTERFACE_DOWN:
            return f"interface down: {self.interface}"
        else:
            return (
                f"address changed on {self.interface}: "
                f"{self.new_addr}"
            )
