"""Rate limiting for pairing attempts (acceptor-side)."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

DEFAULT_MAX_ATTEMPTS_PER_WINDOW: int = 5
DEFAULT_WINDOW_SECS: float = 30.0
DEFAULT_MAX_TOTAL_FAILURES: int = 10
DEFAULT_DELAY_PER_FAILURE_SECS: float = 2.0


class RateLimitError(Exception):
    """Rate limit exceeded."""


class WindowExceededError(RateLimitError):
    """Too many attempts within the sliding window."""

    def __init__(self, attempts: int, window: float) -> None:
        self.attempts = attempts
        self.window = window
        super().__init__(
            f"rate limit exceeded: {attempts} attempts "
            f"in {window}s window"
        )


class AutoInvalidatedError(RateLimitError):
    """PIN auto-invalidated after too many total failures."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        super().__init__(
            f"pin auto-invalidated after {failures} total failures"
        )


@dataclass
class _SourceState:
    attempts: deque[float] = field(default_factory=deque)
    failure_count: int = 0


class RateLimiter:
    """Rate limiter for pairing attempts.

    Enforced by the acceptor (the peer that generates the PIN code).
    Protects the 40-bit entropy of PIN codes against brute-force.

    Controls:
    - max_attempts_per_window attempts per window_secs sliding window
    - max_total_failures total failures -> auto-invalidate PIN
    - delay_per_failure_secs progressive delay after each failure
    """

    def __init__(
        self,
        max_attempts_per_window: int = DEFAULT_MAX_ATTEMPTS_PER_WINDOW,
        window_secs: float = DEFAULT_WINDOW_SECS,
        max_total_failures: int = DEFAULT_MAX_TOTAL_FAILURES,
        delay_per_failure_secs: float = DEFAULT_DELAY_PER_FAILURE_SECS,
    ) -> None:
        self._max_attempts_per_window = max_attempts_per_window
        self._window_secs = window_secs
        self._max_total_failures = max_total_failures
        self._delay_per_failure_secs = delay_per_failure_secs
        self._sources: dict[str, _SourceState] = {}
        self._total_failures: int = 0

    def check_rate_limit(self, source: str) -> float:
        """Check if a new attempt from this source is allowed.

        Returns the required delay (in seconds) before processing.
        Raises RateLimitError if rate limited or auto-invalidated.
        """
        if self.is_invalidated():
            raise AutoInvalidatedError(self._total_failures)

        now = time.monotonic()
        state = self._sources.get(source)
        if state is None:
            state = _SourceState()
            self._sources[source] = state

        # Remove expired entries from the sliding window
        while state.attempts and (
            now - state.attempts[0] > self._window_secs
        ):
            state.attempts.popleft()

        # Check window limit
        current = len(state.attempts)
        if current >= self._max_attempts_per_window:
            raise WindowExceededError(current, self._window_secs)

        # Record this attempt
        state.attempts.append(now)

        # Compute progressive delay
        return self._delay_per_failure_secs * state.failure_count

    def record_failure(self, source: str) -> None:
        """Record a failed attempt from this source."""
        state = self._sources.get(source)
        if state is None:
            state = _SourceState()
            self._sources[source] = state
        state.failure_count += 1
        self._total_failures += 1

    def record_success(self, source: str) -> None:
        """Record a successful attempt (resets per-source delay)."""
        state = self._sources.get(source)
        if state is not None:
            state.failure_count = 0

    def is_invalidated(self) -> bool:
        """Check if the PIN has been auto-invalidated."""
        return self._total_failures >= self._max_total_failures

    def reset(self) -> None:
        """Reset all state (e.g., when a new PIN is generated)."""
        self._sources.clear()
        self._total_failures = 0

    @property
    def total_failures(self) -> int:
        """Get the total failure count across all sources."""
        return self._total_failures
