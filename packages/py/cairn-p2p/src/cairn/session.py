"""Session state machine and session management."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum, auto

from cairn.protocol.envelope import new_msg_id

DEFAULT_SESSION_EXPIRY_SECS: int = 86400  # 24 hours


class SessionState(Enum):
    """Session lifecycle states (spec section 2)."""

    CONNECTED = auto()
    UNSTABLE = auto()
    DISCONNECTED = auto()
    RECONNECTING = auto()
    SUSPENDED = auto()
    RECONNECTED = auto()
    FAILED = auto()


# Valid transitions per spec state diagram
_VALID_TRANSITIONS: set[tuple[SessionState, SessionState]] = {
    (SessionState.CONNECTED, SessionState.UNSTABLE),
    (SessionState.CONNECTED, SessionState.DISCONNECTED),
    (SessionState.UNSTABLE, SessionState.DISCONNECTED),
    (SessionState.UNSTABLE, SessionState.CONNECTED),
    (SessionState.DISCONNECTED, SessionState.RECONNECTING),
    (SessionState.RECONNECTING, SessionState.RECONNECTED),
    (SessionState.RECONNECTING, SessionState.SUSPENDED),
    (SessionState.SUSPENDED, SessionState.RECONNECTING),
    (SessionState.SUSPENDED, SessionState.FAILED),
    (SessionState.RECONNECTED, SessionState.CONNECTED),
}


@dataclass
class SessionEvent:
    """Emitted on every state transition."""

    session_id: bytes
    from_state: SessionState
    to_state: SessionState
    timestamp: float
    reason: str | None = None


class SessionStateMachine:
    """Validates and executes session state transitions."""

    def __init__(
        self,
        session_id: bytes | None = None,
        initial_state: SessionState = SessionState.CONNECTED,
    ) -> None:
        self._session_id = session_id or new_msg_id()
        self._state = initial_state
        self._events: list[SessionEvent] = []
        self._listeners: list[asyncio.Queue[SessionEvent]] = []

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def session_id(self) -> bytes:
        return self._session_id

    def subscribe(self) -> asyncio.Queue[SessionEvent]:
        """Subscribe to session events. Returns an asyncio Queue."""
        q: asyncio.Queue[SessionEvent] = asyncio.Queue()
        self._listeners.append(q)
        return q

    def transition(
        self,
        to: SessionState,
        reason: str | None = None,
    ) -> None:
        """Attempt a state transition.

        Raises ValueError if the transition is invalid.
        """
        if not self.is_valid_transition(self._state, to):
            raise ValueError(
                f"invalid session state transition: "
                f"{self._state.name} -> {to.name}"
            )

        from_state = self._state
        self._state = to

        event = SessionEvent(
            session_id=self._session_id,
            from_state=from_state,
            to_state=to,
            timestamp=time.monotonic(),
            reason=reason,
        )
        self._events.append(event)

        for q in self._listeners:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    @staticmethod
    def is_valid_transition(
        from_state: SessionState, to_state: SessionState
    ) -> bool:
        """Check if a transition is valid per the spec."""
        return (from_state, to_state) in _VALID_TRANSITIONS

    @property
    def events(self) -> list[SessionEvent]:
        """Get all emitted events (for testing)."""
        return list(self._events)


@dataclass
class SessionConfig:
    """Session configuration."""

    expiry_secs: int = DEFAULT_SESSION_EXPIRY_SECS


class Session:
    """Application-facing session object."""

    def __init__(
        self,
        peer_id: bytes,
        session_id: bytes | None = None,
        config: SessionConfig | None = None,
    ) -> None:
        self._peer_id = peer_id
        self._config = config or SessionConfig()
        self._state_machine = SessionStateMachine(
            session_id=session_id,
        )
        self._send_queue: asyncio.Queue[tuple[str, bytes]] = (
            asyncio.Queue()
        )
        self._recv_queue: asyncio.Queue[tuple[str, bytes]] = (
            asyncio.Queue()
        )
        self._created_at = time.time()

    @property
    def peer_id(self) -> bytes:
        return self._peer_id

    @property
    def session_id(self) -> bytes:
        return self._state_machine.session_id

    @property
    def is_connected(self) -> bool:
        return self._state_machine.state == SessionState.CONNECTED

    @property
    def state(self) -> SessionState:
        return self._state_machine.state

    @property
    def state_machine(self) -> SessionStateMachine:
        return self._state_machine

    def is_expired(self, now: float | None = None) -> bool:
        """Check if this session has expired."""
        if now is None:
            now = time.time()
        return now > self._created_at + self._config.expiry_secs

    async def send(self, channel: str, data: bytes) -> None:
        """Queue data to send on a channel."""
        if not self.is_connected:
            raise ConnectionError(
                f"session not connected (state: {self.state.name})"
            )
        await self._send_queue.put((channel, data))

    async def receive(self) -> tuple[str, bytes]:
        """Receive data from the session (channel, data)."""
        return await self._recv_queue.get()

    async def close(self) -> None:
        """Close the session."""
        if self._state_machine.state not in (
            SessionState.FAILED,
            SessionState.DISCONNECTED,
        ):
            try:
                self._state_machine.transition(
                    SessionState.DISCONNECTED
                )
            except ValueError:
                pass

    def _deliver(self, channel: str, data: bytes) -> None:
        """Deliver received data to the receive queue (internal)."""
        try:
            self._recv_queue.put_nowait((channel, data))
        except asyncio.QueueFull:
            pass
