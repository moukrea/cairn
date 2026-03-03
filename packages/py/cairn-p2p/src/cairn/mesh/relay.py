"""Relay session management for multi-hop mesh routing."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cairn.mesh.router import (
    MeshConfig,
    RelayCapacityFullError,
    RelayNotWillingError,
)


@dataclass
class RelaySession:
    """An active relay session forwarding data between two peers."""

    session_id: bytes
    source: bytes
    destination: bytes
    bytes_relayed: int = 0

    def record_forwarded(self, nbytes: int) -> None:
        self.bytes_relayed += nbytes


class RelayManager:
    """Manages relay sessions for a mesh-enabled peer."""

    def __init__(self, config: MeshConfig | None = None) -> None:
        self._config = config or MeshConfig()
        self._sessions: dict[bytes, RelaySession] = {}

    @property
    def config(self) -> MeshConfig:
        return self._config

    @property
    def active_sessions(self) -> int:
        return len(self._sessions)

    def create_session(
        self, source: bytes, destination: bytes
    ) -> RelaySession:
        """Create a new relay session.

        Raises RelayNotWillingError or RelayCapacityFullError.
        """
        if not self._config.relay_willing:
            raise RelayNotWillingError()

        if len(self._sessions) >= self._config.relay_capacity:
            raise RelayCapacityFullError(
                len(self._sessions), self._config.relay_capacity
            )

        session_id = os.urandom(16)
        session = RelaySession(
            session_id=session_id,
            source=source,
            destination=destination,
        )
        self._sessions[session_id] = session
        return session

    def get_session(
        self, session_id: bytes
    ) -> RelaySession | None:
        return self._sessions.get(session_id)

    def close_session(self, session_id: bytes) -> None:
        self._sessions.pop(session_id, None)

    def close_all(self) -> None:
        self._sessions.clear()
