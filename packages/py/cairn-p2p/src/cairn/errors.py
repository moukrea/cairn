"""Error types for cairn (spec 11, section 2)."""

from __future__ import annotations

import enum


class ErrorBehavior(enum.Enum):
    """Recommended recovery action for a given error."""

    RETRY = "retry"
    RECONNECT = "reconnect"
    ABORT = "abort"
    REGENERATE = "regenerate"
    WAIT = "wait"
    INFORM = "inform"


class CairnError(Exception):
    """Base error for all cairn operations."""

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.ABORT


class TransportExhaustedError(CairnError):
    """All transports exhausted."""

    def __init__(
        self, details: str = "", suggestion: str = ""
    ) -> None:
        self.details = details
        self.suggestion = suggestion or (
            "deploy the cairn signaling server and/or TURN relay"
        )
        super().__init__(
            f"all transports exhausted: {details}. "
            f"Suggestion: {self.suggestion}"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.RETRY


class SessionExpiredError(CairnError):
    """Session expired."""

    def __init__(
        self,
        session_id: str = "",
        expiry_duration: float = 0.0,
    ) -> None:
        self.session_id = session_id
        self.expiry_duration = expiry_duration
        super().__init__(
            f"session expired after {expiry_duration}s"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.RECONNECT


class PeerUnreachableError(CairnError):
    """Peer unreachable at any rendezvous point."""

    def __init__(
        self, peer_id: str = "", timeout: float = 0.0
    ) -> None:
        self.peer_id = peer_id
        self.timeout = timeout
        super().__init__(
            f"peer {peer_id} unreachable within {timeout}s"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.WAIT


class AuthenticationFailedError(CairnError):
    """Authentication failed — possible key compromise."""

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        super().__init__(
            f"authentication failed for session {session_id}: "
            f"cryptographic verification failed"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.ABORT


class PairingRejectedError(CairnError):
    """Pairing rejected by remote peer."""

    def __init__(self, peer_id: str = "") -> None:
        self.peer_id = peer_id
        super().__init__(
            f"pairing rejected by remote peer {peer_id}"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.INFORM


class PairingExpiredError(CairnError):
    """Pairing payload expired."""

    def __init__(self, expiry: float = 0.0) -> None:
        self.expiry = expiry
        super().__init__(
            f"pairing payload expired after {expiry}s. "
            f"Generate a new payload to retry."
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.REGENERATE


class MeshRouteNotFoundError(CairnError):
    """No mesh route found to peer."""

    def __init__(
        self, peer_id: str = "", suggestion: str = ""
    ) -> None:
        self.peer_id = peer_id
        self.suggestion = suggestion or (
            "try a direct connection or wait for mesh route discovery"
        )
        super().__init__(
            f"no mesh route found to {peer_id}: {self.suggestion}"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.WAIT


class VersionMismatchError(CairnError):
    """Protocol version mismatch."""

    def __init__(
        self,
        local_version: str = "",
        remote_version: str = "",
        suggestion: str = "",
    ) -> None:
        self.local_version = local_version
        self.remote_version = remote_version
        self.suggestion = suggestion or (
            "peer needs to update to a compatible cairn version"
        )
        super().__init__(
            f"protocol version mismatch: local {local_version}, "
            f"remote {remote_version}. {self.suggestion}"
        )

    @property
    def behavior(self) -> ErrorBehavior:
        return ErrorBehavior.ABORT
