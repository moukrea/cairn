"""Pairing state machine: SPAKE2-based and standard pairing flows.

Ports the Rust ``PairingSession`` state machine with identical constants,
state transitions, key derivation (HKDF-SHA256), and key confirmation
(HMAC-SHA256).
"""

from __future__ import annotations

import hmac
import os
import time
from enum import Enum, auto
from typing import TypedDict

from cairn.crypto.kdf import hkdf_sha256
from cairn.crypto.spake2_pake import Spake2Session

# ---------------------------------------------------------------------------
# Constants (must match Rust / Go / TS)
# ---------------------------------------------------------------------------

HKDF_INFO_PAIRING_SESSION: bytes = b"cairn-pairing-session-key-v1"
"""HKDF info string for pairing session key derivation."""

HKDF_INFO_KEY_CONFIRM: bytes = b"cairn-pairing-key-confirm-v1"
"""HMAC key derivation info for key confirmation."""

DEFAULT_PAIRING_TIMEOUT: float = 300.0
"""Default pairing timeout in seconds (5 minutes)."""

_NONCE_LEN: int = 16


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PairingState(Enum):
    """Pairing session state."""

    Idle = auto()
    AwaitingPakeExchange = auto()
    AwaitingVerification = auto()
    AwaitingConfirmation = auto()
    Completed = auto()
    Failed = auto()


class PairingRole(Enum):
    """Whether this session is acting as initiator or responder."""

    Initiator = auto()
    Responder = auto()


class PairingFlowType(Enum):
    """Pairing flow type."""

    Initiation = auto()
    Standard = auto()


class PairRejectReason(Enum):
    """Reason for rejecting a pairing request."""

    UserRejected = auto()
    AuthenticationFailed = auto()
    Timeout = auto()
    RateLimited = auto()


# ---------------------------------------------------------------------------
# Pairing messages (plain dicts with a ``type`` discriminator)
# ---------------------------------------------------------------------------


class PairRequest(TypedDict):
    type: str  # "request"
    peer_id: bytes
    nonce: bytes
    pake_msg: bytes | None
    flow_type: PairingFlowType


class PairChallenge(TypedDict):
    type: str  # "challenge"
    peer_id: bytes
    nonce: bytes
    pake_msg: bytes


class PairResponse(TypedDict):
    type: str  # "response"
    key_confirmation: bytes


class PairConfirm(TypedDict):
    type: str  # "confirm"
    key_confirmation: bytes


class PairReject(TypedDict):
    type: str  # "reject"
    reason: PairRejectReason


PairingMessage = PairRequest | PairChallenge | PairResponse | PairConfirm | PairReject
"""Union of all pairing messages exchanged during the handshake."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PairingError(Exception):
    """Pairing-specific error."""


class PairingTimeoutError(PairingError):
    """Session timed out."""


class PakeFailureError(PairingError):
    """PAKE authentication failed (key confirmation mismatch)."""


class InvalidTransitionError(PairingError):
    """Invalid state transition."""

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"invalid state transition: expected {expected}, got {actual}"
        )
        self.expected = expected
        self.actual = actual


class RejectedError(PairingError):
    """Rejected by remote peer."""

    def __init__(self, reason: PairRejectReason) -> None:
        super().__init__(f"rejected by peer: {reason.name}")
        self.reason = reason


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_nonce() -> bytes:
    """Generate a 16-byte random nonce."""
    return os.urandom(_NONCE_LEN)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison."""
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# PairingSession
# ---------------------------------------------------------------------------


class PairingSession:
    """A pairing session driving the SPAKE2 exchange and state transitions.

    Follows the Rust ``PairingSession`` state machine:

    * **Initiation flow** (SPAKE2):
      ``PairRequest -> PairChallenge -> PairResponse -> PairConfirm``
    * **Standard flow** (Noise XX + SAS):
      ``PairRequest -> (SAS verification) -> PairResponse -> PairConfirm``

    Factory methods:
        :meth:`new_initiator`, :meth:`new_standard_initiator`,
        :meth:`new_responder`, :meth:`new_standard_responder`.
    """

    __slots__ = (
        "_state",
        "_role",
        "_flow_type",
        "_local_nonce",
        "_remote_nonce",
        "_remote_peer_id",
        "_spake2",
        "_spake2_outbound",
        "_shared_key",
        "_created_at",
        "_timeout",
        "_fail_reason",
    )

    def __init__(
        self,
        *,
        role: PairingRole,
        flow_type: PairingFlowType,
        state: PairingState,
        spake2: Spake2Session | None,
        spake2_outbound: bytes | None,
        timeout: float,
    ) -> None:
        self._state = state
        self._role = role
        self._flow_type = flow_type
        self._local_nonce = _generate_nonce()
        self._remote_nonce: bytes | None = None
        self._remote_peer_id: bytes | None = None
        self._spake2 = spake2
        self._spake2_outbound = spake2_outbound
        self._shared_key: bytes | None = None
        self._created_at = time.monotonic()
        self._timeout = timeout
        self._fail_reason: str | None = None

    # ---- Factory methods --------------------------------------------------

    @classmethod
    def new_initiator(
        cls,
        local_peer_id: bytes,
        password: bytes,
        timeout: float = DEFAULT_PAIRING_TIMEOUT,
    ) -> tuple[PairingSession, PairingMessage]:
        """Create a new initiator session for the initiation flow (SPAKE2).

        Returns the session and the outbound ``PairRequest`` message.
        """
        spake2 = Spake2Session(password, is_initiator=True)
        outbound_msg = spake2.start()

        session = cls(
            role=PairingRole.Initiator,
            flow_type=PairingFlowType.Initiation,
            state=PairingState.AwaitingPakeExchange,
            spake2=spake2,
            spake2_outbound=None,
            timeout=timeout,
        )

        message: PairingMessage = {
            "type": "request",
            "peer_id": local_peer_id,
            "nonce": session._local_nonce,
            "pake_msg": outbound_msg,
            "flow_type": PairingFlowType.Initiation,
        }
        return session, message

    @classmethod
    def new_standard_initiator(
        cls,
        local_peer_id: bytes,
        timeout: float = DEFAULT_PAIRING_TIMEOUT,
    ) -> tuple[PairingSession, PairingMessage]:
        """Create a new initiator session for the standard flow (no SPAKE2).

        Returns the session and the outbound ``PairRequest`` message.
        """
        session = cls(
            role=PairingRole.Initiator,
            flow_type=PairingFlowType.Standard,
            state=PairingState.AwaitingVerification,
            spake2=None,
            spake2_outbound=None,
            timeout=timeout,
        )

        message: PairingMessage = {
            "type": "request",
            "peer_id": local_peer_id,
            "nonce": session._local_nonce,
            "pake_msg": None,
            "flow_type": PairingFlowType.Standard,
        }
        return session, message

    @classmethod
    def new_responder(
        cls,
        password: bytes,
        timeout: float = DEFAULT_PAIRING_TIMEOUT,
    ) -> PairingSession:
        """Create a new responder session for the initiation flow (SPAKE2).

        Call :meth:`handle_message` with the received ``PairRequest`` to proceed.
        """
        spake2 = Spake2Session(password, is_initiator=False)
        outbound = spake2.start()

        return cls(
            role=PairingRole.Responder,
            flow_type=PairingFlowType.Initiation,
            state=PairingState.Idle,
            spake2=spake2,
            spake2_outbound=outbound,
            timeout=timeout,
        )

    @classmethod
    def new_standard_responder(
        cls,
        timeout: float = DEFAULT_PAIRING_TIMEOUT,
    ) -> PairingSession:
        """Create a new responder session for the standard flow (no SPAKE2)."""
        return cls(
            role=PairingRole.Responder,
            flow_type=PairingFlowType.Standard,
            state=PairingState.Idle,
            spake2=None,
            spake2_outbound=None,
            timeout=timeout,
        )

    # ---- Properties -------------------------------------------------------

    @property
    def state(self) -> PairingState:
        """Current session state."""
        return self._state

    @property
    def role(self) -> PairingRole:
        """Session role."""
        return self._role

    @property
    def flow_type(self) -> PairingFlowType:
        """Flow type."""
        return self._flow_type

    @property
    def remote_peer_id(self) -> bytes | None:
        """Remote peer ID (if known)."""
        return self._remote_peer_id

    @property
    def shared_key(self) -> bytes | None:
        """Shared key (only available in Completed state)."""
        if self._state is PairingState.Completed:
            return self._shared_key
        return None

    @property
    def is_expired(self) -> bool:
        """Check if this session has expired."""
        return time.monotonic() - self._created_at > self._timeout

    @property
    def local_nonce(self) -> bytes:
        """Local nonce."""
        return self._local_nonce

    @property
    def fail_reason(self) -> str | None:
        """Failure reason, if any."""
        return self._fail_reason

    # ---- Setters ----------------------------------------------------------

    def set_shared_key(self, key: bytes) -> None:
        """Set a pre-established shared key (from Noise XX handshake, standard flow)."""
        self._shared_key = bytes(key)

    def set_remote_nonce(self, nonce: bytes) -> None:
        """Set the remote peer's nonce."""
        self._remote_nonce = bytes(nonce)

    # ---- Key confirmation -------------------------------------------------

    def send_key_confirmation(
        self, local_peer_id: bytes | None = None,
    ) -> PairingMessage:
        """Produce a key confirmation message and advance to AwaitingConfirmation.

        Call this when the local side is ready to confirm the pairing (e.g.
        after the user confirms the SAS matches). Returns a ``PairResponse``
        (initiator) or ``PairConfirm`` (responder) to send to the peer.
        """
        if self._state is not PairingState.AwaitingVerification:
            raise InvalidTransitionError(
                "AwaitingVerification", self._state.name
            )

        label = (
            b"initiator"
            if self._role is PairingRole.Initiator
            else b"responder"
        )
        confirmation = self._compute_key_confirmation(label)
        self._state = PairingState.AwaitingConfirmation

        if self._role is PairingRole.Initiator:
            return {"type": "response", "key_confirmation": confirmation}
        return {"type": "confirm", "key_confirmation": confirmation}

    # ---- Message dispatch -------------------------------------------------

    def handle_message(
        self,
        msg: PairingMessage,
        local_peer_id: bytes | None = None,
    ) -> PairingMessage | None:
        """Process an incoming pairing message.

        Returns an optional outbound response message, or ``None``.

        Raises:
            PairingError: On invalid transitions, timeout, or authentication
                failure.
        """
        if self.is_expired:
            self._state = PairingState.Failed
            self._fail_reason = "session expired"
            raise PairingTimeoutError(
                f"pairing timed out after {self._timeout}s"
            )

        msg_type = msg["type"]
        if msg_type == "request":
            return self._handle_request(msg, local_peer_id)  # type: ignore[arg-type]
        if msg_type == "challenge":
            return self._handle_challenge(msg)  # type: ignore[arg-type]
        if msg_type == "response":
            return self._handle_response(msg)  # type: ignore[arg-type]
        if msg_type == "confirm":
            return self._handle_confirm(msg)  # type: ignore[arg-type]
        if msg_type == "reject":
            return self._handle_reject(msg)  # type: ignore[arg-type]

        raise PairingError(f"unknown message type: {msg_type}")

    # ---- Message handlers (private) ---------------------------------------

    def _handle_request(
        self,
        req: PairRequest,
        local_peer_id: bytes | None,
    ) -> PairingMessage | None:
        """Responder receives PairRequest."""
        if self._role is not PairingRole.Responder:
            raise InvalidTransitionError("Responder role", "Initiator role")
        if self._state is not PairingState.Idle:
            raise InvalidTransitionError("Idle", self._state.name)

        self._remote_peer_id = bytes(req["peer_id"])
        self._remote_nonce = bytes(req["nonce"])

        if req["flow_type"] is PairingFlowType.Initiation:
            pake_msg = req.get("pake_msg")
            if pake_msg is None:
                raise PairingError(
                    "initiation flow PairRequest must have pake_msg"
                )

            spake2 = self._spake2
            if spake2 is None:
                raise PairingError("SPAKE2 state not initialized")

            # Finish SPAKE2 with the initiator's message.
            raw_key = spake2.finish(pake_msg)
            self._spake2 = None

            # Derive session key.
            self._shared_key = self._derive_session_key(raw_key)

            # Retrieve stored outbound SPAKE2 message.
            outbound = self._spake2_outbound
            if outbound is None:
                raise PairingError("SPAKE2 outbound message not stored")
            self._spake2_outbound = None

            self._state = PairingState.AwaitingVerification

            return {
                "type": "challenge",
                "peer_id": local_peer_id or b"\x00" * 34,
                "nonce": self._local_nonce,
                "pake_msg": outbound,
            }

        # Standard flow -- no PAKE exchange needed.
        self._state = PairingState.AwaitingVerification
        return None

    def _handle_challenge(self, chal: PairChallenge) -> PairingMessage:
        """Initiator receives PairChallenge."""
        if self._role is not PairingRole.Initiator:
            raise InvalidTransitionError("Initiator role", "Responder role")
        if self._state is not PairingState.AwaitingPakeExchange:
            raise InvalidTransitionError(
                "AwaitingPakeExchange", self._state.name
            )

        self._remote_peer_id = bytes(chal["peer_id"])
        self._remote_nonce = bytes(chal["nonce"])

        # Finish SPAKE2 with responder's message.
        spake2 = self._spake2
        if spake2 is None:
            raise PairingError("SPAKE2 state already consumed")

        raw_key = spake2.finish(chal["pake_msg"])
        self._spake2 = None

        # Derive session key.
        self._shared_key = self._derive_session_key(raw_key)

        # Compute key confirmation.
        confirmation = self._compute_key_confirmation(b"initiator")

        self._state = PairingState.AwaitingConfirmation
        return {"type": "response", "key_confirmation": confirmation}

    def _handle_response(self, resp: PairResponse) -> PairingMessage:
        """Responder receives PairResponse (key confirmation from initiator)."""
        if self._role is not PairingRole.Responder:
            raise InvalidTransitionError("Responder role", "Initiator role")
        if self._state is not PairingState.AwaitingVerification:
            raise InvalidTransitionError(
                "AwaitingVerification", self._state.name
            )

        # Verify initiator's key confirmation.
        expected = self._compute_key_confirmation(b"initiator")
        if not _constant_time_eq(resp["key_confirmation"], expected):
            self._state = PairingState.Failed
            self._fail_reason = "key confirmation mismatch"
            raise PakeFailureError(
                "PAKE authentication failed: key confirmation mismatch"
            )

        # Send our own key confirmation.
        confirmation = self._compute_key_confirmation(b"responder")

        self._state = PairingState.AwaitingConfirmation
        return {"type": "confirm", "key_confirmation": confirmation}

    def _handle_confirm(self, confirm: PairConfirm) -> PairingMessage | None:
        """Handle PairConfirm (mutual key confirmation)."""
        if self._state is not PairingState.AwaitingConfirmation:
            raise InvalidTransitionError(
                "AwaitingConfirmation", self._state.name
            )

        # Verify the peer's key confirmation.
        label = (
            b"responder"
            if self._role is PairingRole.Initiator
            else b"initiator"
        )
        expected = self._compute_key_confirmation(label)
        if not _constant_time_eq(confirm["key_confirmation"], expected):
            self._state = PairingState.Failed
            self._fail_reason = "key confirmation mismatch"
            raise PakeFailureError(
                "PAKE authentication failed: key confirmation mismatch"
            )

        self._state = PairingState.Completed

        # Initiator sends their own Confirm back.
        if self._role is PairingRole.Initiator:
            our_confirm = self._compute_key_confirmation(b"initiator")
            return {"type": "confirm", "key_confirmation": our_confirm}

        return None

    def _handle_reject(self, reject: PairReject) -> None:
        """Handle PairReject."""
        self._state = PairingState.Failed
        self._fail_reason = f"rejected: {reject['reason'].name}"
        raise RejectedError(reject["reason"])

    # ---- Key derivation helpers -------------------------------------------

    def _derive_session_key(self, raw_key: bytes) -> bytes:
        """Derive a 32-byte session key from the raw SPAKE2 output via HKDF.

        salt = initiator_nonce || responder_nonce
        """
        parts: list[bytes] = []
        if self._role is PairingRole.Initiator:
            parts.append(self._local_nonce)
            if self._remote_nonce is not None:
                parts.append(self._remote_nonce)
        else:
            if self._remote_nonce is not None:
                parts.append(self._remote_nonce)
            parts.append(self._local_nonce)

        salt = b"".join(parts)
        return hkdf_sha256(raw_key, salt, HKDF_INFO_PAIRING_SESSION, 32)

    def _compute_key_confirmation(self, label: bytes) -> bytes:
        """Compute HMAC-SHA256 key confirmation.

        1. Derive a confirmation key via HKDF(shared_key, info=HKDF_INFO_KEY_CONFIRM).
        2. Return HMAC-SHA256(confirm_key, label).
        """
        if self._shared_key is None:
            raise PairingError("no shared key available for key confirmation")

        confirm_key = hkdf_sha256(
            self._shared_key, None, HKDF_INFO_KEY_CONFIRM, 32
        )
        return hmac.new(confirm_key, label, "sha256").digest()

    # ---- Reject helper ----------------------------------------------------

    def reject(self, reason: str) -> None:
        """Move the session to Failed."""
        self._state = PairingState.Failed
        self._fail_reason = reason

    # ---- repr -------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"PairingSession(state={self._state.name}, "
            f"role={self._role.name}, flow={self._flow_type.name})"
        )
