"""Pre-Shared Key (PSK) pairing mechanism.

A secret configured on both peers ahead of time (config file, environment
variable, secrets manager). Used as PAKE input for the SPAKE2 exchange;
rendezvous ID derived from it via HKDF-SHA256.

Minimum entropy: 128 bits (16 bytes) since PSKs are not time-limited.
"""

from __future__ import annotations

from cairn.crypto.kdf import hkdf_sha256

# ---------------------------------------------------------------------------
# Constants (must match Rust / Go / TS)
# ---------------------------------------------------------------------------

HKDF_INFO_PSK_RENDEZVOUS: bytes = b"cairn-psk-rendezvous-v1"
"""HKDF info string for PSK rendezvous ID derivation."""

DEFAULT_MIN_ENTROPY_BYTES: int = 16
"""Default minimum entropy in bytes (128 bits)."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PskError(Exception):
    """Base error for PSK operations."""


class EmptyKeyError(PskError):
    """The pre-shared key is empty."""

    def __init__(self) -> None:
        super().__init__("empty pre-shared key")


class InsufficientEntropyError(PskError):
    """The pre-shared key has insufficient entropy."""

    def __init__(self, got: int, min_bytes: int) -> None:
        super().__init__(
            f"insufficient PSK entropy: got {got} bytes, "
            f"need at least {min_bytes} bytes ({min_bytes * 8} bits)"
        )
        self.got = got
        self.min_bytes = min_bytes


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_psk_entropy(
    psk: bytes,
    min_bytes: int = DEFAULT_MIN_ENTROPY_BYTES,
) -> None:
    """Validate that a pre-shared key has sufficient entropy.

    Args:
        psk: The pre-shared key bytes.
        min_bytes: Minimum length in bytes (default: 16 = 128 bits).

    Raises:
        EmptyKeyError: If the PSK is empty.
        InsufficientEntropyError: If the PSK is shorter than *min_bytes*.
    """
    if len(psk) == 0:
        raise EmptyKeyError()
    if len(psk) < min_bytes:
        raise InsufficientEntropyError(len(psk), min_bytes)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_psk_rendezvous_id(psk: bytes) -> bytes:
    """Derive a 32-byte rendezvous ID from a pre-shared key.

    Uses HKDF-SHA256 with:
    - ikm: *psk*
    - salt: ``None``
    - info: ``"cairn-psk-rendezvous-v1"``

    Args:
        psk: The pre-shared key bytes (>= 16 bytes).

    Returns:
        32-byte rendezvous ID.

    Raises:
        EmptyKeyError: If the PSK is empty.
        InsufficientEntropyError: If the PSK is too short.
    """
    validate_psk_entropy(psk)
    return hkdf_sha256(psk, None, HKDF_INFO_PSK_RENDEZVOUS, 32)


def psk_to_pake_input(psk: bytes | str) -> bytes:
    """Get the SPAKE2 password input from a PSK.

    The PSK is used directly as the SPAKE2 password bytes.

    Args:
        psk: The pre-shared key, either raw bytes or a string (encoded as
            UTF-8).

    Returns:
        The PSK bytes suitable for use as SPAKE2 password input.

    Raises:
        EmptyKeyError: If the PSK is empty.
        InsufficientEntropyError: If the PSK is too short.
    """
    raw = psk.encode("utf-8") if isinstance(psk, str) else psk
    validate_psk_entropy(raw)
    return raw


# ---------------------------------------------------------------------------
# High-level convenience
# ---------------------------------------------------------------------------


class PskMechanism:
    """Pre-Shared Key pairing mechanism.

    Validates entropy, derives rendezvous IDs, and provides PAKE input
    from a pre-shared key.

    Args:
        min_entropy_bytes: Minimum key length in bytes (default: 16 = 128 bits).
    """

    __slots__ = ("_min_entropy_bytes",)

    def __init__(
        self, min_entropy_bytes: int = DEFAULT_MIN_ENTROPY_BYTES
    ) -> None:
        self._min_entropy_bytes = min_entropy_bytes

    @property
    def min_entropy_bytes(self) -> int:
        """Minimum entropy requirement in bytes."""
        return self._min_entropy_bytes

    def validate_entropy(self, psk: bytes) -> None:
        """Validate that the PSK has sufficient entropy.

        Raises:
            EmptyKeyError: If the PSK is empty.
            InsufficientEntropyError: If the PSK is too short.
        """
        validate_psk_entropy(psk, self._min_entropy_bytes)

    def derive_rendezvous_id(self, psk: bytes) -> bytes:
        """Derive a 32-byte rendezvous ID from the PSK.

        Raises:
            EmptyKeyError: If the PSK is empty.
            InsufficientEntropyError: If the PSK is too short.
        """
        self.validate_entropy(psk)
        return hkdf_sha256(psk, None, HKDF_INFO_PSK_RENDEZVOUS, 32)

    def pake_input(self, psk: bytes) -> bytes:
        """Get the SPAKE2 password input from the PSK.

        The PSK is used directly as the SPAKE2 password bytes.

        Raises:
            EmptyKeyError: If the PSK is empty.
            InsufficientEntropyError: If the PSK is too short.
        """
        self.validate_entropy(psk)
        return bytes(psk)
