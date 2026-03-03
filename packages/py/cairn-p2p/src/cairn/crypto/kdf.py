"""HKDF-SHA256 key derivation with domain separation constants."""

from __future__ import annotations

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Domain separation info strings for HKDF derivations.
HKDF_INFO_SESSION_KEY: bytes = b"cairn-session-key-v1"
HKDF_INFO_RENDEZVOUS: bytes = b"cairn-rendezvous-id-v1"
HKDF_INFO_SAS: bytes = b"cairn-sas-derivation-v1"
HKDF_INFO_CHAIN_KEY: bytes = b"cairn-chain-key-v1"
HKDF_INFO_MESSAGE_KEY: bytes = b"cairn-message-key-v1"


def hkdf_sha256(
    ikm: bytes,
    salt: bytes | None,
    info: bytes,
    length: int,
) -> bytes:
    """Derive key material from input keying material using HKDF-SHA256.

    Args:
        ikm: Input keying material (e.g., DH shared secret).
        salt: Optional salt (None uses a zero-filled salt).
        info: Context-specific info string for domain separation.
        length: Number of bytes to derive.

    Returns:
        Derived key material of the requested length.

    Raises:
        ValueError: If the requested length exceeds HKDF limits.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)
