"""AEAD ciphers: AES-256-GCM and ChaCha20-Poly1305."""

from __future__ import annotations

from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

# Constants matching the Rust implementation.
NONCE_SIZE: int = 12
KEY_SIZE: int = 32
AES_GCM_TAG_SIZE: int = 16
CHACHA_TAG_SIZE: int = 16


class CipherSuite(Enum):
    """Supported AEAD cipher suites."""

    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


def aead_encrypt(
    cipher: CipherSuite,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    """Encrypt plaintext with associated data using the specified cipher.

    Returns ciphertext with appended authentication tag.
    """
    if cipher == CipherSuite.AES_256_GCM:
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    else:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(
    cipher: CipherSuite,
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """Decrypt ciphertext with associated data using the specified cipher.

    Returns plaintext on success.
    Raises cryptography.exceptions.InvalidTag on authentication failure.
    """
    if cipher == CipherSuite.AES_256_GCM:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    else:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
