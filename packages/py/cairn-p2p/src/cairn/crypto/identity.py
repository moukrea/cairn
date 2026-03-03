"""Ed25519 identity keypair and PeerId derivation."""

from __future__ import annotations

import hashlib

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# Multihash constants for SHA2-256.
_MULTIHASH_SHA2_256_CODE: int = 0x12
_MULTIHASH_SHA2_256_LEN: int = 0x20
_PEER_ID_LEN: int = 34


def peer_id_from_public_key(public_key_bytes: bytes) -> bytes:
    """Derive the 32-byte peer ID digest from a raw 32-byte Ed25519 public key."""
    return hashlib.sha256(public_key_bytes).digest()


class PeerId:
    """A peer identifier: 34-byte multihash of an Ed25519 public key.

    Format: [0x12, 0x20, <32-byte SHA-256 digest>].
    Text encoding: base58 (Bitcoin alphabet).
    """

    __slots__ = ("_bytes",)

    def __init__(self, data: bytes) -> None:
        if len(data) != _PEER_ID_LEN:
            raise ValueError(
                f"PeerId must be {_PEER_ID_LEN} bytes, got {len(data)}"
            )
        if data[0] != _MULTIHASH_SHA2_256_CODE:
            raise ValueError(
                f"invalid multihash code: 0x{data[0]:02X}"
            )
        if data[1] != _MULTIHASH_SHA2_256_LEN:
            raise ValueError(
                f"invalid multihash length: 0x{data[1]:02X}"
            )
        self._bytes = bytes(data)

    @classmethod
    def from_public_key(cls, public_key_bytes: bytes) -> PeerId:
        """Derive a PeerId from a raw 32-byte Ed25519 public key."""
        digest = peer_id_from_public_key(public_key_bytes)
        data = bytes([_MULTIHASH_SHA2_256_CODE, _MULTIHASH_SHA2_256_LEN])
        return cls(data + digest)

    @classmethod
    def from_base58(cls, s: str) -> PeerId:
        """Parse a PeerId from a base58 string."""
        data = base58.b58decode(s)
        return cls(data)

    def as_bytes(self) -> bytes:
        """Return the raw 34-byte multihash representation."""
        return self._bytes

    def to_base58(self) -> str:
        """Encode as a base58 string (Bitcoin alphabet)."""
        return base58.b58encode(self._bytes).decode("ascii")

    def __repr__(self) -> str:
        return f"PeerId({self.to_base58()})"

    def __str__(self) -> str:
        return self.to_base58()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PeerId):
            return NotImplemented
        return self._bytes == other._bytes

    def __hash__(self) -> int:
        return hash(self._bytes)


class IdentityKeypair:
    """An Ed25519 identity keypair for signing and peer identification."""

    __slots__ = ("_private_key",)

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> IdentityKeypair:
        """Generate a new random Ed25519 identity keypair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, secret: bytes) -> IdentityKeypair:
        """Restore from a 32-byte secret key seed."""
        if len(secret) != 32:
            raise ValueError(
                f"secret must be 32 bytes, got {len(secret)}"
            )
        return cls(Ed25519PrivateKey.from_private_bytes(secret))

    def secret_bytes(self) -> bytes:
        """Export the 32-byte secret key seed."""
        return self._private_key.private_bytes_raw()

    def public_key_bytes(self) -> bytes:
        """Get the raw 32-byte Ed25519 public key."""
        return self._private_key.public_key().public_bytes_raw()

    def peer_id(self) -> PeerId:
        """Derive the PeerId from this keypair's public key."""
        return PeerId.from_public_key(self.public_key_bytes())

    def peer_id_bytes(self) -> bytes:
        """Derive the 32-byte peer ID digest (SHA-256 of public key)."""
        return peer_id_from_public_key(self.public_key_bytes())

    def sign(self, message: bytes) -> bytes:
        """Sign a message. Returns a 64-byte Ed25519 signature."""
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify a signature against this keypair's public key.

        Raises cryptography.exceptions.InvalidSignature on failure.
        """
        self._private_key.public_key().verify(signature, message)


def verify_signature(
    public_key_bytes: bytes, message: bytes, signature: bytes
) -> None:
    """Verify a signature against a raw 32-byte Ed25519 public key.

    Raises cryptography.exceptions.InvalidSignature on failure.
    """
    pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    pk.verify(signature, message)


class X25519Keypair:
    """An X25519 keypair for Diffie-Hellman key exchange."""

    __slots__ = ("_private_key",)

    def __init__(self, private_key: X25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> X25519Keypair:
        """Generate a new random X25519 keypair."""
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, secret: bytes) -> X25519Keypair:
        """Restore from a 32-byte secret key."""
        if len(secret) != 32:
            raise ValueError(
                f"secret must be 32 bytes, got {len(secret)}"
            )
        return cls(X25519PrivateKey.from_private_bytes(secret))

    def secret_bytes(self) -> bytes:
        """Export the 32-byte secret key."""
        return self._private_key.private_bytes_raw()

    def public_key_bytes(self) -> bytes:
        """Get the raw 32-byte X25519 public key."""
        return self._private_key.public_key().public_bytes_raw()

    def diffie_hellman(self, peer_public: bytes) -> bytes:
        """Perform Diffie-Hellman key exchange with a peer's public key.

        Returns the 32-byte shared secret.
        """
        peer_key = X25519PublicKey.from_public_bytes(peer_public)
        return self._private_key.exchange(peer_key)
