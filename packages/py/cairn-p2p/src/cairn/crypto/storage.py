"""Key storage backends: in-memory and encrypted filesystem (spec 04, section 3).

Provides ``KeyStorage`` ABC, ``InMemoryKeyStorage`` (for testing), and
``FilesystemKeyStorage`` (AES-256-GCM encrypted, PBKDF2-derived key).
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NONCE_SIZE = 12  # AES-GCM nonce
SALT_LEN = 16   # PBKDF2 salt
KEY_SIZE = 32    # AES-256
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for SHA-256


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class KeyStorage(ABC):
    """Abstract key storage interface.

    Implementations store, retrieve, delete, and list opaque key blobs
    identified by string key IDs.
    """

    @abstractmethod
    def store(self, key_id: str, key_data: bytes) -> None:
        """Store key data under the given ID. Overwrites if exists."""

    @abstractmethod
    def load(self, key_id: str) -> bytes | None:
        """Load key data by ID. Returns None if not found."""

    @abstractmethod
    def delete(self, key_id: str) -> bool:
        """Delete key by ID. Returns True if the key existed."""

    @abstractmethod
    def list_keys(self) -> list[str]:
        """Return all stored key IDs."""

    def exists(self, key_id: str) -> bool:
        """Check if a key exists."""
        return self.load(key_id) is not None


# ---------------------------------------------------------------------------
# In-memory backend
# ---------------------------------------------------------------------------


class InMemoryKeyStorage(KeyStorage):
    """Ephemeral in-memory key storage. All data is lost on garbage collection.

    Useful for testing and short-lived processes that do not need persistence.
    """

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def store(self, key_id: str, key_data: bytes) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        self._store[key_id] = key_data

    def load(self, key_id: str) -> bytes | None:
        return self._store.get(key_id)

    def delete(self, key_id: str) -> bool:
        if key_id in self._store:
            del self._store[key_id]
            return True
        return False

    def list_keys(self) -> list[str]:
        return list(self._store.keys())


# ---------------------------------------------------------------------------
# Filesystem backend (encrypted)
# ---------------------------------------------------------------------------


class FilesystemKeyStorage(KeyStorage):
    """Encrypted filesystem key storage using AES-256-GCM.

    Each key is stored as an encrypted file in the configured directory.
    The encryption key is derived from a user-provided passphrase using
    PBKDF2-HMAC-SHA256. A random salt is generated on first creation and
    persisted in a ``salt`` file alongside the key files.

    File format per key: ``[12-byte nonce][ciphertext + 16-byte GCM tag]``

    Writes are atomic (write temp file, then rename) to prevent corruption.
    """

    def __init__(self, base_dir: str | Path, passphrase: str) -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

        salt = self._load_or_create_salt()
        self._encryption_key = self._derive_key(passphrase, salt)

    def store(self, key_id: str, key_data: bytes) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")

        path = self._key_path(key_id)

        # Generate random nonce
        nonce = os.urandom(NONCE_SIZE)

        # Encrypt with key_id as AAD to bind ciphertext to its identifier
        aesgcm = AESGCM(self._encryption_key)
        ciphertext = aesgcm.encrypt(nonce, key_data, key_id.encode())

        # Build file content: [nonce][ciphertext+tag]
        file_content = nonce + ciphertext

        # Atomic write: temp -> rename
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_bytes(file_content)
        tmp_path.rename(path)

    def load(self, key_id: str) -> bytes | None:
        path = self._key_path(key_id)
        if not path.exists():
            return None

        file_content = path.read_bytes()
        if len(file_content) < NONCE_SIZE:
            return None

        nonce = file_content[:NONCE_SIZE]
        ciphertext = file_content[NONCE_SIZE:]

        aesgcm = AESGCM(self._encryption_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, key_id.encode())
        except Exception:
            return None

    def delete(self, key_id: str) -> bool:
        path = self._key_path(key_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_keys(self) -> list[str]:
        keys = []
        for p in self._base_dir.iterdir():
            if p.name in ("salt", "salt.tmp") or p.suffix == ".tmp":
                continue
            if p.is_file():
                try:
                    key_id = bytes.fromhex(p.name).decode()
                    keys.append(key_id)
                except (ValueError, UnicodeDecodeError):
                    continue
        return keys

    def _key_path(self, key_id: str) -> Path:
        """Convert key_id to a safe hex-encoded filename."""
        hex_name = key_id.encode().hex()
        return self._base_dir / hex_name

    def _load_or_create_salt(self) -> bytes:
        """Load salt from disk, or create a new one if missing."""
        salt_path = self._base_dir / "salt"
        if salt_path.exists():
            salt = salt_path.read_bytes()
            if len(salt) != SALT_LEN:
                raise ValueError("corrupt salt file: wrong length")
            return salt

        salt = os.urandom(SALT_LEN)
        # Atomic write
        tmp_path = self._base_dir / "salt.tmp"
        tmp_path.write_bytes(salt)
        tmp_path.rename(salt_path)
        return salt

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        """Derive a 32-byte encryption key from passphrase using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode())
