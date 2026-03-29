"""Cryptographic primitives: identity, key exchange, AEAD, HKDF, Noise, SPAKE2."""

from cairn.crypto.aead import (
    AES_GCM_TAG_SIZE,
    CHACHA_TAG_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    CipherSuite,
    aead_decrypt,
    aead_encrypt,
)
from cairn.crypto.identity import (
    IdentityKeypair,
    PeerId,
    X25519Keypair,
    peer_id_from_public_key,
    verify_signature,
)
from cairn.crypto.kdf import (
    HKDF_INFO_CHAIN_KEY,
    HKDF_INFO_MESSAGE_KEY,
    HKDF_INFO_RENDEZVOUS,
    HKDF_INFO_SAS,
    HKDF_INFO_SESSION_KEY,
    hkdf_sha256,
)
from cairn.crypto.noise import (
    EMOJI_TABLE,
    HandshakeResult,
    NoiseXXHandshake,
    Role,
    derive_emoji_sas,
    derive_numeric_sas,
)
from cairn.crypto.ratchet import (
    DoubleRatchet,
    RatchetConfig,
    RatchetHeader,
)
from cairn.crypto.spake2_pake import Spake2Session
from cairn.crypto.storage import (
    FilesystemKeyStorage,
    InMemoryKeyStorage,
    KeyStorage,
    get_default_storage,
)

__all__ = [
    "AES_GCM_TAG_SIZE",
    "CHACHA_TAG_SIZE",
    "CipherSuite",
    "DoubleRatchet",
    "EMOJI_TABLE",
    "HKDF_INFO_CHAIN_KEY",
    "HKDF_INFO_MESSAGE_KEY",
    "HKDF_INFO_RENDEZVOUS",
    "HKDF_INFO_SAS",
    "HKDF_INFO_SESSION_KEY",
    "HandshakeResult",
    "IdentityKeypair",
    "KEY_SIZE",
    "NONCE_SIZE",
    "NoiseXXHandshake",
    "PeerId",
    "RatchetConfig",
    "RatchetHeader",
    "Role",
    "Spake2Session",
    "X25519Keypair",
    "FilesystemKeyStorage",
    "InMemoryKeyStorage",
    "KeyStorage",
    "get_default_storage",
    "aead_decrypt",
    "aead_encrypt",
    "derive_emoji_sas",
    "derive_numeric_sas",
    "hkdf_sha256",
    "peer_id_from_public_key",
    "verify_signature",
]
