"""Noise XX handshake pattern (Noise_XX_25519_ChaChaPoly_SHA256)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum, auto

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cairn.crypto.aead import CipherSuite, aead_decrypt, aead_encrypt
from cairn.crypto.identity import IdentityKeypair
from cairn.crypto.kdf import HKDF_INFO_SAS, HKDF_INFO_SESSION_KEY, hkdf_sha256

PROTOCOL_NAME: bytes = b"Noise_XX_25519_ChaChaPoly_SHA256"
TAG_SIZE: int = 16
DH_KEY_SIZE: int = 32
ED25519_PUB_SIZE: int = 32
ZERO_NONCE: bytes = bytes(12)

EMOJI_TABLE: list[str] = [
    "dog", "cat", "fish", "bird", "bear", "lion", "wolf", "fox",
    "deer", "owl", "bee", "ant", "star", "moon", "sun", "fire",
    "tree", "leaf", "rose", "wave", "rain", "snow", "bolt", "wind",
    "rock", "gem", "bell", "key", "lock", "flag", "book", "pen",
    "cup", "hat", "shoe", "ring", "cake", "gift", "lamp", "gear",
    "ship", "car", "bike", "drum", "horn", "harp", "dice", "coin",
    "map", "tent", "crown", "sword", "shield", "bow", "axe", "hammer",
    "anchor", "wheel", "clock", "heart", "skull", "ghost", "robot",
    "alien",
]


class Role(Enum):
    INITIATOR = auto()
    RESPONDER = auto()


class _State(Enum):
    INITIATOR_START = auto()
    RESPONDER_WAIT_MSG1 = auto()
    INITIATOR_WAIT_MSG2 = auto()
    RESPONDER_WAIT_MSG3 = auto()
    COMPLETE = auto()


@dataclass
class HandshakeResult:
    """Result of a completed Noise XX handshake."""

    session_key: bytes  # 32 bytes
    remote_static: bytes  # 32-byte Ed25519 public key
    transcript_hash: bytes  # 32 bytes


def _ed25519_private_to_x25519(identity: IdentityKeypair) -> X25519PrivateKey:
    """Convert an Ed25519 private key to an X25519 private key.

    Ed25519 private key bytes are the seed. The actual scalar is derived
    by hashing with SHA-512 and clamping bits, which is what the
    cryptography library does internally for X25519.
    """
    seed = identity.secret_bytes()
    # SHA-512 the seed, take first 32 bytes, clamp for X25519
    h = hashlib.sha512(seed).digest()[:32]
    scalar = bytearray(h)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(scalar))


def _ed25519_public_to_x25519(pub_bytes: bytes) -> bytes:
    """Convert an Ed25519 public key to an X25519 public key.

    Uses the birational map from the Ed25519 curve (twisted Edwards)
    to the X25519 curve (Montgomery). Formula: u = (1 + y) / (1 - y) mod p.
    """
    # Ed25519 uses little-endian encoding of the y coordinate
    # with the sign bit in the top bit of the last byte.
    p = (1 << 255) - 19

    # Extract y coordinate (clear the sign bit)
    y_bytes = bytearray(pub_bytes)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")

    # u = (1 + y) * inverse(1 - y) mod p
    numerator = (1 + y) % p
    denominator = (1 - y) % p
    # Fermat's little theorem for modular inverse
    inv_denom = pow(denominator, p - 2, p)
    u = (numerator * inv_denom) % p

    return u.to_bytes(32, "little")


class NoiseXXHandshake:
    """Noise XX handshake state machine.

    Implements the three-message Noise XX pattern:
        -> e                    (message 1)
        <- e, ee, s, es        (message 2)
        -> s, se               (message 3)

    Initiator flow:
        1. step(None) -> SendMessage(msg1)
        2. step(msg2) -> SendMessage(msg3), result available via result()
    Responder flow:
        1. step(msg1) -> SendMessage(msg2)
        2. step(msg3) -> Complete(result)
    """

    def __init__(
        self, role: Role, identity: IdentityKeypair
    ) -> None:
        self._role = role
        self._identity = identity
        self._local_static_x25519 = _ed25519_private_to_x25519(identity)

        # Initialize handshake hash from protocol name
        if len(PROTOCOL_NAME) <= 32:
            h = bytearray(32)
            h[: len(PROTOCOL_NAME)] = PROTOCOL_NAME
            self._handshake_hash = bytes(h)
        else:
            self._handshake_hash = hashlib.sha256(PROTOCOL_NAME).digest()

        self._chaining_key = self._handshake_hash
        self._current_key: bytes | None = None
        self._pake_secret: bytes | None = None
        self._cached_result: HandshakeResult | None = None

        self._local_ephemeral: X25519PrivateKey | None = None
        self._local_ephemeral_pub: bytes | None = None
        self._remote_ephemeral: bytes | None = None
        self._remote_static: bytes | None = None

        if role == Role.INITIATOR:
            self._state = _State.INITIATOR_START
        else:
            self._state = _State.RESPONDER_WAIT_MSG1

    def with_pake_secret(self, secret: bytes) -> NoiseXXHandshake:
        """Set a SPAKE2-derived pre-shared key for authentication."""
        self._pake_secret = secret
        return self

    def step(
        self, input_data: bytes | None = None
    ) -> tuple[bytes | None, HandshakeResult | None]:
        """Process the next handshake step.

        Returns (message_to_send, result).
        - If message_to_send is not None, send it to the peer.
        - If result is not None, the handshake is complete.
        """
        if self._state == _State.INITIATOR_START:
            if input_data is not None:
                raise ValueError("initiator start expects no input")
            return self._initiator_send_msg1()
        elif self._state == _State.RESPONDER_WAIT_MSG1:
            if input_data is None:
                raise ValueError("responder expects message 1 input")
            return self._responder_recv_msg1_send_msg2(input_data)
        elif self._state == _State.INITIATOR_WAIT_MSG2:
            if input_data is None:
                raise ValueError("initiator expects message 2 input")
            return self._initiator_recv_msg2_send_msg3(input_data)
        elif self._state == _State.RESPONDER_WAIT_MSG3:
            if input_data is None:
                raise ValueError("responder expects message 3 input")
            return self._responder_recv_msg3(input_data)
        else:
            raise ValueError("handshake already complete")

    def result(self) -> HandshakeResult:
        """Get the cached handshake result (initiator only, after msg3)."""
        if self._cached_result is None:
            raise ValueError("handshake not yet complete")
        return self._cached_result

    # --- Message 1: -> e ---

    def _initiator_send_msg1(
        self,
    ) -> tuple[bytes, None]:
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()

        self._mix_hash(eph_pub)
        self._local_ephemeral = eph
        self._local_ephemeral_pub = eph_pub

        self._state = _State.INITIATOR_WAIT_MSG2
        return eph_pub, None

    # --- Message 2: <- e, ee, s, es ---

    def _responder_recv_msg1_send_msg2(
        self, msg1: bytes
    ) -> tuple[bytes, None]:
        if len(msg1) != DH_KEY_SIZE:
            raise ValueError(
                f"message 1 invalid length: expected {DH_KEY_SIZE}, "
                f"got {len(msg1)}"
            )

        remote_e = msg1[:DH_KEY_SIZE]
        self._mix_hash(remote_e)
        self._remote_ephemeral = remote_e

        msg2 = bytearray()

        # e: generate responder ephemeral
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()
        self._mix_hash(eph_pub)
        msg2.extend(eph_pub)

        self._local_ephemeral = eph
        self._local_ephemeral_pub = eph_pub

        # ee: DH(responder_ephemeral, initiator_ephemeral)
        remote_eph_key = X25519PublicKey.from_public_bytes(remote_e)
        ee_shared = eph.exchange(remote_eph_key)
        self._mix_key(ee_shared)

        # s: encrypt and send static Ed25519 public key
        static_pub = self._identity.public_key_bytes()
        encrypted_static = self._encrypt_and_hash(static_pub)
        msg2.extend(encrypted_static)

        # es: DH(responder_static_x25519, initiator_ephemeral)
        es_shared = self._local_static_x25519.exchange(remote_eph_key)
        self._mix_key(es_shared)

        # Encrypt empty payload
        encrypted_payload = self._encrypt_and_hash(b"")
        msg2.extend(encrypted_payload)

        self._state = _State.RESPONDER_WAIT_MSG3
        return bytes(msg2), None

    # --- Initiator: recv msg2, send msg3 ---

    def _initiator_recv_msg2_send_msg3(
        self, msg2: bytes
    ) -> tuple[bytes, None]:
        min_len = DH_KEY_SIZE + (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE
        if len(msg2) < min_len:
            raise ValueError(
                f"message 2 too short: expected >= {min_len}, "
                f"got {len(msg2)}"
            )

        offset = 0

        # e: responder ephemeral
        remote_e = msg2[offset : offset + DH_KEY_SIZE]
        self._mix_hash(remote_e)
        self._remote_ephemeral = remote_e
        offset += DH_KEY_SIZE

        # ee: DH(initiator_ephemeral, responder_ephemeral)
        remote_eph_key = X25519PublicKey.from_public_bytes(remote_e)
        ee_shared = self._local_ephemeral.exchange(remote_eph_key)
        self._mix_key(ee_shared)

        # s: decrypt responder's static public key
        enc_static = msg2[
            offset : offset + ED25519_PUB_SIZE + TAG_SIZE
        ]
        static_pub = self._decrypt_and_hash(enc_static)
        offset += ED25519_PUB_SIZE + TAG_SIZE

        if len(static_pub) != ED25519_PUB_SIZE:
            raise ValueError("decrypted static key wrong size")

        self._remote_static = static_pub

        # Convert remote Ed25519 public to X25519 for DH
        remote_static_x25519 = _ed25519_public_to_x25519(static_pub)
        remote_static_x25519_key = X25519PublicKey.from_public_bytes(
            remote_static_x25519
        )

        # es: DH(initiator_ephemeral, responder_static_x25519)
        es_shared = self._local_ephemeral.exchange(remote_static_x25519_key)
        self._mix_key(es_shared)

        # Decrypt payload
        enc_payload = msg2[offset:]
        self._decrypt_and_hash(enc_payload)

        # Build message 3: -> s, se
        msg3 = bytearray()

        # s: encrypt initiator's static Ed25519 public key
        our_static_pub = self._identity.public_key_bytes()
        encrypted_our_static = self._encrypt_and_hash(our_static_pub)
        msg3.extend(encrypted_our_static)

        # se: DH(initiator_static_x25519, responder_ephemeral)
        se_shared = self._local_static_x25519.exchange(remote_eph_key)
        self._mix_key(se_shared)

        # Mix PAKE secret if present
        if self._pake_secret is not None:
            self._mix_key(self._pake_secret)

        # Encrypt empty payload
        encrypted_payload = self._encrypt_and_hash(b"")
        msg3.extend(encrypted_payload)

        # Derive session key
        session_key = self._derive_session_key()
        self._cached_result = HandshakeResult(
            session_key=session_key,
            remote_static=static_pub,
            transcript_hash=self._handshake_hash,
        )

        self._state = _State.COMPLETE
        return bytes(msg3), None

    # --- Responder: recv msg3 ---

    def _responder_recv_msg3(
        self, msg3: bytes
    ) -> tuple[None, HandshakeResult]:
        min_len = (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE
        if len(msg3) < min_len:
            raise ValueError(
                f"message 3 too short: expected >= {min_len}, "
                f"got {len(msg3)}"
            )

        offset = 0

        # s: decrypt initiator's static public key
        enc_static = msg3[
            offset : offset + ED25519_PUB_SIZE + TAG_SIZE
        ]
        static_pub = self._decrypt_and_hash(enc_static)
        offset += ED25519_PUB_SIZE + TAG_SIZE

        if len(static_pub) != ED25519_PUB_SIZE:
            raise ValueError("decrypted static key wrong size")

        self._remote_static = static_pub

        # Convert remote Ed25519 to X25519
        remote_static_x25519 = _ed25519_public_to_x25519(static_pub)
        remote_static_x25519_key = X25519PublicKey.from_public_bytes(
            remote_static_x25519
        )

        # se: DH(responder_ephemeral, initiator_static_x25519)
        se_shared = self._local_ephemeral.exchange(
            remote_static_x25519_key
        )
        self._mix_key(se_shared)

        # Mix PAKE secret if present
        if self._pake_secret is not None:
            self._mix_key(self._pake_secret)

        # Decrypt payload
        enc_payload = msg3[offset:]
        self._decrypt_and_hash(enc_payload)

        # Derive session key
        session_key = self._derive_session_key()

        self._state = _State.COMPLETE
        result = HandshakeResult(
            session_key=session_key,
            remote_static=static_pub,
            transcript_hash=self._handshake_hash,
        )
        return None, result

    # --- Noise symmetric state operations ---

    def _mix_key(self, ikm: bytes) -> None:
        """Mix a DH result into the chaining key via HKDF."""
        output = hkdf_sha256(ikm, self._chaining_key, b"", 64)
        self._chaining_key = output[:32]
        self._current_key = output[32:64]

    def _mix_hash(self, data: bytes) -> None:
        """Mix data into the handshake hash: h = SHA-256(h || data)."""
        h = hashlib.sha256(self._handshake_hash + data).digest()
        self._handshake_hash = h

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt and mix ciphertext into handshake hash."""
        if self._current_key is None:
            raise ValueError("no encryption key available")
        ct = aead_encrypt(
            CipherSuite.CHACHA20_POLY1305,
            self._current_key,
            ZERO_NONCE,
            plaintext,
            self._handshake_hash,
        )
        self._mix_hash(ct)
        return ct

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Decrypt and mix ciphertext into handshake hash."""
        if self._current_key is None:
            raise ValueError("no decryption key available")
        h_before = self._handshake_hash
        self._mix_hash(ciphertext)
        return aead_decrypt(
            CipherSuite.CHACHA20_POLY1305,
            self._current_key,
            ZERO_NONCE,
            ciphertext,
            h_before,
        )

    def _derive_session_key(self) -> bytes:
        """Derive the final session key from the chaining key."""
        return hkdf_sha256(
            self._chaining_key, None, HKDF_INFO_SESSION_KEY, 32
        )


def derive_numeric_sas(transcript_hash: bytes) -> str:
    """Derive a 6-digit numeric SAS from the handshake transcript hash."""
    derived = hkdf_sha256(transcript_hash, None, HKDF_INFO_SAS, 4)
    value = int.from_bytes(derived, "big") % 1_000_000
    return f"{value:06d}"


def derive_emoji_sas(transcript_hash: bytes) -> list[str]:
    """Derive an emoji SAS (4 emoji names) from the transcript hash."""
    derived = hkdf_sha256(transcript_hash, None, HKDF_INFO_SAS, 4)
    return [EMOJI_TABLE[b % 64] for b in derived]
