"""Signal Double Ratchet for session encryption with forward secrecy."""

from __future__ import annotations

import json
from dataclasses import dataclass

from cairn.crypto.aead import CipherSuite, aead_decrypt, aead_encrypt
from cairn.crypto.identity import X25519Keypair
from cairn.crypto.kdf import hkdf_sha256

# Domain separation constants for the Double Ratchet KDF chains.
HKDF_INFO_ROOT_CHAIN: bytes = b"cairn-root-chain-v1"
HKDF_INFO_CHAIN_ADVANCE: bytes = b"cairn-chain-advance-v1"
HKDF_INFO_MESSAGE_ENCRYPT: bytes = b"cairn-msg-encrypt-v1"


@dataclass
class RatchetConfig:
    """Configuration for the Double Ratchet."""

    max_skip: int = 100
    cipher: CipherSuite = CipherSuite.AES_256_GCM


@dataclass
class RatchetHeader:
    """Header sent alongside each Double Ratchet encrypted message."""

    dh_public: bytes  # 32 bytes
    prev_chain_len: int
    msg_num: int

    def to_bytes(self) -> bytes:
        """Serialize to JSON bytes for use as AEAD AAD."""
        return json.dumps({
            "dh_public": list(self.dh_public),
            "prev_chain_len": self.prev_chain_len,
            "msg_num": self.msg_num,
        }, separators=(",", ":"), sort_keys=True).encode()

    @classmethod
    def from_dict(cls, d: dict) -> RatchetHeader:
        return cls(
            dh_public=bytes(d["dh_public"]),
            prev_chain_len=d["prev_chain_len"],
            msg_num=d["msg_num"],
        )


def _kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Derive new root key and chain key from DH output."""
    output = hkdf_sha256(dh_output, root_key, HKDF_INFO_ROOT_CHAIN, 64)
    return output[:32], output[32:]


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Derive message key from chain key and advance the chain."""
    new_ck = hkdf_sha256(chain_key, None, HKDF_INFO_CHAIN_ADVANCE, 32)
    mk = hkdf_sha256(chain_key, None, HKDF_INFO_MESSAGE_ENCRYPT, 32)
    return new_ck, mk


def _derive_nonce(message_key: bytes, msg_num: int) -> bytes:
    """Derive a 12-byte nonce from a message key and message number."""
    nonce = bytearray(12)
    nonce[:8] = message_key[:8]
    nonce[8:] = msg_num.to_bytes(4, "big")
    return bytes(nonce)


def _decrypt_with_key(
    cipher: CipherSuite,
    message_key: bytes,
    header: RatchetHeader,
    ciphertext: bytes,
) -> bytes:
    """Decrypt ciphertext with a specific message key."""
    nonce = _derive_nonce(message_key, header.msg_num)
    header_bytes = header.to_bytes()
    return aead_decrypt(cipher, message_key, nonce, ciphertext, header_bytes)


class DoubleRatchet:
    """Signal Double Ratchet session.

    Combines DH ratcheting (X25519), root chain KDF, and symmetric chain
    KDF to provide forward secrecy and break-in recovery.
    """

    def __init__(self, config: RatchetConfig | None = None) -> None:
        self._config = config or RatchetConfig()
        self._dh_self: X25519Keypair | None = None
        self._dh_remote: bytes | None = None
        self._root_key: bytes = bytes(32)
        self._chain_key_send: bytes | None = None
        self._chain_key_recv: bytes | None = None
        self._msg_num_send: int = 0
        self._msg_num_recv: int = 0
        self._prev_chain_len: int = 0
        self._skipped_keys: dict[tuple[bytes, int], bytes] = {}

    @classmethod
    def init_initiator(
        cls,
        shared_secret: bytes,
        remote_public: bytes,
        config: RatchetConfig | None = None,
    ) -> DoubleRatchet:
        """Initialize as the initiator (Alice)."""
        ratchet = cls(config)
        ratchet._dh_self = X25519Keypair.generate()
        ratchet._dh_remote = remote_public

        dh_output = ratchet._dh_self.diffie_hellman(remote_public)
        root_key, chain_key_send = _kdf_rk(shared_secret, dh_output)
        ratchet._root_key = root_key
        ratchet._chain_key_send = chain_key_send

        return ratchet

    @classmethod
    def init_responder(
        cls,
        shared_secret: bytes,
        dh_keypair: X25519Keypair,
        config: RatchetConfig | None = None,
    ) -> DoubleRatchet:
        """Initialize as the responder (Bob)."""
        ratchet = cls(config)
        ratchet._dh_self = dh_keypair
        ratchet._root_key = shared_secret
        return ratchet

    def encrypt(self, plaintext: bytes) -> tuple[RatchetHeader, bytes]:
        """Encrypt a message. Returns (header, ciphertext)."""
        if self._chain_key_send is None:
            raise ValueError("no sending chain key established")

        new_ck, message_key = _kdf_ck(self._chain_key_send)
        self._chain_key_send = new_ck

        header = RatchetHeader(
            dh_public=self._dh_self.public_key_bytes(),
            prev_chain_len=self._prev_chain_len,
            msg_num=self._msg_num_send,
        )
        self._msg_num_send += 1

        nonce = _derive_nonce(message_key, header.msg_num)
        header_bytes = header.to_bytes()
        ciphertext = aead_encrypt(
            self._config.cipher, message_key, nonce,
            plaintext, header_bytes,
        )
        return header, ciphertext

    def decrypt(
        self, header: RatchetHeader, ciphertext: bytes
    ) -> bytes:
        """Decrypt a message given the header and ciphertext."""
        # Try skipped keys first.
        skipped_id = (header.dh_public, header.msg_num)
        if skipped_id in self._skipped_keys:
            mk = self._skipped_keys.pop(skipped_id)
            return _decrypt_with_key(
                self._config.cipher, mk, header, ciphertext
            )

        # Check if we need a DH ratchet step.
        need_dh_ratchet = (
            self._dh_remote is None
            or self._dh_remote != header.dh_public
        )

        if need_dh_ratchet:
            self._skip_message_keys(header.prev_chain_len)
            self._dh_ratchet(header.dh_public)

        self._skip_message_keys(header.msg_num)

        if self._chain_key_recv is None:
            raise ValueError("no receiving chain key established")

        new_ck, message_key = _kdf_ck(self._chain_key_recv)
        self._chain_key_recv = new_ck
        self._msg_num_recv += 1

        return _decrypt_with_key(
            self._config.cipher, message_key, header, ciphertext
        )

    def _skip_message_keys(self, until: int) -> None:
        """Skip message keys up to the given message number."""
        if self._chain_key_recv is None:
            return

        to_skip = until - self._msg_num_recv
        if to_skip < 0:
            return
        if to_skip > self._config.max_skip:
            raise ValueError("max skip threshold exceeded")

        ck = self._chain_key_recv
        for _ in range(self._msg_num_recv, until):
            new_ck, mk = _kdf_ck(ck)
            if self._dh_remote is None:
                raise ValueError("no remote DH key for skipping")
            self._skipped_keys[(self._dh_remote, self._msg_num_recv)] = mk
            ck = new_ck
            self._msg_num_recv += 1
        self._chain_key_recv = ck

    def _dh_ratchet(self, new_remote_public: bytes) -> None:
        """Perform a DH ratchet step."""
        self._prev_chain_len = self._msg_num_send
        self._msg_num_send = 0
        self._msg_num_recv = 0
        self._dh_remote = new_remote_public

        # Derive receiving chain key.
        dh_output = self._dh_self.diffie_hellman(new_remote_public)
        root_key, chain_key_recv = _kdf_rk(self._root_key, dh_output)
        self._root_key = root_key
        self._chain_key_recv = chain_key_recv

        # Generate new DH keypair and derive sending chain key.
        self._dh_self = X25519Keypair.generate()
        dh_output2 = self._dh_self.diffie_hellman(new_remote_public)
        root_key2, chain_key_send = _kdf_rk(self._root_key, dh_output2)
        self._root_key = root_key2
        self._chain_key_send = chain_key_send

    def export_state(self) -> bytes:
        """Export ratchet state for persistence."""
        skipped = [
            {"dh_public": list(k[0]), "msg_num": k[1], "key": list(v)}
            for k, v in self._skipped_keys.items()
        ]
        dh_s = self._dh_self
        ck_s = self._chain_key_send
        ck_r = self._chain_key_recv
        state = {
            "dh_self_secret": (
                list(dh_s.secret_bytes()) if dh_s else None
            ),
            "dh_self_public": (
                list(dh_s.public_key_bytes()) if dh_s else None
            ),
            "dh_remote": (
                list(self._dh_remote) if self._dh_remote else None
            ),
            "root_key": list(self._root_key),
            "chain_key_send": list(ck_s) if ck_s else None,
            "chain_key_recv": list(ck_r) if ck_r else None,
            "msg_num_send": self._msg_num_send,
            "msg_num_recv": self._msg_num_recv,
            "prev_chain_len": self._prev_chain_len,
            "skipped_keys": skipped,
            "cipher": self._config.cipher.value,
            "max_skip": self._config.max_skip,
        }
        return json.dumps(state, separators=(",", ":")).encode()

    @classmethod
    def import_state(
        cls, data: bytes, config: RatchetConfig | None = None
    ) -> DoubleRatchet:
        """Import ratchet state from persisted bytes."""
        state = json.loads(data)

        cfg = config or RatchetConfig(
            max_skip=state.get("max_skip", 100),
            cipher=CipherSuite(state.get("cipher", "aes-256-gcm")),
        )
        ratchet = cls(cfg)

        if state["dh_self_secret"] is not None:
            ratchet._dh_self = X25519Keypair.from_bytes(
                bytes(state["dh_self_secret"])
            )
        ratchet._dh_remote = (
            bytes(state["dh_remote"]) if state["dh_remote"] else None
        )
        ratchet._root_key = bytes(state["root_key"])
        ratchet._chain_key_send = (
            bytes(state["chain_key_send"])
            if state["chain_key_send"]
            else None
        )
        ratchet._chain_key_recv = (
            bytes(state["chain_key_recv"])
            if state["chain_key_recv"]
            else None
        )
        ratchet._msg_num_send = state["msg_num_send"]
        ratchet._msg_num_recv = state["msg_num_recv"]
        ratchet._prev_chain_len = state["prev_chain_len"]

        for entry in state.get("skipped_keys", []):
            key = (bytes(entry["dh_public"]), entry["msg_num"])
            ratchet._skipped_keys[key] = bytes(entry["key"])

        return ratchet

    def __del__(self) -> None:
        """Zero sensitive key material on deletion."""
        self._root_key = bytes(32)
        self._chain_key_send = None
        self._chain_key_recv = None
        self._skipped_keys.clear()
