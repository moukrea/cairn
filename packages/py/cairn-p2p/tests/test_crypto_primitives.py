"""Tests for cryptographic primitives."""

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from cairn.crypto.aead import (
    AES_GCM_TAG_SIZE,
    CHACHA_TAG_SIZE,
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


class TestIdentityKeypair:
    def test_generate_and_roundtrip(self):
        kp = IdentityKeypair.generate()
        secret = kp.secret_bytes()
        restored = IdentityKeypair.from_bytes(secret)
        assert kp.public_key_bytes() == restored.public_key_bytes()

    def test_sign_and_verify(self):
        kp = IdentityKeypair.generate()
        sig = kp.sign(b"hello cairn")
        kp.verify(b"hello cairn", sig)  # should not raise

    def test_verify_wrong_message_fails(self):
        kp = IdentityKeypair.generate()
        sig = kp.sign(b"correct message")
        with pytest.raises(InvalidSignature):
            kp.verify(b"wrong message", sig)

    def test_verify_wrong_key_fails(self):
        kp1 = IdentityKeypair.generate()
        kp2 = IdentityKeypair.generate()
        sig = kp1.sign(b"hello")
        with pytest.raises(InvalidSignature):
            kp2.verify(b"hello", sig)

    def test_verify_signature_standalone(self):
        kp = IdentityKeypair.generate()
        sig = kp.sign(b"standalone verify")
        verify_signature(kp.public_key_bytes(), b"standalone verify", sig)
        with pytest.raises(InvalidSignature):
            verify_signature(kp.public_key_bytes(), b"tampered", sig)

    def test_peer_id_is_deterministic(self):
        kp = IdentityKeypair.generate()
        assert kp.peer_id() == kp.peer_id()

    def test_peer_id_from_public_key_matches(self):
        kp = IdentityKeypair.generate()
        id_from_kp = kp.peer_id_bytes()
        id_from_pub = peer_id_from_public_key(kp.public_key_bytes())
        assert id_from_kp == id_from_pub

    def test_different_keys_different_peer_ids(self):
        kp1 = IdentityKeypair.generate()
        kp2 = IdentityKeypair.generate()
        assert kp1.peer_id() != kp2.peer_id()

    def test_signature_is_64_bytes(self):
        kp = IdentityKeypair.generate()
        sig = kp.sign(b"test")
        assert len(sig) == 64

    def test_signature_is_deterministic(self):
        kp = IdentityKeypair.generate()
        sig1 = kp.sign(b"deterministic")
        sig2 = kp.sign(b"deterministic")
        assert sig1 == sig2


class TestPeerId:
    def test_from_public_key_produces_34_bytes(self):
        kp = IdentityKeypair.generate()
        pid = PeerId.from_public_key(kp.public_key_bytes())
        assert len(pid.as_bytes()) == 34
        assert pid.as_bytes()[0] == 0x12
        assert pid.as_bytes()[1] == 0x20

    def test_from_public_key_is_deterministic(self):
        kp = IdentityKeypair.generate()
        pid1 = PeerId.from_public_key(kp.public_key_bytes())
        pid2 = PeerId.from_public_key(kp.public_key_bytes())
        assert pid1 == pid2

    def test_different_keys_different_peer_ids(self):
        kp1 = IdentityKeypair.generate()
        kp2 = IdentityKeypair.generate()
        pid1 = PeerId.from_public_key(kp1.public_key_bytes())
        pid2 = PeerId.from_public_key(kp2.public_key_bytes())
        assert pid1 != pid2

    def test_base58_roundtrip(self):
        kp = IdentityKeypair.generate()
        pid = PeerId.from_public_key(kp.public_key_bytes())
        text = pid.to_base58()
        parsed = PeerId.from_base58(text)
        assert pid == parsed

    def test_from_bytes_roundtrip(self):
        kp = IdentityKeypair.generate()
        pid = PeerId.from_public_key(kp.public_key_bytes())
        restored = PeerId(pid.as_bytes())
        assert pid == restored

    def test_from_bytes_rejects_wrong_prefix(self):
        data = bytes([0xFF, 0x20]) + bytes(32)
        with pytest.raises(ValueError, match="multihash code"):
            PeerId(data)

    def test_from_bytes_rejects_wrong_length_marker(self):
        data = bytes([0x12, 0x10]) + bytes(32)
        with pytest.raises(ValueError, match="multihash length"):
            PeerId(data)

    def test_from_bytes_rejects_wrong_total_length(self):
        with pytest.raises(ValueError, match="34 bytes"):
            PeerId(bytes(20))

    def test_hash_works_in_dict(self):
        kp = IdentityKeypair.generate()
        pid = PeerId.from_public_key(kp.public_key_bytes())
        d: dict[PeerId, str] = {pid: "test"}
        assert d[pid] == "test"

    def test_repr_contains_base58(self):
        kp = IdentityKeypair.generate()
        pid = PeerId.from_public_key(kp.public_key_bytes())
        r = repr(pid)
        assert r.startswith("PeerId(")
        assert r.endswith(")")


class TestX25519Keypair:
    def test_shared_secret_matches_both_sides(self):
        alice = X25519Keypair.generate()
        bob = X25519Keypair.generate()
        alice_shared = alice.diffie_hellman(bob.public_key_bytes())
        bob_shared = bob.diffie_hellman(alice.public_key_bytes())
        assert alice_shared == bob_shared

    def test_different_peers_different_shared_secrets(self):
        alice = X25519Keypair.generate()
        bob = X25519Keypair.generate()
        charlie = X25519Keypair.generate()
        ab = alice.diffie_hellman(bob.public_key_bytes())
        ac = alice.diffie_hellman(charlie.public_key_bytes())
        assert ab != ac

    def test_from_bytes_roundtrip(self):
        kp = X25519Keypair.generate()
        secret = kp.secret_bytes()
        restored = X25519Keypair.from_bytes(secret)
        assert kp.public_key_bytes() == restored.public_key_bytes()


class TestHKDF:
    def test_deterministic_output(self):
        ikm = b"shared-secret-material"
        out1 = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 32)
        out2 = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 32)
        assert out1 == out2

    def test_domain_separation_produces_different_keys(self):
        ikm = b"same-input-keying-material"
        session = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 32)
        rendezvous = hkdf_sha256(ikm, None, HKDF_INFO_RENDEZVOUS, 32)
        assert session != rendezvous

    def test_with_salt_differs_from_without(self):
        ikm = b"input-keying-material"
        salt = b"some-salt-value"
        with_salt = hkdf_sha256(ikm, salt, HKDF_INFO_SESSION_KEY, 32)
        without_salt = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 32)
        assert with_salt != without_salt

    def test_various_output_lengths(self):
        ikm = b"key-material"
        short = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 16)
        assert len(short) == 16
        long = hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, 64)
        assert len(long) == 64

    def test_all_domain_constants_unique(self):
        constants = [
            HKDF_INFO_SESSION_KEY,
            HKDF_INFO_RENDEZVOUS,
            HKDF_INFO_SAS,
            HKDF_INFO_CHAIN_KEY,
            HKDF_INFO_MESSAGE_KEY,
        ]
        assert len(set(constants)) == len(constants)


class TestAEAD:
    KEY = bytes([0x42]) + bytes(30) + bytes([0xFF])
    NONCE = bytes([0x01]) + bytes(11)

    def test_aes_gcm_roundtrip(self):
        ct = aead_encrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, b"hello cairn aes-gcm", b"aad",
        )
        pt = aead_decrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, ct, b"aad",
        )
        assert pt == b"hello cairn aes-gcm"

    def test_chacha20_roundtrip(self):
        ct = aead_encrypt(
            CipherSuite.CHACHA20_POLY1305,
            self.KEY, self.NONCE, b"hello cairn chacha20", b"aad",
        )
        pt = aead_decrypt(
            CipherSuite.CHACHA20_POLY1305,
            self.KEY, self.NONCE, ct, b"aad",
        )
        assert pt == b"hello cairn chacha20"

    def test_aes_gcm_tampered_rejected(self):
        ct = bytearray(aead_encrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, b"sensitive data", b"aad",
        ))
        ct[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.AES_256_GCM,
                self.KEY, self.NONCE, bytes(ct), b"aad",
            )

    def test_chacha20_tampered_rejected(self):
        ct = bytearray(aead_encrypt(
            CipherSuite.CHACHA20_POLY1305,
            self.KEY, self.NONCE, b"sensitive data", b"aad",
        ))
        ct[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.CHACHA20_POLY1305,
                self.KEY, self.NONCE, bytes(ct), b"aad",
            )

    def test_wrong_aad_rejected(self):
        ct = aead_encrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, b"data", b"correct-aad",
        )
        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.AES_256_GCM,
                self.KEY, self.NONCE, ct, b"wrong-aad",
            )

    def test_wrong_key_rejected(self):
        ct = aead_encrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, b"data", b"aad",
        )
        wrong_key = bytearray(self.KEY)
        wrong_key[0] ^= 0x01
        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.AES_256_GCM,
                bytes(wrong_key), self.NONCE, ct, b"aad",
            )

    def test_ciphertext_includes_tag(self):
        pt = b"hello"
        ct_aes = aead_encrypt(
            CipherSuite.AES_256_GCM,
            self.KEY, self.NONCE, pt, b"",
        )
        assert len(ct_aes) == len(pt) + AES_GCM_TAG_SIZE

        ct_chacha = aead_encrypt(
            CipherSuite.CHACHA20_POLY1305,
            self.KEY, self.NONCE, pt, b"",
        )
        assert len(ct_chacha) == len(pt) + CHACHA_TAG_SIZE

    def test_empty_plaintext_roundtrip(self):
        for suite in [CipherSuite.AES_256_GCM, CipherSuite.CHACHA20_POLY1305]:
            ct = aead_encrypt(suite, self.KEY, self.NONCE, b"", b"ctx")
            pt = aead_decrypt(suite, self.KEY, self.NONCE, ct, b"ctx")
            assert pt == b""

    def test_empty_aad_roundtrip(self):
        for suite in [CipherSuite.AES_256_GCM, CipherSuite.CHACHA20_POLY1305]:
            ct = aead_encrypt(
                suite, self.KEY, self.NONCE, b"data with no aad", b"",
            )
            pt = aead_decrypt(suite, self.KEY, self.NONCE, ct, b"")
            assert pt == b"data with no aad"
