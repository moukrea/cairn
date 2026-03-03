"""Crypto known-answer tests: RFC 7748, RFC 8032, RFC 5869."""


import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cairn.crypto.aead import (
    CipherSuite,
    aead_decrypt,
    aead_encrypt,
)
from cairn.crypto.identity import (
    IdentityKeypair,
    X25519Keypair,
)
from cairn.crypto.kdf import hkdf_sha256

# ===========================================================================
# RFC 7748 - X25519 Diffie-Hellman known-answer tests
# ===========================================================================


class TestRFC7748X25519:
    """RFC 7748, Section 6.1: X25519 test vectors."""

    def test_vector_1(self):
        # Alice's private key scalar (clamped) and Bob's public key (u-coordinate)
        # From RFC 7748 Section 6.1
        alice_scalar = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645"
            "df4c2f87ebc0992ab177fba51db92c2a"
        )
        bob_public = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece43537"
            "3f8343c85b78674dadfc7e146f882b4f"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25"
            "e07e21c947d19e3376f09b3c1e161742"
        )

        alice_key = X25519PrivateKey.from_private_bytes(
            alice_scalar
        )
        bob_key = X25519PublicKey.from_public_bytes(bob_public)
        shared = alice_key.exchange(bob_key)
        assert shared == expected_shared

    def test_vector_2(self):
        # Second test vector from RFC 7748 Section 6.1
        alice_scalar = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee6"
            "6f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        bob_public = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a"
            "0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25"
            "e07e21c947d19e3376f09b3c1e161742"
        )

        alice_key = X25519PrivateKey.from_private_bytes(
            alice_scalar
        )
        bob_key = X25519PublicKey.from_public_bytes(bob_public)
        shared = alice_key.exchange(bob_key)
        assert shared == expected_shared

    def test_dh_symmetry(self):
        """Verify that DH shared secrets are symmetric."""
        alice = X25519Keypair.generate()
        bob = X25519Keypair.generate()
        shared_ab = alice.diffie_hellman(bob.public_key_bytes())
        shared_ba = bob.diffie_hellman(alice.public_key_bytes())
        assert shared_ab == shared_ba


# ===========================================================================
# RFC 8032 - Ed25519 known-answer tests
# ===========================================================================


class TestRFC8032Ed25519:
    """RFC 8032, Section 7.1: Ed25519 test vectors."""

    def test_vector_1_empty_message(self):
        # Test Vector 1: empty message
        private_seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60"
        )
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )
        message = b""

        key = Ed25519PrivateKey.from_private_bytes(private_seed)
        sig = key.sign(message)
        assert sig == expected_sig
        assert len(sig) == 64

        # Verify round-trip
        key.public_key().verify(sig, message)

    def test_vector_2_single_byte(self):
        # Test Vector 2: one-byte message (0x72)
        private_seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        message = bytes([0x72])

        key = Ed25519PrivateKey.from_private_bytes(private_seed)
        sig = key.sign(message)
        assert len(sig) == 64
        # Verify round-trip
        key.public_key().verify(sig, message)

    def test_sign_verify_roundtrip(self):
        """Verify sign/verify round-trip with IdentityKeypair."""
        kp = IdentityKeypair.generate()
        message = b"cairn test message"
        sig = kp.sign(message)
        assert len(sig) == 64
        # Should not raise (verify takes message, signature)
        kp.verify(message, sig)

    def test_wrong_key_rejects(self):
        """Verify that a different key cannot verify the signature."""
        kp1 = IdentityKeypair.generate()
        kp2 = IdentityKeypair.generate()
        message = b"cairn test message"
        sig = kp1.sign(message)
        from cryptography.exceptions import InvalidSignature

        with pytest.raises(InvalidSignature):
            kp2.verify(message, sig)


# ===========================================================================
# RFC 5869 - HKDF-SHA256 known-answer tests
# ===========================================================================


class TestRFC5869HKDF:
    """RFC 5869: HKDF test vectors for SHA-256."""

    def test_vector_1(self):
        # RFC 5869, Test Case 1
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        length = 42

        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

        okm = hkdf_sha256(ikm, salt, info, length)
        assert okm == expected_okm

    def test_vector_2(self):
        # RFC 5869, Test Case 2 (longer inputs)
        ikm = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        )
        salt = bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )
        info = bytes.fromhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )
        length = 82

        expected_okm = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )

        okm = hkdf_sha256(ikm, salt, info, length)
        assert okm == expected_okm

    def test_vector_3_no_salt(self):
        # RFC 5869, Test Case 3 (no salt, no info)
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = None
        info = b""
        length = 42

        expected_okm = bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        )

        okm = hkdf_sha256(ikm, salt, info, length)
        assert okm == expected_okm

    def test_output_length(self):
        """Verify that HKDF produces the requested output length."""
        for length in [16, 32, 48, 64]:
            okm = hkdf_sha256(b"test-ikm", None, b"info", length)
            assert len(okm) == length


# ===========================================================================
# AEAD encrypt/decrypt round-trip and cross-cipher tests
# ===========================================================================


class TestAEADVectors:
    def test_aes_gcm_roundtrip(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"hello cairn"
        aad = b"additional data"

        ct = aead_encrypt(
            CipherSuite.AES_256_GCM, key, nonce, plaintext, aad
        )
        pt = aead_decrypt(
            CipherSuite.AES_256_GCM, key, nonce, ct, aad
        )
        assert pt == plaintext

    def test_chacha20_roundtrip(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"hello cairn"
        aad = b"additional data"

        ct = aead_encrypt(
            CipherSuite.CHACHA20_POLY1305,
            key,
            nonce,
            plaintext,
            aad,
        )
        pt = aead_decrypt(
            CipherSuite.CHACHA20_POLY1305,
            key,
            nonce,
            ct,
            aad,
        )
        assert pt == plaintext

    def test_wrong_key_aes_gcm(self):
        key = bytes(range(32))
        wrong_key = bytes(range(1, 33))
        nonce = bytes(range(12))
        plaintext = b"hello cairn"
        aad = b"aad"

        ct = aead_encrypt(
            CipherSuite.AES_256_GCM, key, nonce, plaintext, aad
        )
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.AES_256_GCM,
                wrong_key,
                nonce,
                ct,
                aad,
            )

    def test_wrong_aad_rejects(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"hello cairn"

        ct = aead_encrypt(
            CipherSuite.AES_256_GCM,
            key,
            nonce,
            plaintext,
            b"correct aad",
        )
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            aead_decrypt(
                CipherSuite.AES_256_GCM,
                key,
                nonce,
                ct,
                b"wrong aad",
            )

    def test_ciphertext_includes_tag(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"X" * 100
        aad = b""

        ct = aead_encrypt(
            CipherSuite.AES_256_GCM, key, nonce, plaintext, aad
        )
        # Ciphertext = plaintext_len + 16 byte tag
        assert len(ct) == len(plaintext) + 16
