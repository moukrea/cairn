"""Tests for the Double Ratchet protocol."""

import pytest

from cairn.crypto.aead import CipherSuite
from cairn.crypto.identity import X25519Keypair
from cairn.crypto.ratchet import (
    DoubleRatchet,
    RatchetConfig,
)


def setup_pair(
    config: RatchetConfig | None = None,
) -> tuple[DoubleRatchet, DoubleRatchet]:
    """Set up an Alice-Bob ratchet pair."""
    shared_secret = bytes([0x42] * 32)
    bob_kp = X25519Keypair.generate()
    bob_public = bob_kp.public_key_bytes()

    alice = DoubleRatchet.init_initiator(
        shared_secret, bob_public, config
    )
    bob = DoubleRatchet.init_responder(
        shared_secret, bob_kp, config
    )
    return alice, bob


class TestDoubleRatchet:
    def test_alice_sends_bob_receives(self):
        alice, bob = setup_pair()
        header, ct = alice.encrypt(b"hello bob")
        pt = bob.decrypt(header, ct)
        assert pt == b"hello bob"

    def test_multiple_messages_one_direction(self):
        alice, bob = setup_pair()
        for i in range(10):
            msg = f"message {i}".encode()
            header, ct = alice.encrypt(msg)
            pt = bob.decrypt(header, ct)
            assert pt == msg

    def test_bidirectional_messages(self):
        alice, bob = setup_pair()

        # Alice -> Bob
        h1, ct1 = alice.encrypt(b"hello bob")
        assert bob.decrypt(h1, ct1) == b"hello bob"

        # Bob -> Alice
        h2, ct2 = bob.encrypt(b"hello alice")
        assert alice.decrypt(h2, ct2) == b"hello alice"

        # Alice -> Bob again
        h3, ct3 = alice.encrypt(b"how are you?")
        assert bob.decrypt(h3, ct3) == b"how are you?"

    def test_out_of_order_messages(self):
        alice, bob = setup_pair()

        h1, ct1 = alice.encrypt(b"msg 0")
        h2, ct2 = alice.encrypt(b"msg 1")
        h3, ct3 = alice.encrypt(b"msg 2")

        # Deliver out of order: 2, 0, 1
        assert bob.decrypt(h3, ct3) == b"msg 2"
        assert bob.decrypt(h1, ct1) == b"msg 0"
        assert bob.decrypt(h2, ct2) == b"msg 1"

    def test_max_skip_threshold(self):
        config = RatchetConfig(max_skip=2)
        alice, bob = setup_pair(config)

        alice.encrypt(b"skip 0")
        alice.encrypt(b"skip 1")
        alice.encrypt(b"skip 2")
        h4, ct4 = alice.encrypt(b"msg 3")

        with pytest.raises(ValueError, match="max skip"):
            bob.decrypt(h4, ct4)

    def test_state_export_import_roundtrip(self):
        alice, bob = setup_pair()

        h1, ct1 = alice.encrypt(b"before persist")
        assert bob.decrypt(h1, ct1) == b"before persist"

        exported = alice.export_state()
        alice2 = DoubleRatchet.import_state(exported)

        h2, ct2 = alice2.encrypt(b"after persist")
        assert bob.decrypt(h2, ct2) == b"after persist"

    def test_multiple_ratchet_turns(self):
        alice, bob = setup_pair()

        for r in range(5):
            msg_ab = f"alice round {r}".encode()
            h, ct = alice.encrypt(msg_ab)
            assert bob.decrypt(h, ct) == msg_ab

            msg_ba = f"bob round {r}".encode()
            h, ct = bob.encrypt(msg_ba)
            assert alice.decrypt(h, ct) == msg_ba

    def test_tampered_ciphertext_rejected(self):
        alice, bob = setup_pair()
        header, ct = alice.encrypt(b"tamper test")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            bob.decrypt(header, bytes(tampered))

    def test_chacha20_cipher_suite(self):
        config = RatchetConfig(cipher=CipherSuite.CHACHA20_POLY1305)
        alice, bob = setup_pair(config)

        h, ct = alice.encrypt(b"chacha20 test")
        assert bob.decrypt(h, ct) == b"chacha20 test"

    def test_empty_plaintext(self):
        alice, bob = setup_pair()
        h, ct = alice.encrypt(b"")
        assert bob.decrypt(h, ct) == b""

    def test_message_numbers_increment(self):
        alice, _ = setup_pair()
        h1, _ = alice.encrypt(b"msg0")
        h2, _ = alice.encrypt(b"msg1")
        h3, _ = alice.encrypt(b"msg2")
        assert h1.msg_num == 0
        assert h2.msg_num == 1
        assert h3.msg_num == 2

    def test_dh_public_key_changes_on_ratchet(self):
        alice, bob = setup_pair()

        h1, ct1 = alice.encrypt(b"from alice")
        pk1 = h1.dh_public
        bob.decrypt(h1, ct1)

        h2, ct2 = bob.encrypt(b"from bob")
        alice.decrypt(h2, ct2)

        h3, _ = alice.encrypt(b"from alice again")
        pk2 = h3.dh_public

        assert pk1 != pk2

    def test_import_state_invalid_data(self):
        with pytest.raises(Exception):
            DoubleRatchet.import_state(b"not valid json")
