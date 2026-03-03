"""Tests for Noise XX handshake and SPAKE2."""

import pytest

from cairn.crypto.identity import IdentityKeypair
from cairn.crypto.noise import (
    EMOJI_TABLE,
    HandshakeResult,
    NoiseXXHandshake,
    Role,
    derive_emoji_sas,
    derive_numeric_sas,
)
from cairn.crypto.spake2_pake import Spake2Session


def run_handshake(
    pake_secret: bytes | None = None,
    alice_id: IdentityKeypair | None = None,
    bob_id: IdentityKeypair | None = None,
) -> tuple[HandshakeResult, HandshakeResult]:
    """Run a complete Noise XX handshake between two peers."""
    if alice_id is None:
        alice_id = IdentityKeypair.generate()
    if bob_id is None:
        bob_id = IdentityKeypair.generate()

    initiator = NoiseXXHandshake(Role.INITIATOR, alice_id)
    responder = NoiseXXHandshake(Role.RESPONDER, bob_id)

    if pake_secret is not None:
        initiator.with_pake_secret(pake_secret)
        responder.with_pake_secret(pake_secret)

    # Initiator sends msg1
    msg1, _ = initiator.step(None)
    assert msg1 is not None

    # Responder receives msg1, sends msg2
    msg2, _ = responder.step(msg1)
    assert msg2 is not None

    # Initiator receives msg2, sends msg3
    msg3, _ = initiator.step(msg2)
    assert msg3 is not None

    # Get initiator's cached result
    init_result = initiator.result()

    # Responder receives msg3 -> complete
    _, resp_result = responder.step(msg3)
    assert resp_result is not None

    return init_result, resp_result


class TestNoiseXXHandshake:
    def test_matching_session_keys(self):
        init_r, resp_r = run_handshake()
        assert init_r.session_key == resp_r.session_key

    def test_reveals_remote_static_keys(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()
        alice_pub = alice.public_key_bytes()
        bob_pub = bob.public_key_bytes()

        init_r, resp_r = run_handshake(alice_id=alice, bob_id=bob)
        assert init_r.remote_static == bob_pub
        assert resp_r.remote_static == alice_pub

    def test_transcript_hashes_match(self):
        init_r, resp_r = run_handshake()
        assert init_r.transcript_hash == resp_r.transcript_hash

    def test_different_handshakes_different_keys(self):
        r1, _ = run_handshake()
        r2, _ = run_handshake()
        assert r1.session_key != r2.session_key

    def test_with_pake_secret(self):
        pake = bytes(32)
        pake = bytes([42]) * 32
        init_r, resp_r = run_handshake(pake_secret=pake)
        assert init_r.session_key == resp_r.session_key

    def test_mismatched_pake_secrets_fail(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)
        initiator.with_pake_secret(bytes([1]) * 32)
        responder.with_pake_secret(bytes([2]) * 32)

        msg1, _ = initiator.step(None)
        msg2, _ = responder.step(msg1)
        msg3, _ = initiator.step(msg2)

        # Responder should fail to decrypt msg3
        with pytest.raises(Exception):
            responder.step(msg3)

    def test_msg1_is_32_bytes(self):
        alice = IdentityKeypair.generate()
        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        msg1, _ = initiator.step(None)
        assert len(msg1) == 32

    def test_msg1_wrong_length_rejected(self):
        bob = IdentityKeypair.generate()
        responder = NoiseXXHandshake(Role.RESPONDER, bob)
        with pytest.raises(ValueError, match="invalid length"):
            responder.step(bytes(16))

    def test_msg2_too_short_rejected(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)

        msg1, _ = initiator.step(None)
        msg2, _ = responder.step(msg1)

        with pytest.raises(ValueError, match="too short"):
            initiator.step(msg2[:10])

    def test_msg3_too_short_rejected(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)

        msg1, _ = initiator.step(None)
        responder.step(msg1)

        with pytest.raises(ValueError, match="too short"):
            responder.step(bytes(5))

    def test_tampered_msg2_rejected(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)

        msg1, _ = initiator.step(None)
        msg2, _ = responder.step(msg1)

        tampered = bytearray(msg2)
        if len(tampered) > 40:
            tampered[40] ^= 0xFF
        with pytest.raises(Exception):
            initiator.step(bytes(tampered))

    def test_tampered_msg3_rejected(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)

        msg1, _ = initiator.step(None)
        msg2, _ = responder.step(msg1)
        msg3, _ = initiator.step(msg2)

        tampered = bytearray(msg3)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            responder.step(bytes(tampered))

    def test_out_of_order_step_rejected(self):
        alice = IdentityKeypair.generate()
        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        with pytest.raises(ValueError, match="no input"):
            initiator.step(bytes(32))

    def test_responder_rejects_no_input(self):
        bob = IdentityKeypair.generate()
        responder = NoiseXXHandshake(Role.RESPONDER, bob)
        with pytest.raises(ValueError, match="expects message"):
            responder.step(None)

    def test_step_after_complete_rejected(self):
        alice = IdentityKeypair.generate()
        bob = IdentityKeypair.generate()

        initiator = NoiseXXHandshake(Role.INITIATOR, alice)
        responder = NoiseXXHandshake(Role.RESPONDER, bob)

        msg1, _ = initiator.step(None)
        msg2, _ = responder.step(msg1)
        msg3, _ = initiator.step(msg2)
        _, result = responder.step(msg3)
        assert result is not None

        with pytest.raises(ValueError, match="already complete"):
            responder.step(None)


class TestSAS:
    def test_sas_matches_between_peers(self):
        init_r, resp_r = run_handshake()
        init_sas = derive_numeric_sas(init_r.transcript_hash)
        resp_sas = derive_numeric_sas(resp_r.transcript_hash)
        assert init_sas == resp_sas

    def test_emoji_sas_matches(self):
        init_r, resp_r = run_handshake()
        init_emoji = derive_emoji_sas(init_r.transcript_hash)
        resp_emoji = derive_emoji_sas(resp_r.transcript_hash)
        assert init_emoji == resp_emoji

    def test_numeric_sas_format(self):
        sas = derive_numeric_sas(bytes([42]) * 32)
        assert len(sas) == 6
        assert sas.isdigit()

    def test_numeric_sas_deterministic(self):
        h = bytes([99]) * 32
        assert derive_numeric_sas(h) == derive_numeric_sas(h)

    def test_different_transcripts_different_sas(self):
        sas1 = derive_numeric_sas(bytes([1]) * 32)
        sas2 = derive_numeric_sas(bytes([2]) * 32)
        assert sas1 != sas2

    def test_emoji_sas_returns_4(self):
        emojis = derive_emoji_sas(bytes([42]) * 32)
        assert len(emojis) == 4

    def test_emoji_sas_deterministic(self):
        h = bytes([99]) * 32
        assert derive_emoji_sas(h) == derive_emoji_sas(h)

    def test_emoji_sas_from_table(self):
        emojis = derive_emoji_sas(bytes([77]) * 32)
        for e in emojis:
            assert e in EMOJI_TABLE


class TestSpake2:
    def test_matching_passwords_produce_same_key(self):
        password = b"test-password"
        a = Spake2Session(password, is_initiator=True)
        b = Spake2Session(password, is_initiator=False)

        msg_a = a.start()
        msg_b = b.start()

        key_a = a.finish(msg_b)
        key_b = b.finish(msg_a)

        assert key_a == key_b

    def test_different_passwords_different_keys(self):
        a = Spake2Session(b"password-a", is_initiator=True)
        b = Spake2Session(b"password-b", is_initiator=False)

        msg_a = a.start()
        msg_b = b.start()

        key_a = a.finish(msg_b)
        key_b = b.finish(msg_a)

        # With wrong passwords, keys will not match
        assert key_a != key_b
