"""Tests for pairing extras: SAS, adapter, rate limiting."""


import pytest

from cairn.crypto.identity import IdentityKeypair
from cairn.crypto.noise import (
    EMOJI_TABLE,
    NoiseXXHandshake,
    Role,
    derive_emoji_sas,
    derive_numeric_sas,
)
from cairn.pairing.adapter import PairingAdapter
from cairn.pairing.payload import PairingPayload
from cairn.pairing.rate_limit import (
    AutoInvalidatedError,
    RateLimiter,
    WindowExceededError,
)
from cairn.pairing.sas import verify_emoji_sas, verify_numeric_sas


def _do_handshake() -> tuple[bytes, bytes]:
    """Complete a Noise XX handshake, return both transcript hashes."""
    initiator_id = IdentityKeypair.generate()
    responder_id = IdentityKeypair.generate()

    init_hs = NoiseXXHandshake(Role.INITIATOR, initiator_id)
    resp_hs = NoiseXXHandshake(Role.RESPONDER, responder_id)

    msg1, _ = init_hs.step()
    msg2, _ = resp_hs.step(msg1)
    msg3, _ = init_hs.step(msg2)
    _, resp_result = resp_hs.step(msg3)
    init_result = init_hs.result()

    return init_result.transcript_hash, resp_result.transcript_hash


class TestNumericSAS:
    def test_derive_returns_6_digits(self):
        t1, _ = _do_handshake()
        code = derive_numeric_sas(t1)
        assert len(code) == 6
        assert code.isdigit()

    def test_both_peers_derive_same_code(self):
        t1, t2 = _do_handshake()
        assert derive_numeric_sas(t1) == derive_numeric_sas(t2)

    def test_different_handshakes_different_codes(self):
        t1, _ = _do_handshake()
        t3, _ = _do_handshake()
        # Extremely unlikely to collide (1 in 1M)
        assert derive_numeric_sas(t1) != derive_numeric_sas(t3)

    def test_verify_matching(self):
        t1, t2 = _do_handshake()
        code = derive_numeric_sas(t1)
        assert verify_numeric_sas(t2, code) is True

    def test_verify_non_matching(self):
        t1, _ = _do_handshake()
        assert verify_numeric_sas(t1, "000000") is False

    def test_deterministic(self):
        t1, _ = _do_handshake()
        assert derive_numeric_sas(t1) == derive_numeric_sas(t1)


class TestEmojiSAS:
    def test_derive_returns_4_emoji(self):
        t1, _ = _do_handshake()
        emoji = derive_emoji_sas(t1)
        assert len(emoji) == 4
        for e in emoji:
            assert e in EMOJI_TABLE

    def test_both_peers_derive_same_emoji(self):
        t1, t2 = _do_handshake()
        assert derive_emoji_sas(t1) == derive_emoji_sas(t2)

    def test_different_handshakes_different_emoji(self):
        t1, _ = _do_handshake()
        t3, _ = _do_handshake()
        assert derive_emoji_sas(t1) != derive_emoji_sas(t3)

    def test_verify_matching(self):
        t1, t2 = _do_handshake()
        emoji = derive_emoji_sas(t1)
        assert verify_emoji_sas(t2, emoji) is True

    def test_verify_non_matching(self):
        t1, _ = _do_handshake()
        assert verify_emoji_sas(t1, ["x", "y", "z", "w"]) is False

    def test_emoji_table_has_64_entries(self):
        assert len(EMOJI_TABLE) == 64

    def test_deterministic(self):
        t1, _ = _do_handshake()
        assert derive_emoji_sas(t1) == derive_emoji_sas(t1)


class TestRateLimiter:
    def test_new_clean_state(self):
        rl = RateLimiter()
        assert rl.total_failures == 0
        assert not rl.is_invalidated()

    def test_first_attempt_zero_delay(self):
        rl = RateLimiter()
        delay = rl.check_rate_limit("source-1")
        assert delay == 0.0

    def test_five_attempts_allowed(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check_rate_limit("source-1")

    def test_sixth_attempt_rejected(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check_rate_limit("source-1")
        with pytest.raises(WindowExceededError) as exc_info:
            rl.check_rate_limit("source-1")
        assert exc_info.value.attempts == 5

    def test_different_sources_independent_windows(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.check_rate_limit("source-1")
        # source-2 should still be allowed
        delay = rl.check_rate_limit("source-2")
        assert delay == 0.0

    def test_progressive_delay_increases(self):
        rl = RateLimiter()

        delay = rl.check_rate_limit("src")
        assert delay == 0.0

        rl.record_failure("src")
        delay = rl.check_rate_limit("src")
        assert delay == 2.0

        rl.record_failure("src")
        delay = rl.check_rate_limit("src")
        assert delay == 4.0

    def test_record_success_resets_source_delay(self):
        rl = RateLimiter()

        rl.check_rate_limit("src")
        rl.record_failure("src")
        rl.record_failure("src")

        delay = rl.check_rate_limit("src")
        assert delay == 4.0

        rl.record_success("src")
        delay = rl.check_rate_limit("src")
        assert delay == 0.0

    def test_auto_invalidation(self):
        rl = RateLimiter()
        for i in range(10):
            source = f"source-{i}"
            rl.check_rate_limit(source)
            rl.record_failure(source)

        assert rl.is_invalidated()
        assert rl.total_failures == 10

        with pytest.raises(AutoInvalidatedError) as exc_info:
            rl.check_rate_limit("source-new")
        assert exc_info.value.failures == 10

    def test_reset_clears_all(self):
        rl = RateLimiter()
        for i in range(5):
            source = f"source-{i}"
            rl.check_rate_limit(source)
            rl.record_failure(source)

        assert rl.total_failures == 5
        rl.reset()
        assert rl.total_failures == 0
        assert not rl.is_invalidated()
        delay = rl.check_rate_limit("source-0")
        assert delay == 0.0

    def test_custom_config(self):
        rl = RateLimiter(
            max_attempts_per_window=3,
            window_secs=10.0,
            max_total_failures=5,
            delay_per_failure_secs=1.0,
        )
        for _ in range(3):
            rl.check_rate_limit("src")
        with pytest.raises(WindowExceededError):
            rl.check_rate_limit("src")

        rl.reset()
        for i in range(5):
            rl.check_rate_limit(f"s-{i}")
            rl.record_failure(f"s-{i}")
        assert rl.is_invalidated()

    def test_custom_delay_per_failure(self):
        rl = RateLimiter(
            max_attempts_per_window=10,
            window_secs=60.0,
            max_total_failures=20,
            delay_per_failure_secs=3.0,
        )
        rl.check_rate_limit("src")
        rl.record_failure("src")

        delay = rl.check_rate_limit("src")
        assert delay == 3.0

        rl.record_failure("src")
        delay = rl.check_rate_limit("src")
        assert delay == 6.0

    def test_total_failures_across_sources(self):
        rl = RateLimiter()
        rl.check_rate_limit("a")
        rl.record_failure("a")
        rl.check_rate_limit("b")
        rl.record_failure("b")
        rl.check_rate_limit("c")
        rl.record_failure("c")
        assert rl.total_failures == 3

    def test_success_does_not_reduce_total_failures(self):
        rl = RateLimiter()
        rl.check_rate_limit("src")
        rl.record_failure("src")
        assert rl.total_failures == 1
        rl.record_success("src")
        assert rl.total_failures == 1

    def test_record_success_unknown_source_noop(self):
        rl = RateLimiter()
        rl.record_success("nonexistent")
        assert rl.total_failures == 0

    def test_error_messages(self):
        err = WindowExceededError(5, 30.0)
        assert "5 attempts" in str(err)
        assert "30" in str(err)

        err = AutoInvalidatedError(10)
        assert "10 total failures" in str(err)

    def test_error_inheritance(self):
        from cairn.pairing.rate_limit import RateLimitError
        assert issubclass(WindowExceededError, RateLimitError)
        assert issubclass(AutoInvalidatedError, RateLimitError)


class TestPairingAdapter:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            PairingAdapter()

    def test_concrete_subclass_works(self):
        class TestAdapter(PairingAdapter):
            def __init__(self):
                self._cred = bytes(32)
                self._payload = None

            def generate_payload(self) -> PairingPayload:
                kp = IdentityKeypair.generate()
                return PairingPayload(
                    peer_id=kp.peer_id().as_bytes(),
                    nonce=bytes(16),
                    pake_credential=self._cred,
                    connection_hints=None,
                    created_at=1700000000,
                    expires_at=2**63,
                )

            def consume_payload(self, payload: PairingPayload) -> None:
                self._payload = payload

            def get_pake_credential(self) -> bytes:
                return self._cred

        adapter = TestAdapter()
        p = adapter.generate_payload()
        assert isinstance(p, PairingPayload)
        assert adapter.get_pake_credential() == bytes(32)

        adapter.consume_payload(p)
        assert adapter._payload is p

    def test_partial_implementation_raises(self):
        class PartialAdapter(PairingAdapter):
            def generate_payload(self) -> PairingPayload:
                pass  # pragma: no cover

        with pytest.raises(TypeError):
            PartialAdapter()

    def test_isinstance_check(self):
        class FullAdapter(PairingAdapter):
            def generate_payload(self) -> PairingPayload:
                pass  # pragma: no cover

            def consume_payload(self, payload: PairingPayload) -> None:
                pass  # pragma: no cover

            def get_pake_credential(self) -> bytes:
                return b""

        adapter = FullAdapter()
        assert isinstance(adapter, PairingAdapter)
