"""Tests for pairing mechanisms: QR, PIN, link, payload."""


import pytest

from cairn.crypto.identity import IdentityKeypair
from cairn.pairing.link import pair_from_link, pair_generate_link
from cairn.pairing.payload import (
    ConnectionHint,
    PairingPayload,
)
from cairn.pairing.pin import (
    CROCKFORD_ALPHABET,
    decode_crockford,
    derive_pin_rendezvous_id,
    encode_crockford,
    normalize_pin,
    pair_enter_pin,
    pair_generate_pin,
)
from cairn.pairing.qr import (
    MAX_QR_PAYLOAD_SIZE,
    pair_generate_qr,
    pair_scan_qr,
    render_qr,
)


def make_payload(
    expires_at: int = 2**63,
) -> PairingPayload:
    """Create a test pairing payload."""
    kp = IdentityKeypair.generate()
    pid = kp.peer_id()
    return PairingPayload(
        peer_id=pid.as_bytes(),
        nonce=bytes([0x42] * 16),
        pake_credential=bytes([0xAB] * 32),
        connection_hints=[
            ConnectionHint("rendezvous", "relay.example.com:9090")
        ],
        created_at=1700000000,
        expires_at=expires_at,
    )


class TestPairingPayload:
    def test_cbor_roundtrip(self):
        p = make_payload()
        data = p.to_cbor()
        r = PairingPayload.from_cbor(data)
        assert r.peer_id == p.peer_id
        assert r.nonce == p.nonce
        assert r.pake_credential == p.pake_credential
        assert r.created_at == p.created_at
        assert r.expires_at == p.expires_at
        assert len(r.connection_hints) == 1
        assert r.connection_hints[0].hint_type == "rendezvous"

    def test_cbor_roundtrip_no_hints(self):
        kp = IdentityKeypair.generate()
        p = PairingPayload(
            peer_id=kp.peer_id().as_bytes(),
            nonce=bytes(16),
            pake_credential=bytes(32),
            connection_hints=None,
            created_at=100,
            expires_at=400,
        )
        r = PairingPayload.from_cbor(p.to_cbor())
        assert r.connection_hints is None

    def test_expiry_check(self):
        p = make_payload(expires_at=1700000300)
        assert not p.is_expired(1700000100)
        assert p.is_expired(1700000301)
        assert not p.is_expired(1700000300)

    def test_cbor_rejects_invalid_data(self):
        with pytest.raises(Exception):
            PairingPayload.from_cbor(bytes([0xFF, 0xFF]))


class TestQRCode:
    def test_generate_and_scan_roundtrip(self):
        kp = IdentityKeypair.generate()
        payload, cbor_bytes = pair_generate_qr(
            peer_id=kp.peer_id().as_bytes(),
            pake_credential=bytes(32),
        )
        assert len(cbor_bytes) <= MAX_QR_PAYLOAD_SIZE

        scanned = pair_scan_qr(cbor_bytes)
        assert scanned.peer_id == payload.peer_id
        assert scanned.pake_credential == payload.pake_credential

    def test_render_qr_works(self):
        kp = IdentityKeypair.generate()
        _, cbor_bytes = pair_generate_qr(
            peer_id=kp.peer_id().as_bytes(),
            pake_credential=bytes(32),
        )
        qr = render_qr(cbor_bytes)
        # QR version 14 = 73x73 modules
        matrix = qr.get_matrix()
        assert len(matrix) <= 73

    def test_rejects_oversized(self):
        kp = IdentityKeypair.generate()
        with pytest.raises(ValueError, match="too large"):
            pair_generate_qr(
                peer_id=kp.peer_id().as_bytes(),
                pake_credential=bytes(300),
            )

    def test_typical_payload_fits(self):
        kp = IdentityKeypair.generate()
        _, cbor_bytes = pair_generate_qr(
            peer_id=kp.peer_id().as_bytes(),
            pake_credential=bytes(32),
            hints=[
                ConnectionHint("rendezvous", "relay.example.com:9090")
            ],
        )
        assert len(cbor_bytes) <= 200


class TestPinCode:
    def test_format(self):
        pin = pair_generate_pin()
        assert len(pin) == 9
        assert pin[4] == "-"

    def test_only_crockford_chars(self):
        for _ in range(50):
            pin = pair_generate_pin()
            raw = pin.replace("-", "")
            for ch in raw:
                assert ch in CROCKFORD_ALPHABET

    def test_encode_decode_roundtrip(self):
        import os
        for _ in range(50):
            data = os.urandom(5)
            encoded = encode_crockford(data)
            decoded = decode_crockford(encoded)
            assert data == decoded

    def test_known_values(self):
        assert encode_crockford(bytes(5)) == "00000000"
        assert encode_crockford(bytes([0xFF] * 5)) == "ZZZZZZZZ"

    def test_normalize_case_insensitive(self):
        assert normalize_pin("abcd-efgh") == "ABCDEFGH"

    def test_normalize_strips_separators(self):
        assert normalize_pin("AB CD-EF GH") == "ABCDEFGH"

    def test_normalize_substitutions(self):
        assert normalize_pin("ILOO-AAAA") == "1100AAAA"

    def test_normalize_removes_u(self):
        assert normalize_pin("AUBU-CUDU") == "ABCD"

    def test_pair_enter_pin_valid(self):
        result = pair_enter_pin("98AF-XZ2A")
        assert result == "98AFXZ2A"

    def test_pair_enter_pin_case_insensitive(self):
        result = pair_enter_pin("98af-xz2a")
        assert result == "98AFXZ2A"

    def test_pair_enter_pin_rejects_invalid_chars(self):
        with pytest.raises(ValueError):
            pair_enter_pin("!!!!")

    def test_pair_enter_pin_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            pair_enter_pin("ABC")

    def test_rendezvous_id_deterministic(self):
        id1 = derive_pin_rendezvous_id(b"98AFXZ2A")
        id2 = derive_pin_rendezvous_id(b"98AFXZ2A")
        assert id1 == id2
        assert len(id1) == 32

    def test_rendezvous_id_differs_for_different_pins(self):
        id1 = derive_pin_rendezvous_id(b"98AFXZ2A")
        id2 = derive_pin_rendezvous_id(b"ABCDEFGH")
        assert id1 != id2

    def test_40_bits_entropy(self):
        for _ in range(20):
            pin = pair_generate_pin().replace("-", "")
            decoded = decode_crockford(pin)
            assert len(decoded) == 5


class TestPairingLink:
    def test_generate_and_parse_roundtrip(self):
        p = make_payload()
        uri = pair_generate_link(p)
        assert uri.startswith("cairn://pair?")

        r = pair_from_link(uri)
        assert r.peer_id == p.peer_id
        assert r.nonce == p.nonce
        assert r.pake_credential == p.pake_credential
        assert r.created_at == p.created_at
        assert r.expires_at == p.expires_at
        assert len(r.connection_hints) == 1
        assert r.connection_hints[0].hint_type == "rendezvous"

    def test_roundtrip_without_hints(self):
        kp = IdentityKeypair.generate()
        p = PairingPayload(
            peer_id=kp.peer_id().as_bytes(),
            nonce=bytes([0xFF] * 16),
            pake_credential=bytes(32),
            connection_hints=None,
            created_at=1700000000,
            expires_at=2**63,
        )
        uri = pair_generate_link(p)
        r = pair_from_link(uri)
        assert r.connection_hints is None

    def test_rejects_wrong_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            pair_from_link("https://pair?pid=a&nonce=b&pake=c")

    def test_rejects_missing_pid(self):
        with pytest.raises(ValueError, match="pid"):
            pair_from_link("cairn://pair?nonce=aa&pake=bb")

    def test_rejects_missing_nonce(self):
        with pytest.raises(ValueError):
            pair_from_link("cairn://pair?pid=abc&pake=bb")

    def test_rejects_missing_pake(self):
        with pytest.raises(ValueError):
            pair_from_link("cairn://pair?pid=abc&nonce=aa")

    def test_custom_scheme(self):
        p = make_payload()
        uri = pair_generate_link(p, scheme="myapp")
        assert uri.startswith("myapp://pair?")
        r = pair_from_link(uri, scheme="myapp")
        assert r.peer_id == p.peer_id

    def test_rejects_expired(self):
        p = make_payload(expires_at=1000)
        uri = pair_generate_link(p)
        with pytest.raises(ValueError, match="expired"):
            pair_from_link(uri)
