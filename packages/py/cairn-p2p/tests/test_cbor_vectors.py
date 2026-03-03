"""CBOR golden-vector tests: deterministic encoding, decode stability."""

import cbor2
import pytest

from cairn.protocol.envelope import MessageEnvelope, new_msg_id
from cairn.protocol.types import DATA_MESSAGE, HEARTBEAT, PAIR_REQUEST


class TestCBORGoldenVectors:
    """Test deterministic CBOR encoding with known outputs."""

    def _fixed_envelope(
        self,
        msg_type: int = DATA_MESSAGE,
        session_id: bytes | None = None,
        auth_tag: bytes | None = None,
    ) -> MessageEnvelope:
        return MessageEnvelope(
            version=1,
            msg_type=msg_type,
            msg_id=bytes(range(16)),
            session_id=session_id,
            payload=b"hello",
            auth_tag=auth_tag,
        )

    def test_encode_decode_roundtrip(self):
        env = self._fixed_envelope()
        encoded = env.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.version == 1
        assert decoded.msg_type == DATA_MESSAGE
        assert decoded.msg_id == bytes(range(16))
        assert decoded.payload == b"hello"
        assert decoded.session_id is None
        assert decoded.auth_tag is None

    def test_deterministic_encoding_is_stable(self):
        """Same envelope produces identical bytes each time."""
        env = self._fixed_envelope()
        enc1 = env.encode_deterministic()
        enc2 = env.encode_deterministic()
        assert enc1 == enc2

    def test_deterministic_encoding_known_structure(self):
        """Verify the CBOR map uses integer keys 0-4."""
        env = self._fixed_envelope()
        encoded = env.encode_deterministic()
        decoded_map = cbor2.loads(encoded)
        assert isinstance(decoded_map, dict)
        assert 0 in decoded_map  # version
        assert 1 in decoded_map  # msg_type
        assert 2 in decoded_map  # msg_id
        assert 4 in decoded_map  # payload
        assert 3 not in decoded_map  # session_id is None
        assert 5 not in decoded_map  # auth_tag is None

    def test_optional_session_id(self):
        """When session_id is set, key 3 appears in the CBOR map."""
        env = self._fixed_envelope(session_id=bytes(32))
        encoded = env.encode()
        decoded_map = cbor2.loads(encoded)
        assert 3 in decoded_map
        assert len(decoded_map[3]) == 32

    def test_optional_auth_tag(self):
        """When auth_tag is set, key 5 appears in the CBOR map."""
        env = self._fixed_envelope(auth_tag=b"\xaa" * 16)
        encoded = env.encode()
        decoded_map = cbor2.loads(encoded)
        assert 5 in decoded_map
        assert decoded_map[5] == b"\xaa" * 16

    def test_all_fields_present(self):
        """Envelope with all fields populated."""
        env = MessageEnvelope(
            version=1,
            msg_type=PAIR_REQUEST,
            msg_id=bytes(16),
            session_id=bytes(32),
            payload=b"\xde\xad\xbe\xef",
            auth_tag=b"\xff" * 16,
        )
        encoded = env.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.version == 1
        assert decoded.msg_type == PAIR_REQUEST
        assert decoded.session_id == bytes(32)
        assert decoded.auth_tag == b"\xff" * 16

    def test_cross_encode_decode_idempotent(self):
        """Encode, decode, re-encode produces identical bytes."""
        env = self._fixed_envelope(
            session_id=bytes(32), auth_tag=b"\xcc" * 16
        )
        encoded1 = env.encode_deterministic()
        decoded = MessageEnvelope.decode(encoded1)
        encoded2 = decoded.encode_deterministic()
        assert encoded1 == encoded2

    def test_decode_rejects_non_map(self):
        data = cbor2.dumps([1, 2, 3])
        with pytest.raises(ValueError, match="CBOR map"):
            MessageEnvelope.decode(data)

    def test_decode_rejects_missing_version(self):
        data = cbor2.dumps(
            {1: 0x0100, 2: bytes(16), 4: b"payload"}
        )
        with pytest.raises(ValueError, match="version"):
            MessageEnvelope.decode(data)

    def test_decode_rejects_bad_msg_id_length(self):
        data = cbor2.dumps(
            {0: 1, 1: 0x0100, 2: bytes(8), 4: b"payload"}
        )
        with pytest.raises(ValueError, match="16 bytes"):
            MessageEnvelope.decode(data)

    def test_decode_rejects_bad_session_id_length(self):
        data = cbor2.dumps(
            {
                0: 1,
                1: 0x0100,
                2: bytes(16),
                3: bytes(16),
                4: b"payload",
            }
        )
        with pytest.raises(ValueError, match="32 bytes"):
            MessageEnvelope.decode(data)

    def test_new_msg_id_format(self):
        """Verify UUID v7 structure."""
        mid = new_msg_id()
        assert len(mid) == 16
        # Version bits: byte 6 high nibble = 0x7
        assert (mid[6] >> 4) == 7
        # Variant bits: byte 8 high 2 bits = 10
        assert (mid[8] >> 6) == 2

    def test_msg_id_uniqueness(self):
        """Two generated IDs should differ."""
        a = new_msg_id()
        b = new_msg_id()
        assert a != b

    def test_heartbeat_type_encoding(self):
        """Heartbeat uses a specific message type code."""
        env = MessageEnvelope(
            version=1,
            msg_type=HEARTBEAT,
            msg_id=bytes(16),
            session_id=None,
            payload=b"",
            auth_tag=None,
        )
        encoded = env.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.msg_type == HEARTBEAT
