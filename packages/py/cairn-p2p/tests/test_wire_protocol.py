"""Tests for the cairn wire protocol (envelope, message types, version)."""

import cbor2
import pytest

from cairn.protocol.envelope import MessageEnvelope, new_msg_id
from cairn.protocol.types import (
    DATA_MESSAGE,
    DATA_NACK,
    FORWARD_PURGE,
    FORWARD_REQUEST,
    HEARTBEAT,
    HEARTBEAT_ACK,
    PAIR_REQUEST,
    PAIR_REVOKE,
    RELAY_ACK,
    RENDEZVOUS_PUBLISH,
    RENDEZVOUS_RESPONSE,
    ROUTE_REQUEST,
    SESSION_CLOSE,
    SESSION_RESUME,
    TRANSPORT_MIGRATE_ACK,
    VERSION_NEGOTIATE,
    message_category,
)
from cairn.protocol.version import (
    CURRENT_PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
    create_version_negotiate,
    handle_version_negotiate,
    parse_version_negotiate,
    select_version,
)


class TestNewMsgId:
    def test_is_16_bytes(self):
        msg_id = new_msg_id()
        assert len(msg_id) == 16

    def test_unique(self):
        id1 = new_msg_id()
        id2 = new_msg_id()
        assert id1 != id2

    def test_is_bytes(self):
        msg_id = new_msg_id()
        assert isinstance(msg_id, bytes)


class TestMessageEnvelope:
    def test_roundtrip_minimal(self):
        envelope = MessageEnvelope(
            version=1,
            msg_type=HEARTBEAT,
            msg_id=new_msg_id(),
            session_id=None,
            payload=b"",
            auth_tag=None,
        )
        encoded = envelope.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.version == envelope.version
        assert decoded.msg_type == envelope.msg_type
        assert decoded.msg_id == envelope.msg_id
        assert decoded.session_id is None
        assert decoded.payload == envelope.payload
        assert decoded.auth_tag is None

    def test_roundtrip_full(self):
        session_id = bytes([0xAB] * 32)
        envelope = MessageEnvelope(
            version=1,
            msg_type=DATA_MESSAGE,
            msg_id=new_msg_id(),
            session_id=session_id,
            payload=bytes([0xCA, 0xFE, 0xBA, 0xBE]),
            auth_tag=bytes([0xDE, 0xAD]),
        )
        encoded = envelope.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.version == envelope.version
        assert decoded.msg_type == envelope.msg_type
        assert decoded.msg_id == envelope.msg_id
        assert decoded.session_id == session_id
        assert decoded.payload == envelope.payload
        assert decoded.auth_tag == envelope.auth_tag

    def test_optional_fields_absent(self):
        envelope = MessageEnvelope(
            version=1,
            msg_type=PAIR_REQUEST,
            msg_id=new_msg_id(),
            session_id=None,
            payload=b"\x01",
            auth_tag=None,
        )
        encoded = envelope.encode()
        decoded = MessageEnvelope.decode(encoded)
        assert decoded.session_id is None
        assert decoded.auth_tag is None

    def test_deterministic_encoding_stable(self):
        envelope = MessageEnvelope(
            version=1,
            msg_type=HEARTBEAT,
            msg_id=bytes([1] * 16),
            session_id=bytes([2] * 32),
            payload=b"\xFF",
            auth_tag=bytes([0x00, 0x01]),
        )
        enc1 = envelope.encode_deterministic()
        enc2 = envelope.encode_deterministic()
        assert enc1 == enc2

    def test_decode_invalid_cbor(self):
        with pytest.raises(Exception):
            MessageEnvelope.decode(bytes([0xFF, 0xFF, 0xFF]))

    def test_version_field_preserved(self):
        for v in [0, 1, 255]:
            envelope = MessageEnvelope(
                version=v,
                msg_type=HEARTBEAT,
                msg_id=bytes(16),
                session_id=None,
                payload=b"",
                auth_tag=None,
            )
            decoded = MessageEnvelope.decode(envelope.encode())
            assert decoded.version == v

    def test_integer_keys_used(self):
        envelope = MessageEnvelope(
            version=1,
            msg_type=HEARTBEAT,
            msg_id=bytes(16),
            session_id=None,
            payload=b"",
            auth_tag=None,
        )
        encoded = envelope.encode()
        raw = cbor2.loads(encoded)
        assert isinstance(raw, dict)
        assert all(isinstance(k, int) for k in raw.keys())
        assert 0 in raw  # version
        assert 1 in raw  # msg_type
        assert 2 in raw  # msg_id
        assert 4 in raw  # payload
        assert 3 not in raw  # session_id absent
        assert 5 not in raw  # auth_tag absent

    def test_decode_missing_version_raises(self):
        data = cbor2.dumps({1: 0x0400, 2: bytes(16), 4: b""})
        with pytest.raises(ValueError, match="version"):
            MessageEnvelope.decode(data)

    def test_decode_missing_msg_type_raises(self):
        data = cbor2.dumps({0: 1, 2: bytes(16), 4: b""})
        with pytest.raises(ValueError, match="msg_type"):
            MessageEnvelope.decode(data)

    def test_decode_invalid_msg_id_length(self):
        data = cbor2.dumps({0: 1, 1: 0x0400, 2: bytes(8), 4: b""})
        with pytest.raises(ValueError, match="16 bytes"):
            MessageEnvelope.decode(data)

    def test_decode_invalid_session_id_length(self):
        data = cbor2.dumps(
            {0: 1, 1: 0x0400, 2: bytes(16), 3: bytes(16), 4: b""}
        )
        with pytest.raises(ValueError, match="32 bytes"):
            MessageEnvelope.decode(data)


class TestMessageCategory:
    def test_version(self):
        assert message_category(VERSION_NEGOTIATE) == "version"

    def test_pairing(self):
        assert message_category(PAIR_REQUEST) == "pairing"
        assert message_category(PAIR_REVOKE) == "pairing"

    def test_session(self):
        assert message_category(SESSION_RESUME) == "session"
        assert message_category(SESSION_CLOSE) == "session"

    def test_data(self):
        assert message_category(DATA_MESSAGE) == "data"
        assert message_category(DATA_NACK) == "data"

    def test_control(self):
        assert message_category(HEARTBEAT) == "control"
        assert message_category(TRANSPORT_MIGRATE_ACK) == "control"

    def test_mesh(self):
        assert message_category(ROUTE_REQUEST) == "mesh"
        assert message_category(RELAY_ACK) == "mesh"

    def test_rendezvous(self):
        assert message_category(RENDEZVOUS_PUBLISH) == "rendezvous"
        assert message_category(RENDEZVOUS_RESPONSE) == "rendezvous"

    def test_forward(self):
        assert message_category(FORWARD_REQUEST) == "forward"
        assert message_category(FORWARD_PURGE) == "forward"

    def test_application(self):
        assert message_category(0xF000) == "application"
        assert message_category(0xFFFF) == "application"

    def test_reserved(self):
        assert message_category(0x0800) == "reserved"
        assert message_category(HEARTBEAT_ACK) == "control"


class TestVersionNegotiation:
    def test_current_version_is_1(self):
        assert CURRENT_PROTOCOL_VERSION == 1

    def test_supported_versions_contains_current(self):
        assert CURRENT_PROTOCOL_VERSION in SUPPORTED_VERSIONS

    def test_supported_versions_highest_first(self):
        for i in range(len(SUPPORTED_VERSIONS) - 1):
            assert SUPPORTED_VERSIONS[i] >= SUPPORTED_VERSIONS[i + 1]

    def test_select_version_common(self):
        assert select_version([3, 2, 1], [2, 1]) == 2

    def test_select_version_exact_match(self):
        assert select_version([1], [1]) == 1

    def test_select_version_picks_highest_mutual(self):
        assert select_version([5, 3, 1], [4, 3, 2, 1]) == 3

    def test_select_version_no_common(self):
        with pytest.raises(ValueError, match="version mismatch"):
            select_version([3, 2], [5, 4])

    def test_select_version_empty_ours(self):
        with pytest.raises(ValueError):
            select_version([], [1])

    def test_select_version_empty_peer(self):
        with pytest.raises(ValueError):
            select_version([1], [])

    def test_create_version_negotiate_envelope(self):
        envelope = create_version_negotiate()
        assert envelope.version == CURRENT_PROTOCOL_VERSION
        assert envelope.msg_type == VERSION_NEGOTIATE
        assert envelope.session_id is None
        assert envelope.auth_tag is None
        payload = parse_version_negotiate(envelope)
        assert payload.versions == SUPPORTED_VERSIONS

    def test_parse_wrong_type(self):
        envelope = MessageEnvelope(
            version=1,
            msg_type=PAIR_REQUEST,
            msg_id=new_msg_id(),
            session_id=None,
            payload=b"",
            auth_tag=None,
        )
        with pytest.raises(ValueError, match="VERSION_NEGOTIATE"):
            parse_version_negotiate(envelope)

    def test_handle_compatible(self):
        initiator = create_version_negotiate()
        selected, response = handle_version_negotiate(initiator)
        assert selected == 1
        assert response.msg_type == VERSION_NEGOTIATE
        resp_payload = parse_version_negotiate(response)
        assert resp_payload.versions == [1]

    def test_handle_incompatible(self):
        payload = cbor2.dumps({"versions": [99]})
        envelope = MessageEnvelope(
            version=99,
            msg_type=VERSION_NEGOTIATE,
            msg_id=new_msg_id(),
            session_id=None,
            payload=payload,
            auth_tag=None,
        )
        with pytest.raises(ValueError, match="version mismatch"):
            handle_version_negotiate(envelope)

    def test_full_negotiation_roundtrip(self):
        alice_offer = create_version_negotiate()
        alice_wire = alice_offer.encode()

        bob_received = MessageEnvelope.decode(alice_wire)
        selected, bob_response = handle_version_negotiate(bob_received)
        assert selected == 1
        bob_wire = bob_response.encode()

        alice_received = MessageEnvelope.decode(bob_wire)
        resp_payload = parse_version_negotiate(alice_received)
        assert resp_payload.versions == [1]
