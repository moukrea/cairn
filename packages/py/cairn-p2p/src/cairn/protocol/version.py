"""Protocol version negotiation."""

from __future__ import annotations

from dataclasses import dataclass

import cbor2

from cairn.protocol.envelope import MessageEnvelope, new_msg_id
from cairn.protocol.types import VERSION_NEGOTIATE

CURRENT_PROTOCOL_VERSION: int = 1
SUPPORTED_VERSIONS: list[int] = [1]


@dataclass
class VersionNegotiatePayload:
    """Payload for VersionNegotiate messages."""

    versions: list[int]


@dataclass
class VersionMismatch:
    """Version mismatch error details."""

    local_versions: list[int]
    remote_versions: list[int]

    def __str__(self) -> str:
        return (
            f"version mismatch: local supports {self.local_versions}, "
            f"remote supports {self.remote_versions}"
        )


def select_version(
    our_versions: list[int], peer_versions: list[int]
) -> int:
    """Select the highest mutually supported version.

    Raises ValueError if no common version exists.
    """
    for v in our_versions:
        if v in peer_versions:
            return v
    raise ValueError(
        f"version mismatch: local supports {our_versions}, "
        f"remote supports {peer_versions}"
    )


def create_version_negotiate() -> MessageEnvelope:
    """Create a VersionNegotiate message advertising our supported versions."""
    payload = cbor2.dumps({"versions": SUPPORTED_VERSIONS})
    return MessageEnvelope(
        version=CURRENT_PROTOCOL_VERSION,
        msg_type=VERSION_NEGOTIATE,
        msg_id=new_msg_id(),
        session_id=None,
        payload=payload,
        auth_tag=None,
    )


def parse_version_negotiate(
    envelope: MessageEnvelope,
) -> VersionNegotiatePayload:
    """Parse a VersionNegotiate envelope and extract the payload.

    Raises ValueError if message type is wrong or payload is invalid.
    """
    if envelope.msg_type != VERSION_NEGOTIATE:
        raise ValueError(
            f"expected VERSION_NEGOTIATE (0x{VERSION_NEGOTIATE:04X}), "
            f"got 0x{envelope.msg_type:04X}"
        )
    data = cbor2.loads(envelope.payload)
    return VersionNegotiatePayload(versions=data["versions"])


def handle_version_negotiate(
    received: MessageEnvelope,
) -> tuple[int, MessageEnvelope]:
    """Process a received VersionNegotiate and produce a response.

    Returns (selected_version, response_envelope).
    Raises ValueError if versions are incompatible.
    """
    peer_payload = parse_version_negotiate(received)
    selected = select_version(SUPPORTED_VERSIONS, peer_payload.versions)
    response_payload = cbor2.dumps({"versions": [selected]})
    response = MessageEnvelope(
        version=CURRENT_PROTOCOL_VERSION,
        msg_type=VERSION_NEGOTIATE,
        msg_id=new_msg_id(),
        session_id=None,
        payload=response_payload,
        auth_tag=None,
    )
    return selected, response
