"""CBOR message envelope for the cairn wire protocol."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import cbor2


def new_msg_id() -> bytes:
    """Generate a new UUID v7 message ID as 16 bytes (RFC 9562)."""
    # 48-bit unix timestamp in milliseconds
    timestamp_ms = int(time.time() * 1000)
    rand_bytes = os.urandom(10)

    # Bytes 0-5: 48-bit timestamp (big-endian)
    b = bytearray(16)
    b[0] = (timestamp_ms >> 40) & 0xFF
    b[1] = (timestamp_ms >> 32) & 0xFF
    b[2] = (timestamp_ms >> 24) & 0xFF
    b[3] = (timestamp_ms >> 16) & 0xFF
    b[4] = (timestamp_ms >> 8) & 0xFF
    b[5] = timestamp_ms & 0xFF
    # Bytes 6-7: version (0111) + 12 bits random
    b[6] = 0x70 | (rand_bytes[0] & 0x0F)
    b[7] = rand_bytes[1]
    # Bytes 8-9: variant (10) + 14 bits random
    b[8] = 0x80 | (rand_bytes[2] & 0x3F)
    b[9] = rand_bytes[3]
    # Bytes 10-15: 48 bits random
    b[10:16] = rand_bytes[4:10]
    return bytes(b)


@dataclass
class MessageEnvelope:
    """Wire-level message envelope for all cairn protocol messages.

    Serialized as a CBOR map with integer keys 0-5.
    """

    version: int
    msg_type: int
    msg_id: bytes
    session_id: bytes | None
    payload: bytes
    auth_tag: bytes | None

    def _to_cbor_map(self) -> dict[int, object]:
        """Build the integer-keyed CBOR map, omitting None optional fields."""
        m: dict[int, object] = {
            0: self.version,
            1: self.msg_type,
            2: self.msg_id,
            4: self.payload,
        }
        if self.session_id is not None:
            m[3] = self.session_id
        if self.auth_tag is not None:
            m[5] = self.auth_tag
        return m

    def encode(self) -> bytes:
        """Encode the envelope to CBOR bytes."""
        return cbor2.dumps(self._to_cbor_map())

    def encode_deterministic(self) -> bytes:
        """Encode the envelope to deterministic CBOR (RFC 8949 section 4.2).

        Used when the output will be input to a signature or HMAC computation.
        """
        return cbor2.dumps(self._to_cbor_map(), canonical=True)

    @classmethod
    def decode(cls, data: bytes) -> MessageEnvelope:
        """Decode a MessageEnvelope from CBOR bytes.

        Raises ValueError on invalid CBOR or missing required fields.
        """
        m = cbor2.loads(data)
        if not isinstance(m, dict):
            raise ValueError("expected CBOR map")

        if 0 not in m:
            raise ValueError("missing required field: version (key 0)")
        if 1 not in m:
            raise ValueError("missing required field: msg_type (key 1)")
        if 2 not in m:
            raise ValueError("missing required field: msg_id (key 2)")
        if 4 not in m:
            raise ValueError("missing required field: payload (key 4)")

        msg_id = bytes(m[2])
        if len(msg_id) != 16:
            raise ValueError(
                f"msg_id must be 16 bytes, got {len(msg_id)}"
            )

        session_id = None
        if 3 in m:
            session_id = bytes(m[3])
            if len(session_id) != 32:
                raise ValueError(
                    f"session_id must be 32 bytes, got {len(session_id)}"
                )

        auth_tag = None
        if 5 in m:
            auth_tag = bytes(m[5])

        return cls(
            version=int(m[0]),
            msg_type=int(m[1]),
            msg_id=msg_id,
            session_id=session_id,
            payload=bytes(m[4]),
            auth_tag=auth_tag,
        )
