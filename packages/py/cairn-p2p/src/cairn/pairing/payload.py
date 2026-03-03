"""Pairing payload: data exchanged during pairing initiation."""

from __future__ import annotations

import time
from dataclasses import dataclass

import cbor2


@dataclass
class ConnectionHint:
    """A hint for how to reach a peer."""

    hint_type: str
    value: str


@dataclass
class PairingPayload:
    """The data exchanged during pairing initiation.

    CBOR key mapping: 0=peer_id, 1=nonce, 2=pake_credential,
    3=hints, 4=created_at, 5=expires_at.
    """

    peer_id: bytes  # 34-byte multihash
    nonce: bytes  # 16 bytes
    pake_credential: bytes
    connection_hints: list[ConnectionHint] | None
    created_at: int  # unix seconds
    expires_at: int  # unix seconds

    def is_expired(self, now_unix: int | None = None) -> bool:
        """Check whether this payload has expired."""
        if now_unix is None:
            now_unix = int(time.time())
        return now_unix > self.expires_at

    def to_cbor(self) -> bytes:
        """Serialize to CBOR with compact integer keys."""
        m: dict[int, object] = {
            0: self.peer_id,
            1: self.nonce,
            2: self.pake_credential,
        }
        if self.connection_hints:
            m[3] = [
                [h.hint_type, h.value]
                for h in self.connection_hints
            ]
        m[4] = self.created_at
        m[5] = self.expires_at
        return cbor2.dumps(m)

    @classmethod
    def from_cbor(cls, data: bytes) -> PairingPayload:
        """Deserialize from CBOR with compact integer keys."""
        m = cbor2.loads(data)
        if not isinstance(m, dict):
            raise ValueError("expected CBOR map")

        peer_id = bytes(m[0])
        nonce = bytes(m[1])
        if len(nonce) != 16:
            raise ValueError("nonce must be 16 bytes")
        pake_credential = bytes(m[2])

        hints = None
        if 3 in m:
            hints = [
                ConnectionHint(hint_type=h[0], value=h[1])
                for h in m[3]
            ]

        return cls(
            peer_id=peer_id,
            nonce=nonce,
            pake_credential=pake_credential,
            connection_hints=hints,
            created_at=m.get(4, 0),
            expires_at=m.get(5, 0),
        )
