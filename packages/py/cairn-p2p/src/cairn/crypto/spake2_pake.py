"""SPAKE2 balanced PAKE for pairing authentication."""

from __future__ import annotations

import spake2


class Spake2Session:
    """Stateful SPAKE2 session for use in pairing flows.

    Usage:
        session = Spake2Session(password, is_initiator=True)
        outbound_msg = session.start()
        # send outbound_msg to peer, receive their message
        shared_key = session.finish(peer_msg)
    """

    def __init__(self, password: bytes, *, is_initiator: bool) -> None:
        if is_initiator:
            self._session = spake2.SPAKE2_A(
                password,
                idA=b"cairn-initiator",
                idB=b"cairn-responder",
            )
        else:
            self._session = spake2.SPAKE2_B(
                password,
                idA=b"cairn-initiator",
                idB=b"cairn-responder",
            )
        self._outbound: bytes | None = None

    def start(self) -> bytes:
        """Start the SPAKE2 exchange. Returns the outbound message."""
        self._outbound = self._session.start()
        return self._outbound

    def finish(self, peer_msg: bytes) -> bytes:
        """Finish the SPAKE2 exchange. Returns the shared key."""
        return self._session.finish(peer_msg)
