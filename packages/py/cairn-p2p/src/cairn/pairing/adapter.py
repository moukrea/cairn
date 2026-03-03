"""Abstract base class for custom pairing adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cairn.pairing.payload import PairingPayload


class PairingAdapter(ABC):
    """Interface for custom pairing transports.

    Subclass this to implement arbitrary pairing mechanisms
    (NFC, BLE, email, hardware token, etc.). The pairing session
    calls these methods at the appropriate phases.
    """

    @abstractmethod
    def generate_payload(self) -> PairingPayload:
        """Generate a pairing payload to send to the remote peer.

        Called by the initiator to create the outbound pairing data.
        The adapter is responsible for filling in peer_id, nonce,
        pake_credential, connection_hints, and timestamps.
        """

    @abstractmethod
    def consume_payload(self, payload: PairingPayload) -> None:
        """Process a received pairing payload from the remote peer.

        Called when the acceptor receives pairing data. The adapter
        should validate the payload and store any relevant state
        (e.g., the remote peer ID and connection hints).

        Raises ValueError if the payload is invalid or rejected.
        """

    @abstractmethod
    def get_pake_credential(self) -> bytes:
        """Return the PAKE credential for this pairing session.

        The returned bytes are used as input to the SPAKE2 exchange.
        This is called after generate_payload() or consume_payload()
        to retrieve the credential that will authenticate the
        Noise handshake.
        """
