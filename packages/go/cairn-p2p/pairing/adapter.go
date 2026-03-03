package pairing

import (
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

// PairingPayload is a generic pairing payload used by adapters.
type PairingPayload struct {
	PeerID   [34]byte
	Nonce    [16]byte
	PakeCred []byte
	Hints    []string
}

// PairingAdapter allows applications to provide custom pairing flows
// (e.g., NFC, Bluetooth LE, email-based, hardware token).
type PairingAdapter interface {
	// GeneratePayload creates a pairing payload for the given identity.
	GeneratePayload(identity *crypto.IdentityKeypair) ([]byte, error)

	// ConsumePayload parses raw bytes into a PairingPayload.
	ConsumePayload(data []byte) (*PairingPayload, error)

	// IntegrateKeyExchange integrates a payload into the key exchange,
	// returning the PAKE credential bytes.
	IntegrateKeyExchange(payload *PairingPayload) ([]byte, error)
}
