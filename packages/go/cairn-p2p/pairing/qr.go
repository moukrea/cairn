package pairing

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/fxamacker/cbor/v2"
)

const maxQRPayloadSize = 256

// DefaultPairingTTL is the default expiry for pairing payloads (5 minutes).
const DefaultPairingTTL = 5 * time.Minute

// QRPairingData holds the data encoded in a QR pairing payload.
type QRPairingData struct {
	PeerID    [34]byte `cbor:"0,keyasint"`
	Nonce     [16]byte `cbor:"1,keyasint"`
	PakeCred  [32]byte `cbor:"2,keyasint"`
	Hints     []string `cbor:"3,keyasint,omitempty"`
	CreatedAt uint64   `cbor:"4,keyasint"`
	ExpiresAt uint64   `cbor:"5,keyasint"`
}

// GenerateQRPayload creates a new QR pairing payload.
// Returns the pairing data and CBOR-encoded bytes.
func GenerateQRPayload(identity *crypto.IdentityKeypair, ttl time.Duration, hints []string) (*QRPairingData, []byte, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	var pakeCred [32]byte
	if _, err := io.ReadFull(rand.Reader, pakeCred[:]); err != nil {
		return nil, nil, fmt.Errorf("PAKE credential generation failed: %w", err)
	}

	now := uint64(time.Now().Unix())
	data := &QRPairingData{
		PeerID:    identity.PeerID(),
		Nonce:     nonce,
		PakeCred:  pakeCred,
		Hints:     hints,
		CreatedAt: now,
		ExpiresAt: now + uint64(ttl.Seconds()),
	}

	encoded, err := cbor.Marshal(data)
	if err != nil {
		return nil, nil, fmt.Errorf("CBOR encode failed: %w", err)
	}
	if len(encoded) > maxQRPayloadSize {
		return nil, nil, fmt.Errorf("QR payload too large: %d bytes (max %d)", len(encoded), maxQRPayloadSize)
	}

	return data, encoded, nil
}

// ParseQRPayload decodes a CBOR-encoded QR pairing payload.
func ParseQRPayload(data []byte) (*QRPairingData, error) {
	if len(data) > maxQRPayloadSize {
		return nil, fmt.Errorf("QR payload too large: %d bytes (max %d)", len(data), maxQRPayloadSize)
	}
	var qr QRPairingData
	if err := cbor.Unmarshal(data, &qr); err != nil {
		return nil, fmt.Errorf("CBOR decode failed: %w", err)
	}
	return &qr, nil
}

// IsExpired reports whether the QR payload has expired.
func (q *QRPairingData) IsExpired() bool {
	return uint64(time.Now().Unix()) > q.ExpiresAt
}
