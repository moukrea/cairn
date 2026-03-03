package pairing

import (
	"fmt"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

var hkdfInfoPSKRendezvous = []byte("cairn-psk-rendezvous-v1")

const defaultMinEntropyBytes = 16 // 128 bits

// PskPairingData holds the validated PSK data.
type PskPairingData struct {
	PakeInput    []byte
	RendezvousID [32]byte
}

// PairWithPSK validates a pre-shared key and derives PAKE input and rendezvous ID.
// The PSK must be at least 16 bytes (128 bits) of entropy.
func PairWithPSK(psk []byte) (*PskPairingData, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("empty pre-shared key")
	}
	if len(psk) < defaultMinEntropyBytes {
		return nil, fmt.Errorf("insufficient PSK entropy: got %d bytes, need at least %d", len(psk), defaultMinEntropyBytes)
	}

	rendezvousBytes, err := crypto.HkdfSHA256(psk, nil, hkdfInfoPSKRendezvous, 32)
	if err != nil {
		return nil, fmt.Errorf("PSK rendezvous derivation failed: %w", err)
	}
	var rendezvousID [32]byte
	copy(rendezvousID[:], rendezvousBytes)

	return &PskPairingData{
		PakeInput:    psk,
		RendezvousID: rendezvousID,
	}, nil
}
