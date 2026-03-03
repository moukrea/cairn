package pairing

import (
	"fmt"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

// HKDF info string for pairing rendezvous ID derivation.
var HkdfInfoPairingRendezvous = []byte("cairn-pairing-rendezvous-v1")

// PairingRendezvousID derives a rendezvous ID from the PAKE credential and nonce.
// rendezvousID = HKDF(pakeCred, "cairn-pairing-rendezvous-v1", nonce)
func PairingRendezvousID(pakeCred, nonce []byte) ([]byte, error) {
	result, err := crypto.HkdfSHA256(pakeCred, nonce, HkdfInfoPairingRendezvous, 32)
	if err != nil {
		return nil, fmt.Errorf("rendezvous ID derivation failed: %w", err)
	}
	return result, nil
}
