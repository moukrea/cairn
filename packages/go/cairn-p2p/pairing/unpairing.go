package pairing

import (
	"fmt"

	"github.com/mr-tron/base58"
)

// UnpairingEvent is emitted when a peer is unpaired.
type UnpairingEvent struct {
	PeerID [34]byte
	Remote bool // true if initiated by remote peer (PairRevoke)
}

// TrustStore is a minimal interface for unpairing operations.
type TrustStore interface {
	IsPaired(peerID [34]byte) bool
	RemovePeer(peerID [34]byte) error
}

// Unpair executes the local unpairing protocol for a peer.
// Returns an UnpairingEvent on success.
func Unpair(peerID [34]byte, store TrustStore) (*UnpairingEvent, error) {
	if !store.IsPaired(peerID) {
		return nil, fmt.Errorf("peer not found in trust store: %s", base58.Encode(peerID[:]))
	}
	if err := store.RemovePeer(peerID); err != nil {
		return nil, fmt.Errorf("failed to remove peer state: %w", err)
	}
	return &UnpairingEvent{PeerID: peerID, Remote: false}, nil
}

// HandlePairRevoke handles an incoming PairRevoke message from a remote peer.
// Removes the peer from the trust store (if present) and returns an event.
func HandlePairRevoke(peerID [34]byte, store TrustStore) *UnpairingEvent {
	_ = store.RemovePeer(peerID) // best-effort removal
	return &UnpairingEvent{PeerID: peerID, Remote: true}
}
