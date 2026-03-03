package discovery

import (
	"context"
	"fmt"
)

// SignalingDiscovery provides WebSocket-based signaling server discovery (Tier 1+).
// Rendezvous ID maps to a topic/room on the signaling server.
// Provides sub-second real-time reachability exchange.
//
// This is a Tier 1+ feature requiring a deployed cairn signaling server.
type SignalingDiscovery struct {
	serverURL string
}

// NewSignalingDiscovery creates a signaling discovery backend.
// If serverURL is empty, this backend is a no-op (Tier 0 mode).
func NewSignalingDiscovery(serverURL string) *SignalingDiscovery {
	return &SignalingDiscovery{serverURL: serverURL}
}

// Name returns "signaling".
func (s *SignalingDiscovery) Name() string {
	return "signaling"
}

// Publish publishes reachability to the signaling server's rendezvous room.
func (s *SignalingDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if s.serverURL == "" {
		return fmt.Errorf("signaling: no server configured (Tier 1+ required)")
	}
	if len(rendezvousID) == 0 {
		return fmt.Errorf("signaling: empty rendezvous ID")
	}

	// Full implementation will:
	// 1. Connect to signaling server via WebSocket (WSS)
	// 2. Join room with rendezvous ID as topic
	// 3. Publish reachability info
	return nil
}

// Query queries the signaling server for peers in the rendezvous room.
func (s *SignalingDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if s.serverURL == "" {
		return nil, fmt.Errorf("signaling: no server configured (Tier 1+ required)")
	}
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("signaling: empty rendezvous ID")
	}

	// Full implementation will query signaling server for peers in room.
	return nil, nil
}

// Close disconnects from the signaling server.
func (s *SignalingDiscovery) Close() error {
	return nil
}

// IsConfigured reports whether a signaling server URL is configured.
func (s *SignalingDiscovery) IsConfigured() bool {
	return s.serverURL != ""
}
