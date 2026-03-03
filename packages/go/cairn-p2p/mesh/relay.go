package mesh

import (
	"fmt"
	"sync"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// RelayConnection represents an active relay connection between two peers.
type RelayConnection struct {
	From cairn.PeerID
	To   cairn.PeerID
}

// RelayManager tracks active relay connections and enforces capacity limits.
// Relay peers forward only opaque encrypted bytes — E2E encryption between
// communicating endpoints is maintained through relay hops.
type RelayManager struct {
	mu       sync.Mutex
	settings MeshSettings
	relays   []RelayConnection
}

// NewRelayManager creates a relay manager with the given settings.
func NewRelayManager(settings MeshSettings) *RelayManager {
	return &RelayManager{
		settings: settings,
	}
}

// HandleRelayRequest processes a relay request from one peer to another.
// Returns an error if relaying is not enabled, capacity is exceeded, or max hops are exceeded.
func (rm *RelayManager) HandleRelayRequest(from, to cairn.PeerID, hopCount int) error {
	if !rm.settings.RelayWilling {
		return cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			"this node is not willing to relay",
			"Enable relay via MeshSettings{RelayWilling: true}.",
		)
	}

	if hopCount > int(rm.settings.MaxHops) {
		return cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			fmt.Sprintf("relay request exceeds max hops (%d > %d)", hopCount, rm.settings.MaxHops),
			"Route requires too many hops.",
		)
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if uint32(len(rm.relays)) >= rm.settings.RelayCapacity {
		return cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			fmt.Sprintf("relay capacity exceeded (%d/%d)", len(rm.relays), rm.settings.RelayCapacity),
			"This relay node is at capacity. Try a different relay.",
		)
	}

	rm.relays = append(rm.relays, RelayConnection{From: from, To: to})
	return nil
}

// RemoveRelay removes an active relay connection.
func (rm *RelayManager) RemoveRelay(from, to cairn.PeerID) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, r := range rm.relays {
		if r.From == from && r.To == to {
			rm.relays = append(rm.relays[:i], rm.relays[i+1:]...)
			return
		}
	}
}

// ActiveRelays returns the number of active relay connections.
func (rm *RelayManager) ActiveRelays() int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.relays)
}

// IsWilling reports whether this node is willing to relay.
func (rm *RelayManager) IsWilling() bool {
	return rm.settings.RelayWilling
}
