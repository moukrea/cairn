package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
)

// DhtDiscovery provides Kademlia DHT-based peer discovery.
// Rendezvous ID is used as the DHT key, encrypted reachability as the value.
//
// Full implementation will integrate with go-libp2p-kad-dht
// (github.com/libp2p/go-libp2p-kad-dht).
type DhtDiscovery struct {
	mu        sync.Mutex
	published map[string][]byte // rendezvousID hex -> reachability
}

// NewDhtDiscovery creates a new DHT discovery backend.
func NewDhtDiscovery() *DhtDiscovery {
	return &DhtDiscovery{
		published: make(map[string][]byte),
	}
}

// Name returns "dht".
func (d *DhtDiscovery) Name() string {
	return "dht"
}

// Publish stores encrypted reachability at the given rendezvous ID in the DHT.
func (d *DhtDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("dht: empty rendezvous ID")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	key := hex.EncodeToString(rendezvousID)
	d.published[key] = reachability

	// Full implementation will use kad-dht PutValue with rendezvous ID as key.
	return nil
}

// Query retrieves reachability info from the DHT for the given rendezvous ID.
func (d *DhtDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("dht: empty rendezvous ID")
	}

	// Full implementation will use kad-dht GetValue/FindProviders.
	// For now, return nil (not found).
	return nil, nil
}

// Close releases DHT resources.
func (d *DhtDiscovery) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.published = make(map[string][]byte)
	return nil
}
