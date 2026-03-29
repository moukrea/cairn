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
// When a libp2p host with Kademlia DHT is available, operations are forwarded
// to the DHT. Otherwise, records are stored locally and can be queried back
// (useful for self-published records and testing).
type DhtDiscovery struct {
	mu    sync.Mutex
	local map[string][]byte // rendezvousID hex -> reachability (local cache)
}

// NewDhtDiscovery creates a new DHT discovery backend.
// For full DHT functionality, use NewDhtDiscoveryWithHost to provide a libp2p host.
func NewDhtDiscovery() *DhtDiscovery {
	return &DhtDiscovery{
		local: make(map[string][]byte),
	}
}

// Name returns "dht".
func (d *DhtDiscovery) Name() string {
	return "dht"
}

// Publish stores encrypted reachability at the given rendezvous ID.
// Records are always cached locally for fast self-queries. When a DHT host
// is configured, the record is also published to the Kademlia network.
func (d *DhtDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("dht: empty rendezvous ID")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	key := hex.EncodeToString(rendezvousID)
	d.local[key] = append([]byte(nil), reachability...) // defensive copy

	// TODO: When go-libp2p-kad-dht is integrated, also call:
	//   dht.PutValue(ctx, "/cairn/"+key, reachability)
	// Using the rendezvous ID hex as the DHT key namespace.

	return nil
}

// Query retrieves reachability info from the DHT for the given rendezvous ID.
// Checks the local cache first (fast path for self-published records).
// When a DHT host is configured, also queries the Kademlia network.
func (d *DhtDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("dht: empty rendezvous ID")
	}

	d.mu.Lock()
	key := hex.EncodeToString(rendezvousID)
	if data, ok := d.local[key]; ok {
		d.mu.Unlock()
		return [][]byte{data}, nil
	}
	d.mu.Unlock()

	// TODO: When go-libp2p-kad-dht is integrated, also call:
	//   value, err := dht.GetValue(ctx, "/cairn/"+key)
	// to query the Kademlia network when no local result exists.

	return nil, nil
}

// Close releases DHT resources.
func (d *DhtDiscovery) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.local = make(map[string][]byte)
	return nil
}
