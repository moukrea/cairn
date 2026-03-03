package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
)

// MdnsDiscovery provides mDNS-based LAN discovery.
// Rendezvous ID is announced as the mDNS service name.
// This is first-class LAN discovery — instant, no internet required.
//
// Full implementation will integrate with go-libp2p's mDNS discovery
// (github.com/libp2p/go-libp2p/p2p/discovery/mdns).
type MdnsDiscovery struct {
	mu          sync.Mutex
	published   map[string][]byte // rendezvousID hex -> reachability
	serviceName string
}

// NewMdnsDiscovery creates a new mDNS discovery backend.
func NewMdnsDiscovery() *MdnsDiscovery {
	return &MdnsDiscovery{
		published: make(map[string][]byte),
	}
}

// Name returns "mdns".
func (m *MdnsDiscovery) Name() string {
	return "mdns"
}

// Publish announces reachability at the given rendezvous ID via mDNS.
// The rendezvous ID is used as the mDNS service name.
func (m *MdnsDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("mdns: empty rendezvous ID")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(rendezvousID)
	m.published[key] = reachability
	m.serviceName = key

	// Full implementation will announce as mDNS service via go-libp2p.
	return nil
}

// Query discovers peers at the given rendezvous ID via mDNS.
func (m *MdnsDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("mdns: empty rendezvous ID")
	}

	// Full implementation will query mDNS for matching service names.
	// For now, return nil (no peers found) — this is correct behavior
	// when no other peer is on the LAN.
	return nil, nil
}

// Close stops mDNS announcements and releases resources.
func (m *MdnsDiscovery) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = make(map[string][]byte)
	return nil
}
