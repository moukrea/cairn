package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
)

// MdnsDiscovery provides mDNS-based LAN discovery.
// Rendezvous ID hex is used as the mDNS service name.
// This is first-class LAN discovery — instant, no internet required.
//
// Records are cached locally and returned for self-queries.
// For full multicast I/O, integrate with go-libp2p's mDNS discovery
// (github.com/libp2p/go-libp2p/p2p/discovery/mdns) or net package multicast.
type MdnsDiscovery struct {
	mu    sync.Mutex
	local map[string][]byte // rendezvousID hex -> reachability
}

// NewMdnsDiscovery creates a new mDNS discovery backend.
func NewMdnsDiscovery() *MdnsDiscovery {
	return &MdnsDiscovery{
		local: make(map[string][]byte),
	}
}

// Name returns "mdns".
func (m *MdnsDiscovery) Name() string {
	return "mdns"
}

// Publish announces reachability at the given rendezvous ID via mDNS.
// The rendezvous ID hex is used as the mDNS service name.
// Records are cached locally for self-queries.
func (m *MdnsDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("mdns: empty rendezvous ID")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(rendezvousID)
	m.local[key] = append([]byte(nil), reachability...) // defensive copy

	// TODO: When go-libp2p-mdns or raw multicast is integrated,
	// also announce the service name on the LAN via mDNS TXT records.

	return nil
}

// Query discovers peers at the given rendezvous ID via mDNS.
// Checks local cache first. For actual LAN discovery, requires
// multicast integration.
func (m *MdnsDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("mdns: empty rendezvous ID")
	}

	m.mu.Lock()
	key := hex.EncodeToString(rendezvousID)
	if data, ok := m.local[key]; ok {
		m.mu.Unlock()
		return [][]byte{data}, nil
	}
	m.mu.Unlock()

	// TODO: When go-libp2p-mdns or raw multicast is integrated,
	// query the LAN for services matching this rendezvous ID hex.

	return nil, nil
}

// Close stops mDNS announcements and releases resources.
func (m *MdnsDiscovery) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local = make(map[string][]byte)
	return nil
}
