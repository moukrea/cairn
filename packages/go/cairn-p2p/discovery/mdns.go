package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// mdnsMulticastAddr is the standard mDNS multicast group address.
	mdnsMulticastAddr = "224.0.0.251:5353"

	// mdnsServicePrefix is the prefix for cairn mDNS service names.
	// The full name is _cairn-<hex[:16]>._tcp.local.
	mdnsServicePrefix = "_cairn-"
	mdnsServiceSuffix = "._tcp.local."

	// mdnsTTL is the TTL in seconds for mDNS announcements.
	mdnsTTL = 120

	// mdnsQueryTimeout is the time to wait for multicast responses.
	mdnsQueryTimeout = 2 * time.Second

	// mdnsMaxPacket is the maximum mDNS UDP packet size.
	mdnsMaxPacket = 9000

	// mdnsAnnounceInterval is the interval between periodic re-announcements.
	mdnsAnnounceInterval = 60 * time.Second
)

// MdnsDiscovery provides mDNS-based LAN discovery using real UDP multicast.
// Rendezvous ID hex is used as the mDNS service name.
// This is first-class LAN discovery -- instant, no internet required.
//
// Publish sends mDNS announcement packets to the multicast group.
// Query sends mDNS query packets and listens for responses.
type MdnsDiscovery struct {
	mu     sync.Mutex
	local  map[string][]byte // rendezvousID hex -> reachability
	conn   *net.UDPConn      // multicast connection (nil until first use)
	closed bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
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

// serviceName builds the mDNS service name from a rendezvous ID hex string.
// Format: _cairn-<hex[:16]>._tcp.local.
func serviceName(rendezvousHex string) string {
	truncated := rendezvousHex
	if len(truncated) > 16 {
		truncated = truncated[:16]
	}
	return mdnsServicePrefix + truncated + mdnsServiceSuffix
}

// ensureConn creates the multicast UDP connection if not already open.
// Must be called with m.mu held.
func (m *MdnsDiscovery) ensureConn() error {
	if m.conn != nil {
		return nil
	}
	if m.closed {
		return fmt.Errorf("mdns: discovery closed")
	}

	addr, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return fmt.Errorf("mdns: resolve multicast addr: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("mdns: listen multicast: %w", err)
	}

	conn.SetReadBuffer(mdnsMaxPacket)
	m.conn = conn

	// Start background listener
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go m.listenLoop(ctx)

	return nil
}

// listenLoop reads incoming mDNS packets and processes responses.
func (m *MdnsDiscovery) listenLoop(ctx context.Context) {
	defer m.wg.Done()
	buf := make([]byte, mdnsMaxPacket)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		m.mu.Lock()
		conn := m.conn
		m.mu.Unlock()
		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Connection closed or other error
			return
		}

		if n > 0 {
			m.handlePacket(buf[:n])
		}
	}
}

// handlePacket processes a received mDNS packet.
// Our wire format: "CAIRN" (5) + keyLen (1) + key + data
func (m *MdnsDiscovery) handlePacket(data []byte) {
	if len(data) < 7 || string(data[:5]) != "CAIRN" {
		return // not our packet
	}

	keyLen := int(data[5])
	if len(data) < 6+keyLen+1 {
		return
	}

	key := string(data[6 : 6+keyLen])
	reachability := make([]byte, len(data)-(6+keyLen))
	copy(reachability, data[6+keyLen:])

	m.mu.Lock()
	defer m.mu.Unlock()
	m.local[key] = reachability
}

// buildAnnouncePacket creates a wire-format mDNS announcement.
// Format: "CAIRN" (5) + keyLen (1) + key + reachability
func buildAnnouncePacket(key string, reachability []byte) []byte {
	if len(key) > 255 {
		key = key[:255]
	}
	pkt := make([]byte, 0, 6+len(key)+len(reachability))
	pkt = append(pkt, "CAIRN"...)
	pkt = append(pkt, byte(len(key)))
	pkt = append(pkt, []byte(key)...)
	pkt = append(pkt, reachability...)
	return pkt
}

// Publish announces reachability at the given rendezvous ID via mDNS multicast.
// The rendezvous ID hex is used as the mDNS service name.
// Sends a UDP multicast packet to 224.0.0.251:5353.
func (m *MdnsDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("mdns: empty rendezvous ID")
	}

	key := hex.EncodeToString(rendezvousID)

	m.mu.Lock()
	m.local[key] = append([]byte(nil), reachability...) // defensive copy
	m.mu.Unlock()

	// Send multicast announcement
	addr, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return nil // degrade gracefully, local cache still works
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil // degrade gracefully
	}
	defer conn.Close()

	svc := serviceName(key)
	pkt := buildAnnouncePacket(svc, reachability)

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		// Non-fatal: local cache still works
		return nil
	}

	// Also ensure the listener is running for incoming responses
	m.mu.Lock()
	_ = m.ensureConn()
	m.mu.Unlock()

	return nil
}

// Query discovers peers at the given rendezvous ID via mDNS multicast.
// Checks local cache first. If no local hit, sends a multicast query
// and waits briefly for responses.
func (m *MdnsDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("mdns: empty rendezvous ID")
	}

	key := hex.EncodeToString(rendezvousID)
	svc := serviceName(key)

	// Check local cache first
	m.mu.Lock()
	if data, ok := m.local[svc]; ok {
		m.mu.Unlock()
		return [][]byte{data}, nil
	}
	// Also check by raw hex key (from our own Publish)
	if data, ok := m.local[key]; ok {
		m.mu.Unlock()
		return [][]byte{data}, nil
	}
	m.mu.Unlock()

	// Send multicast query
	addr, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return nil, nil
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	// Send a query packet (same format, empty reachability means query)
	pkt := buildAnnouncePacket(svc, nil)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(pkt)

	// Ensure listener is running
	m.mu.Lock()
	_ = m.ensureConn()
	m.mu.Unlock()

	// Wait for responses
	timer := time.NewTimer(mdnsQueryTimeout)
	defer timer.Stop()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, nil
		case <-ticker.C:
			m.mu.Lock()
			if data, ok := m.local[svc]; ok {
				m.mu.Unlock()
				return [][]byte{data}, nil
			}
			m.mu.Unlock()
		}
	}
}

// Close stops mDNS announcements and releases resources.
func (m *MdnsDiscovery) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.local = make(map[string][]byte)

	if m.cancel != nil {
		m.cancel()
	}

	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
	}

	m.mu.Unlock()
	m.wg.Wait()
	m.mu.Lock()

	return nil
}
