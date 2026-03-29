package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

const (
	// MinReannounceInterval is the minimum interval between tracker announces (BEP 3/15).
	MinReannounceInterval = 15 * time.Minute

	// udpTrackerTimeout is the timeout for individual UDP tracker operations.
	udpTrackerTimeout = 5 * time.Second

	// bep15ProtocolID is the magic constant for BEP 15 connection requests.
	bep15ProtocolID uint64 = 0x41727101980
)

// DefaultTrackers is a curated list of permissive BitTorrent trackers for discovery.
var DefaultTrackers = []string{
	"udp://tracker.opentrackr.org:1337/announce",
	"udp://open.dstud.io:6969/announce",
	"udp://tracker.openbittorrent.com:6969/announce",
}

// TrackerDiscovery provides BitTorrent tracker-based discovery.
// Rendezvous ID is truncated to 20 bytes and used as the info_hash.
// Supports BEP 15 (UDP) tracker protocol.
type TrackerDiscovery struct {
	mu              sync.Mutex
	trackers        []string
	reannounceAfter time.Duration
	peerID          [20]byte
	announceState   map[string]*announceState // info_hash hex -> state
}

type announceState struct {
	lastAnnounce time.Time
	payload      []byte
}

// NewTrackerDiscovery creates a tracker discovery backend with the given tracker URLs.
func NewTrackerDiscovery(trackers []string) *TrackerDiscovery {
	if len(trackers) == 0 {
		trackers = DefaultTrackers
	}
	var peerID [20]byte
	rand.Read(peerID[:])
	// Set cairn prefix for peer ID identification
	copy(peerID[:8], []byte("-CR0001-"))
	return &TrackerDiscovery{
		trackers:        trackers,
		reannounceAfter: MinReannounceInterval,
		peerID:          peerID,
		announceState:   make(map[string]*announceState),
	}
}

// Name returns "tracker".
func (t *TrackerDiscovery) Name() string {
	return "tracker"
}

// ToInfoHash converts a 32-byte rendezvous ID to a 20-byte info_hash
// by truncation. Matches Rust's BitTorrentBackend::to_info_hash.
func ToInfoHash(rendezvousID []byte) [20]byte {
	var hash [20]byte
	copy(hash[:], rendezvousID[:min(20, len(rendezvousID))])
	return hash
}

// Publish announces presence at the rendezvous ID (info_hash) to all configured trackers.
// Respects the minimum 15-minute re-announce interval.
func (t *TrackerDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("tracker: empty rendezvous ID")
	}

	infoHash := ToInfoHash(rendezvousID)
	key := hex.EncodeToString(infoHash[:])

	t.mu.Lock()
	state, exists := t.announceState[key]
	if exists && time.Since(state.lastAnnounce) < t.reannounceAfter {
		state.payload = append([]byte(nil), reachability...)
		t.mu.Unlock()
		return nil // rate limited
	}
	t.mu.Unlock()

	// Announce to all trackers, collecting the first error if any
	var firstErr error
	for _, trackerURL := range t.trackers {
		if err := t.announceToTracker(ctx, trackerURL, infoHash, 2); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}

	t.mu.Lock()
	if t.announceState[key] == nil {
		t.announceState[key] = &announceState{}
	}
	t.announceState[key].lastAnnounce = time.Now()
	t.announceState[key].payload = append([]byte(nil), reachability...)
	t.mu.Unlock()

	return nil // success even if some trackers failed
}

// Query queries all configured trackers for peers at the given rendezvous ID.
func (t *TrackerDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("tracker: empty rendezvous ID")
	}

	infoHash := ToInfoHash(rendezvousID)
	key := hex.EncodeToString(infoHash[:])

	// Check local cache first
	t.mu.Lock()
	if state, ok := t.announceState[key]; ok && state.payload != nil {
		result := append([]byte(nil), state.payload...)
		t.mu.Unlock()
		return [][]byte{result}, nil
	}
	t.mu.Unlock()

	// Query trackers for peers
	for _, trackerURL := range t.trackers {
		peers, err := t.queryTracker(ctx, trackerURL, infoHash)
		if err != nil {
			continue
		}
		if len(peers) > 0 {
			return peers, nil
		}
	}

	return nil, nil
}

// Close releases tracker resources.
func (t *TrackerDiscovery) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.announceState = make(map[string]*announceState)
	return nil
}

// Trackers returns the configured tracker URLs.
func (t *TrackerDiscovery) Trackers() []string {
	return t.trackers
}

// announceToTracker sends a BEP 15 UDP announce to a single tracker.
func (t *TrackerDiscovery) announceToTracker(ctx context.Context, trackerURL string, infoHash [20]byte, event uint32) error {
	parsed, err := url.Parse(trackerURL)
	if err != nil {
		return fmt.Errorf("invalid tracker URL: %w", err)
	}

	if parsed.Scheme != "udp" {
		return fmt.Errorf("only UDP trackers supported, got %s", parsed.Scheme)
	}

	host := parsed.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "6969")
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(udpTrackerTimeout)
	}

	conn, err := net.DialTimeout("udp", host, udpTrackerTimeout)
	if err != nil {
		return fmt.Errorf("connect to tracker %s: %w", host, err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	// Step 1: BEP 15 connect request
	connectionID, err := bep15Connect(conn)
	if err != nil {
		return fmt.Errorf("bep15 connect to %s: %w", host, err)
	}

	// Step 2: BEP 15 announce
	return bep15Announce(conn, connectionID, infoHash, t.peerID, event)
}

// queryTracker queries a tracker for peers with the given info_hash.
func (t *TrackerDiscovery) queryTracker(ctx context.Context, trackerURL string, infoHash [20]byte) ([][]byte, error) {
	parsed, err := url.Parse(trackerURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "udp" {
		return nil, fmt.Errorf("only UDP trackers supported")
	}

	host := parsed.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "6969")
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(udpTrackerTimeout)
	}

	conn, err := net.DialTimeout("udp", host, udpTrackerTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	connectionID, err := bep15Connect(conn)
	if err != nil {
		return nil, err
	}

	return bep15AnnounceQuery(conn, connectionID, infoHash, t.peerID)
}

// bep15Connect sends a BEP 15 connect request and returns the connection_id.
func bep15Connect(conn net.Conn) (uint64, error) {
	var tid [4]byte
	rand.Read(tid[:])
	transactionID := binary.BigEndian.Uint32(tid[:])

	// Connect request: 16 bytes
	var req [16]byte
	binary.BigEndian.PutUint64(req[0:8], bep15ProtocolID) // protocol_id
	binary.BigEndian.PutUint32(req[8:12], 0)              // action: connect
	binary.BigEndian.PutUint32(req[12:16], transactionID) // transaction_id

	if _, err := conn.Write(req[:]); err != nil {
		return 0, err
	}

	// Connect response: 16 bytes
	var resp [16]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return 0, err
	}
	if n < 16 {
		return 0, fmt.Errorf("connect response too short: %d bytes", n)
	}

	respAction := binary.BigEndian.Uint32(resp[0:4])
	respTID := binary.BigEndian.Uint32(resp[4:8])
	connectionID := binary.BigEndian.Uint64(resp[8:16])

	if respAction != 0 {
		return 0, fmt.Errorf("connect response action=%d (expected 0)", respAction)
	}
	if respTID != transactionID {
		return 0, fmt.Errorf("transaction ID mismatch")
	}

	return connectionID, nil
}

// bep15Announce sends a BEP 15 announce request (fire-and-forget for publish).
func bep15Announce(conn net.Conn, connectionID uint64, infoHash, peerID [20]byte, event uint32) error {
	var tid [4]byte
	rand.Read(tid[:])
	transactionID := binary.BigEndian.Uint32(tid[:])

	var req [98]byte
	binary.BigEndian.PutUint64(req[0:8], connectionID)
	binary.BigEndian.PutUint32(req[8:12], 1)              // action: announce
	binary.BigEndian.PutUint32(req[12:16], transactionID) // transaction_id
	copy(req[16:36], infoHash[:])                         // info_hash
	copy(req[36:56], peerID[:])                           // peer_id
	// downloaded (56-64) = 0, left (64-72) = 0, uploaded (72-80) = 0
	binary.BigEndian.PutUint32(req[80:84], event) // event
	// ip (84-88) = 0 (default), key (88-92) = random
	rand.Read(req[88:92])
	binary.BigEndian.PutUint32(req[92:96], 0xFFFFFFFF) // num_want = -1 (default)
	// port (96-98) = 0

	_, err := conn.Write(req[:])
	return err
}

// bep15AnnounceQuery sends a BEP 15 announce and parses the peer list response.
func bep15AnnounceQuery(conn net.Conn, connectionID uint64, infoHash, peerID [20]byte) ([][]byte, error) {
	if err := bep15Announce(conn, connectionID, infoHash, peerID, 0); err != nil {
		return nil, err
	}

	// Read announce response
	var resp [1024]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return nil, err
	}
	if n < 20 {
		return nil, fmt.Errorf("announce response too short: %d bytes", n)
	}

	respAction := binary.BigEndian.Uint32(resp[0:4])
	if respAction != 1 {
		if respAction == 3 {
			// Error response
			msg := string(resp[8:n])
			return nil, fmt.Errorf("tracker error: %s", msg)
		}
		return nil, fmt.Errorf("unexpected action %d", respAction)
	}

	// Parse compact peer list (6 bytes per peer: 4-byte IP + 2-byte port)
	peerData := resp[20:n]
	var peers [][]byte
	for i := 0; i+6 <= len(peerData); i += 6 {
		peer := make([]byte, 6)
		copy(peer, peerData[i:i+6])
		peers = append(peers, peer)
	}

	return peers, nil
}
