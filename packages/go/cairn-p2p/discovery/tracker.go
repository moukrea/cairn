package discovery

import (
	"context"
	"fmt"
	"time"
)

const (
	// MinReannounceInterval is the minimum interval between tracker announces (BEP 3/15).
	MinReannounceInterval = 15 * time.Minute
)

// DefaultTrackers is a curated list of permissive BitTorrent trackers for discovery.
var DefaultTrackers = []string{
	"udp://tracker.opentrackr.org:1337/announce",
	"udp://open.dstud.io:6969/announce",
	"udp://tracker.openbittorrent.com:6969/announce",
}

// TrackerDiscovery provides BitTorrent tracker-based discovery.
// Rendezvous ID is used as the info_hash. Supports BEP 3 (HTTP) and BEP 15 (UDP).
type TrackerDiscovery struct {
	trackers        []string
	reannounceAfter time.Duration
	lastAnnounce    time.Time
}

// NewTrackerDiscovery creates a tracker discovery backend with the given tracker URLs.
func NewTrackerDiscovery(trackers []string) *TrackerDiscovery {
	if len(trackers) == 0 {
		trackers = DefaultTrackers
	}
	return &TrackerDiscovery{
		trackers:        trackers,
		reannounceAfter: MinReannounceInterval,
	}
}

// Name returns "tracker".
func (t *TrackerDiscovery) Name() string {
	return "tracker"
}

// Publish announces presence at the rendezvous ID (info_hash) to all configured trackers.
// Respects the minimum 15-minute re-announce interval.
func (t *TrackerDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if len(rendezvousID) == 0 {
		return fmt.Errorf("tracker: empty rendezvous ID")
	}

	if !t.lastAnnounce.IsZero() && time.Since(t.lastAnnounce) < t.reannounceAfter {
		return nil // rate limited, skip this announce
	}

	t.lastAnnounce = time.Now()

	// Full implementation will:
	// 1. Compute info_hash from rendezvous ID (SHA-1 for tracker compatibility)
	// 2. Send BEP 15 (UDP) announce to each tracker
	// 3. Fall back to BEP 3 (HTTP) if UDP fails
	return nil
}

// Query queries all configured trackers for peers at the given rendezvous ID.
func (t *TrackerDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("tracker: empty rendezvous ID")
	}

	// Full implementation will query trackers for peers with matching info_hash.
	return nil, nil
}

// Close releases tracker resources.
func (t *TrackerDiscovery) Close() error {
	return nil
}

// Trackers returns the configured tracker URLs.
func (t *TrackerDiscovery) Trackers() []string {
	return t.trackers
}
