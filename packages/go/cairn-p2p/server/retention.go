package server

import (
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

const (
	// DefaultRetentionMaxAge is the default maximum message age (7 days).
	DefaultRetentionMaxAge = 7 * 24 * time.Hour

	// DefaultRetentionMaxPerPeer is the default maximum messages per peer.
	DefaultRetentionMaxPerPeer = 1000

	// DefaultRetentionMaxTotalSize is the default maximum total storage (1 GB).
	DefaultRetentionMaxTotalSize = 1 << 30 // 1 GB
)

// RetentionConfig defines message retention limits.
// Whichever limit is reached first triggers eviction.
type RetentionConfig struct {
	MaxAge       time.Duration // Maximum message age (default: 7 days)
	MaxPerPeer   int           // Maximum messages per peer (default: 1000)
	MaxTotalSize int64         // Maximum total storage in bytes (default: 1 GB)

	// PerPeerOverrides allows per-peer retention customization.
	PerPeerOverrides map[cairn.PeerID]RetentionOverride
}

// RetentionOverride allows per-peer retention customization.
type RetentionOverride struct {
	MaxPerPeer int
	MaxAge     time.Duration
}

// DefaultRetentionConfig returns the default retention configuration.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		MaxAge:           DefaultRetentionMaxAge,
		MaxPerPeer:       DefaultRetentionMaxPerPeer,
		MaxTotalSize:     DefaultRetentionMaxTotalSize,
		PerPeerOverrides: make(map[cairn.PeerID]RetentionOverride),
	}
}
