package discovery

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

const (
	// DefaultRotationInterval is the default epoch rotation interval for rendezvous IDs.
	DefaultRotationInterval = 24 * time.Hour

	// DefaultOverlapWindow is the default transition overlap window (centered on epoch boundary).
	DefaultOverlapWindow = 1 * time.Hour

	// DefaultClockTolerance is the assumed maximum clock drift between peers.
	DefaultClockTolerance = 5 * time.Minute
)

// RotationConfig controls epoch-based rendezvous ID rotation.
type RotationConfig struct {
	RotationInterval time.Duration
	OverlapWindow    time.Duration
	ClockTolerance   time.Duration
}

// DefaultRotationConfig returns the default rotation configuration matching Rust.
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		RotationInterval: DefaultRotationInterval,
		OverlapWindow:    DefaultOverlapWindow,
		ClockTolerance:   DefaultClockTolerance,
	}
}

// DeriveRendezvousID derives a rendezvous ID from a pairing secret and epoch number.
// Uses HKDF-SHA256 with epoch as salt and "cairn-rendezvous-v1" as info.
// Wire-compatible with Rust's derive_rendezvous_id.
func DeriveRendezvousID(pairingSecret []byte, epoch uint64) ([]byte, error) {
	return DeriveRendezvousIDWithApp(pairingSecret, epoch, "")
}

// DeriveRendezvousIDWithApp derives a rendezvous ID with an optional app identifier
// for namespace isolation. Different app identifiers produce different IDs.
func DeriveRendezvousIDWithApp(pairingSecret []byte, epoch uint64, appIdentifier string) ([]byte, error) {
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, epoch)
	info := buildInfo(crypto.HkdfInfoRendezvous, appIdentifier)
	return crypto.HkdfSHA256(pairingSecret, salt, info, 32)
}

// buildInfo appends an app identifier to the base HKDF info string.
// Format: "base-info" or "base-info:{app_id}"
func buildInfo(base []byte, appIdentifier string) []byte {
	if appIdentifier == "" {
		return base
	}
	info := make([]byte, 0, len(base)+1+len(appIdentifier))
	info = append(info, base...)
	info = append(info, ':')
	info = append(info, []byte(appIdentifier)...)
	return info
}

// DerivePairingRendezvousID derives a rendezvous ID for initial pairing bootstrap.
// Used before a pairing secret exists (PIN, QR, link).
func DerivePairingRendezvousID(pakeCredential, nonce []byte) ([]byte, error) {
	return crypto.HkdfSHA256(pakeCredential, nonce, crypto.HkdfInfoPairingRendezvous, 32)
}

// deriveEpochOffset derives a per-secret epoch offset to make epoch boundaries
// unpredictable to observers. Matches Rust's derive_epoch_offset.
func deriveEpochOffset(pairingSecret []byte) (uint64, error) {
	offsetBytes, err := crypto.HkdfSHA256(pairingSecret, nil, crypto.HkdfInfoEpochOffset, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(offsetBytes), nil
}

// ComputeEpoch computes the epoch number for a given pairing secret and timestamp.
// The epoch boundary is offset by a value derived from the pairing secret.
// Wire-compatible with Rust's compute_epoch.
func ComputeEpoch(pairingSecret []byte, rotationInterval time.Duration, timestampSecs uint64) (uint64, error) {
	offset, err := deriveEpochOffset(pairingSecret)
	if err != nil {
		return 0, err
	}
	interval := uint64(rotationInterval.Seconds())
	if interval == 0 {
		return 0, fmt.Errorf("rotation interval must be > 0")
	}
	adjusted := timestampSecs + offset // wrapping add in Go (uint64 overflow wraps)
	return adjusted / interval, nil
}

// CurrentEpoch computes the current epoch number from the system clock.
func CurrentEpoch(pairingSecret []byte, rotationInterval time.Duration) (uint64, error) {
	return ComputeEpoch(pairingSecret, rotationInterval, uint64(time.Now().Unix()))
}

// ActiveRendezvousIDs returns the rendezvous IDs that should be published/queried
// at the given timestamp. Returns both current and adjacent epoch IDs during overlap.
// Wire-compatible with Rust's active_rendezvous_ids_at.
func ActiveRendezvousIDs(pairingSecret []byte, config RotationConfig, timestampSecs uint64) ([][]byte, error) {
	interval := uint64(config.RotationInterval.Seconds())
	if interval == 0 {
		return nil, fmt.Errorf("rotation interval must be > 0")
	}

	offset, err := deriveEpochOffset(pairingSecret)
	if err != nil {
		return nil, err
	}

	adjusted := timestampSecs + offset
	currentEpoch := adjusted / interval
	positionInEpoch := adjusted % interval

	halfOverlap := uint64(config.OverlapWindow.Seconds())/2 + uint64(config.ClockTolerance.Seconds())

	currentID, err := DeriveRendezvousID(pairingSecret, currentEpoch)
	if err != nil {
		return nil, err
	}

	inOverlap := positionInEpoch < halfOverlap || positionInEpoch > interval-halfOverlap

	if inOverlap && currentEpoch > 0 {
		var otherEpoch uint64
		if positionInEpoch < halfOverlap {
			otherEpoch = currentEpoch - 1
		} else {
			otherEpoch = currentEpoch + 1
		}
		otherID, err := DeriveRendezvousID(pairingSecret, otherEpoch)
		if err != nil {
			return nil, err
		}
		return [][]byte{currentID, otherID}, nil
	}

	return [][]byte{currentID}, nil
}

// ActiveRendezvousIDsNow returns the active rendezvous IDs using the system clock.
func ActiveRendezvousIDsNow(pairingSecret []byte, config RotationConfig) ([][]byte, error) {
	return ActiveRendezvousIDs(pairingSecret, config, uint64(time.Now().Unix()))
}
