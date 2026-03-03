package discovery

import (
	"encoding/binary"
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

// DeriveRendezvousID derives a rendezvous ID from a pairing secret and epoch number.
// rendezvousID = HKDF(pairingSecret, "cairn-rendezvous-id-v1", epoch_as_bytes)
func DeriveRendezvousID(pairingSecret []byte, epoch uint64) ([]byte, error) {
	context := make([]byte, 8)
	binary.BigEndian.PutUint64(context, epoch)
	return crypto.HkdfSHA256(pairingSecret, nil, crypto.HkdfInfoRendezvous, 32)
}

// DeriveRendezvousIDWithContext derives a rendezvous ID with an explicit context.
// rendezvousID = HKDF(pairingSecret, "cairn-rendezvous-id-v1", context)
func DeriveRendezvousIDWithContext(pairingSecret, context []byte) ([]byte, error) {
	return crypto.HkdfSHA256(pairingSecret, context, crypto.HkdfInfoRendezvous, 32)
}

// CurrentEpoch computes the current epoch number from the rotation interval.
// epoch = floor(unixTimestamp / rotationInterval)
func CurrentEpoch(rotationInterval time.Duration) uint64 {
	return uint64(time.Now().Unix()) / uint64(rotationInterval.Seconds())
}

// EpochAt computes the epoch number for a given time.
func EpochAt(t time.Time, rotationInterval time.Duration) uint64 {
	return uint64(t.Unix()) / uint64(rotationInterval.Seconds())
}

// IsInOverlap reports whether the current time is within the overlap window
// centered on the epoch boundary.
// During overlap, both current and previous epoch rendezvous IDs should be published/queried.
func IsInOverlap(rotationInterval, overlapWindow time.Duration) bool {
	return IsInOverlapAt(time.Now(), rotationInterval, overlapWindow)
}

// IsInOverlapAt reports whether the given time is within the overlap window.
func IsInOverlapAt(t time.Time, rotationInterval, overlapWindow time.Duration) bool {
	halfOverlap := overlapWindow / 2
	rotSec := int64(rotationInterval.Seconds())
	unix := t.Unix()

	// Distance from nearest epoch boundary
	posInEpoch := unix % rotSec
	distFromBoundary := posInEpoch
	if posInEpoch > rotSec/2 {
		distFromBoundary = rotSec - posInEpoch
	}

	return distFromBoundary < int64(halfOverlap.Seconds())
}

// ActiveEpochs returns the epoch numbers that should be used for publishing/querying
// at the given time. Returns both current and previous during overlap, otherwise just current.
func ActiveEpochs(t time.Time, rotationInterval, overlapWindow time.Duration) []uint64 {
	current := EpochAt(t, rotationInterval)
	if IsInOverlapAt(t, rotationInterval, overlapWindow) && current > 0 {
		return []uint64{current, current - 1}
	}
	return []uint64{current}
}

// RendezvousIDsForPeer returns all rendezvous IDs that should be published/queried
// for a given pairing secret at the current time.
func RendezvousIDsForPeer(pairingSecret []byte, rotationInterval, overlapWindow time.Duration) ([][]byte, error) {
	epochs := ActiveEpochs(time.Now(), rotationInterval, overlapWindow)
	ids := make([][]byte, 0, len(epochs))
	for _, epoch := range epochs {
		id, err := DeriveRendezvousID(pairingSecret, epoch)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
