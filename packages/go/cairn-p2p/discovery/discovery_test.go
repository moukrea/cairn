package discovery

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Rendezvous ID tests ---

func TestDeriveRendezvousIDDeterministic(t *testing.T) {
	secret := []byte("test-pairing-secret")
	id1, err := DeriveRendezvousID(secret, 100)
	require.NoError(t, err)
	id2, err := DeriveRendezvousID(secret, 100)
	require.NoError(t, err)
	assert.Equal(t, id1, id2)
}

func TestDeriveRendezvousIDIs32Bytes(t *testing.T) {
	secret := []byte("test-pairing-secret")
	id, err := DeriveRendezvousID(secret, 0)
	require.NoError(t, err)
	assert.Len(t, id, 32)
}

func TestDeriveRendezvousIDDifferentSecrets(t *testing.T) {
	id1, err := DeriveRendezvousID([]byte("secret-a"), 0)
	require.NoError(t, err)
	id2, err := DeriveRendezvousID([]byte("secret-b"), 0)
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2)
}

func TestCurrentEpochReturnsNonZero(t *testing.T) {
	epoch := CurrentEpoch(DefaultRotationInterval)
	assert.Greater(t, epoch, uint64(0))
}

func TestEpochAtDeterministic(t *testing.T) {
	fixed := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	epoch := EpochAt(fixed, DefaultRotationInterval)
	// 2025-06-15 12:00 UTC = 1750075200 seconds since epoch
	// 1750075200 / 86400 = 20255.0 days
	expected := uint64(fixed.Unix()) / uint64(DefaultRotationInterval.Seconds())
	assert.Equal(t, expected, epoch)
}

func TestEpochBoundaryChangesEpoch(t *testing.T) {
	rotation := 1 * time.Hour // 1h rotation for testing
	t1 := time.Date(2025, 1, 1, 10, 30, 0, 0, time.UTC)
	t2 := time.Date(2025, 1, 1, 11, 30, 0, 0, time.UTC)
	e1 := EpochAt(t1, rotation)
	e2 := EpochAt(t2, rotation)
	assert.NotEqual(t, e1, e2)
}

// --- Overlap tests ---

func TestIsInOverlapAtBoundary(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute

	// Right at the boundary (t = 0 mod rotation)
	boundary := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	assert.True(t, IsInOverlapAt(boundary, rotation, overlap))
}

func TestIsInOverlapJustBeforeBoundary(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute

	// 4 minutes before the boundary (within overlap/2 = 5min)
	justBefore := time.Date(2025, 1, 1, 9, 56, 0, 0, time.UTC)
	assert.True(t, IsInOverlapAt(justBefore, rotation, overlap))
}

func TestIsInOverlapJustAfterBoundary(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute

	// 3 minutes after the boundary (within overlap/2 = 5min)
	justAfter := time.Date(2025, 1, 1, 10, 3, 0, 0, time.UTC)
	assert.True(t, IsInOverlapAt(justAfter, rotation, overlap))
}

func TestNotInOverlapMidEpoch(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute

	// 30 minutes into the epoch — well outside 5min overlap
	mid := time.Date(2025, 1, 1, 10, 30, 0, 0, time.UTC)
	assert.False(t, IsInOverlapAt(mid, rotation, overlap))
}

// --- ActiveEpochs tests ---

func TestActiveEpochsSingleOutsideOverlap(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute
	mid := time.Date(2025, 1, 1, 10, 30, 0, 0, time.UTC) // mid-epoch
	epochs := ActiveEpochs(mid, rotation, overlap)
	assert.Len(t, epochs, 1)
}

func TestActiveEpochsDualDuringOverlap(t *testing.T) {
	rotation := 1 * time.Hour
	overlap := 10 * time.Minute
	boundary := time.Date(2025, 1, 1, 10, 2, 0, 0, time.UTC) // just after boundary
	epochs := ActiveEpochs(boundary, rotation, overlap)
	assert.Len(t, epochs, 2)
	// Current and previous
	assert.Equal(t, epochs[1], epochs[0]-1)
}

// --- DiscoveryBackend interface compliance tests ---

func TestMdnsImplementsBackend(t *testing.T) {
	var _ DiscoveryBackend = (*MdnsDiscovery)(nil)
}

func TestDhtImplementsBackend(t *testing.T) {
	var _ DiscoveryBackend = (*DhtDiscovery)(nil)
}

func TestTrackerImplementsBackend(t *testing.T) {
	var _ DiscoveryBackend = (*TrackerDiscovery)(nil)
}

func TestSignalingImplementsBackend(t *testing.T) {
	var _ DiscoveryBackend = (*SignalingDiscovery)(nil)
}

// --- Backend names ---

func TestBackendNames(t *testing.T) {
	assert.Equal(t, "mdns", NewMdnsDiscovery().Name())
	assert.Equal(t, "dht", NewDhtDiscovery().Name())
	assert.Equal(t, "tracker", NewTrackerDiscovery(nil).Name())
	assert.Equal(t, "signaling", NewSignalingDiscovery("").Name())
}

// --- mDNS tests ---

func TestMdnsPublish(t *testing.T) {
	m := NewMdnsDiscovery()
	err := m.Publish(context.Background(), []byte("rendezvous-id"), []byte("reachability"))
	assert.NoError(t, err)
}

func TestMdnsPublishEmptyIDReturnsError(t *testing.T) {
	m := NewMdnsDiscovery()
	err := m.Publish(context.Background(), nil, []byte("data"))
	assert.Error(t, err)
}

func TestMdnsQueryReturnsNil(t *testing.T) {
	m := NewMdnsDiscovery()
	result, err := m.Query(context.Background(), []byte("rendezvous-id"))
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestMdnsClose(t *testing.T) {
	m := NewMdnsDiscovery()
	assert.NoError(t, m.Close())
}

// --- DHT tests ---

func TestDhtPublish(t *testing.T) {
	d := NewDhtDiscovery()
	err := d.Publish(context.Background(), []byte("key"), []byte("value"))
	assert.NoError(t, err)
}

func TestDhtPublishEmptyIDReturnsError(t *testing.T) {
	d := NewDhtDiscovery()
	err := d.Publish(context.Background(), nil, []byte("value"))
	assert.Error(t, err)
}

func TestDhtClose(t *testing.T) {
	d := NewDhtDiscovery()
	assert.NoError(t, d.Close())
}

// --- Tracker tests ---

func TestTrackerDefaultTrackers(t *testing.T) {
	tr := NewTrackerDiscovery(nil)
	assert.Equal(t, DefaultTrackers, tr.Trackers())
}

func TestTrackerCustomTrackers(t *testing.T) {
	custom := []string{"udp://tracker.example.com:1337/announce"}
	tr := NewTrackerDiscovery(custom)
	assert.Equal(t, custom, tr.Trackers())
}

func TestTrackerPublish(t *testing.T) {
	tr := NewTrackerDiscovery(nil)
	err := tr.Publish(context.Background(), []byte("info-hash"), []byte("data"))
	assert.NoError(t, err)
}

func TestTrackerPublishEmptyIDReturnsError(t *testing.T) {
	tr := NewTrackerDiscovery(nil)
	err := tr.Publish(context.Background(), nil, []byte("data"))
	assert.Error(t, err)
}

func TestTrackerClose(t *testing.T) {
	tr := NewTrackerDiscovery(nil)
	assert.NoError(t, tr.Close())
}

// --- Signaling tests ---

func TestSignalingNoServerConfigured(t *testing.T) {
	s := NewSignalingDiscovery("")
	assert.False(t, s.IsConfigured())
	err := s.Publish(context.Background(), []byte("id"), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no server configured")
}

func TestSignalingWithServer(t *testing.T) {
	s := NewSignalingDiscovery("wss://signal.example.com")
	assert.True(t, s.IsConfigured())
	err := s.Publish(context.Background(), []byte("id"), []byte("data"))
	assert.NoError(t, err)
}

func TestSignalingClose(t *testing.T) {
	s := NewSignalingDiscovery("wss://signal.example.com")
	assert.NoError(t, s.Close())
}

// --- MultiBackendDiscovery tests ---

type mockBackend struct {
	name          string
	publishResult error
	queryResult   [][]byte
	queryErr      error
}

func (m *mockBackend) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	return m.publishResult
}
func (m *mockBackend) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	return m.queryResult, m.queryErr
}
func (m *mockBackend) Name() string   { return m.name }
func (m *mockBackend) Close() error   { return nil }

func TestMultiBackendQueryFirstSuccess(t *testing.T) {
	failing := &mockBackend{name: "failing", queryErr: fmt.Errorf("fail")}
	succeeding := &mockBackend{name: "good", queryResult: [][]byte{[]byte("found")}}

	mbd := NewMultiBackendDiscovery(failing, succeeding)
	result, err := mbd.QueryFirst(context.Background(), []byte("id"))
	require.NoError(t, err)
	assert.Equal(t, "good", result.Backend)
	assert.Len(t, result.Reachability, 1)
}

func TestMultiBackendQueryFirstAllFail(t *testing.T) {
	b1 := &mockBackend{name: "b1", queryErr: fmt.Errorf("fail1")}
	b2 := &mockBackend{name: "b2", queryErr: fmt.Errorf("fail2")}

	mbd := NewMultiBackendDiscovery(b1, b2)
	_, err := mbd.QueryFirst(context.Background(), []byte("id"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all discovery backends failed")
}

func TestMultiBackendNoBackends(t *testing.T) {
	mbd := NewMultiBackendDiscovery()
	_, err := mbd.QueryFirst(context.Background(), []byte("id"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no discovery backends configured")
}

func TestMultiBackendPublishAll(t *testing.T) {
	b1 := &mockBackend{name: "b1"}
	b2 := &mockBackend{name: "b2", publishResult: fmt.Errorf("fail")}

	mbd := NewMultiBackendDiscovery(b1, b2)
	errs := mbd.PublishAll(context.Background(), []byte("id"), []byte("data"))
	assert.Len(t, errs, 1) // only b2 failed
}

func TestMultiBackendAddBackend(t *testing.T) {
	mbd := NewMultiBackendDiscovery()
	assert.Len(t, mbd.Backends(), 0)

	mbd.AddBackend(&mockBackend{name: "new"})
	assert.Len(t, mbd.Backends(), 1)
}

func TestMultiBackendClose(t *testing.T) {
	b1 := &mockBackend{name: "b1"}
	b2 := &mockBackend{name: "b2"}
	mbd := NewMultiBackendDiscovery(b1, b2)
	assert.NoError(t, mbd.Close())
}

// --- RendezvousIDsForPeer test ---

func TestRendezvousIDsForPeerReturnsAtLeastOne(t *testing.T) {
	ids, err := RendezvousIDsForPeer([]byte("secret"), DefaultRotationInterval, DefaultOverlapWindow)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ids), 1)
	assert.LessOrEqual(t, len(ids), 2)
}
