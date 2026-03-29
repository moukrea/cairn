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

func TestDeriveRendezvousIDDifferentEpochsDiffer(t *testing.T) {
	secret := []byte("shared-pairing-secret")
	id1, err := DeriveRendezvousID(secret, 1)
	require.NoError(t, err)
	id2, err := DeriveRendezvousID(secret, 2)
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2)
}

func TestDerivePairingRendezvousIDDeterministic(t *testing.T) {
	cred := []byte("pake-credential")
	nonce := []byte("nonce-123")
	id1, err := DerivePairingRendezvousID(cred, nonce)
	require.NoError(t, err)
	id2, err := DerivePairingRendezvousID(cred, nonce)
	require.NoError(t, err)
	assert.Equal(t, id1, id2)
}

func TestDerivePairingRendezvousDiffersFromStandard(t *testing.T) {
	secret := []byte("same-input")
	standard, err := DeriveRendezvousID(secret, 1)
	require.NoError(t, err)
	epochSalt := []byte{0, 0, 0, 0, 0, 0, 0, 1} // epoch 1 as big-endian
	pairing, err := DerivePairingRendezvousID(secret, epochSalt)
	require.NoError(t, err)
	assert.NotEqual(t, standard, pairing)
}

// --- Epoch computation tests ---

func TestComputeEpochDeterministic(t *testing.T) {
	secret := []byte("test-secret")
	interval := time.Hour
	ts := uint64(1700000000)
	e1, err := ComputeEpoch(secret, interval, ts)
	require.NoError(t, err)
	e2, err := ComputeEpoch(secret, interval, ts)
	require.NoError(t, err)
	assert.Equal(t, e1, e2)
}

func TestComputeEpochAdvancesWithTime(t *testing.T) {
	secret := []byte("test-secret")
	interval := time.Hour
	e1, err := ComputeEpoch(secret, interval, 1700000000)
	require.NoError(t, err)
	e2, err := ComputeEpoch(secret, interval, 1700000000+3600)
	require.NoError(t, err)
	assert.Equal(t, e2, e1+1)
}

func TestComputeEpochZeroIntervalRejected(t *testing.T) {
	_, err := ComputeEpoch([]byte("secret"), 0, 1700000000)
	assert.Error(t, err)
}

func TestComputeEpochDifferentSecretsDifferentOffsets(t *testing.T) {
	interval := time.Hour
	ts := uint64(1700000000)
	e1, err := ComputeEpoch([]byte("secret-a"), interval, ts)
	require.NoError(t, err)
	e2, err := ComputeEpoch([]byte("secret-b"), interval, ts)
	require.NoError(t, err)
	assert.NotEqual(t, e1, e2)
}

func TestCurrentEpochReturnsNonZero(t *testing.T) {
	epoch, err := CurrentEpoch([]byte("test-secret"), DefaultRotationInterval)
	require.NoError(t, err)
	assert.Greater(t, epoch, uint64(0))
}

// --- ActiveRendezvousIDs tests ---

func TestActiveRendezvousIDsSingleOutsideOverlap(t *testing.T) {
	secret := []byte("test-secret")
	config := DefaultRotationConfig()

	// Find a timestamp well within the middle of an epoch
	offset, err := deriveEpochOffset(secret)
	require.NoError(t, err)
	interval := uint64(config.RotationInterval.Seconds())
	baseTs := uint64(1700000000)
	adjusted := baseTs + offset
	position := adjusted % interval
	halfOverlap := uint64(config.OverlapWindow.Seconds())/2 + uint64(config.ClockTolerance.Seconds())

	midTs := baseTs + (interval/2 - position)
	adjustedMid := midTs + offset
	posMid := adjustedMid % interval

	if posMid >= halfOverlap && posMid <= interval-halfOverlap {
		ids, err := ActiveRendezvousIDs(secret, config, midTs)
		require.NoError(t, err)
		assert.Len(t, ids, 1)
	}
}

func TestActiveRendezvousIDsDualNearBoundary(t *testing.T) {
	secret := []byte("test-secret")
	config := DefaultRotationConfig()

	offset, err := deriveEpochOffset(secret)
	require.NoError(t, err)
	interval := uint64(config.RotationInterval.Seconds())

	// Find a timestamp right at an epoch boundary
	n := (uint64(1700000000) + offset) / interval + 1
	boundaryAdjusted := n * interval
	boundaryTs := boundaryAdjusted - offset

	// Just after the boundary
	ids, err := ActiveRendezvousIDs(secret, config, boundaryTs+100)
	require.NoError(t, err)
	assert.Len(t, ids, 2, "should have 2 IDs near epoch boundary (just after)")

	// Just before the boundary
	ids, err = ActiveRendezvousIDs(secret, config, boundaryTs-100)
	require.NoError(t, err)
	assert.Len(t, ids, 2, "should have 2 IDs near epoch boundary (just before)")
}

func TestActiveRendezvousIDsIncludesCurrentEpochID(t *testing.T) {
	secret := []byte("test-secret")
	config := DefaultRotationConfig()
	ts := uint64(1700000000)

	ids, err := ActiveRendezvousIDs(secret, config, ts)
	require.NoError(t, err)

	epoch, err := ComputeEpoch(secret, config.RotationInterval, ts)
	require.NoError(t, err)
	expectedID, err := DeriveRendezvousID(secret, epoch)
	require.NoError(t, err)

	found := false
	for _, id := range ids {
		if assert.ObjectsAreEqual(id, expectedID) {
			found = true
			break
		}
	}
	assert.True(t, found, "active IDs must include current epoch's ID")
}

func TestActiveRendezvousIDsNowReturnsAtLeastOne(t *testing.T) {
	ids, err := ActiveRendezvousIDsNow([]byte("secret"), DefaultRotationConfig())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ids), 1)
	assert.LessOrEqual(t, len(ids), 2)
}

// --- Cross-language test vectors ---

func TestDeriveRendezvousIDMatchesRust(t *testing.T) {
	// Test vector generated from Rust/Python HKDF-SHA256 with:
	//   IKM: "shared-pairing-secret", salt: epoch=42 as big-endian u64,
	//   info: "cairn-rendezvous-v1", output: 32 bytes
	secret := []byte("shared-pairing-secret")
	id, err := DeriveRendezvousID(secret, 42)
	require.NoError(t, err)
	expected := "5d7d828909a532f5fa29d721a875413ef1a6e3fb5a34412eb0a317e347224b19"
	assert.Equal(t, expected, fmt.Sprintf("%x", id))
}

func TestDeriveRendezvousIDWithAppIsolation(t *testing.T) {
	secret := []byte("shared-pairing-secret")
	epoch := uint64(42)

	// Default (no app ID) matches the standard derivation
	idDefault, err := DeriveRendezvousIDWithApp(secret, epoch, "")
	require.NoError(t, err)
	idStandard, err := DeriveRendezvousID(secret, epoch)
	require.NoError(t, err)
	assert.Equal(t, idStandard, idDefault)

	// Different app IDs produce different rendezvous IDs
	idJaunt, err := DeriveRendezvousIDWithApp(secret, epoch, "jaunt")
	require.NoError(t, err)
	idChat, err := DeriveRendezvousIDWithApp(secret, epoch, "my-chat-app")
	require.NoError(t, err)

	assert.NotEqual(t, idDefault, idJaunt)
	assert.NotEqual(t, idDefault, idChat)
	assert.NotEqual(t, idJaunt, idChat)
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

func TestDhtQueryLocalHit(t *testing.T) {
	d := NewDhtDiscovery()
	key := []byte("test-key-12345678901234567890ab")
	value := []byte("test-reachability-data")

	err := d.Publish(context.Background(), key, value)
	require.NoError(t, err)

	results, err := d.Query(context.Background(), key)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, value, results[0])
}

func TestDhtQueryLocalMiss(t *testing.T) {
	d := NewDhtDiscovery()
	results, err := d.Query(context.Background(), []byte("unknown-key"))
	assert.NoError(t, err)
	assert.Nil(t, results)
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
func (m *mockBackend) Name() string { return m.name }
func (m *mockBackend) Close() error { return nil }

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
