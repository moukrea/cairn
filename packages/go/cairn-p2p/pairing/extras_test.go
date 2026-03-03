package pairing

import (
	"fmt"
	"testing"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SAS tests ---

func TestDeriveSASFromHandshake(t *testing.T) {
	aliceID, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	bobID, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	initiator := crypto.NewNoiseXX(crypto.RoleInitiator, aliceID, nil)
	responder := crypto.NewNoiseXX(crypto.RoleResponder, bobID, nil)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)
	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)
	out3, err := initiator.Step(out2.Message)
	require.NoError(t, err)
	initResult, err := initiator.Result()
	require.NoError(t, err)
	out4, err := responder.Step(out3.Message)
	require.NoError(t, err)

	_ = out4

	saInit, err := DeriveSAS(initResult.TranscriptHash)
	require.NoError(t, err)
	saResp, err := DeriveSAS(out4.Complete.TranscriptHash)
	require.NoError(t, err)

	assert.Equal(t, saInit.Numeric, saResp.Numeric)
	assert.Equal(t, saInit.Emoji, saResp.Emoji)
	assert.Len(t, saInit.Numeric, 6)
	assert.Len(t, saInit.Emoji, 4)
}

// --- Rate limiter tests ---

func TestNewRateLimiterCleanState(t *testing.T) {
	rl := NewPairingRateLimiter()
	assert.Equal(t, uint32(0), rl.TotalFailures())
	assert.False(t, rl.IsInvalidated())
}

func TestFirstAttemptAllowed(t *testing.T) {
	rl := NewPairingRateLimiter()
	delay, err := rl.CheckAttempt("source-1")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), delay)
}

func TestFiveAttemptsAllowed(t *testing.T) {
	rl := NewPairingRateLimiter()
	for i := 0; i < 5; i++ {
		_, err := rl.CheckAttempt("source-1")
		require.NoError(t, err)
	}
}

func TestSixthAttemptRejected(t *testing.T) {
	rl := NewPairingRateLimiter()
	for i := 0; i < 5; i++ {
		_, err := rl.CheckAttempt("source-1")
		require.NoError(t, err)
	}
	_, err := rl.CheckAttempt("source-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit exceeded")
}

func TestDifferentSourcesIndependent(t *testing.T) {
	rl := NewPairingRateLimiter()
	for i := 0; i < 5; i++ {
		_, err := rl.CheckAttempt("source-1")
		require.NoError(t, err)
	}
	_, err := rl.CheckAttempt("source-2")
	assert.NoError(t, err)
}

func TestProgressiveDelayIncreasesWithFailures(t *testing.T) {
	rl := NewPairingRateLimiter()

	delay, err := rl.CheckAttempt("src")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), delay)

	rl.RecordFailure("src")
	delay, err = rl.CheckAttempt("src")
	require.NoError(t, err)
	assert.Equal(t, 2*time.Second, delay)

	rl.RecordFailure("src")
	delay, err = rl.CheckAttempt("src")
	require.NoError(t, err)
	assert.Equal(t, 4*time.Second, delay)
}

func TestRecordSuccessResetsDelay(t *testing.T) {
	rl := NewPairingRateLimiter()

	rl.CheckAttempt("src")
	rl.RecordFailure("src")
	rl.RecordFailure("src")

	rl.RecordSuccess("src")

	delay, err := rl.CheckAttempt("src")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), delay)
}

func TestAutoInvalidationAfterMaxFailures(t *testing.T) {
	rl := NewPairingRateLimiter()

	for i := 0; i < 10; i++ {
		src := fmt.Sprintf("source-%d", i)
		_, err := rl.CheckAttempt(src)
		require.NoError(t, err)
		rl.RecordFailure(src)
	}

	assert.True(t, rl.IsInvalidated())
	assert.Equal(t, uint32(10), rl.TotalFailures())

	_, err := rl.CheckAttempt("source-new")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-invalidated")
}

func TestResetClearsState(t *testing.T) {
	rl := NewPairingRateLimiter()

	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("source-%d", i)
		rl.CheckAttempt(src)
		rl.RecordFailure(src)
	}

	rl.Reset()
	assert.Equal(t, uint32(0), rl.TotalFailures())
	assert.False(t, rl.IsInvalidated())

	_, err := rl.CheckAttempt("source-0")
	assert.NoError(t, err)
}

func TestCustomConfig(t *testing.T) {
	rl := NewPairingRateLimiterWithConfig(3, 10*time.Second, 5, 1*time.Second)

	for i := 0; i < 3; i++ {
		_, err := rl.CheckAttempt("src")
		require.NoError(t, err)
	}
	_, err := rl.CheckAttempt("src")
	assert.Error(t, err)

	rl.Reset()
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("s-%d", i)
		rl.CheckAttempt(src)
		rl.RecordFailure(src)
	}
	assert.True(t, rl.IsInvalidated())
}

func TestTotalFailuresAcrossSources(t *testing.T) {
	rl := NewPairingRateLimiter()
	rl.CheckAttempt("a")
	rl.RecordFailure("a")
	rl.CheckAttempt("b")
	rl.RecordFailure("b")
	rl.CheckAttempt("c")
	rl.RecordFailure("c")
	assert.Equal(t, uint32(3), rl.TotalFailures())
}

func TestSuccessDoesNotReduceTotalFailures(t *testing.T) {
	rl := NewPairingRateLimiter()
	rl.CheckAttempt("src")
	rl.RecordFailure("src")
	assert.Equal(t, uint32(1), rl.TotalFailures())
	rl.RecordSuccess("src")
	assert.Equal(t, uint32(1), rl.TotalFailures())
}

func TestRecordSuccessOnUnknownSourceIsNoop(t *testing.T) {
	rl := NewPairingRateLimiter()
	rl.RecordSuccess("nonexistent")
	assert.Equal(t, uint32(0), rl.TotalFailures())
}

// --- Unpairing tests ---

type mockTrustStore struct {
	peers map[[34]byte]bool
}

func newMockTrustStore() *mockTrustStore {
	return &mockTrustStore{peers: make(map[[34]byte]bool)}
}

func (m *mockTrustStore) IsPaired(peerID [34]byte) bool {
	return m.peers[peerID]
}

func (m *mockTrustStore) RemovePeer(peerID [34]byte) error {
	delete(m.peers, peerID)
	return nil
}

func (m *mockTrustStore) addPeer(peerID [34]byte) {
	m.peers[peerID] = true
}

func TestUnpairRemovesPeer(t *testing.T) {
	store := newMockTrustStore()
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	pid := id.PeerID()
	store.addPeer(pid)

	event, err := Unpair(pid, store)
	require.NoError(t, err)
	assert.Equal(t, pid, event.PeerID)
	assert.False(t, event.Remote)
	assert.False(t, store.IsPaired(pid))
}

func TestUnpairUnknownPeerReturnsError(t *testing.T) {
	store := newMockTrustStore()
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	_, err = Unpair(id.PeerID(), store)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestHandlePairRevokeRemovesPeer(t *testing.T) {
	store := newMockTrustStore()
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	pid := id.PeerID()
	store.addPeer(pid)

	event := HandlePairRevoke(pid, store)
	assert.Equal(t, pid, event.PeerID)
	assert.True(t, event.Remote)
	assert.False(t, store.IsPaired(pid))
}

func TestHandlePairRevokeUnknownPeerSucceeds(t *testing.T) {
	store := newMockTrustStore()
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	event := HandlePairRevoke(id.PeerID(), store)
	assert.True(t, event.Remote)
}

func TestUnpairDoesNotAffectOtherPeers(t *testing.T) {
	store := newMockTrustStore()
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()
	pid1 := id1.PeerID()
	pid2 := id2.PeerID()
	store.addPeer(pid1)
	store.addPeer(pid2)

	Unpair(pid1, store)
	assert.False(t, store.IsPaired(pid1))
	assert.True(t, store.IsPaired(pid2))
}
