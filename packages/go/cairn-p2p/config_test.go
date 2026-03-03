package cairn

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- DefaultConfig tests ---

func TestDefaultConfigHasStunServers(t *testing.T) {
	cfg := DefaultConfig()
	assert.Len(t, cfg.StunServers, 3)
	assert.Contains(t, cfg.StunServers, "stun.l.google.com:19302")
}

func TestDefaultConfigMeshDisabled(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.MeshConfig.Enabled)
}

func TestDefaultConfigEventBufferSize(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 256, cfg.EventBufferSize)
}

// --- DefaultReconnectionPolicy tests ---

func TestDefaultReconnectionPolicy(t *testing.T) {
	rp := DefaultReconnectionPolicy()
	assert.Equal(t, 30*time.Second, rp.ConnectTimeout)
	assert.Equal(t, 10*time.Second, rp.TransportTimeout)
	assert.Equal(t, 1*time.Hour, rp.ReconnectMaxDuration)
	assert.Equal(t, 1*time.Second, rp.BackoffInitial)
	assert.Equal(t, 60*time.Second, rp.BackoffMax)
	assert.Equal(t, 2.0, rp.BackoffFactor)
	assert.Equal(t, 30*time.Second, rp.RendezvousPollInterval)
	assert.Equal(t, 24*time.Hour, rp.SessionExpiry)
	assert.Equal(t, 5*time.Minute, rp.PairingPayloadExpiry)
	assert.Equal(t, 30*time.Second, rp.HeartbeatInterval)
	assert.Equal(t, 90*time.Second, rp.HeartbeatTimeout)
}

// --- Functional options tests ---

func TestWithStunServers(t *testing.T) {
	cfg := DefaultConfig()
	WithStunServers("custom:3478")(cfg)
	assert.Equal(t, []string{"custom:3478"}, cfg.StunServers)
}

func TestWithTurnServers(t *testing.T) {
	cfg := DefaultConfig()
	WithTurnServers(TurnServerConfig{URL: "turn:example.com:3478"})(cfg)
	assert.Len(t, cfg.TurnServers, 1)
}

func TestWithSignalingServers(t *testing.T) {
	cfg := DefaultConfig()
	WithSignalingServers("wss://signal.example.com")(cfg)
	assert.Equal(t, []string{"wss://signal.example.com"}, cfg.SignalingServers)
}

func TestWithMeshConfig(t *testing.T) {
	cfg := DefaultConfig()
	WithMeshConfig(MeshConfig{Enabled: true, MaxHops: 5})(cfg)
	assert.True(t, cfg.MeshConfig.Enabled)
	assert.Equal(t, uint8(5), cfg.MeshConfig.MaxHops)
}

func TestWithReconnectionPolicy(t *testing.T) {
	cfg := DefaultConfig()
	custom := ReconnectionPolicy{ConnectTimeout: 5 * time.Second}
	WithReconnectionPolicy(custom)(cfg)
	assert.Equal(t, 5*time.Second, cfg.ReconnectionPolicy.ConnectTimeout)
}

func TestWithEventBufferSize(t *testing.T) {
	cfg := DefaultConfig()
	WithEventBufferSize(512)(cfg)
	assert.Equal(t, 512, cfg.EventBufferSize)
}

func TestWithTrackerURLs(t *testing.T) {
	cfg := DefaultConfig()
	WithTrackerURLs("http://tracker.example.com/announce")(cfg)
	assert.Len(t, cfg.TrackerURLs, 1)
}

func TestWithBootstrapNodes(t *testing.T) {
	cfg := DefaultConfig()
	WithBootstrapNodes("/dnsaddr/bootstrap.example.com")(cfg)
	assert.Len(t, cfg.BootstrapNodes, 1)
}

// --- Create tests ---

func TestCreateReturnsNode(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	assert.NotNil(t, node)
	defer node.Close()
}

func TestCreateWithOptions(t *testing.T) {
	node, err := Create(
		WithStunServers("custom:3478"),
		WithEventBufferSize(128),
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"custom:3478"}, node.Config().StunServers)
	assert.Equal(t, 128, node.Config().EventBufferSize)
	defer node.Close()
}

func TestCreateNodeHasUniquePeerID(t *testing.T) {
	n1, err := Create()
	require.NoError(t, err)
	defer n1.Close()

	n2, err := Create()
	require.NoError(t, err)
	defer n2.Close()

	assert.NotEqual(t, n1.PeerID(), n2.PeerID())
}

// --- CreateServer tests ---

func TestCreateServerDefaults(t *testing.T) {
	node, err := CreateServer()
	require.NoError(t, err)
	defer node.Close()

	assert.True(t, node.Config().ServerMode)
	assert.True(t, node.Config().MeshConfig.Enabled)
	assert.True(t, node.Config().MeshConfig.RelayWilling)
	assert.Equal(t, uint32(100), node.Config().MeshConfig.RelayCapacity)
	assert.Equal(t, 7*24*time.Hour, node.Config().ReconnectionPolicy.SessionExpiry)
	assert.Equal(t, 60*time.Second, node.Config().ReconnectionPolicy.HeartbeatInterval)
	assert.Equal(t, time.Duration(0), node.Config().ReconnectionPolicy.ReconnectMaxDuration)
}

func TestCreateServerWithOverrides(t *testing.T) {
	node, err := CreateServer(
		WithMeshConfig(MeshConfig{Enabled: true, MaxHops: 5, RelayWilling: true, RelayCapacity: 50}),
	)
	require.NoError(t, err)
	defer node.Close()

	assert.Equal(t, uint32(50), node.Config().MeshConfig.RelayCapacity)
	assert.Equal(t, uint8(5), node.Config().MeshConfig.MaxHops)
}

// --- Node tests ---

func TestNodeEventsChannel(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	ch := node.Events()
	assert.NotNil(t, ch)
}

func TestNodeConnect(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0xAA}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)
	assert.Equal(t, pid, session.PeerID())
	assert.Equal(t, StateConnected, session.State())
}

func TestNodeConnectReusesExistingSession(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0xBB}
	s1, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)
	s2, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)
	assert.Equal(t, s1.SessionID(), s2.SessionID())
}

func TestNodeUnpairEmitsEvent(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)

	pid := PeerID{0x12, 0x20, 0xCC}
	node.Connect(context.Background(), pid)

	err = node.Unpair(context.Background(), pid)
	require.NoError(t, err)

	select {
	case ev := <-node.Events():
		upe, ok := ev.(PeerUnpairedEvent)
		require.True(t, ok)
		assert.Equal(t, pid, upe.PeerID)
	default:
		t.Fatal("expected PeerUnpairedEvent")
	}

	node.Close()
}

func TestNodeNetworkInfo(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	info := node.NetworkInfo()
	assert.Equal(t, node.PeerID(), info.PeerID)
	assert.Equal(t, "unknown", info.NatType)
}

func TestNodeClose(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)

	pid := PeerID{0x12, 0x20, 0xDD}
	session, _ := node.Connect(context.Background(), pid)

	err = node.Close()
	require.NoError(t, err)

	// Session should be failed after close
	assert.Equal(t, StateFailed, session.State())
}

// --- Pairing method stub tests ---

func TestPairingMethodStubsReturnErrors(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	ctx := context.Background()

	_, err = node.PairGenerateQR(ctx)
	assert.Error(t, err)

	_, err = node.PairScanQR(ctx, nil)
	assert.Error(t, err)

	_, err = node.PairGeneratePin(ctx)
	assert.Error(t, err)

	_, err = node.PairEnterPin(ctx, "test")
	assert.Error(t, err)

	_, err = node.PairGenerateLink(ctx)
	assert.Error(t, err)

	_, err = node.PairFromLink(ctx, "cairn://pair?test")
	assert.Error(t, err)

	_, err = node.Pair(ctx, PeerID{}, PairingQR)
	assert.Error(t, err)
}
