package cairn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Integration tests ---
// These test end-to-end flows using multiple Node instances.

func TestTwoNodesCreateAndHaveUniquePeerIDs(t *testing.T) {
	alice, err := Create()
	require.NoError(t, err)
	defer alice.Close()

	bob, err := Create()
	require.NoError(t, err)
	defer bob.Close()

	assert.NotEqual(t, alice.PeerID(), bob.PeerID())
}

func TestNodeConnectCreatesSessions(t *testing.T) {
	alice, err := Create()
	require.NoError(t, err)
	defer alice.Close()

	bob, err := Create()
	require.NoError(t, err)
	defer bob.Close()

	session, err := alice.Connect(context.Background(), bob.PeerID())
	require.NoError(t, err)
	assert.Equal(t, bob.PeerID(), session.PeerID())
	assert.Equal(t, StateConnected, session.State())
}

func TestReservedChannelRejectedInSession(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0x01}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	_, err = session.OpenChannel(context.Background(), ReservedChannelForward)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestSessionChannelLifecycle(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0x01}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	// Open a channel
	ch, err := session.OpenChannel(context.Background(), "data")
	require.NoError(t, err)
	assert.True(t, ch.IsOpen())
	assert.Equal(t, "data", ch.Name())

	// Send on open channel
	err = session.Send(context.Background(), ch, []byte("hello"))
	assert.NoError(t, err)

	// Close channel
	ch.Close()
	assert.False(t, ch.IsOpen())

	// Send on closed channel fails
	err = session.Send(context.Background(), ch, []byte("goodbye"))
	assert.Error(t, err)
}

func TestSessionStateTransitionCycle(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0x02}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	// Simulate: Connected -> Disconnected -> Reconnecting -> Reconnected -> Connected
	require.NoError(t, session.Transition(StateDisconnected))
	require.NoError(t, session.Transition(StateReconnecting))
	require.NoError(t, session.Transition(StateReconnected))
	require.NoError(t, session.Transition(StateConnected))

	assert.Equal(t, StateConnected, session.State())

	// Verify events were emitted
	events := node.Events()
	collected := 0
	for collected < 4 {
		select {
		case ev := <-events:
			_, ok := ev.(StateChangedEvent)
			assert.True(t, ok)
			collected++
		default:
			t.Fatalf("expected 4 events, got %d", collected)
		}
	}
}

func TestCustomMessageHandlerIntegration(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0x03}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	// Register a custom handler
	var received []byte
	err = session.OnCustomMessage(0xF100, func(data []byte) {
		received = data
	})
	require.NoError(t, err)

	// Dispatch a message to it
	ok := session.DispatchCustomMessage(0xF100, []byte("custom-data"))
	assert.True(t, ok)
	assert.Equal(t, []byte("custom-data"), received)

	// Out of range rejected
	err = session.OnCustomMessage(0x0200, func(data []byte) {})
	assert.Error(t, err)
}

func TestUnpairClosesSessionAndEmitsEvent(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)

	pid := PeerID{0x12, 0x20, 0x04}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	ch, err := session.OpenChannel(context.Background(), "data")
	require.NoError(t, err)
	assert.True(t, ch.IsOpen())

	err = node.Unpair(context.Background(), pid)
	require.NoError(t, err)

	// Session should be closed
	assert.Equal(t, StateFailed, session.State())
	assert.False(t, ch.IsOpen())

	// Event should be emitted
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

func TestServerModeIntegration(t *testing.T) {
	server, err := CreateServer()
	require.NoError(t, err)
	defer server.Close()

	assert.True(t, server.Config().ServerMode)
	assert.True(t, server.Config().MeshConfig.Enabled)
	assert.True(t, server.Config().MeshConfig.RelayWilling)

	// Server can still connect and manage sessions
	pid := PeerID{0x12, 0x20, 0x05}
	session, err := server.Connect(context.Background(), pid)
	require.NoError(t, err)
	assert.Equal(t, StateConnected, session.State())
}

func TestMultipleChannelsOnOneSession(t *testing.T) {
	node, err := Create()
	require.NoError(t, err)
	defer node.Close()

	pid := PeerID{0x12, 0x20, 0x06}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	ch1, err := session.OpenChannel(context.Background(), "data")
	require.NoError(t, err)
	ch2, err := session.OpenChannel(context.Background(), "control")
	require.NoError(t, err)
	ch3, err := session.OpenChannel(context.Background(), "media")
	require.NoError(t, err)

	names := session.Channels()
	assert.Len(t, names, 3)

	// Close one channel; others remain
	ch2.Close()
	names = session.Channels()
	assert.Len(t, names, 2)

	assert.True(t, ch1.IsOpen())
	assert.False(t, ch2.IsOpen())
	assert.True(t, ch3.IsOpen())
}
