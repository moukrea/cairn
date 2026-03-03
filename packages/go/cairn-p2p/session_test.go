package cairn

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ConnectionState tests ---

func TestConnectionStateString(t *testing.T) {
	cases := []struct {
		state ConnectionState
		name  string
	}{
		{StateConnected, "connected"},
		{StateUnstable, "unstable"},
		{StateDisconnected, "disconnected"},
		{StateReconnecting, "reconnecting"},
		{StateSuspended, "suspended"},
		{StateReconnected, "reconnected"},
		{StateFailed, "failed"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.name, tc.state.String())
	}
}

func TestConnectionStateStringUnknown(t *testing.T) {
	unknown := ConnectionState(99)
	assert.Contains(t, unknown.String(), "unknown")
}

// --- Session creation tests ---

func TestNewSessionHasConnectedState(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	assert.Equal(t, StateConnected, s.State())
}

func TestNewSessionHasUniqueSessionID(t *testing.T) {
	events := make(chan Event, 10)
	s1 := NewSession(PeerID{}, nil, events)
	s2 := NewSession(PeerID{}, nil, events)
	assert.NotEqual(t, s1.SessionID(), s2.SessionID())
}

func TestNewSessionNotExpired(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	assert.False(t, s.IsExpired())
}

func TestNewSessionWithCustomConfig(t *testing.T) {
	events := make(chan Event, 10)
	cfg := &SessionConfig{
		SessionExpiry:          1 * time.Hour,
		HeartbeatInterval:      10 * time.Second,
		HeartbeatTimeout:       30 * time.Second,
		ReconnectInitialDelay:  500 * time.Millisecond,
		ReconnectMaxDelay:      30 * time.Second,
		ReconnectBackoffFactor: 1.5,
	}
	s := NewSession(PeerID{}, cfg, events)
	assert.Equal(t, StateConnected, s.State())
}

func TestSessionPeerID(t *testing.T) {
	events := make(chan Event, 10)
	pid := PeerID{0x12, 0x20, 0x01, 0x02}
	s := NewSession(pid, nil, events)
	assert.Equal(t, pid, s.PeerID())
}

// --- State machine transition tests ---

func TestValidTransitionConnectedToUnstable(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.Transition(StateUnstable)
	require.NoError(t, err)
	assert.Equal(t, StateUnstable, s.State())
}

func TestValidTransitionConnectedToDisconnected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.Transition(StateDisconnected)
	require.NoError(t, err)
	assert.Equal(t, StateDisconnected, s.State())
}

func TestValidTransitionUnstableToConnected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateUnstable)
	err := s.Transition(StateConnected)
	require.NoError(t, err)
	assert.Equal(t, StateConnected, s.State())
}

func TestValidTransitionDisconnectedToReconnecting(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	err := s.Transition(StateReconnecting)
	require.NoError(t, err)
	assert.Equal(t, StateReconnecting, s.State())
}

func TestValidTransitionReconnectingToSuspended(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	s.Transition(StateReconnecting)
	err := s.Transition(StateSuspended)
	require.NoError(t, err)
	assert.Equal(t, StateSuspended, s.State())
}

func TestValidTransitionReconnectingToReconnected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	s.Transition(StateReconnecting)
	err := s.Transition(StateReconnected)
	require.NoError(t, err)
	assert.Equal(t, StateReconnected, s.State())
}

func TestValidTransitionSuspendedToFailed(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	s.Transition(StateReconnecting)
	s.Transition(StateSuspended)
	err := s.Transition(StateFailed)
	require.NoError(t, err)
	assert.Equal(t, StateFailed, s.State())
}

func TestValidTransitionReconnectedToConnected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	s.Transition(StateReconnecting)
	s.Transition(StateReconnected)
	err := s.Transition(StateConnected)
	require.NoError(t, err)
	assert.Equal(t, StateConnected, s.State())
}

func TestInvalidTransitionConnectedToFailed(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.Transition(StateFailed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")
	assert.Equal(t, StateConnected, s.State())
}

func TestInvalidTransitionConnectedToReconnecting(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.Transition(StateReconnecting)
	assert.Error(t, err)
	assert.Equal(t, StateConnected, s.State())
}

func TestNoTransitionsFromFailed(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Transition(StateDisconnected)
	s.Transition(StateReconnecting)
	s.Transition(StateSuspended)
	s.Transition(StateFailed)

	err := s.Transition(StateConnected)
	assert.Error(t, err)
	assert.Equal(t, StateFailed, s.State())
}

// --- Event emission tests ---

func TestTransitionEmitsStateChangedEvent(t *testing.T) {
	events := make(chan Event, 10)
	pid := PeerID{0x12, 0x20, 0xAA}
	s := NewSession(pid, nil, events)

	err := s.Transition(StateUnstable)
	require.NoError(t, err)

	select {
	case ev := <-events:
		sce, ok := ev.(StateChangedEvent)
		require.True(t, ok)
		assert.Equal(t, pid, sce.PeerID)
		assert.Equal(t, StateUnstable, sce.State)
	default:
		t.Fatal("expected StateChangedEvent but none received")
	}
}

func TestFullReconnectionCycleEmitsEvents(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)

	transitions := []ConnectionState{
		StateDisconnected,
		StateReconnecting,
		StateReconnected,
		StateConnected,
	}

	for _, newState := range transitions {
		require.NoError(t, s.Transition(newState))
	}

	for _, expected := range transitions {
		select {
		case ev := <-events:
			sce, ok := ev.(StateChangedEvent)
			require.True(t, ok)
			assert.Equal(t, expected, sce.State)
		default:
			t.Fatalf("expected event for state %s", expected)
		}
	}
}

// --- Channel tests ---

func TestOpenChannel(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, err := s.OpenChannel(context.Background(), "data")
	require.NoError(t, err)
	assert.Equal(t, "data", ch.Name())
	assert.True(t, ch.IsOpen())
}

func TestOpenChannelReservedNameRejected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	_, err := s.OpenChannel(context.Background(), ReservedChannelForward)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestOpenDuplicateChannelRejected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	_, err := s.OpenChannel(context.Background(), "test")
	require.NoError(t, err)
	_, err = s.OpenChannel(context.Background(), "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestOpenChannelOnFailedSessionRejected(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.Close()
	_, err := s.OpenChannel(context.Background(), "test")
	assert.Error(t, err)
}

func TestGetChannel(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.OpenChannel(context.Background(), "test")
	ch := s.GetChannel("test")
	assert.NotNil(t, ch)
	assert.Equal(t, "test", ch.Name())
}

func TestGetChannelNotFound(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch := s.GetChannel("nonexistent")
	assert.Nil(t, ch)
}

func TestChannels(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	s.OpenChannel(context.Background(), "a")
	s.OpenChannel(context.Background(), "b")
	names := s.Channels()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "a")
	assert.Contains(t, names, "b")
}

func TestChannelClose(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, _ := s.OpenChannel(context.Background(), "test")
	assert.True(t, ch.IsOpen())
	ch.Close()
	assert.False(t, ch.IsOpen())
}

func TestClosedChannelsNotInList(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, _ := s.OpenChannel(context.Background(), "test")
	ch.Close()
	names := s.Channels()
	assert.Empty(t, names)
}

// --- Send tests ---

func TestSendOnOpenChannel(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, _ := s.OpenChannel(context.Background(), "data")
	err := s.Send(context.Background(), ch, []byte("hello"))
	assert.NoError(t, err)
}

func TestSendOnClosedChannelFails(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, _ := s.OpenChannel(context.Background(), "data")
	ch.Close()
	err := s.Send(context.Background(), ch, []byte("hello"))
	assert.Error(t, err)
}

func TestSendOnNilChannelFails(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.Send(context.Background(), nil, []byte("hello"))
	assert.Error(t, err)
}

func TestSendOnFailedSessionFails(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch, _ := s.OpenChannel(context.Background(), "data")
	s.Close()
	err := s.Send(context.Background(), ch, []byte("hello"))
	assert.Error(t, err)
}

// --- Custom message handler tests ---

func TestOnCustomMessageValidRange(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.OnCustomMessage(0xF000, func(data []byte) {})
	assert.NoError(t, err)

	err = s.OnCustomMessage(0xFFFF, func(data []byte) {})
	assert.NoError(t, err)
}

func TestOnCustomMessageInvalidRange(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	err := s.OnCustomMessage(0x0100, func(data []byte) {})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside the application range")
}

func TestDispatchCustomMessage(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)

	var received []byte
	s.OnCustomMessage(0xF001, func(data []byte) {
		received = data
	})

	ok := s.DispatchCustomMessage(0xF001, []byte("test-data"))
	assert.True(t, ok)
	assert.Equal(t, []byte("test-data"), received)
}

func TestDispatchUnregisteredCustomMessage(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ok := s.DispatchCustomMessage(0xF999, []byte("test"))
	assert.False(t, ok)
}

// --- HandleChannelOpened tests ---

func TestHandleChannelOpenedEmitsEvent(t *testing.T) {
	events := make(chan Event, 10)
	pid := PeerID{0x12, 0x20, 0xBB}
	s := NewSession(pid, nil, events)

	ch := s.HandleChannelOpened("remote-data")
	assert.NotNil(t, ch)
	assert.Equal(t, "remote-data", ch.Name())
	assert.True(t, ch.IsOpen())

	select {
	case ev := <-events:
		coe, ok := ev.(ChannelOpenedEvent)
		require.True(t, ok)
		assert.Equal(t, pid, coe.PeerID)
		assert.Equal(t, "remote-data", coe.ChannelName)
	default:
		t.Fatal("expected ChannelOpenedEvent")
	}
}

// --- Session Close tests ---

func TestSessionCloseClosesAllChannels(t *testing.T) {
	events := make(chan Event, 10)
	s := NewSession(PeerID{}, nil, events)
	ch1, _ := s.OpenChannel(context.Background(), "a")
	ch2, _ := s.OpenChannel(context.Background(), "b")
	s.Close()
	assert.False(t, ch1.IsOpen())
	assert.False(t, ch2.IsOpen())
	assert.Equal(t, StateFailed, s.State())
}

// --- Default config tests ---

func TestDefaultSessionConfig(t *testing.T) {
	cfg := DefaultSessionConfig()
	assert.Equal(t, DefaultSessionExpiry, cfg.SessionExpiry)
	assert.Equal(t, DefaultHeartbeatInterval, cfg.HeartbeatInterval)
	assert.Equal(t, DefaultHeartbeatTimeout, cfg.HeartbeatTimeout)
	assert.Equal(t, DefaultReconnectInitialDelay, cfg.ReconnectInitialDelay)
	assert.Equal(t, DefaultReconnectMaxDelay, cfg.ReconnectMaxDelay)
	assert.Equal(t, DefaultReconnectFactor, cfg.ReconnectBackoffFactor)
}
