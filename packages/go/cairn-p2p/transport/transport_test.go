package transport

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Transport type tests ---

func TestTransportTypeString(t *testing.T) {
	cases := []struct {
		tt   TransportType
		name string
	}{
		{TransportDirectQUIC, "direct-quic"},
		{TransportSTUNHolePunch, "stun-hole-punch"},
		{TransportDirectTCP, "direct-tcp"},
		{TransportTURNUDP, "turn-udp"},
		{TransportTURNTCP, "turn-tcp"},
		{TransportWebSocket, "websocket"},
		{TransportWebTransport, "webtransport"},
		{TransportCircuitRelayV2, "circuit-relay-v2"},
		{TransportHTTPSPolling, "https-polling"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.name, tc.tt.String())
	}
}

func TestTransportTypeStringUnknown(t *testing.T) {
	unknown := TransportType(99)
	assert.Contains(t, unknown.String(), "unknown")
}

func TestTransportPriorityOrder(t *testing.T) {
	assert.Equal(t, TransportType(1), TransportDirectQUIC)
	assert.Equal(t, TransportType(2), TransportSTUNHolePunch)
	assert.Equal(t, TransportType(3), TransportDirectTCP)
	assert.Equal(t, TransportType(4), TransportTURNUDP)
	assert.Equal(t, TransportType(5), TransportTURNTCP)
	assert.Equal(t, TransportType(6), TransportWebSocket)
	assert.Equal(t, TransportType(7), TransportWebTransport)
	assert.Equal(t, TransportType(8), TransportCircuitRelayV2)
	assert.Equal(t, TransportType(9), TransportHTTPSPolling)
}

func TestAllTransportsContainsNine(t *testing.T) {
	assert.Len(t, AllTransports, 9)
}

func TestTier0TransportsContainsThree(t *testing.T) {
	assert.Len(t, Tier0Transports, 3)
	assert.Equal(t, TransportDirectQUIC, Tier0Transports[0])
	assert.Equal(t, TransportSTUNHolePunch, Tier0Transports[1])
	assert.Equal(t, TransportDirectTCP, Tier0Transports[2])
}

// --- Config tests ---

func TestDefaultTransportConfig(t *testing.T) {
	cfg := DefaultTransportConfig()
	assert.Equal(t, DefaultTransportTimeout, cfg.TransportTimeout)
	assert.Equal(t, DefaultStunServers, cfg.StunServers)
	assert.Len(t, cfg.EnabledTransports, 9)
}

func TestDefaultStunServers(t *testing.T) {
	assert.Len(t, DefaultStunServers, 3)
	assert.Contains(t, DefaultStunServers, "stun.l.google.com:19302")
	assert.Contains(t, DefaultStunServers, "stun1.l.google.com:19302")
	assert.Contains(t, DefaultStunServers, "stun.cloudflare.com:3478")
}

// --- Mock transport provider ---

type mockProvider struct {
	transportType TransportType
	available     bool
	dialErr       error
	dialDelay     time.Duration
}

func (m *mockProvider) Type() TransportType { return m.transportType }

func (m *mockProvider) Dial(ctx context.Context, peerID cairn.PeerID, addrs []string) error {
	if m.dialDelay > 0 {
		select {
		case <-time.After(m.dialDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.dialErr
}

func (m *mockProvider) IsAvailable() bool { return m.available }

// --- TransportChain tests ---

func TestNewTransportChainWithDefaults(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	tc := NewTransportChain(id, nil)
	assert.NotNil(t, tc)
	assert.Equal(t, DefaultTransportTimeout, tc.Config().TransportTimeout)
}

func TestNewTransportChainWithConfig(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	cfg := &TransportConfig{
		TransportTimeout:  5 * time.Second,
		StunServers:       []string{"stun.example.com:3478"},
		EnabledTransports: Tier0Transports,
	}
	tc := NewTransportChain(id, cfg)
	assert.Equal(t, 5*time.Second, tc.Config().TransportTimeout)
	assert.Len(t, tc.Config().EnabledTransports, 3)
}

func TestRegisterProvider(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	tc := NewTransportChain(id, nil)
	provider := &mockProvider{transportType: TransportDirectQUIC, available: true}
	tc.RegisterProvider(provider)
	assert.Contains(t, tc.providers, TransportDirectQUIC)
}

func TestConnectFirstSuccessWins(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout: 5 * time.Second,
		EnabledTransports: []TransportType{
			TransportDirectQUIC,
			TransportDirectTCP,
		},
	}
	tc := NewTransportChain(id, cfg)

	// QUIC fails, TCP succeeds
	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectQUIC,
		available:     true,
		dialErr:       fmt.Errorf("QUIC unreachable"),
	})
	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectTCP,
		available:     true,
		dialErr:       nil,
	})

	result, err := tc.Connect(context.Background(), cairn.PeerID{}, nil)
	require.NoError(t, err)
	assert.Equal(t, TransportDirectTCP, result)
}

func TestConnectAllFailReturnsExhausted(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout:  1 * time.Second,
		EnabledTransports: []TransportType{TransportDirectQUIC, TransportDirectTCP},
	}
	tc := NewTransportChain(id, cfg)

	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectQUIC,
		available:     true,
		dialErr:       fmt.Errorf("QUIC fail"),
	})
	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectTCP,
		available:     true,
		dialErr:       fmt.Errorf("TCP fail"),
	})

	_, err = tc.Connect(context.Background(), cairn.PeerID{}, nil)
	require.Error(t, err)

	var cairnErr *cairn.CairnError
	require.True(t, errors.As(err, &cairnErr))
	assert.Equal(t, cairn.ErrKindTransportExhausted, cairnErr.Kind)
	assert.Contains(t, cairnErr.Message, "all transports exhausted")
}

func TestConnectNoProvidersReturnsExhausted(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout:  1 * time.Second,
		EnabledTransports: []TransportType{TransportDirectQUIC},
	}
	tc := NewTransportChain(id, cfg)
	// No provider registered for QUIC

	_, err = tc.Connect(context.Background(), cairn.PeerID{}, nil)
	require.Error(t, err)

	var cairnErr *cairn.CairnError
	require.True(t, errors.As(err, &cairnErr))
	assert.Equal(t, cairn.ErrKindTransportExhausted, cairnErr.Kind)
}

func TestConnectNoEnabledTransportsReturnsExhausted(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout:  1 * time.Second,
		EnabledTransports: []TransportType{},
	}
	tc := NewTransportChain(id, cfg)

	_, err = tc.Connect(context.Background(), cairn.PeerID{}, nil)
	require.Error(t, err)

	var cairnErr *cairn.CairnError
	require.True(t, errors.As(err, &cairnErr))
	assert.Contains(t, cairnErr.Message, "no transports enabled")
}

func TestConnectUnavailableProviderSkipped(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout: 5 * time.Second,
		EnabledTransports: []TransportType{
			TransportDirectQUIC,
			TransportDirectTCP,
		},
	}
	tc := NewTransportChain(id, cfg)

	// QUIC not available, TCP succeeds
	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectQUIC,
		available:     false,
	})
	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectTCP,
		available:     true,
		dialErr:       nil,
	})

	result, err := tc.Connect(context.Background(), cairn.PeerID{}, nil)
	require.NoError(t, err)
	assert.Equal(t, TransportDirectTCP, result)
}

func TestConnectContextCancelled(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	cfg := &TransportConfig{
		TransportTimeout: 30 * time.Second,
		EnabledTransports: []TransportType{
			TransportDirectQUIC,
		},
	}
	tc := NewTransportChain(id, cfg)

	tc.RegisterProvider(&mockProvider{
		transportType: TransportDirectQUIC,
		available:     true,
		dialDelay:     10 * time.Second, // slow transport
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = tc.Connect(ctx, cairn.PeerID{}, nil)
	require.Error(t, err)
}

func TestTransportExhaustedErrorIncludesDetails(t *testing.T) {
	failures := []TransportAttemptResult{
		{Transport: TransportDirectQUIC, Err: fmt.Errorf("timeout"), Duration: 10 * time.Second},
		{Transport: TransportDirectTCP, Err: fmt.Errorf("refused"), Duration: 1 * time.Second},
	}
	err := newTransportExhaustedError(failures)
	assert.Contains(t, err.Message, "direct-quic")
	assert.Contains(t, err.Message, "direct-tcp")
	assert.Contains(t, err.Suggestion, "Deploy companion TURN relay")
}

func TestTransportExhaustedSuggestionForFullChain(t *testing.T) {
	failures := make([]TransportAttemptResult, 9)
	for i, tt := range AllTransports {
		failures[i] = TransportAttemptResult{
			Transport: tt,
			Err:       fmt.Errorf("failed"),
			Duration:  1 * time.Second,
		}
	}
	err := newTransportExhaustedError(failures)
	assert.Contains(t, err.Suggestion, "Check network connectivity")
}

// --- NAT type tests ---

func TestAllNatTypes(t *testing.T) {
	types := AllNatTypes()
	assert.Len(t, types, 6)
	assert.Contains(t, types, NatOpen)
	assert.Contains(t, types, NatFullCone)
	assert.Contains(t, types, NatRestrictedCone)
	assert.Contains(t, types, NatPortRestricted)
	assert.Contains(t, types, NatSymmetric)
	assert.Contains(t, types, NatUnknown)
}

func TestDetectNATTypeReturnsValidType(t *testing.T) {
	result := DetectNATType(context.Background(), DefaultStunServers)
	assert.Contains(t, AllNatTypes(), result)
}

func TestDetectNATTypeEmptyServersReturnsUnknown(t *testing.T) {
	result := DetectNATType(context.Background(), nil)
	assert.Equal(t, NatUnknown, result)
}

func TestNatDetectorWithDefaults(t *testing.T) {
	d := NewNatDetector(nil)
	assert.Equal(t, DefaultStunServers, d.StunServers())
	result := d.Detect(context.Background())
	assert.Contains(t, AllNatTypes(), result)
}

func TestNatDetectorCustomServers(t *testing.T) {
	servers := []string{"stun.example.com:3478"}
	d := NewNatDetector(servers)
	assert.Equal(t, servers, d.StunServers())
}

// --- Network monitor tests ---

func TestNoopNetworkMonitor(t *testing.T) {
	m := &NoopNetworkMonitor{}
	assert.NoError(t, m.Start(func(e NetworkEvent) {}))
	assert.NoError(t, m.Stop())
}

func TestNewNetworkMonitorReturnsImpl(t *testing.T) {
	m := NewNetworkMonitor()
	// On Linux, returns NetlinkNetworkMonitor; on other platforms, NoopNetworkMonitor.
	// Both implement NetworkMonitor.
	var _ NetworkMonitor = m
	assert.NotNil(t, m)
}

// --- TURN stub tests ---

func TestTurnUDPTransportType(t *testing.T) {
	turn := NewTurnUDPTransport(TurnServer{URL: "turn:example.com:3478"})
	assert.Equal(t, TransportTURNUDP, turn.Type())
}

func TestTurnTCPTransportType(t *testing.T) {
	turn := NewTurnTCPTransport(TurnServer{URL: "turn:example.com:3478"})
	assert.Equal(t, TransportTURNTCP, turn.Type())
}

func TestTurnIsAvailableWithServer(t *testing.T) {
	turn := NewTurnUDPTransport(TurnServer{URL: "turn:example.com:3478"})
	assert.True(t, turn.IsAvailable())
}

func TestTurnIsNotAvailableWithoutServer(t *testing.T) {
	turn := NewTurnUDPTransport(TurnServer{})
	assert.False(t, turn.IsAvailable())
}

func TestTurnDialReturnsStubError(t *testing.T) {
	turn := NewTurnUDPTransport(TurnServer{URL: "turn:example.com:3478"})
	err := turn.Dial(context.Background(), cairn.PeerID{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

// --- HTTPS polling stub tests ---

func TestHTTPSPollingTransportType(t *testing.T) {
	p := NewHTTPSPollingTransport("https://relay.example.com")
	assert.Equal(t, TransportHTTPSPolling, p.Type())
}

func TestHTTPSPollingIsAvailableWithURL(t *testing.T) {
	p := NewHTTPSPollingTransport("https://relay.example.com")
	assert.True(t, p.IsAvailable())
}

func TestHTTPSPollingIsNotAvailableWithoutURL(t *testing.T) {
	p := NewHTTPSPollingTransport("")
	assert.False(t, p.IsAvailable())
}

func TestHTTPSPollingDialReturnsStubError(t *testing.T) {
	p := NewHTTPSPollingTransport("https://relay.example.com")
	err := p.Dial(context.Background(), cairn.PeerID{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}
