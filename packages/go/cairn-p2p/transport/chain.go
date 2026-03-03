package transport

import (
	"context"
	"fmt"
	"sync"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

// TransportType represents a transport in the 9-level fallback chain.
type TransportType int

const (
	TransportDirectQUIC     TransportType = iota + 1 // Priority 1: Direct UDP (QUIC v1, RFC 9000)
	TransportSTUNHolePunch                            // Priority 2: STUN-assisted UDP hole punch
	TransportDirectTCP                                // Priority 3: Direct TCP
	TransportTURNUDP                                  // Priority 4: TURN relay (UDP)
	TransportTURNTCP                                  // Priority 5: TURN relay (TCP)
	TransportWebSocket                                // Priority 6: WebSocket over TLS (port 443)
	TransportWebTransport                             // Priority 7: WebTransport over HTTP/3 (port 443)
	TransportCircuitRelayV2                           // Priority 8: Circuit Relay v2 (transient)
	TransportHTTPSPolling                             // Priority 9: HTTPS long-polling (port 443)
)

// String returns a human-readable name for the transport type.
func (t TransportType) String() string {
	switch t {
	case TransportDirectQUIC:
		return "direct-quic"
	case TransportSTUNHolePunch:
		return "stun-hole-punch"
	case TransportDirectTCP:
		return "direct-tcp"
	case TransportTURNUDP:
		return "turn-udp"
	case TransportTURNTCP:
		return "turn-tcp"
	case TransportWebSocket:
		return "websocket"
	case TransportWebTransport:
		return "webtransport"
	case TransportCircuitRelayV2:
		return "circuit-relay-v2"
	case TransportHTTPSPolling:
		return "https-polling"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// Tier0Transports are transports available at Tier 0 (no companion infrastructure).
var Tier0Transports = []TransportType{
	TransportDirectQUIC,
	TransportSTUNHolePunch,
	TransportDirectTCP,
}

// AllTransports is the full 9-level transport priority list.
var AllTransports = []TransportType{
	TransportDirectQUIC,
	TransportSTUNHolePunch,
	TransportDirectTCP,
	TransportTURNUDP,
	TransportTURNTCP,
	TransportWebSocket,
	TransportWebTransport,
	TransportCircuitRelayV2,
	TransportHTTPSPolling,
}

const (
	// DefaultTransportTimeout is the default per-transport connection timeout.
	DefaultTransportTimeout = 10 * time.Second
)

// DefaultStunServers are public STUN servers used for NAT type detection at Tier 0.
var DefaultStunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// TransportConfig holds configuration for the transport chain.
type TransportConfig struct {
	// TransportTimeout is the per-transport connection timeout (default 10s).
	TransportTimeout time.Duration

	// StunServers for NAT type detection.
	StunServers []string

	// TurnServers for relay transports (priorities 4-5).
	TurnServers []TurnServer

	// EnabledTransports controls which transports to attempt (default: all).
	EnabledTransports []TransportType
}

// TurnServer holds TURN relay server configuration.
type TurnServer struct {
	URL      string
	Username string
	Password string
}

// DefaultTransportConfig returns a TransportConfig with default values.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		TransportTimeout:  DefaultTransportTimeout,
		StunServers:       DefaultStunServers,
		EnabledTransports: AllTransports,
	}
}

// TransportAttemptResult records the outcome of attempting a single transport.
type TransportAttemptResult struct {
	Transport TransportType
	Err       error
	Duration  time.Duration
}

// TransportProvider is the interface that individual transport implementations must satisfy.
type TransportProvider interface {
	// Type returns the transport type.
	Type() TransportType

	// Dial attempts to connect to a peer via this transport.
	Dial(ctx context.Context, peerID cairn.PeerID, addrs []string) error

	// IsAvailable reports whether this transport can be attempted in the current environment.
	IsAvailable() bool
}

// TransportChain manages the 9-level transport fallback chain with parallel ICE-style probing.
type TransportChain struct {
	mu sync.Mutex

	identity  *crypto.IdentityKeypair
	config    *TransportConfig
	providers map[TransportType]TransportProvider
}

// NewTransportChain creates a new transport chain with the given identity and configuration.
func NewTransportChain(identity *crypto.IdentityKeypair, config *TransportConfig) *TransportChain {
	if config == nil {
		config = DefaultTransportConfig()
	}
	return &TransportChain{
		identity:  identity,
		config:    config,
		providers: make(map[TransportType]TransportProvider),
	}
}

// RegisterProvider registers a transport provider for a specific transport type.
func (tc *TransportChain) RegisterProvider(provider TransportProvider) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.providers[provider.Type()] = provider
}

// Connect attempts to connect to a peer using the fallback chain with parallel probing.
// Returns the transport type that succeeded, or a TransportExhausted error with details.
func (tc *TransportChain) Connect(ctx context.Context, peerID cairn.PeerID, addrs []string) (TransportType, error) {
	tc.mu.Lock()
	enabled := tc.config.EnabledTransports
	timeout := tc.config.TransportTimeout
	providers := make(map[TransportType]TransportProvider)
	for k, v := range tc.providers {
		providers[k] = v
	}
	tc.mu.Unlock()

	type probeResult struct {
		transport TransportType
		err       error
		duration  time.Duration
	}

	resultCh := make(chan probeResult, len(enabled))

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Launch parallel probes for all enabled transports that have providers
	launched := 0
	for _, tt := range enabled {
		provider, ok := providers[tt]
		if !ok || !provider.IsAvailable() {
			resultCh <- probeResult{
				transport: tt,
				err:       fmt.Errorf("transport %s: not available", tt),
			}
			launched++
			continue
		}

		launched++
		go func(p TransportProvider, t TransportType) {
			tCtx, tCancel := context.WithTimeout(probeCtx, timeout)
			defer tCancel()

			start := time.Now()
			err := p.Dial(tCtx, peerID, addrs)
			resultCh <- probeResult{
				transport: t,
				err:       err,
				duration:  time.Since(start),
			}
		}(provider, tt)
	}

	if launched == 0 {
		return 0, cairn.NewCairnError(
			cairn.ErrKindTransportExhausted,
			"all transports exhausted: no transports enabled",
			"Enable at least one transport or deploy companion infrastructure.",
		)
	}

	// Collect results; first success wins (ICE-style parallel probing)
	var failures []TransportAttemptResult
	for i := 0; i < launched; i++ {
		select {
		case r := <-resultCh:
			if r.err == nil {
				cancel() // cancel remaining probes
				return r.transport, nil
			}
			failures = append(failures, TransportAttemptResult{
				Transport: r.transport,
				Err:       r.err,
				Duration:  r.duration,
			})
		case <-ctx.Done():
			return 0, cairn.NewCairnError(
				cairn.ErrKindTransportExhausted,
				fmt.Sprintf("all transports exhausted: context cancelled after %d/%d attempts", len(failures), launched),
				"Check network connectivity and retry.",
			)
		}
	}

	// All transports failed — build detailed error
	return 0, newTransportExhaustedError(failures)
}

// Config returns the current transport configuration.
func (tc *TransportChain) Config() *TransportConfig {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.config
}

// newTransportExhaustedError builds a detailed TransportExhausted error with per-transport details.
func newTransportExhaustedError(failures []TransportAttemptResult) *cairn.CairnError {
	details := ""
	for _, f := range failures {
		details += fmt.Sprintf("  %s: %v (%v)\n", f.Transport, f.Err, f.Duration)
	}

	suggestion := "Check network connectivity and retry."
	hasTier0Failure := false
	for _, f := range failures {
		switch f.Transport {
		case TransportDirectQUIC, TransportSTUNHolePunch, TransportDirectTCP:
			hasTier0Failure = true
		}
	}
	if hasTier0Failure && len(failures) <= 3 {
		suggestion = "Deploy companion TURN relay infrastructure to enable additional transports (priorities 4-9)."
	}

	return cairn.NewCairnError(
		cairn.ErrKindTransportExhausted,
		fmt.Sprintf("all transports exhausted (%d attempted):\n%s", len(failures), details),
		suggestion,
	)
}
