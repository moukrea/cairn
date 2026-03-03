package transport

import (
	"context"
	"fmt"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// TurnTransport is a stub for TURN relay transports (priorities 4-5).
// TURN (RFC 8656) relays traffic through a server when direct connectivity
// and hole punching fail. This is a Tier 1+ feature requiring companion
// infrastructure deployment.
type TurnTransport struct {
	transportType TransportType // TransportTURNUDP or TransportTURNTCP
	server        TurnServer
}

// NewTurnUDPTransport creates a TURN UDP relay transport stub (priority 4).
func NewTurnUDPTransport(server TurnServer) *TurnTransport {
	return &TurnTransport{
		transportType: TransportTURNUDP,
		server:        server,
	}
}

// NewTurnTCPTransport creates a TURN TCP relay transport stub (priority 5).
func NewTurnTCPTransport(server TurnServer) *TurnTransport {
	return &TurnTransport{
		transportType: TransportTURNTCP,
		server:        server,
	}
}

// Type returns the transport type.
func (t *TurnTransport) Type() TransportType {
	return t.transportType
}

// Dial is a stub that always returns an error.
// Full TURN implementation will use RFC 8656 TURN client.
func (t *TurnTransport) Dial(ctx context.Context, peerID cairn.PeerID, addrs []string) error {
	return fmt.Errorf("transport %s: TURN relay not yet implemented (requires companion infrastructure)", t.transportType)
}

// IsAvailable reports whether TURN is configured with a server.
func (t *TurnTransport) IsAvailable() bool {
	return t.server.URL != ""
}
