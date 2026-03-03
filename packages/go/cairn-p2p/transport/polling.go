package transport

import (
	"context"
	"fmt"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// HTTPSPollingTransport is a stub for HTTPS long-polling (priority 9).
// This is the absolute worst-case transport for environments where all
// other transports are blocked by aggressive proxies/firewalls.
// Traffic is encoded as standard HTTP request/response pairs, which is
// indistinguishable from normal web API traffic.
// This is a Tier 1+ feature requiring a relay server on port 443.
type HTTPSPollingTransport struct {
	relayURL string
}

// NewHTTPSPollingTransport creates an HTTPS long-polling transport stub.
func NewHTTPSPollingTransport(relayURL string) *HTTPSPollingTransport {
	return &HTTPSPollingTransport{relayURL: relayURL}
}

// Type returns TransportHTTPSPolling.
func (t *HTTPSPollingTransport) Type() TransportType {
	return TransportHTTPSPolling
}

// Dial is a stub that always returns an error.
// Full implementation will use net/http for standard HTTP request/response pairs.
func (t *HTTPSPollingTransport) Dial(ctx context.Context, peerID cairn.PeerID, addrs []string) error {
	return fmt.Errorf("transport %s: HTTPS long-polling not yet implemented (requires relay on port 443)", TransportHTTPSPolling)
}

// IsAvailable reports whether a relay URL is configured.
func (t *HTTPSPollingTransport) IsAvailable() bool {
	return t.relayURL != ""
}
