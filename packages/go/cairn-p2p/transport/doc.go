// Package transport implements the 9-level transport fallback chain, transport
// migration, and NAT traversal for the cairn P2P connectivity library.
//
// The transport chain attempts transports in priority order with parallel
// ICE-style probing: Direct QUIC -> STUN hole punch -> Direct TCP -> TURN UDP ->
// TURN TCP -> WebSocket -> WebTransport -> Circuit Relay v2 -> HTTPS long-polling.
//
// Tier 0 (no companion infrastructure): priorities 1-3 are available out of the box.
// Tier 1+ (companion infrastructure deployed): priorities 4-9 become available.
package transport
