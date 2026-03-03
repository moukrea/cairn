package cairn

import (
	"time"
)

// defaultNodeWiring is called after newNode() to set up default handlers.
// It is set by the api package's init() function via RegisterDefaultWiring.
var defaultNodeWiring func(node *Node) error

// RegisterDefaultWiring registers a function to wire default handlers on new nodes.
// Called by the api package's init() to provide automatic crypto/pairing integration.
func RegisterDefaultWiring(fn func(node *Node) error) {
	defaultNodeWiring = fn
}

// Create creates a new cairn Node with the given options.
// With no options, returns a Tier 0 node with zero-config defaults.
// If the api package has been imported, handlers are automatically wired.
func Create(opts ...Option) (*Node, error) {
	config := DefaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return newNode(config)
}

// CreateServer creates a cairn Node configured for server mode.
// Server-mode defaults (spec/10 section 10.2):
//   - Mesh enabled, relay willing, relay capacity 100
//   - Store-and-forward enabled
//   - Session expiry: 7 days
//   - Heartbeat interval: 60s
//   - Reconnect max duration: unlimited (0)
//   - Headless: true
//
// All settings individually overridable via Option functions.
func CreateServer(opts ...Option) (*Node, error) {
	config := DefaultConfig()

	// Apply server-mode defaults
	config.ServerMode = true
	config.MeshConfig = MeshConfig{
		Enabled:       true,
		MaxHops:       3,
		RelayWilling:  true,
		RelayCapacity: 100,
	}
	config.ReconnectionPolicy.SessionExpiry = 7 * 24 * time.Hour
	config.ReconnectionPolicy.HeartbeatInterval = 60 * time.Second
	config.ReconnectionPolicy.HeartbeatTimeout = 3 * 60 * time.Second // 3x interval
	config.ReconnectionPolicy.ReconnectMaxDuration = 0                // unlimited

	// Apply user overrides
	for _, opt := range opts {
		opt(config)
	}

	return newNode(config)
}
