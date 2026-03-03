package cairn

import (
	"time"
)

// Config holds all configuration for a cairn Node.
type Config struct {
	StunServers          []string
	SignalingServers      []string
	TrackerURLs          []string
	BootstrapNodes       []string
	TurnServers          []TurnServerConfig
	TransportPreferences []int // transport type priorities (1-9)
	ReconnectionPolicy   ReconnectionPolicy
	MeshConfig           MeshConfig
	StorageBackend       StorageBackend
	ServerMode           bool

	// Event channel buffer capacity (default: 256).
	EventBufferSize int
}

// TurnServerConfig holds TURN relay server configuration.
type TurnServerConfig struct {
	URL        string
	Username   string
	Credential string
}

// MeshConfig configures mesh networking behavior.
type MeshConfig struct {
	Enabled       bool   // Mesh routing enabled (default: false)
	MaxHops       uint8  // Maximum relay hops (default: 3)
	RelayWilling  bool   // Willing to relay for other peers (default: false)
	RelayCapacity uint32 // Maximum concurrent relay connections (default: 10)
}

// ReconnectionPolicy holds all configurable timeouts and backoff parameters.
type ReconnectionPolicy struct {
	ConnectTimeout         time.Duration // Initial connection timeout (default: 30s)
	TransportTimeout       time.Duration // Per-transport attempt timeout (default: 10s)
	ReconnectMaxDuration   time.Duration // Total reconnection time before Failed (default: 1h)
	BackoffInitial         time.Duration // Exponential backoff initial delay (default: 1s)
	BackoffMax             time.Duration // Exponential backoff maximum delay (default: 60s)
	BackoffFactor          float64       // Exponential backoff factor (default: 2.0)
	RendezvousPollInterval time.Duration // Rendezvous poll interval (default: 30s)
	SessionExpiry          time.Duration // Session expiry window (default: 24h)
	PairingPayloadExpiry   time.Duration // Pairing payload expiry (default: 5min)
	HeartbeatInterval      time.Duration // Heartbeat send interval (default: 30s)
	HeartbeatTimeout       time.Duration // No-data timeout (default: 90s)
}

// Option is a functional option for configuring a cairn Node.
type Option func(*Config)

// DefaultStunServerList is the default set of public STUN servers.
var DefaultStunServerList = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// DefaultConfig returns Tier 0 zero-config defaults.
func DefaultConfig() *Config {
	return &Config{
		StunServers: DefaultStunServerList,
		ReconnectionPolicy: DefaultReconnectionPolicy(),
		MeshConfig: MeshConfig{
			Enabled:       false,
			MaxHops:       3,
			RelayWilling:  false,
			RelayCapacity: 10,
		},
		EventBufferSize: 256,
	}
}

// DefaultReconnectionPolicy returns the spec-defined default timeouts.
func DefaultReconnectionPolicy() ReconnectionPolicy {
	return ReconnectionPolicy{
		ConnectTimeout:         30 * time.Second,
		TransportTimeout:       10 * time.Second,
		ReconnectMaxDuration:   1 * time.Hour,
		BackoffInitial:         1 * time.Second,
		BackoffMax:             60 * time.Second,
		BackoffFactor:          2.0,
		RendezvousPollInterval: 30 * time.Second,
		SessionExpiry:          24 * time.Hour,
		PairingPayloadExpiry:   5 * time.Minute,
		HeartbeatInterval:      30 * time.Second,
		HeartbeatTimeout:       90 * time.Second,
	}
}

// WithStunServers configures STUN servers for NAT traversal.
func WithStunServers(servers ...string) Option {
	return func(c *Config) {
		c.StunServers = servers
	}
}

// WithTurnServers configures TURN relay servers.
func WithTurnServers(servers ...TurnServerConfig) Option {
	return func(c *Config) {
		c.TurnServers = servers
	}
}

// WithSignalingServers configures WebSocket signaling servers (Tier 1+).
func WithSignalingServers(servers ...string) Option {
	return func(c *Config) {
		c.SignalingServers = servers
	}
}

// WithTransportPreferences configures the transport fallback order.
func WithTransportPreferences(prefs ...int) Option {
	return func(c *Config) {
		c.TransportPreferences = prefs
	}
}

// WithReconnectionPolicy configures reconnection timeouts and backoff.
func WithReconnectionPolicy(policy ReconnectionPolicy) Option {
	return func(c *Config) {
		c.ReconnectionPolicy = policy
	}
}

// WithMeshConfig configures mesh networking.
func WithMeshConfig(mesh MeshConfig) Option {
	return func(c *Config) {
		c.MeshConfig = mesh
	}
}

// WithStorageBackend configures the persistent storage backend.
func WithStorageBackend(backend StorageBackend) Option {
	return func(c *Config) {
		c.StorageBackend = backend
	}
}

// WithTrackerURLs configures BitTorrent tracker URLs for discovery.
func WithTrackerURLs(urls ...string) Option {
	return func(c *Config) {
		c.TrackerURLs = urls
	}
}

// WithBootstrapNodes configures DHT bootstrap nodes.
func WithBootstrapNodes(nodes ...string) Option {
	return func(c *Config) {
		c.BootstrapNodes = nodes
	}
}

// WithEventBufferSize configures the event channel buffer capacity.
func WithEventBufferSize(size int) Option {
	return func(c *Config) {
		c.EventBufferSize = size
	}
}
