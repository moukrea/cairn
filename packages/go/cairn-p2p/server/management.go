package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// ManagementAPI is a minimal interface for server management.
type ManagementAPI interface {
	PairedPeers() []cairn.PeerID
	QueueDepth(peer cairn.PeerID) int
	RelayStats() RelayStatsInfo
}

// RelayStatsInfo holds relay statistics for the management API.
type RelayStatsInfo struct {
	ActiveRelays  int    `json:"active_relays"`
	TotalRelayed  uint64 `json:"total_relayed"`
	RelayCapacity uint32 `json:"relay_capacity"`
	RelayWilling  bool   `json:"relay_willing"`
}

// ServerConfig holds server-mode configuration deltas from standard node defaults.
type ServerConfig struct {
	StoreForwardEnabled bool
	Headless            bool
	Retention           RetentionConfig
}

// DefaultServerConfig returns server-mode defaults (spec/10 section 10.2).
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		StoreForwardEnabled: true,
		Headless:            true,
		Retention:           DefaultRetentionConfig(),
	}
}

// ---------------------------------------------------------------------------
// Management API HTTP server
// ---------------------------------------------------------------------------

// ManagementConfig holds management API configuration.
type ManagementConfig struct {
	Enabled     bool   `json:"enabled"`
	BindAddress string `json:"bind_address"`
	Port        int    `json:"port"`
	AuthToken   string `json:"auth_token"`
}

// DefaultManagementConfig returns the default management API configuration.
func DefaultManagementConfig() ManagementConfig {
	return ManagementConfig{
		Enabled:     false,
		BindAddress: "127.0.0.1",
		Port:        9090,
		AuthToken:   "",
	}
}

// PeerInfo describes a paired peer for the management API.
type PeerInfo struct {
	PeerID    string  `json:"peer_id"`
	Name      string  `json:"name"`
	Connected bool    `json:"connected"`
	LastSeen  *string `json:"last_seen"`
}

// QueueInfo describes a per-peer store-and-forward queue.
type QueueInfo struct {
	PeerID              string `json:"peer_id"`
	PendingMessages     int    `json:"pending_messages"`
	OldestMessageAge    *int64 `json:"oldest_message_age_secs"`
	TotalBytes          int64  `json:"total_bytes"`
}

// PeerRelayStats holds per-peer relay statistics.
type PeerRelayStats struct {
	PeerID        string `json:"peer_id"`
	BytesRelayed  uint64 `json:"bytes_relayed"`
	ActiveStreams uint32 `json:"active_streams"`
}

// RelayStatsDetail holds relay statistics overview.
type RelayStatsDetail struct {
	ActiveConnections uint32           `json:"active_connections"`
	PerPeer           []PeerRelayStats `json:"per_peer"`
}

// PeersResponse is the JSON response for GET /peers.
type PeersResponse struct {
	Peers []PeerInfo `json:"peers"`
}

// QueuesResponse is the JSON response for GET /queues.
type QueuesResponse struct {
	Queues []QueueInfo `json:"queues"`
}

// RelayStatsResponse is the JSON response for GET /relay/stats.
type RelayStatsResponse struct {
	Relay RelayStatsDetail `json:"relay"`
}

// HealthResponse is the JSON response for GET /health.
type HealthResponse struct {
	Status         string `json:"status"`
	UptimeSecs     int64  `json:"uptime_secs"`
	ConnectedPeers int    `json:"connected_peers"`
	TotalPeers     int    `json:"total_peers"`
}

// ManagementState holds shared state for the management API handlers.
type ManagementState struct {
	mu         sync.RWMutex
	authToken  []byte
	peers      []PeerInfo
	queues     []QueueInfo
	relayStats RelayStatsDetail
	startedAt  time.Time
}

// NewManagementState creates a new management state with the given auth token.
func NewManagementState(authToken string) *ManagementState {
	return &ManagementState{
		authToken:  []byte(authToken),
		peers:      []PeerInfo{},
		queues:     []QueueInfo{},
		relayStats: RelayStatsDetail{PerPeer: []PeerRelayStats{}},
		startedAt:  time.Now(),
	}
}

// SetPeers updates the peers list.
func (s *ManagementState) SetPeers(peers []PeerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = peers
}

// SetQueues updates the queues list.
func (s *ManagementState) SetQueues(queues []QueueInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queues = queues
}

// SetRelayStats updates the relay statistics.
func (s *ManagementState) SetRelayStats(stats RelayStatsDetail) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayStats = stats
}

// ManagementServer is the HTTP server for the management API.
type ManagementServer struct {
	config ManagementConfig
	state  *ManagementState
	server *http.Server
}

// NewManagementServer creates a new management API server.
// Returns an error if the auth token is empty.
func NewManagementServer(config ManagementConfig, state *ManagementState) (*ManagementServer, error) {
	if config.AuthToken == "" {
		return nil, fmt.Errorf("management API auth token is empty")
	}

	// Warn on non-loopback bind address.
	ip := net.ParseIP(config.BindAddress)
	if ip != nil && !ip.IsLoopback() {
		log.Printf("WARNING: Management API exposed on non-loopback interface %s without TLS. This is insecure.", config.BindAddress)
	}

	mux := http.NewServeMux()
	ms := &ManagementServer{
		config: config,
		state:  state,
	}

	mux.HandleFunc("/peers", ms.withAuth(ms.handlePeers))
	mux.HandleFunc("/queues", ms.withAuth(ms.handleQueues))
	mux.HandleFunc("/relay/stats", ms.withAuth(ms.handleRelayStats))
	mux.HandleFunc("/health", ms.withAuth(ms.handleHealth))
	mux.HandleFunc("/pairing/qr", ms.withAuth(ms.handlePairingQR))

	ms.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.BindAddress, config.Port),
		Handler: mux,
	}

	return ms, nil
}

// withAuth wraps a handler with bearer token authentication.
func (ms *ManagementServer) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		provided := []byte(auth[len(prefix):])
		expected := ms.state.authToken

		if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		handler(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

func (ms *ManagementServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	ms.state.mu.RLock()
	peers := ms.state.peers
	ms.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, PeersResponse{Peers: peers})
}

func (ms *ManagementServer) handleQueues(w http.ResponseWriter, r *http.Request) {
	ms.state.mu.RLock()
	queues := ms.state.queues
	ms.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, QueuesResponse{Queues: queues})
}

func (ms *ManagementServer) handleRelayStats(w http.ResponseWriter, r *http.Request) {
	ms.state.mu.RLock()
	stats := ms.state.relayStats
	ms.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, RelayStatsResponse{Relay: stats})
}

func (ms *ManagementServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ms.state.mu.RLock()
	peers := ms.state.peers
	ms.state.mu.RUnlock()

	totalPeers := len(peers)
	connectedPeers := 0
	for _, p := range peers {
		if p.Connected {
			connectedPeers++
		}
	}

	uptimeSecs := int64(time.Since(ms.state.startedAt).Seconds())

	status := "degraded"
	if connectedPeers > 0 {
		status = "healthy"
	}

	writeJSON(w, http.StatusOK, HealthResponse{
		Status:         status,
		UptimeSecs:     uptimeSecs,
		ConnectedPeers: connectedPeers,
		TotalPeers:     totalPeers,
	})
}

func (ms *ManagementServer) handlePairingQR(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"error": "pairing QR generation not yet available (pending headless pairing integration)",
	})
}

// Start begins listening and serving. Blocks until the server stops.
func (ms *ManagementServer) Start() error {
	return ms.server.ListenAndServe()
}

// Close stops the management server.
func (ms *ManagementServer) Close() error {
	return ms.server.Close()
}

// Handler returns the http.Handler for testing purposes.
func (ms *ManagementServer) Handler() http.Handler {
	return ms.server.Handler
}
