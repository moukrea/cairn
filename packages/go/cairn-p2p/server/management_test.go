package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testManagementState() *ManagementState {
	return NewManagementState("test-secret-token")
}

func testManagementServer(t *testing.T) *ManagementServer {
	t.Helper()
	config := ManagementConfig{
		Enabled:     true,
		BindAddress: "127.0.0.1",
		Port:        0,
		AuthToken:   "test-secret-token",
	}
	state := testManagementState()
	ms, err := NewManagementServer(config, state)
	require.NoError(t, err)
	return ms
}

func authRequest(t *testing.T, method, path, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// --- ManagementConfig ---

func TestDefaultManagementConfig(t *testing.T) {
	cfg := DefaultManagementConfig()
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "127.0.0.1", cfg.BindAddress)
	assert.Equal(t, 9090, cfg.Port)
	assert.Empty(t, cfg.AuthToken)
}

// --- Authentication ---

func TestAuthRejectsMissingToken(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	ms.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRejectsWrongToken(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/health", "wrong-token")
	ms.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRejectsMalformedHeader(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Authorization", "test-secret-token") // no "Bearer " prefix
	ms.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthAcceptsCorrectToken(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/health", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Empty token rejection ---

func TestNewManagementServerRejectsEmptyToken(t *testing.T) {
	config := ManagementConfig{
		Enabled:   true,
		AuthToken: "",
	}
	_, err := NewManagementServer(config, testManagementState())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// --- GET /health ---

func TestHealthDegradedNoConnectedPeers(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/health", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp HealthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, 0, resp.ConnectedPeers)
	assert.Equal(t, 0, resp.TotalPeers)
	assert.GreaterOrEqual(t, resp.UptimeSecs, int64(0))
}

func TestHealthHealthyWithConnectedPeer(t *testing.T) {
	ms := testManagementServer(t)
	ms.state.SetPeers([]PeerInfo{
		{PeerID: "peer-1", Name: "alpha", Connected: true, LastSeen: strPtr("2026-03-01T12:00:00Z")},
		{PeerID: "peer-2", Name: "beta", Connected: false, LastSeen: nil},
	})

	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/health", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp HealthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, 1, resp.ConnectedPeers)
	assert.Equal(t, 2, resp.TotalPeers)
}

// --- GET /peers ---

func TestPeersEmpty(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/peers", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp PeersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Peers, 0)
}

func TestPeersWithData(t *testing.T) {
	ms := testManagementServer(t)
	ms.state.SetPeers([]PeerInfo{
		{PeerID: "peer-1", Name: "alpha", Connected: true, LastSeen: strPtr("2026-03-01T12:00:00Z")},
	})

	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/peers", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp PeersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Peers, 1)
	assert.Equal(t, "alpha", resp.Peers[0].Name)
	assert.True(t, resp.Peers[0].Connected)
}

// --- GET /queues ---

func TestQueuesEmpty(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/queues", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp QueuesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Queues, 0)
}

func TestQueuesWithData(t *testing.T) {
	ms := testManagementServer(t)
	age := int64(120)
	ms.state.SetQueues([]QueueInfo{
		{PeerID: "peer-1", PendingMessages: 5, OldestMessageAge: &age, TotalBytes: 1024},
	})

	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/queues", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp QueuesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Queues, 1)
	assert.Equal(t, 5, resp.Queues[0].PendingMessages)
	assert.Equal(t, int64(1024), resp.Queues[0].TotalBytes)
}

// --- GET /relay/stats ---

func TestRelayStatsDefault(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/relay/stats", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp RelayStatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, uint32(0), resp.Relay.ActiveConnections)
	assert.Len(t, resp.Relay.PerPeer, 0)
}

func TestRelayStatsWithData(t *testing.T) {
	ms := testManagementServer(t)
	ms.state.SetRelayStats(RelayStatsDetail{
		ActiveConnections: 3,
		PerPeer: []PeerRelayStats{
			{PeerID: "peer-1", BytesRelayed: 1048576, ActiveStreams: 2},
		},
	})

	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/relay/stats", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)

	var resp RelayStatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, uint32(3), resp.Relay.ActiveConnections)
	assert.Len(t, resp.Relay.PerPeer, 1)
	assert.Equal(t, uint64(1048576), resp.Relay.PerPeer[0].BytesRelayed)
}

// --- GET /pairing/qr ---

func TestPairingQRReturns503(t *testing.T) {
	ms := testManagementServer(t)
	w := httptest.NewRecorder()
	req := authRequest(t, "GET", "/pairing/qr", "test-secret-token")
	ms.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func strPtr(s string) *string {
	return &s
}
