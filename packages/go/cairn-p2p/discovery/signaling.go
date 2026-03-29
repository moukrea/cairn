package discovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// SignalingDiscovery provides WebSocket-based signaling server discovery (Tier 1+).
// Rendezvous ID maps to a topic/room on the signaling server.
// Provides sub-second real-time reachability exchange.
//
// This is a Tier 1+ feature requiring a deployed cairn signaling server.
type SignalingDiscovery struct {
	serverURL string
	authToken string
	mu        sync.Mutex
	local     map[string][]byte // rendezvous hex -> reachability (local cache)
}

// NewSignalingDiscovery creates a signaling discovery backend.
// If serverURL is empty, this backend is a no-op (Tier 0 mode).
func NewSignalingDiscovery(serverURL string) *SignalingDiscovery {
	return &SignalingDiscovery{
		serverURL: serverURL,
		local:     make(map[string][]byte),
	}
}

// NewSignalingDiscoveryWithAuth creates a signaling backend with authentication.
func NewSignalingDiscoveryWithAuth(serverURL, authToken string) *SignalingDiscovery {
	return &SignalingDiscovery{
		serverURL: serverURL,
		authToken: authToken,
		local:     make(map[string][]byte),
	}
}

// Name returns "signaling".
func (s *SignalingDiscovery) Name() string {
	return "signaling"
}

// signalingMessage is the JSON message format for the signaling server.
type signalingMessage struct {
	Type      string   `json:"type"`
	Topic     string   `json:"topic"`
	PeerID    string   `json:"peer_id,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Peers     []struct {
		PeerID    string   `json:"peer_id"`
		Addresses []string `json:"addresses"`
	} `json:"peers,omitempty"`
}

// Publish publishes reachability to the signaling server's rendezvous room.
func (s *SignalingDiscovery) Publish(ctx context.Context, rendezvousID, reachability []byte) error {
	if s.serverURL == "" {
		return fmt.Errorf("signaling: no server configured (Tier 1+ required)")
	}
	if len(rendezvousID) == 0 {
		return fmt.Errorf("signaling: empty rendezvous ID")
	}

	key := hex.EncodeToString(rendezvousID)

	// Always cache locally
	s.mu.Lock()
	s.local[key] = append([]byte(nil), reachability...)
	s.mu.Unlock()

	// Attempt WebSocket announce
	if err := s.wsAnnounce(ctx, key, reachability); err != nil {
		// Non-fatal: local cache still works
		return nil
	}

	return nil
}

// Query queries the signaling server for peers in the rendezvous room.
func (s *SignalingDiscovery) Query(ctx context.Context, rendezvousID []byte) ([][]byte, error) {
	if s.serverURL == "" {
		return nil, fmt.Errorf("signaling: no server configured (Tier 1+ required)")
	}
	if len(rendezvousID) == 0 {
		return nil, fmt.Errorf("signaling: empty rendezvous ID")
	}

	key := hex.EncodeToString(rendezvousID)

	// Check local cache
	s.mu.Lock()
	if data, ok := s.local[key]; ok {
		s.mu.Unlock()
		return [][]byte{data}, nil
	}
	s.mu.Unlock()

	// Attempt WebSocket query
	results, err := s.wsQuery(ctx, key)
	if err != nil {
		return nil, nil // degrade gracefully
	}

	return results, nil
}

// Close disconnects from the signaling server.
func (s *SignalingDiscovery) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.local = make(map[string][]byte)
	return nil
}

// IsConfigured reports whether a signaling server URL is configured.
func (s *SignalingDiscovery) IsConfigured() bool {
	return s.serverURL != ""
}

// wsAnnounce sends an announce message to the signaling server.
func (s *SignalingDiscovery) wsAnnounce(ctx context.Context, topic string, reachability []byte) error {
	wsConfig, err := websocket.NewConfig(s.serverURL, s.serverURL)
	if err != nil {
		return err
	}
	if s.authToken != "" {
		wsConfig.Header = http.Header{
			"Authorization": []string{"Bearer " + s.authToken},
		}
	}

	conn, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := signalingMessage{
		Type:      "announce",
		Topic:     topic,
		Addresses: []string{hex.EncodeToString(reachability)},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

// wsQuery sends a query message to the signaling server and returns peer data.
func (s *SignalingDiscovery) wsQuery(ctx context.Context, topic string) ([][]byte, error) {
	wsConfig, err := websocket.NewConfig(s.serverURL, s.serverURL)
	if err != nil {
		return nil, err
	}
	if s.authToken != "" {
		wsConfig.Header = http.Header{
			"Authorization": []string{"Bearer " + s.authToken},
		}
	}

	conn, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := signalingMessage{
		Type:  "query",
		Topic: topic,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	// Read response
	var resp [4096]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return nil, err
	}

	var respMsg signalingMessage
	if err := json.Unmarshal(resp[:n], &respMsg); err != nil {
		return nil, err
	}

	var results [][]byte
	for _, peer := range respMsg.Peers {
		for _, addr := range peer.Addresses {
			decoded, err := hex.DecodeString(addr)
			if err == nil {
				results = append(results, decoded)
			}
		}
	}

	return results, nil
}
