package cairn

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ConnectionState represents the state of a session's connection.
type ConnectionState int

const (
	StateConnected    ConnectionState = iota // Active, healthy connection
	StateUnstable                            // Degradation detected, probing alternatives
	StateDisconnected                        // Transport lost, entering reconnection
	StateReconnecting                        // Actively attempting to re-establish transport
	StateSuspended                           // Reconnection paused (exponential backoff)
	StateReconnected                         // Transport re-established, session resumed
	StateFailed                              // Max retry budget exhausted or session expired
)

// String returns a human-readable name for the connection state.
func (s ConnectionState) String() string {
	switch s {
	case StateConnected:
		return "connected"
	case StateUnstable:
		return "unstable"
	case StateDisconnected:
		return "disconnected"
	case StateReconnecting:
		return "reconnecting"
	case StateSuspended:
		return "suspended"
	case StateReconnected:
		return "reconnected"
	case StateFailed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

const (
	// ReservedChannelForward is the reserved channel name for store-and-forward operations.
	ReservedChannelForward = "__cairn_forward"

	// DefaultSessionExpiry is the default session expiry window (24 hours).
	DefaultSessionExpiry = 24 * time.Hour

	// DefaultHeartbeatInterval is the default heartbeat/keepalive interval.
	DefaultHeartbeatInterval = 30 * time.Second

	// DefaultHeartbeatTimeout is the default heartbeat timeout (3x interval).
	DefaultHeartbeatTimeout = 3 * DefaultHeartbeatInterval

	// DefaultReconnectInitialDelay is the initial reconnection backoff delay.
	DefaultReconnectInitialDelay = 1 * time.Second

	// DefaultReconnectMaxDelay is the maximum reconnection backoff delay.
	DefaultReconnectMaxDelay = 60 * time.Second

	// DefaultReconnectFactor is the exponential backoff multiplier.
	DefaultReconnectFactor = 2.0
)

// validTransitions defines legal state transitions for the session state machine.
var validTransitions = map[ConnectionState][]ConnectionState{
	StateConnected:    {StateUnstable, StateDisconnected},
	StateUnstable:     {StateConnected, StateDisconnected},
	StateDisconnected: {StateReconnecting},
	StateReconnecting: {StateReconnected, StateSuspended},
	StateSuspended:    {StateReconnecting, StateFailed},
	StateReconnected:  {StateConnected},
	StateFailed:       {},
}

// Event is the interface for all session events delivered to the application.
type Event interface {
	eventMarker()
}

// StateChangedEvent is emitted when a session's connection state changes.
type StateChangedEvent struct {
	PeerID PeerID
	State  ConnectionState
}

func (StateChangedEvent) eventMarker() {}

// MessageReceivedEvent is emitted when a data message is received.
type MessageReceivedEvent struct {
	PeerID  PeerID
	Channel string
	Data    []byte
}

func (MessageReceivedEvent) eventMarker() {}

// ChannelOpenedEvent is emitted when a remote peer opens a channel.
type ChannelOpenedEvent struct {
	PeerID      PeerID
	ChannelName string
}

func (ChannelOpenedEvent) eventMarker() {}

// PeerUnpairedEvent is emitted when a remote peer unpairs.
type PeerUnpairedEvent struct {
	PeerID PeerID
}

func (PeerUnpairedEvent) eventMarker() {}

// Session manages a secure communication session with a paired peer.
// It encapsulates the connection state machine, channel multiplexing,
// encryption via the Encryptor interface, and message queuing.
type Session struct {
	mu sync.RWMutex

	sessionID [16]byte // UUID v7
	peerID    PeerID
	state     ConnectionState
	createdAt time.Time
	expiresAt time.Time

	channels       map[string]*Channel
	customHandlers map[uint16]func([]byte)
	events         chan<- Event

	// Reconnection backoff state
	reconnectDelay time.Duration

	// E2E encryption (nil if not yet set up)
	encryptor *Encryptor

	// Message sequencing and queuing
	sequenceCounter atomic.Uint64
	outbox          [][]byte
	messageQueue    [][]byte // Offline message buffer
}

// SessionConfig holds configuration for session behavior.
type SessionConfig struct {
	SessionExpiry          time.Duration
	HeartbeatInterval      time.Duration
	HeartbeatTimeout       time.Duration
	ReconnectInitialDelay  time.Duration
	ReconnectMaxDelay      time.Duration
	ReconnectBackoffFactor float64
}

// DefaultSessionConfig returns a SessionConfig with default values.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		SessionExpiry:          DefaultSessionExpiry,
		HeartbeatInterval:      DefaultHeartbeatInterval,
		HeartbeatTimeout:       DefaultHeartbeatTimeout,
		ReconnectInitialDelay:  DefaultReconnectInitialDelay,
		ReconnectMaxDelay:      DefaultReconnectMaxDelay,
		ReconnectBackoffFactor: DefaultReconnectFactor,
	}
}

// NewSession creates a new session with a unique UUID v7 session ID.
func NewSession(peerID PeerID, config *SessionConfig, events chan<- Event) *Session {
	if config == nil {
		config = DefaultSessionConfig()
	}
	now := time.Now()
	return &Session{
		sessionID:      uuid.Must(uuid.NewV7()),
		peerID:         peerID,
		state:          StateConnected,
		createdAt:      now,
		expiresAt:      now.Add(config.SessionExpiry),
		channels:       make(map[string]*Channel),
		customHandlers: make(map[uint16]func([]byte)),
		events:         events,
		reconnectDelay: config.ReconnectInitialDelay,
	}
}

// SessionID returns the session's unique identifier (UUID v7).
func (s *Session) SessionID() [16]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// PeerID returns the remote peer's ID.
func (s *Session) PeerID() PeerID {
	return s.peerID
}

// State returns the current connection state.
func (s *Session) State() ConnectionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// IsExpired reports whether the session has expired.
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Now().After(s.expiresAt)
}

// SetEncryptor sets the encryption handler for this session.
func (s *Session) SetEncryptor(enc *Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = enc
}

// HasEncryptor reports whether the session has an encryptor set.
func (s *Session) HasEncryptor() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encryptor != nil
}

// Transition attempts to transition the session to a new state.
// Returns an error if the transition is not valid.
// Emits a StateChangedEvent on successful transition.
func (s *Session) Transition(newState ConnectionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	allowed, ok := validTransitions[s.state]
	if !ok {
		return fmt.Errorf("no transitions defined from state %s", s.state)
	}

	valid := false
	for _, a := range allowed {
		if a == newState {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid transition from %s to %s", s.state, newState)
	}

	s.state = newState

	if s.events != nil {
		s.events <- StateChangedEvent{
			PeerID: s.peerID,
			State:  newState,
		}
	}

	return nil
}

// OpenChannel creates a new channel on this session. The channel name
// "__cairn_forward" is reserved and cannot be opened by applications.
// If an encryptor is available, a ChannelInit envelope is added to the outbox.
func (s *Session) OpenChannel(ctx context.Context, name string) (*Channel, error) {
	if name == ReservedChannelForward {
		return nil, fmt.Errorf("channel name %q is reserved for internal use", ReservedChannelForward)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateFailed {
		return nil, fmt.Errorf("session is in failed state")
	}

	if _, exists := s.channels[name]; exists {
		return nil, fmt.Errorf("channel %q already exists", name)
	}

	ch := NewChannel(name)
	s.channels[name] = ch

	// If we have an encryptor, produce a ChannelInit envelope
	if s.encryptor != nil {
		envBytes, err := createChannelInitEnvelope(s.sessionID, name)
		if err == nil {
			s.outbox = append(s.outbox, envBytes)
		}
	}

	return ch, nil
}

// GetChannel returns a channel by name, or nil if not found.
func (s *Session) GetChannel(name string) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channels[name]
}

// Channels returns a list of all open channel names.
func (s *Session) Channels() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.channels))
	for name, ch := range s.channels {
		if ch.IsOpen() {
			names = append(names, name)
		}
	}
	return names
}

// Send sends data to the remote peer on the given channel.
// If an encryptor is set, data is encrypted and wrapped in an envelope.
// If the session is disconnected/reconnecting/suspended, data is queued.
func (s *Session) Send(ctx context.Context, ch *Channel, data []byte) error {
	if ch == nil {
		return fmt.Errorf("channel is nil")
	}
	if !ch.IsOpen() {
		return fmt.Errorf("channel %q is closed", ch.Name())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateFailed {
		return fmt.Errorf("session is in failed state")
	}

	// Queue messages when disconnected
	if s.state == StateDisconnected || s.state == StateReconnecting || s.state == StateSuspended {
		s.messageQueue = append(s.messageQueue, data)
		return nil
	}

	// Encrypt with encryptor if available
	if s.encryptor != nil {
		headerBytes, ciphertext, err := s.encryptor.Encrypt(data)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		// Format: [4-byte header_len BE][header][ciphertext]
		payload := make([]byte, 4+len(headerBytes)+len(ciphertext))
		binary.BigEndian.PutUint32(payload[:4], uint32(len(headerBytes)))
		copy(payload[4:4+len(headerBytes)], headerBytes)
		copy(payload[4+len(headerBytes):], ciphertext)

		seqNum := s.sequenceCounter.Add(1)
		envBytes, err := createDataEnvelope(s.sessionID, seqNum, payload)
		if err != nil {
			return fmt.Errorf("envelope creation: %w", err)
		}
		s.outbox = append(s.outbox, envBytes)
	} else {
		// No encryptor: wrap plaintext in envelope
		seqNum := s.sequenceCounter.Add(1)
		envBytes, err := createDataEnvelope(s.sessionID, seqNum, data)
		if err != nil {
			return fmt.Errorf("envelope creation: %w", err)
		}
		s.outbox = append(s.outbox, envBytes)
	}

	return nil
}

// SendForward sends data through the store-and-forward channel.
func (s *Session) SendForward(ctx context.Context, ch *Channel, data []byte) error {
	return s.Send(ctx, ch, data)
}

// OnCustomMessage registers a handler for application-defined message types
// in the 0xF000-0xFFFF range.
func (s *Session) OnCustomMessage(typeCode uint16, handler func([]byte)) error {
	if typeCode < 0xF000 || typeCode > 0xFFFF {
		return fmt.Errorf("custom message type 0x%04X is outside the application range (0xF000-0xFFFF)", typeCode)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.customHandlers[typeCode] = handler
	return nil
}

// DispatchCustomMessage dispatches an incoming custom message to the registered handler.
// Returns false if no handler is registered for the given type code.
func (s *Session) DispatchCustomMessage(typeCode uint16, data []byte) bool {
	s.mu.RLock()
	handler, ok := s.customHandlers[typeCode]
	s.mu.RUnlock()

	if !ok {
		return false
	}
	handler(data)
	return true
}

// DispatchIncoming handles an incoming binary envelope.
// Decodes the envelope, decrypts data messages if an encryptor is available,
// and dispatches to the appropriate handler or events channel.
func (s *Session) DispatchIncoming(envBytes []byte) error {
	version, msgType, _, _, payload, err := decodeEnvelopeSimple(envBytes)
	if err != nil {
		return fmt.Errorf("envelope decode: %w", err)
	}
	_ = version

	// Custom message handlers (0xF000-0xFFFF)
	if msgType >= 0xF000 && msgType <= 0xFFFF {
		s.DispatchCustomMessage(msgType, payload)
		return nil
	}

	// ChannelInit messages
	if msgType == MsgChannelInit {
		name, err := cborDecodeChannelInit(payload)
		if err != nil {
			return fmt.Errorf("channel init decode: %w", err)
		}
		s.HandleChannelOpened(name)
		return nil
	}

	// Data messages (0x0300)
	if msgType == 0x0300 {
		var plaintext []byte

		s.mu.RLock()
		enc := s.encryptor
		s.mu.RUnlock()

		if enc != nil && len(payload) > 4 {
			headerLen := binary.BigEndian.Uint32(payload[:4])
			if int(headerLen)+4 <= len(payload) {
				headerBytes := payload[4 : 4+headerLen]
				ciphertext := payload[4+headerLen:]

				decrypted, err := enc.Decrypt(headerBytes, ciphertext)
				if err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				plaintext = decrypted
			} else {
				plaintext = payload
			}
		} else {
			plaintext = payload
		}

		if s.events != nil {
			s.events <- MessageReceivedEvent{
				PeerID: s.peerID,
				Data:   plaintext,
			}
		}
		return nil
	}

	return nil
}

// Outbox returns and clears all pending outbound envelopes.
func (s *Session) Outbox() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.outbox
	s.outbox = nil
	return out
}

// DrainMessageQueue returns and clears all queued messages (buffered during disconnection).
func (s *Session) DrainMessageQueue() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	queued := s.messageQueue
	s.messageQueue = nil
	return queued
}

// PersistState serializes the session state for storage via a StorageBackend.
// This captures the session metadata and, if an encryptor with an ExportFunc
// is set, the Double Ratchet state, enabling session resumption after restart.
func (s *Session) PersistState() (SessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sp := sessionPersisted{
		SessionID:  s.sessionID,
		PeerID:     s.peerID,
		State:      int(s.state),
		CreatedAt:  s.createdAt.UnixNano(),
		ExpiresAt:  s.expiresAt.UnixNano(),
		SeqCounter: s.sequenceCounter.Load(),
	}

	// Export encryptor state if available
	if s.encryptor != nil && s.encryptor.ExportFunc != nil {
		ratchetData, err := s.encryptor.ExportFunc()
		if err != nil {
			return SessionState{}, fmt.Errorf("session persist: export ratchet: %w", err)
		}
		sp.RatchetState = ratchetData
	}

	// Collect open channel names
	for name, ch := range s.channels {
		if ch.IsOpen() {
			sp.Channels = append(sp.Channels, name)
		}
	}

	data, err := cborMarshal(sp)
	if err != nil {
		return SessionState{}, fmt.Errorf("session persist: marshal: %w", err)
	}
	return SessionState{Data: data}, nil
}

// RestoreState restores session metadata from a persisted SessionState.
// The caller must separately restore the encryptor (Double Ratchet) using
// the RatchetState bytes from the persisted data and set it via SetEncryptor.
// Returns the raw ratchet state bytes for the caller to reconstruct the
// encryptor outside the session package.
func RestoreSession(state SessionState, events chan<- Event) (*Session, []byte, error) {
	var sp sessionPersisted
	if err := cborUnmarshal(state.Data, &sp); err != nil {
		return nil, nil, fmt.Errorf("session restore: unmarshal: %w", err)
	}

	s := &Session{
		sessionID:      sp.SessionID,
		peerID:         sp.PeerID,
		state:          ConnectionState(sp.State),
		createdAt:      time.Unix(0, sp.CreatedAt),
		expiresAt:      time.Unix(0, sp.ExpiresAt),
		channels:       make(map[string]*Channel),
		customHandlers: make(map[uint16]func([]byte)),
		events:         events,
	}
	s.sequenceCounter.Store(sp.SeqCounter)

	// Re-create channels
	for _, name := range sp.Channels {
		s.channels[name] = NewChannel(name)
	}

	return s, sp.RatchetState, nil
}

// sessionPersisted is the serializable form of a session.
type sessionPersisted struct {
	SessionID    [16]byte `json:"session_id"`
	PeerID       PeerID   `json:"peer_id"`
	State        int      `json:"state"`
	CreatedAt    int64    `json:"created_at"`
	ExpiresAt    int64    `json:"expires_at"`
	SeqCounter   uint64   `json:"seq_counter"`
	RatchetState []byte   `json:"ratchet_state,omitempty"`
	Channels     []string `json:"channels,omitempty"`
}

// cborMarshal is a simple JSON-based serialization (matching our envelope format).
// Using JSON for session persistence since CBOR is used for wire protocol.
func cborMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// cborUnmarshal deserializes from JSON.
func cborUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// PersistToStore saves the session state to the given StorageBackend.
func (s *Session) PersistToStore(store StorageBackend) error {
	state, err := s.PersistState()
	if err != nil {
		return err
	}
	return store.StoreSession(fmt.Sprintf("%x", s.sessionID), state)
}

// RestoreSessionFromStore loads a session from the given StorageBackend.
// Returns the session and the raw ratchet state bytes for encryptor reconstruction.
func RestoreSessionFromStore(store StorageBackend, sessionID string, events chan<- Event) (*Session, []byte, error) {
	state, err := store.LoadSession(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("session restore from store: %w", err)
	}
	return RestoreSession(state, events)
}

// Close closes the session and all its channels.
// Zeroizes encryption state if present.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ch := range s.channels {
		ch.Close()
	}
	s.channels = make(map[string]*Channel)

	if s.encryptor != nil && s.encryptor.CloseFunc != nil {
		s.encryptor.CloseFunc()
	}
	s.encryptor = nil

	s.state = StateFailed
	return nil
}

// HandleChannelOpened handles a remote channel open, adds the channel, and emits an event.
func (s *Session) HandleChannelOpened(name string) *Channel {
	s.mu.Lock()
	ch := NewChannel(name)
	s.channels[name] = ch
	s.mu.Unlock()

	if s.events != nil {
		s.events <- ChannelOpenedEvent{
			PeerID:      s.peerID,
			ChannelName: name,
		}
	}
	return ch
}
