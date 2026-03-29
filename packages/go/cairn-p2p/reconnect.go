package cairn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"sync"
	"time"
)

// BackoffPolicy defines exponential backoff parameters for reconnection.
type BackoffPolicy struct {
	Initial time.Duration // Initial delay (default: 1s)
	Max     time.Duration // Maximum delay (default: 60s)
	Factor  float64       // Backoff multiplier (default: 2.0)
}

// DefaultBackoffPolicy returns backoff parameters matching the spec defaults.
func DefaultBackoffPolicy() *BackoffPolicy {
	return &BackoffPolicy{
		Initial: DefaultReconnectInitialDelay,
		Max:     DefaultReconnectMaxDelay,
		Factor:  DefaultReconnectFactor,
	}
}

// NextDelay computes the delay for the given attempt number (0-indexed).
// delay = min(Initial * Factor^attempt, Max)
func (b *BackoffPolicy) NextDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return b.Initial
	}
	delay := float64(b.Initial) * math.Pow(b.Factor, float64(attempt))
	if delay > float64(b.Max) {
		return b.Max
	}
	return time.Duration(delay)
}

// HeartbeatConfig holds heartbeat/keepalive configuration.
type HeartbeatConfig struct {
	Interval time.Duration // Heartbeat send interval (default: 30s)
	Timeout  time.Duration // No-data timeout -> Disconnected (default: 90s = 3x interval)
}

// DefaultHeartbeatConfig returns heartbeat configuration matching spec defaults.
func DefaultHeartbeatConfig() *HeartbeatConfig {
	return &HeartbeatConfig{
		Interval: DefaultHeartbeatInterval,
		Timeout:  DefaultHeartbeatTimeout,
	}
}

// QueueStrategy determines message ordering during disconnection.
type QueueStrategy int

const (
	// QueueFIFO delivers oldest messages first (default). Queue rejects new messages when full.
	QueueFIFO QueueStrategy = iota
	// QueueLIFO delivers newest messages first, discarding oldest when full.
	QueueLIFO
)

// String returns a human-readable name for the queue strategy.
func (s QueueStrategy) String() string {
	switch s {
	case QueueFIFO:
		return "fifo"
	case QueueLIFO:
		return "lifo"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

const (
	// DefaultQueueMaxSize is the default maximum number of queued messages.
	DefaultQueueMaxSize = 1000

	// DefaultQueueMaxAge is the default maximum age for queued messages.
	DefaultQueueMaxAge = 1 * time.Hour
)

// QueuedMessage is a message buffered during disconnection.
type QueuedMessage struct {
	Channel   string
	Data      []byte
	QueuedAt  time.Time
	SeqNumber uint64
}

// MessageQueue buffers messages during disconnection for retransmission on resumption.
type MessageQueue struct {
	mu sync.Mutex

	enabled  bool
	maxSize  int
	maxAge   time.Duration
	strategy QueueStrategy

	messages  []QueuedMessage
	nextSeqNo uint64
}

// MessageQueueConfig holds configuration for the message queue.
type MessageQueueConfig struct {
	Enabled  bool
	MaxSize  int
	MaxAge   time.Duration
	Strategy QueueStrategy
}

// DefaultMessageQueueConfig returns the default message queue configuration.
func DefaultMessageQueueConfig() *MessageQueueConfig {
	return &MessageQueueConfig{
		Enabled:  true,
		MaxSize:  DefaultQueueMaxSize,
		MaxAge:   DefaultQueueMaxAge,
		Strategy: QueueFIFO,
	}
}

// NewMessageQueue creates a message queue with the given configuration.
func NewMessageQueue(config *MessageQueueConfig) *MessageQueue {
	if config == nil {
		config = DefaultMessageQueueConfig()
	}
	return &MessageQueue{
		enabled:  config.Enabled,
		maxSize:  config.MaxSize,
		maxAge:   config.MaxAge,
		strategy: config.Strategy,
	}
}

// Enqueue adds a message to the queue. Returns an error if the queue is full (FIFO)
// or not enabled.
func (q *MessageQueue) Enqueue(channel string, data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.enabled {
		return fmt.Errorf("message queuing is disabled")
	}

	q.pruneExpired()

	if len(q.messages) >= q.maxSize {
		switch q.strategy {
		case QueueFIFO:
			return fmt.Errorf("message queue full (%d messages)", q.maxSize)
		case QueueLIFO:
			// Discard oldest message to make room
			q.messages = q.messages[1:]
		}
	}

	q.messages = append(q.messages, QueuedMessage{
		Channel:   channel,
		Data:      data,
		QueuedAt:  time.Now(),
		SeqNumber: q.nextSeqNo,
	})
	q.nextSeqNo++
	return nil
}

// Drain returns all queued messages in sequence order and clears the queue.
// Used during session resumption to retransmit buffered messages.
func (q *MessageQueue) Drain() []QueuedMessage {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pruneExpired()

	msgs := q.messages
	q.messages = nil
	return msgs
}

// Discard clears all queued messages without returning them.
// Used on session re-establishment (after expiry) when sequence numbers restart.
func (q *MessageQueue) Discard() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.messages = nil
	q.nextSeqNo = 0
}

// Len returns the number of messages currently in the queue.
func (q *MessageQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.messages)
}

// IsEnabled reports whether the queue is accepting messages.
func (q *MessageQueue) IsEnabled() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.enabled
}

// pruneExpired removes messages older than maxAge. Must be called with lock held.
func (q *MessageQueue) pruneExpired() {
	if q.maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-q.maxAge)
	i := 0
	for i < len(q.messages) && q.messages[i].QueuedAt.Before(cutoff) {
		i++
	}
	if i > 0 {
		q.messages = q.messages[i:]
	}
}

// TimeoutConfig holds all 7 configurable timeouts from the spec.
type TimeoutConfig struct {
	ConnectTimeout       time.Duration // Initial connection timeout (default: 30s)
	TransportTimeout     time.Duration // Per-transport attempt timeout (default: 10s)
	ReconnectMaxDuration time.Duration // Total reconnection time before Failed (default: 1h)
	BackoffInitial       time.Duration // Exponential backoff initial delay (default: 1s)
	BackoffMax           time.Duration // Exponential backoff maximum delay (default: 60s)
	BackoffFactor        float64       // Exponential backoff factor (default: 2.0)
	RendezvousPollInterval time.Duration // Rendezvous poll interval (default: 30s)
	SessionExpiry        time.Duration // Session expiry window (default: 24h)
	PairingPayloadExpiry time.Duration // Pairing payload expiry (default: 5min)
	HeartbeatInterval    time.Duration // Heartbeat send interval (default: 30s)
	HeartbeatTimeout     time.Duration // No-data timeout (default: 90s)
}

// DefaultTimeoutConfig returns the spec-defined timeout defaults.
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
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

// --- Session Resumption HMAC-SHA256 Proof ---

const (
	// resumeNonceSize is the size of the anti-replay nonce in bytes.
	resumeNonceSize = 16

	// resumeMaxTrackedNonces is the maximum number of nonces retained for
	// anti-replay checks. Oldest nonces are evicted when this limit is reached.
	resumeMaxTrackedNonces = 1024

	// resumeHMACInfo is the HKDF info string used to derive the HMAC key
	// from the session key.
	resumeHMACInfo = "cairn-resume-hmac-v1"
)

// ResumeVerifier tracks seen nonces and provides HMAC-SHA256 proof
// generation/verification for session resumption.
type ResumeVerifier struct {
	mu     sync.Mutex
	nonces map[[resumeNonceSize]byte]struct{}
	ring   [][resumeNonceSize]byte // ring buffer for eviction order
	pos    int
}

// NewResumeVerifier creates a ResumeVerifier with capacity for anti-replay tracking.
func NewResumeVerifier() *ResumeVerifier {
	return &ResumeVerifier{
		nonces: make(map[[resumeNonceSize]byte]struct{}, resumeMaxTrackedNonces),
		ring:   make([][resumeNonceSize]byte, resumeMaxTrackedNonces),
	}
}

// GenerateResumeProof generates an HMAC-SHA256 proof and a fresh random nonce.
// The proof binds the nonce to the session key so only holders of that key
// can produce a valid proof.
//
//	proof = HMAC-SHA256(key=sessionKey, message=nonce)
func GenerateResumeProof(sessionKey []byte) (proof, nonce []byte, err error) {
	if len(sessionKey) == 0 {
		return nil, nil, fmt.Errorf("resume proof: empty session key")
	}

	nonce = make([]byte, resumeNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("resume proof: nonce generation: %w", err)
	}

	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(nonce)
	proof = mac.Sum(nil)

	return proof, nonce, nil
}

// VerifyResumeProof verifies an HMAC-SHA256 session resumption proof.
// Returns true only if the proof is valid AND the nonce has not been seen before.
// Seen nonces are recorded to prevent replay attacks.
func (rv *ResumeVerifier) VerifyResumeProof(sessionKey, proof, nonce []byte) bool {
	if len(sessionKey) == 0 || len(proof) == 0 || len(nonce) != resumeNonceSize {
		return false
	}

	// Verify HMAC
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	if !hmac.Equal(proof, expected) {
		return false
	}

	// Anti-replay: reject duplicate nonces
	var nonceKey [resumeNonceSize]byte
	copy(nonceKey[:], nonce)

	rv.mu.Lock()
	defer rv.mu.Unlock()

	if _, seen := rv.nonces[nonceKey]; seen {
		return false
	}

	// Evict the oldest nonce if at capacity
	if len(rv.nonces) >= resumeMaxTrackedNonces {
		evict := rv.ring[rv.pos]
		delete(rv.nonces, evict)
	}

	rv.ring[rv.pos] = nonceKey
	rv.nonces[nonceKey] = struct{}{}
	rv.pos = (rv.pos + 1) % resumeMaxTrackedNonces

	return true
}
