package pairing

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

// HKDF info constants for pairing session key derivation.
var (
	hkdfInfoPairingSession = []byte("cairn-pairing-session-key-v1")
	hkdfInfoKeyConfirm     = []byte("cairn-pairing-key-confirm-v1")
)

// PairingState represents the pairing session state.
type PairingState int

const (
	StateIdle PairingState = iota
	StateAwaitingPakeExchange
	StateAwaitingVerification
	StateAwaitingConfirmation
	StateCompleted
	StateFailed
)

func (s PairingState) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateAwaitingPakeExchange:
		return "AwaitingPakeExchange"
	case StateAwaitingVerification:
		return "AwaitingVerification"
	case StateAwaitingConfirmation:
		return "AwaitingConfirmation"
	case StateCompleted:
		return "Completed"
	case StateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// PairingRole identifies initiator or responder.
type PairingRole int

const (
	RoleInitiator PairingRole = iota
	RoleResponder
)

// PairingFlowType identifies the pairing flow type.
type PairingFlowType int

const (
	FlowInitiation PairingFlowType = iota
	FlowStandard
)

// PairingSession drives the pairing protocol state machine.
type PairingSession struct {
	state    PairingState
	role     PairingRole
	flowType PairingFlowType

	localIdentity *crypto.IdentityKeypair
	localNonce    []byte
	remoteNonce   []byte
	sharedKey     []byte

	// SPAKE2 state for initiation flow
	spake2State    *crypto.Spake2
	spake2Outbound []byte

	createdAt time.Time
	timeout   time.Duration

	failReason string
}

// NewInitiator creates a new initiator pairing session with SPAKE2.
// Returns the session and the SPAKE2 outbound message to include in PairRequest.
func NewInitiator(identity *crypto.IdentityKeypair, password []byte, timeout time.Duration) (*PairingSession, []byte, error) {
	nonce := generateNonce()

	spake2, outbound, err := crypto.NewSpake2(crypto.RoleInitiator, password)
	if err != nil {
		return nil, nil, fmt.Errorf("SPAKE2 init failed: %w", err)
	}

	session := &PairingSession{
		state:       StateAwaitingPakeExchange,
		role:        RoleInitiator,
		flowType:    FlowInitiation,
		localIdentity: identity,
		localNonce:  nonce,
		spake2State: spake2,
		createdAt:   time.Now(),
		timeout:     timeout,
	}

	return session, outbound, nil
}

// NewResponder creates a new responder pairing session with SPAKE2.
func NewResponder(identity *crypto.IdentityKeypair, password []byte, timeout time.Duration) (*PairingSession, error) {
	nonce := generateNonce()

	spake2, outbound, err := crypto.NewSpake2(crypto.RoleResponder, password)
	if err != nil {
		return nil, fmt.Errorf("SPAKE2 init failed: %w", err)
	}

	return &PairingSession{
		state:          StateIdle,
		role:           RoleResponder,
		flowType:       FlowInitiation,
		localIdentity:  identity,
		localNonce:     nonce,
		spake2State:    spake2,
		spake2Outbound: outbound,
		createdAt:      time.Now(),
		timeout:        timeout,
	}, nil
}

// NewStandardInitiator creates an initiator session for the standard flow (no SPAKE2).
func NewStandardInitiator(identity *crypto.IdentityKeypair, timeout time.Duration) *PairingSession {
	return &PairingSession{
		state:         StateAwaitingVerification,
		role:          RoleInitiator,
		flowType:      FlowStandard,
		localIdentity: identity,
		localNonce:    generateNonce(),
		createdAt:     time.Now(),
		timeout:       timeout,
	}
}

// NewStandardResponder creates a responder session for the standard flow (no SPAKE2).
func NewStandardResponder(identity *crypto.IdentityKeypair, timeout time.Duration) *PairingSession {
	return &PairingSession{
		state:         StateIdle,
		role:          RoleResponder,
		flowType:      FlowStandard,
		localIdentity: identity,
		localNonce:    generateNonce(),
		createdAt:     time.Now(),
		timeout:       timeout,
	}
}

// State returns the current session state.
func (s *PairingSession) State() PairingState { return s.state }

// Role returns the session role.
func (s *PairingSession) Role() PairingRole { return s.role }

// FlowType returns the flow type.
func (s *PairingSession) FlowType() PairingFlowType { return s.flowType }

// IsExpired reports whether the session has timed out.
func (s *PairingSession) IsExpired() bool {
	return time.Since(s.createdAt) > s.timeout
}

// SharedKey returns the shared key if the session has completed.
func (s *PairingSession) SharedKey() []byte {
	if s.state == StateCompleted {
		return s.sharedKey
	}
	return nil
}

// SetSharedKey sets the shared key (used in standard flow from Noise XX).
func (s *PairingSession) SetSharedKey(key []byte) {
	s.sharedKey = key
}

// Nonce returns the local nonce.
func (s *PairingSession) Nonce() []byte { return s.localNonce }

// SetRemoteNonce sets the remote peer's nonce.
func (s *PairingSession) SetRemoteNonce(nonce []byte) { s.remoteNonce = nonce }

// HandlePakeMessage processes a SPAKE2 message from the peer.
// For the initiator: the peer's challenge message -> produces the initiator's key confirmation.
// For the responder: the peer's request PAKE message -> produces the outbound challenge.
func (s *PairingSession) HandlePakeMessage(peerMessage []byte) (outbound []byte, err error) {
	if s.IsExpired() {
		s.state = StateFailed
		s.failReason = "session expired"
		return nil, fmt.Errorf("pairing session expired")
	}

	if s.spake2State == nil {
		return nil, fmt.Errorf("no SPAKE2 state")
	}

	if s.role == RoleResponder && s.state == StateIdle {
		// Finish SPAKE2 with the initiator's message
		rawKey, err := s.spake2State.Finish(peerMessage)
		if err != nil {
			s.state = StateFailed
			s.failReason = "PAKE failure"
			return nil, fmt.Errorf("SPAKE2 finish failed: %w", err)
		}
		sessionKey, err := s.deriveSessionKey(rawKey[:])
		if err != nil {
			return nil, err
		}
		s.sharedKey = sessionKey
		s.spake2State = nil
		s.state = StateAwaitingVerification

		// Return our stored outbound
		outbound = s.spake2Outbound
		s.spake2Outbound = nil
		return outbound, nil
	}

	if s.role == RoleInitiator && s.state == StateAwaitingPakeExchange {
		// Finish SPAKE2 with the responder's message
		rawKey, err := s.spake2State.Finish(peerMessage)
		if err != nil {
			s.state = StateFailed
			s.failReason = "PAKE failure"
			return nil, fmt.Errorf("SPAKE2 finish failed: %w", err)
		}
		sessionKey, err := s.deriveSessionKey(rawKey[:])
		if err != nil {
			return nil, err
		}
		s.sharedKey = sessionKey
		s.spake2State = nil
		s.state = StateAwaitingVerification
		return nil, nil
	}

	return nil, fmt.Errorf("invalid state for PAKE message: %s", s.state)
}

// SendKeyConfirmation produces a key confirmation value and advances to AwaitingConfirmation.
func (s *PairingSession) SendKeyConfirmation() ([]byte, error) {
	if s.state != StateAwaitingVerification {
		return nil, fmt.Errorf("invalid state for key confirmation: expected AwaitingVerification, got %s", s.state)
	}

	var label string
	if s.role == RoleInitiator {
		label = "initiator"
	} else {
		label = "responder"
	}

	confirmation, err := s.computeKeyConfirmation([]byte(label))
	if err != nil {
		return nil, err
	}
	s.state = StateAwaitingConfirmation
	return confirmation, nil
}

// VerifyKeyConfirmation verifies a peer's key confirmation and completes the session.
func (s *PairingSession) VerifyKeyConfirmation(peerConfirmation []byte) error {
	if s.state != StateAwaitingConfirmation {
		return fmt.Errorf("invalid state for verification: expected AwaitingConfirmation, got %s", s.state)
	}

	var label string
	if s.role == RoleInitiator {
		label = "responder"
	} else {
		label = "initiator"
	}

	expected, err := s.computeKeyConfirmation([]byte(label))
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(peerConfirmation, expected) != 1 {
		s.state = StateFailed
		s.failReason = "key confirmation mismatch"
		return fmt.Errorf("key confirmation verification failed")
	}

	s.state = StateCompleted
	return nil
}

// HandleStandardRequest advances a standard responder from Idle to AwaitingVerification.
func (s *PairingSession) HandleStandardRequest(remoteNonce []byte) error {
	if s.role != RoleResponder || s.state != StateIdle {
		return fmt.Errorf("invalid state for standard request: expected Responder+Idle")
	}
	if s.flowType != FlowStandard {
		return fmt.Errorf("HandleStandardRequest only for standard flow")
	}
	s.remoteNonce = remoteNonce
	s.state = StateAwaitingVerification
	return nil
}

// Reject moves the session to Failed.
func (s *PairingSession) Reject(reason string) {
	s.state = StateFailed
	s.failReason = reason
}

// FailReason returns the failure reason, if any.
func (s *PairingSession) FailReason() string { return s.failReason }

// --- Internal key derivation ---

func (s *PairingSession) deriveSessionKey(rawKey []byte) ([]byte, error) {
	// salt = initiator_nonce || responder_nonce
	var salt []byte
	if s.role == RoleInitiator {
		salt = append(salt, s.localNonce...)
		if s.remoteNonce != nil {
			salt = append(salt, s.remoteNonce...)
		}
	} else {
		if s.remoteNonce != nil {
			salt = append(salt, s.remoteNonce...)
		}
		salt = append(salt, s.localNonce...)
	}

	return crypto.HkdfSHA256(rawKey, salt, hkdfInfoPairingSession, 32)
}

func (s *PairingSession) computeKeyConfirmation(label []byte) ([]byte, error) {
	if s.sharedKey == nil {
		return nil, fmt.Errorf("no shared key available")
	}

	confirmKey, err := crypto.HkdfSHA256(s.sharedKey, nil, hkdfInfoKeyConfirm, 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}

	mac := hmac.New(sha256.New, confirmKey)
	mac.Write(label)
	return mac.Sum(nil), nil
}

func generateNonce() []byte {
	nonce := make([]byte, 16)
	_, _ = crand.Read(nonce)
	return nonce
}
