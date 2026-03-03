package cairn

import (
	"errors"
	"fmt"
)

// ErrorKind identifies the category of a CairnError.
type ErrorKind int

const (
	ErrKindTransportExhausted ErrorKind = iota
	ErrKindSessionExpired
	ErrKindPeerUnreachable
	ErrKindAuthenticationFailed
	ErrKindPairingRejected
	ErrKindPairingExpired
	ErrKindMeshRouteNotFound
	ErrKindVersionMismatch
)

// ErrorBehavior recommends a recovery action for the caller.
type ErrorBehavior int

const (
	Retry      ErrorBehavior = iota // Retry with different transport configuration
	Reconnect                       // Re-establish session (no re-pairing)
	Wait                            // Background poll / wait for availability
	Abort                           // Stop — manual intervention required
	Inform                          // Inform the user — no automatic recovery
	ReGenerate                      // Generate a new pairing payload
)

// CairnError is the primary error type for the cairn library.
type CairnError struct {
	Kind       ErrorKind
	Message    string
	Suggestion string
	Behavior   ErrorBehavior
}

func (e *CairnError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s. Suggestion: %s", e.Message, e.Suggestion)
	}
	return e.Message
}

// Is supports errors.Is matching by comparing ErrorKind.
func (e *CairnError) Is(target error) bool {
	var t *CairnError
	if errors.As(target, &t) {
		return e.Kind == t.Kind
	}
	return false
}

// Sentinel errors for the 8 spec error types.
var (
	ErrTransportExhausted = &CairnError{
		Kind:       ErrKindTransportExhausted,
		Message:    "all transports exhausted",
		Suggestion: "deploy the cairn signaling server and/or TURN relay",
		Behavior:   Retry,
	}
	ErrSessionExpired = &CairnError{
		Kind:     ErrKindSessionExpired,
		Message:  "session expired",
		Behavior: Reconnect,
	}
	ErrPeerUnreachable = &CairnError{
		Kind:     ErrKindPeerUnreachable,
		Message:  "peer unreachable at any rendezvous point",
		Behavior: Wait,
	}
	ErrAuthenticationFailed = &CairnError{
		Kind:     ErrKindAuthenticationFailed,
		Message:  "authentication failed: cryptographic verification failed",
		Behavior: Abort,
	}
	ErrPairingRejected = &CairnError{
		Kind:     ErrKindPairingRejected,
		Message:  "pairing rejected by remote peer",
		Behavior: Inform,
	}
	ErrPairingExpired = &CairnError{
		Kind:     ErrKindPairingExpired,
		Message:  "pairing payload expired",
		Behavior: ReGenerate,
	}
	ErrMeshRouteNotFound = &CairnError{
		Kind:       ErrKindMeshRouteNotFound,
		Message:    "no mesh route found to peer",
		Suggestion: "try a direct connection or wait for mesh route discovery",
		Behavior:   Wait,
	}
	ErrVersionMismatch = &CairnError{
		Kind:       ErrKindVersionMismatch,
		Message:    "protocol version mismatch",
		Suggestion: "peer needs to update to a compatible cairn version",
		Behavior:   Abort,
	}
)

// defaultSuggestion returns the default suggestion text for error kinds that
// have actionable guidance.
func defaultSuggestion(kind ErrorKind) string {
	switch kind {
	case ErrKindTransportExhausted:
		return "deploy the cairn signaling server and/or TURN relay"
	case ErrKindMeshRouteNotFound:
		return "try a direct connection or wait for mesh route discovery"
	case ErrKindVersionMismatch:
		return "peer needs to update to a compatible cairn version"
	default:
		return ""
	}
}

// NewCairnError creates a CairnError with a specific kind, message, and suggestion.
// When suggestion is empty and the kind has a default suggestion, the default is used.
func NewCairnError(kind ErrorKind, message, suggestion string) *CairnError {
	var behavior ErrorBehavior
	switch kind {
	case ErrKindTransportExhausted:
		behavior = Retry
	case ErrKindSessionExpired:
		behavior = Reconnect
	case ErrKindPeerUnreachable:
		behavior = Wait
	case ErrKindAuthenticationFailed:
		behavior = Abort
	case ErrKindPairingRejected:
		behavior = Inform
	case ErrKindPairingExpired:
		behavior = ReGenerate
	case ErrKindMeshRouteNotFound:
		behavior = Wait
	case ErrKindVersionMismatch:
		behavior = Abort
	}
	if suggestion == "" {
		suggestion = defaultSuggestion(kind)
	}
	return &CairnError{
		Kind:       kind,
		Message:    message,
		Suggestion: suggestion,
		Behavior:   behavior,
	}
}
