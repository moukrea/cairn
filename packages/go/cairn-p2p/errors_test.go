package cairn

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCairnErrorError(t *testing.T) {
	err := &CairnError{
		Kind:    ErrKindTransportExhausted,
		Message: "QUIC: timeout, TCP: refused",
	}
	assert.Equal(t, "QUIC: timeout, TCP: refused", err.Error())
}

func TestCairnErrorErrorWithSuggestion(t *testing.T) {
	err := &CairnError{
		Kind:       ErrKindTransportExhausted,
		Message:    "all transports exhausted",
		Suggestion: "deploy a TURN relay",
	}
	assert.Equal(t, "all transports exhausted. Suggestion: deploy a TURN relay", err.Error())
}

func TestCairnErrorIs(t *testing.T) {
	err := NewCairnError(ErrKindTransportExhausted, "QUIC failed", "try TCP")
	assert.True(t, errors.Is(err, ErrTransportExhausted))
	assert.False(t, errors.Is(err, ErrSessionExpired))
}

func TestCairnErrorAs(t *testing.T) {
	var wrapped error = NewCairnError(ErrKindPairingRejected, "rejected", "")
	var target *CairnError
	require.True(t, errors.As(wrapped, &target))
	assert.Equal(t, ErrKindPairingRejected, target.Kind)
}

func TestSentinelErrorBehaviors(t *testing.T) {
	tests := []struct {
		err      *CairnError
		behavior ErrorBehavior
	}{
		{ErrTransportExhausted, Retry},
		{ErrSessionExpired, Reconnect},
		{ErrPeerUnreachable, Wait},
		{ErrAuthenticationFailed, Abort},
		{ErrPairingRejected, Inform},
		{ErrPairingExpired, ReGenerate},
		{ErrMeshRouteNotFound, Wait},
		{ErrVersionMismatch, Abort},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.behavior, tc.err.Behavior, "wrong behavior for %s", tc.err.Message)
	}
}

func TestNewCairnErrorBehavior(t *testing.T) {
	tests := []struct {
		kind     ErrorKind
		behavior ErrorBehavior
	}{
		{ErrKindTransportExhausted, Retry},
		{ErrKindSessionExpired, Reconnect},
		{ErrKindPeerUnreachable, Wait},
		{ErrKindAuthenticationFailed, Abort},
		{ErrKindPairingRejected, Inform},
		{ErrKindPairingExpired, ReGenerate},
		{ErrKindMeshRouteNotFound, Wait},
		{ErrKindVersionMismatch, Abort},
	}
	for _, tc := range tests {
		err := NewCairnError(tc.kind, "test", "")
		assert.Equal(t, tc.behavior, err.Behavior)
	}
}

func TestWrappedCairnErrorIs(t *testing.T) {
	inner := NewCairnError(ErrKindSessionExpired, "session expired after 24h", "reconnect")
	wrapped := fmt.Errorf("connection failed: %w", inner)
	assert.True(t, errors.Is(wrapped, ErrSessionExpired))
}

func TestSentinelErrorSuggestions(t *testing.T) {
	assert.NotEmpty(t, ErrTransportExhausted.Suggestion)
	assert.Contains(t, ErrTransportExhausted.Suggestion, "signaling server")
	assert.NotEmpty(t, ErrMeshRouteNotFound.Suggestion)
	assert.Contains(t, ErrMeshRouteNotFound.Suggestion, "direct connection")
	assert.NotEmpty(t, ErrVersionMismatch.Suggestion)
	assert.Contains(t, ErrVersionMismatch.Suggestion, "update")
}

func TestNewCairnErrorDefaultSuggestion(t *testing.T) {
	err := NewCairnError(ErrKindTransportExhausted, "QUIC failed", "")
	assert.Equal(t, "deploy the cairn signaling server and/or TURN relay", err.Suggestion)

	err = NewCairnError(ErrKindMeshRouteNotFound, "no route", "")
	assert.Equal(t, "try a direct connection or wait for mesh route discovery", err.Suggestion)

	err = NewCairnError(ErrKindVersionMismatch, "mismatch", "")
	assert.Equal(t, "peer needs to update to a compatible cairn version", err.Suggestion)
}

func TestNewCairnErrorCustomSuggestion(t *testing.T) {
	err := NewCairnError(ErrKindTransportExhausted, "failed", "custom suggestion")
	assert.Equal(t, "custom suggestion", err.Suggestion)
}
