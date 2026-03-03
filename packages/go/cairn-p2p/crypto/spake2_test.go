package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpake2MatchingPasswordsYieldMatchingSecrets(t *testing.T) {
	password := []byte("correct-horse-battery-staple")

	alice, msgA, err := NewSpake2(RoleInitiator, password)
	require.NoError(t, err)
	bob, msgB, err := NewSpake2(RoleResponder, password)
	require.NoError(t, err)

	secretA, err := alice.Finish(msgB)
	require.NoError(t, err)
	secretB, err := bob.Finish(msgA)
	require.NoError(t, err)

	assert.Equal(t, secretA, secretB)
}

func TestSpake2MismatchedPasswordsYieldDifferentSecrets(t *testing.T) {
	alice, msgA, err := NewSpake2(RoleInitiator, []byte("password1"))
	require.NoError(t, err)
	bob, msgB, err := NewSpake2(RoleResponder, []byte("password2"))
	require.NoError(t, err)

	secretA, err := alice.Finish(msgB)
	require.NoError(t, err)
	secretB, err := bob.Finish(msgA)
	require.NoError(t, err)

	// With different passwords, the secrets should NOT match
	assert.NotEqual(t, secretA, secretB)
}

func TestSpake2DifferentSessionsProduceDifferentSecrets(t *testing.T) {
	password := []byte("same-password")

	alice1, msgA1, err := NewSpake2(RoleInitiator, password)
	require.NoError(t, err)
	bob1, msgB1, err := NewSpake2(RoleResponder, password)
	require.NoError(t, err)

	secret1A, err := alice1.Finish(msgB1)
	require.NoError(t, err)
	_, err = bob1.Finish(msgA1)
	require.NoError(t, err)

	alice2, msgA2, err := NewSpake2(RoleInitiator, password)
	require.NoError(t, err)
	bob2, msgB2, err := NewSpake2(RoleResponder, password)
	require.NoError(t, err)

	secret2A, err := alice2.Finish(msgB2)
	require.NoError(t, err)
	_, err = bob2.Finish(msgA2)
	require.NoError(t, err)

	// Different random scalars -> different secrets
	assert.NotEqual(t, secret1A, secret2A)
}

func TestSpake2MessageIs32Bytes(t *testing.T) {
	_, msg, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)
	assert.Len(t, msg, 32)
}

func TestSpake2EmptyPassword(t *testing.T) {
	alice, msgA, err := NewSpake2(RoleInitiator, []byte{})
	require.NoError(t, err)
	bob, msgB, err := NewSpake2(RoleResponder, []byte{})
	require.NoError(t, err)

	secretA, err := alice.Finish(msgB)
	require.NoError(t, err)
	secretB, err := bob.Finish(msgA)
	require.NoError(t, err)

	assert.Equal(t, secretA, secretB)
}

func TestSpake2InvalidPeerMessage(t *testing.T) {
	_, _, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)
	// Note: we need a real spake2 instance to call Finish
	alice, _, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)

	// Invalid point encoding
	_, err = alice.Finish([]byte{0xFF, 0xFF, 0xFF})
	assert.Error(t, err)
}
