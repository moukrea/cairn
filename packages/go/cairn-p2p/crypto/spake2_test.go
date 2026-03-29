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

	assert.NotEqual(t, secret1A, secret2A)
}

func TestSpake2MessageIs33Bytes(t *testing.T) {
	_, msg, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)
	assert.Len(t, msg, 33)
	assert.Equal(t, byte(0x41), msg[0], "initiator side byte should be 0x41")

	_, msg, err = NewSpake2(RoleResponder, []byte("test"))
	require.NoError(t, err)
	assert.Len(t, msg, 33)
	assert.Equal(t, byte(0x42), msg[0], "responder side byte should be 0x42")
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
	alice, _, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)

	// Wrong length
	_, err = alice.Finish([]byte{0xFF, 0xFF, 0xFF})
	assert.Error(t, err)
}

func TestSpake2BadSideByte(t *testing.T) {
	alice, _, err := NewSpake2(RoleInitiator, []byte("test"))
	require.NoError(t, err)

	// Initiator expects side byte 0x42, craft a message with 0x41
	badMsg := make([]byte, 33)
	badMsg[0] = 0x41 // wrong side
	_, err = alice.Finish(badMsg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad side byte")
}
