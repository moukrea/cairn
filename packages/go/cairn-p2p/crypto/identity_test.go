package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndRoundtripKeypair(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	seed := kp.Seed()
	restored, err := IdentityFromSeed(seed)
	require.NoError(t, err)

	assert.Equal(t, kp.PublicKey(), restored.PublicKey())
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	message := []byte("hello cairn")
	sig := kp.Sign(message)
	assert.Len(t, sig, 64)

	err = kp.Verify(message, sig)
	assert.NoError(t, err)
}

func TestVerifyWrongMessageFails(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	sig := kp.Sign([]byte("correct message"))
	err = kp.Verify([]byte("wrong message"), sig)
	assert.Error(t, err)
}

func TestVerifyWrongKeyFails(t *testing.T) {
	kp1, err := GenerateIdentity()
	require.NoError(t, err)
	kp2, err := GenerateIdentity()
	require.NoError(t, err)

	sig := kp1.Sign([]byte("hello"))
	err = kp2.Verify([]byte("hello"), sig)
	assert.Error(t, err)
}

func TestVerifySignatureStandalone(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	message := []byte("standalone verify")
	sig := kp.Sign(message)

	assert.NoError(t, VerifySignature(kp.PublicKey(), message, sig))
	assert.Error(t, VerifySignature(kp.PublicKey(), []byte("tampered"), sig))
}

func TestPeerIDIsDeterministic(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	id1 := kp.PeerID()
	id2 := kp.PeerID()
	assert.Equal(t, id1, id2)
}

func TestDifferentKeysProduceDifferentPeerIDs(t *testing.T) {
	kp1, err := GenerateIdentity()
	require.NoError(t, err)
	kp2, err := GenerateIdentity()
	require.NoError(t, err)

	assert.NotEqual(t, kp1.PeerID(), kp2.PeerID())
}

func TestSignatureIsDeterministic(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	message := []byte("deterministic")
	sig1 := kp.Sign(message)
	sig2 := kp.Sign(message)
	assert.Equal(t, sig1, sig2)
}

func TestIdentityFromSeedRejectsWrongLength(t *testing.T) {
	_, err := IdentityFromSeed([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestPeerIDMultihashFormat(t *testing.T) {
	kp, err := GenerateIdentity()
	require.NoError(t, err)

	pid := kp.PeerID()
	assert.Equal(t, byte(0x12), pid[0])
	assert.Equal(t, byte(0x20), pid[1])
}
