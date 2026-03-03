package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX25519SharedSecretMatchesBothSides(t *testing.T) {
	alice, err := GenerateX25519()
	require.NoError(t, err)
	bob, err := GenerateX25519()
	require.NoError(t, err)

	aliceShared, err := alice.DiffieHellman(bob.PublicKeyBytes())
	require.NoError(t, err)
	bobShared, err := bob.DiffieHellman(alice.PublicKeyBytes())
	require.NoError(t, err)

	assert.Equal(t, aliceShared, bobShared)
}

func TestDifferentPeersProduceDifferentSharedSecrets(t *testing.T) {
	alice, err := GenerateX25519()
	require.NoError(t, err)
	bob, err := GenerateX25519()
	require.NoError(t, err)
	charlie, err := GenerateX25519()
	require.NoError(t, err)

	ab, err := alice.DiffieHellman(bob.PublicKeyBytes())
	require.NoError(t, err)
	ac, err := alice.DiffieHellman(charlie.PublicKeyBytes())
	require.NoError(t, err)

	assert.NotEqual(t, ab, ac)
}

func TestX25519FromBytesRoundtrip(t *testing.T) {
	orig, err := GenerateX25519()
	require.NoError(t, err)

	restored, err := X25519FromBytes(orig.PrivateKeyBytes())
	require.NoError(t, err)

	assert.Equal(t, orig.PublicKeyBytes(), restored.PublicKeyBytes())
}

func TestHkdfProducesDeterministicOutput(t *testing.T) {
	ikm := []byte("shared-secret-material")

	out1, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 32)
	require.NoError(t, err)
	out2, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 32)
	require.NoError(t, err)

	assert.Equal(t, out1, out2)
}

func TestHkdfDomainSeparationProducesDifferentKeys(t *testing.T) {
	ikm := []byte("same-input-keying-material")

	sessionKey, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 32)
	require.NoError(t, err)
	rendezvousKey, err := HkdfSHA256(ikm, nil, HkdfInfoRendezvous, 32)
	require.NoError(t, err)

	assert.NotEqual(t, sessionKey, rendezvousKey)
}

func TestHkdfWithSaltDiffersFromWithout(t *testing.T) {
	ikm := []byte("input-keying-material")
	salt := []byte("some-salt-value")

	withSalt, err := HkdfSHA256(ikm, salt, HkdfInfoSessionKey, 32)
	require.NoError(t, err)
	withoutSalt, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 32)
	require.NoError(t, err)

	assert.NotEqual(t, withSalt, withoutSalt)
}

func TestHkdfVariousOutputLengths(t *testing.T) {
	ikm := []byte("key-material")

	short, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 16)
	require.NoError(t, err)
	assert.Len(t, short, 16)

	long, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 64)
	require.NoError(t, err)
	assert.Len(t, long, 64)
}

func TestHkdfRejectsTooLongOutput(t *testing.T) {
	ikm := []byte("key-material")
	// HKDF-SHA256 max output is 255 * 32 = 8160 bytes
	_, err := HkdfSHA256(ikm, nil, HkdfInfoSessionKey, 8161)
	assert.Error(t, err)
}

func TestAllDomainSeparationConstantsAreUnique(t *testing.T) {
	constants := [][]byte{
		HkdfInfoSessionKey,
		HkdfInfoRendezvous,
		HkdfInfoSAS,
		HkdfInfoChainKey,
		HkdfInfoMessageKey,
	}
	for i, a := range constants {
		for j, b := range constants {
			if i != j {
				assert.NotEqual(t, a, b, "domain separation constants at index %d and %d collide", i, j)
			}
		}
	}
}
