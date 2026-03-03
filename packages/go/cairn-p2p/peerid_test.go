package cairn

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub
}

func TestPeerIDFromPublicKey(t *testing.T) {
	pub := generateTestKey(t)
	pid := PeerIDFromPublicKey(pub)
	assert.Equal(t, byte(0x12), pid[0])
	assert.Equal(t, byte(0x20), pid[1])
	assert.Len(t, pid, 34)
}

func TestPeerIDDeterministic(t *testing.T) {
	pub := generateTestKey(t)
	pid1 := PeerIDFromPublicKey(pub)
	pid2 := PeerIDFromPublicKey(pub)
	assert.Equal(t, pid1, pid2)
}

func TestPeerIDDifferentKeys(t *testing.T) {
	pub1 := generateTestKey(t)
	pub2 := generateTestKey(t)
	pid1 := PeerIDFromPublicKey(pub1)
	pid2 := PeerIDFromPublicKey(pub2)
	assert.NotEqual(t, pid1, pid2)
}

func TestPeerIDStringRoundtrip(t *testing.T) {
	pub := generateTestKey(t)
	pid := PeerIDFromPublicKey(pub)
	s := pid.String()
	parsed, err := PeerIDFromString(s)
	require.NoError(t, err)
	assert.Equal(t, pid, parsed)
}

func TestPeerIDFromBytesRoundtrip(t *testing.T) {
	pub := generateTestKey(t)
	pid := PeerIDFromPublicKey(pub)
	restored, err := PeerIDFromBytes(pid[:])
	require.NoError(t, err)
	assert.Equal(t, pid, restored)
}

func TestPeerIDFromBytesRejectsWrongLength(t *testing.T) {
	_, err := PeerIDFromBytes([]byte{0x12, 0x20, 0x00})
	assert.Error(t, err)
}

func TestPeerIDFromBytesRejectsWrongPrefix(t *testing.T) {
	b := make([]byte, 34)
	b[0] = 0xFF
	b[1] = 0x20
	_, err := PeerIDFromBytes(b)
	assert.Error(t, err)
}

func TestPeerIDFromStringRejectsInvalid(t *testing.T) {
	_, err := PeerIDFromString("!!!invalid!!!")
	assert.Error(t, err)
}

func TestPeerIDMarshalTextRoundtrip(t *testing.T) {
	pub := generateTestKey(t)
	pid := PeerIDFromPublicKey(pub)
	text, err := pid.MarshalText()
	require.NoError(t, err)

	var restored PeerID
	err = restored.UnmarshalText(text)
	require.NoError(t, err)
	assert.Equal(t, pid, restored)
}
