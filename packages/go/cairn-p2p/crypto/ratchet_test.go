package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPair(t *testing.T) (*DoubleRatchet, *DoubleRatchet) {
	t.Helper()
	sharedSecret := [32]byte{0x42}
	for i := 1; i < 32; i++ {
		sharedSecret[i] = 0x42
	}
	bobKP, err := GenerateX25519()
	require.NoError(t, err)
	bobPublic := bobKP.PublicKeyBytes()

	alice, err := InitSender(sharedSecret, bobPublic, nil)
	require.NoError(t, err)

	bob, err := InitReceiver(sharedSecret, bobKP, nil)
	require.NoError(t, err)

	return alice, bob
}

func TestAliceSendsBobReceives(t *testing.T) {
	alice, bob := setupPair(t)

	header, ct, err := alice.Encrypt([]byte("hello bob"))
	require.NoError(t, err)

	pt, err := bob.Decrypt(header, ct)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello bob"), pt)
}

func TestMultipleMessagesOneDirection(t *testing.T) {
	alice, bob := setupPair(t)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		header, ct, err := alice.Encrypt(msg)
		require.NoError(t, err)
		pt, err := bob.Decrypt(header, ct)
		require.NoError(t, err)
		assert.Equal(t, msg, pt)
	}
}

func TestBidirectionalMessages(t *testing.T) {
	alice, bob := setupPair(t)

	// Alice -> Bob
	h1, ct1, err := alice.Encrypt([]byte("hello bob"))
	require.NoError(t, err)
	pt1, err := bob.Decrypt(h1, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello bob"), pt1)

	// Bob -> Alice
	h2, ct2, err := bob.Encrypt([]byte("hello alice"))
	require.NoError(t, err)
	pt2, err := alice.Decrypt(h2, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello alice"), pt2)

	// Alice -> Bob again
	h3, ct3, err := alice.Encrypt([]byte("how are you?"))
	require.NoError(t, err)
	pt3, err := bob.Decrypt(h3, ct3)
	require.NoError(t, err)
	assert.Equal(t, []byte("how are you?"), pt3)
}

func TestOutOfOrderMessages(t *testing.T) {
	alice, bob := setupPair(t)

	h1, ct1, err := alice.Encrypt([]byte("msg 0"))
	require.NoError(t, err)
	h2, ct2, err := alice.Encrypt([]byte("msg 1"))
	require.NoError(t, err)
	h3, ct3, err := alice.Encrypt([]byte("msg 2"))
	require.NoError(t, err)

	// Deliver out of order: 2, 0, 1
	pt3, err := bob.Decrypt(h3, ct3)
	require.NoError(t, err)
	assert.Equal(t, []byte("msg 2"), pt3)

	pt1, err := bob.Decrypt(h1, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("msg 0"), pt1)

	pt2, err := bob.Decrypt(h2, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("msg 1"), pt2)
}

func TestMaxSkipThresholdRespected(t *testing.T) {
	sharedSecret := [32]byte{0x42}
	for i := 1; i < 32; i++ {
		sharedSecret[i] = 0x42
	}
	bobKP, err := GenerateX25519()
	require.NoError(t, err)
	bobPublic := bobKP.PublicKeyBytes()

	cfg := &RatchetConfig{Cipher: CipherAes256Gcm, MaxSkip: 2}

	alice, err := InitSender(sharedSecret, bobPublic, cfg)
	require.NoError(t, err)
	bob, err := InitReceiver(sharedSecret, bobKP, cfg)
	require.NoError(t, err)

	// Send 4 messages, only try to decrypt the last one
	_, _, _ = alice.Encrypt([]byte("skip 0"))
	_, _, _ = alice.Encrypt([]byte("skip 1"))
	_, _, _ = alice.Encrypt([]byte("skip 2"))
	h4, ct4, err := alice.Encrypt([]byte("msg 3"))
	require.NoError(t, err)

	_, err = bob.Decrypt(h4, ct4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max skip threshold exceeded")
}

func TestStateExportImportRoundtrip(t *testing.T) {
	alice, bob := setupPair(t)

	// Exchange some messages
	h1, ct1, err := alice.Encrypt([]byte("before persist"))
	require.NoError(t, err)
	pt1, err := bob.Decrypt(h1, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("before persist"), pt1)

	// Export and reimport
	exported, err := alice.ExportState()
	require.NoError(t, err)

	alice2, err := ImportState(exported, nil)
	require.NoError(t, err)

	// Alice2 should continue sending
	h2, ct2, err := alice2.Encrypt([]byte("after persist"))
	require.NoError(t, err)
	pt2, err := bob.Decrypt(h2, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("after persist"), pt2)
}

func TestMultipleRatchetTurns(t *testing.T) {
	alice, bob := setupPair(t)

	for round := 0; round < 5; round++ {
		msgAB := []byte(fmt.Sprintf("alice round %d", round))
		h, ct, err := alice.Encrypt(msgAB)
		require.NoError(t, err)
		pt, err := bob.Decrypt(h, ct)
		require.NoError(t, err)
		assert.Equal(t, msgAB, pt)

		msgBA := []byte(fmt.Sprintf("bob round %d", round))
		h, ct, err = bob.Encrypt(msgBA)
		require.NoError(t, err)
		pt, err = alice.Decrypt(h, ct)
		require.NoError(t, err)
		assert.Equal(t, msgBA, pt)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	alice, bob := setupPair(t)

	header, ct, err := alice.Encrypt([]byte("tamper test"))
	require.NoError(t, err)

	ct[0] ^= 0xFF
	_, err = bob.Decrypt(header, ct)
	assert.Error(t, err)
}

func TestChaCha20CipherSuite(t *testing.T) {
	sharedSecret := [32]byte{0x42}
	for i := 1; i < 32; i++ {
		sharedSecret[i] = 0x42
	}
	bobKP, err := GenerateX25519()
	require.NoError(t, err)
	bobPublic := bobKP.PublicKeyBytes()

	cfg := &RatchetConfig{Cipher: CipherChaCha20Poly1305, MaxSkip: 100}

	alice, err := InitSender(sharedSecret, bobPublic, cfg)
	require.NoError(t, err)
	bob, err := InitReceiver(sharedSecret, bobKP, cfg)
	require.NoError(t, err)

	h, ct, err := alice.Encrypt([]byte("chacha20 test"))
	require.NoError(t, err)
	pt, err := bob.Decrypt(h, ct)
	require.NoError(t, err)
	assert.Equal(t, []byte("chacha20 test"), pt)
}

func TestEmptyPlaintext(t *testing.T) {
	alice, bob := setupPair(t)

	h, ct, err := alice.Encrypt([]byte(""))
	require.NoError(t, err)
	pt, err := bob.Decrypt(h, ct)
	require.NoError(t, err)
	assert.Empty(t, pt)
}

func TestMessageNumbersIncrement(t *testing.T) {
	alice, _ := setupPair(t)

	h1, _, err := alice.Encrypt([]byte("msg0"))
	require.NoError(t, err)
	h2, _, err := alice.Encrypt([]byte("msg1"))
	require.NoError(t, err)
	h3, _, err := alice.Encrypt([]byte("msg2"))
	require.NoError(t, err)

	assert.Equal(t, uint32(0), h1.MsgNum)
	assert.Equal(t, uint32(1), h2.MsgNum)
	assert.Equal(t, uint32(2), h3.MsgNum)
}

func TestDHPublicKeyChangesOnRatchet(t *testing.T) {
	alice, bob := setupPair(t)

	h1, ct1, err := alice.Encrypt([]byte("from alice"))
	require.NoError(t, err)
	alicePK1 := h1.DHPublic
	_, err = bob.Decrypt(h1, ct1)
	require.NoError(t, err)

	h2, ct2, err := bob.Encrypt([]byte("from bob"))
	require.NoError(t, err)
	_, err = alice.Decrypt(h2, ct2)
	require.NoError(t, err)

	h3, _, err := alice.Encrypt([]byte("from alice again"))
	require.NoError(t, err)
	alicePK2 := h3.DHPublic

	assert.NotEqual(t, alicePK1, alicePK2, "DH public key should change after ratchet step")
}

func TestImportStateInvalidData(t *testing.T) {
	_, err := ImportState([]byte("not valid json"), nil)
	assert.Error(t, err)
}

func TestCloseZeroizesKeys(t *testing.T) {
	alice, _ := setupPair(t)
	alice.Close()

	assert.Equal(t, [32]byte{}, alice.rootKey)
}
