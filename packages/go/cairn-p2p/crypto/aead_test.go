package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey() [32]byte {
	var key [32]byte
	key[0] = 0x42
	key[31] = 0xFF
	return key
}

func testNonce() [12]byte {
	var nonce [12]byte
	nonce[0] = 0x01
	return nonce
}

func TestAesGcmEncryptDecryptRoundtrip(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("hello cairn aes-gcm")
	aad := []byte("associated-data")

	ciphertext, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, aad)
	require.NoError(t, err)

	decrypted, err := AeadDecrypt(CipherAes256Gcm, key, nonce, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20EncryptDecryptRoundtrip(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("hello cairn chacha20")
	aad := []byte("associated-data")

	ciphertext, err := AeadEncrypt(CipherChaCha20Poly1305, key, nonce, plaintext, aad)
	require.NoError(t, err)

	decrypted, err := AeadDecrypt(CipherChaCha20Poly1305, key, nonce, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAesGcmTamperedCiphertextRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("sensitive data")
	aad := []byte("aad")

	ciphertext, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, aad)
	require.NoError(t, err)

	ciphertext[0] ^= 0xFF
	_, err = AeadDecrypt(CipherAes256Gcm, key, nonce, ciphertext, aad)
	assert.Error(t, err)
}

func TestChaCha20TamperedCiphertextRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("sensitive data")
	aad := []byte("aad")

	ciphertext, err := AeadEncrypt(CipherChaCha20Poly1305, key, nonce, plaintext, aad)
	require.NoError(t, err)

	ciphertext[0] ^= 0xFF
	_, err = AeadDecrypt(CipherChaCha20Poly1305, key, nonce, ciphertext, aad)
	assert.Error(t, err)
}

func TestAesGcmWrongAADRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("data")

	ciphertext, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, []byte("correct-aad"))
	require.NoError(t, err)

	_, err = AeadDecrypt(CipherAes256Gcm, key, nonce, ciphertext, []byte("wrong-aad"))
	assert.Error(t, err)
}

func TestChaCha20WrongAADRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("data")

	ciphertext, err := AeadEncrypt(CipherChaCha20Poly1305, key, nonce, plaintext, []byte("correct-aad"))
	require.NoError(t, err)

	_, err = AeadDecrypt(CipherChaCha20Poly1305, key, nonce, ciphertext, []byte("wrong-aad"))
	assert.Error(t, err)
}

func TestWrongKeyRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("data")
	aad := []byte("aad")

	ciphertext, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, aad)
	require.NoError(t, err)

	wrongKey := key
	wrongKey[0] ^= 0x01
	_, err = AeadDecrypt(CipherAes256Gcm, wrongKey, nonce, ciphertext, aad)
	assert.Error(t, err)
}

func TestWrongNonceRejected(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("data")
	aad := []byte("aad")

	ciphertext, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, aad)
	require.NoError(t, err)

	wrongNonce := nonce
	wrongNonce[0] ^= 0x01
	_, err = AeadDecrypt(CipherAes256Gcm, key, wrongNonce, ciphertext, aad)
	assert.Error(t, err)
}

func TestCiphertextIncludesTag(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("hello")
	aad := []byte("")

	ctAes, err := AeadEncrypt(CipherAes256Gcm, key, nonce, plaintext, aad)
	require.NoError(t, err)
	assert.Len(t, ctAes, len(plaintext)+TagSize)

	ctChacha, err := AeadEncrypt(CipherChaCha20Poly1305, key, nonce, plaintext, aad)
	require.NoError(t, err)
	assert.Len(t, ctChacha, len(plaintext)+TagSize)
}

func TestEmptyPlaintextRoundtrip(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("")
	aad := []byte("some-context")

	for _, suite := range []CipherSuite{CipherAes256Gcm, CipherChaCha20Poly1305} {
		ciphertext, err := AeadEncrypt(suite, key, nonce, plaintext, aad)
		require.NoError(t, err)
		decrypted, err := AeadDecrypt(suite, key, nonce, ciphertext, aad)
		require.NoError(t, err)
		assert.Empty(t, decrypted)
	}
}

func TestEmptyAADRoundtrip(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	plaintext := []byte("data with no aad")
	aad := []byte("")

	for _, suite := range []CipherSuite{CipherAes256Gcm, CipherChaCha20Poly1305} {
		ciphertext, err := AeadEncrypt(suite, key, nonce, plaintext, aad)
		require.NoError(t, err)
		decrypted, err := AeadDecrypt(suite, key, nonce, ciphertext, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}
