package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// NonceSize is the nonce size for both AEAD ciphers: 12 bytes.
	NonceSize = 12
	// KeySize is the key size for both AEAD ciphers: 32 bytes.
	KeySize = 32
	// TagSize is the authentication tag size for both ciphers: 16 bytes.
	TagSize = 16
)

// CipherSuite identifies an AEAD cipher.
type CipherSuite int

const (
	CipherAes256Gcm        CipherSuite = iota
	CipherChaCha20Poly1305
)

// AeadEncrypt encrypts plaintext with associated data using the specified cipher.
// Returns ciphertext with appended authentication tag.
func AeadEncrypt(cs CipherSuite, key [32]byte, nonce [12]byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(cs, key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	return ciphertext, nil
}

// AeadDecrypt decrypts ciphertext with associated data using the specified cipher.
// Returns plaintext on success, or error if authentication fails.
func AeadDecrypt(cs CipherSuite, key [32]byte, nonce [12]byte, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(cs, key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AEAD decryption failed: %w", err)
	}
	return plaintext, nil
}

func newAEAD(cs CipherSuite, key [32]byte) (cipher.AEAD, error) {
	switch cs {
	case CipherAes256Gcm:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, fmt.Errorf("AES cipher creation failed: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("AES-GCM creation failed: %w", err)
		}
		return aead, nil
	case CipherChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key[:])
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305 creation failed: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unknown cipher suite: %d", cs)
	}
}
