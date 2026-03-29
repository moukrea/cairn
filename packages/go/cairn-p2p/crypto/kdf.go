package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HKDF domain separation constants (must match Rust exactly).
var (
	HkdfInfoSessionKey        = []byte("cairn-session-key-v1")
	HkdfInfoRendezvous        = []byte("cairn-rendezvous-v1")
	HkdfInfoPairingRendezvous = []byte("cairn-pairing-rendezvous-v1")
	HkdfInfoEpochOffset       = []byte("cairn-epoch-offset-v1")
	HkdfInfoSAS               = []byte("cairn-sas-derivation-v1")
	HkdfInfoChainKey          = []byte("cairn-chain-key-v1")
	HkdfInfoMessageKey        = []byte("cairn-message-key-v1")
)

// X25519Keypair is an X25519 keypair for Diffie-Hellman key exchange.
type X25519Keypair struct {
	privateKey [32]byte
	publicKey  [32]byte
}

// GenerateX25519 creates a new random X25519 keypair.
func GenerateX25519() (*X25519Keypair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, fmt.Errorf("x25519 key generation failed: %w", err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 scalar base mult failed: %w", err)
	}
	var kp X25519Keypair
	kp.privateKey = priv
	copy(kp.publicKey[:], pub)
	return &kp, nil
}

// X25519FromBytes restores an X25519 keypair from a 32-byte secret key.
func X25519FromBytes(secret [32]byte) (*X25519Keypair, error) {
	pub, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 scalar base mult failed: %w", err)
	}
	var kp X25519Keypair
	kp.privateKey = secret
	copy(kp.publicKey[:], pub)
	return &kp, nil
}

// PublicKeyBytes returns the 32-byte X25519 public key.
func (kp *X25519Keypair) PublicKeyBytes() [32]byte {
	return kp.publicKey
}

// PrivateKeyBytes returns the 32-byte X25519 private key.
func (kp *X25519Keypair) PrivateKeyBytes() [32]byte {
	return kp.privateKey
}

// DiffieHellman performs X25519 Diffie-Hellman with a peer's public key,
// returning the 32-byte shared secret.
func (kp *X25519Keypair) DiffieHellman(peerPublic [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(kp.privateKey[:], peerPublic[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("x25519 DH failed: %w", err)
	}
	var result [32]byte
	copy(result[:], shared)
	return result, nil
}

// HkdfSHA256 derives key material using HKDF-SHA256 (RFC 5869).
//
// Parameters:
//   - ikm: input keying material (e.g. DH shared secret)
//   - salt: optional salt (nil uses a zero-filled salt)
//   - info: context-specific info string for domain separation
//   - length: number of bytes to derive
func HkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	output := make([]byte, length)
	if _, err := io.ReadFull(reader, output); err != nil {
		return nil, fmt.Errorf("HKDF-SHA256 expand failed: %w", err)
	}
	return output, nil
}
