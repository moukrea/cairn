package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// PeerIDLen is the byte length of a PeerID: 2-byte multihash prefix + 32-byte SHA-256 digest.
const PeerIDLen = 34

// RawPeerID is a 34-byte peer identifier (multihash of Ed25519 public key).
// This is the same underlying type as cairn.PeerID but defined here to avoid import cycles.
type RawPeerID = [PeerIDLen]byte

// PeerIDFromPublicKey derives a raw PeerID from an Ed25519 public key.
func PeerIDFromPublicKey(pub ed25519.PublicKey) RawPeerID {
	digest := sha256.Sum256(pub)
	var id RawPeerID
	id[0] = 0x12 // multihash SHA2-256 code
	id[1] = 0x20 // digest length 32
	copy(id[2:], digest[:])
	return id
}

// IdentityKeypair wraps an Ed25519 private key for signing and peer identification.
type IdentityKeypair struct {
	privateKey ed25519.PrivateKey
}

// GenerateIdentity creates a new random Ed25519 identity keypair.
func GenerateIdentity() (*IdentityKeypair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key generation failed: %w", err)
	}
	return &IdentityKeypair{privateKey: priv}, nil
}

// IdentityFromSeed restores an identity from a 32-byte seed.
func IdentityFromSeed(seed []byte) (*IdentityKeypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &IdentityKeypair{privateKey: priv}, nil
}

// Seed returns the 32-byte seed of the private key.
func (id *IdentityKeypair) Seed() []byte {
	return id.privateKey.Seed()
}

// PublicKey returns the Ed25519 public key.
func (id *IdentityKeypair) PublicKey() ed25519.PublicKey {
	return id.privateKey.Public().(ed25519.PublicKey)
}

// PeerID derives the PeerID from the keypair's public key.
func (id *IdentityKeypair) PeerID() RawPeerID {
	return PeerIDFromPublicKey(id.PublicKey())
}

// Sign produces a 64-byte Ed25519 signature. Deterministic (no randomness needed).
func (id *IdentityKeypair) Sign(message []byte) []byte {
	return ed25519.Sign(id.privateKey, message)
}

// Verify checks a signature against this keypair's public key.
func (id *IdentityKeypair) Verify(message, signature []byte) error {
	return VerifySignature(id.PublicKey(), message, signature)
}

// VerifySignature checks an Ed25519 signature against an arbitrary public key.
func VerifySignature(publicKey ed25519.PublicKey, message, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("ed25519 signature verification failed")
	}
	return nil
}
