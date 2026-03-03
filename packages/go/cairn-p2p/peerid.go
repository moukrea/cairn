package cairn

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/mr-tron/base58"
)

const (
	// Multihash SHA2-256 code (0x12) and digest length (0x20 = 32).
	multihashSHA256Code byte = 0x12
	multihashSHA256Len  byte = 0x20

	// PeerIDLen is the total byte length of a PeerId: 2-byte prefix + 32-byte digest.
	PeerIDLen = 34
)

// PeerID is a peer identifier derived from the SHA-256 multihash of an Ed25519 public key.
// Internal format: [0x12, 0x20, <32-byte SHA-256 digest>] (34 bytes).
type PeerID [PeerIDLen]byte

// PeerIDFromPublicKey derives a PeerID from an Ed25519 public key.
func PeerIDFromPublicKey(pub ed25519.PublicKey) PeerID {
	digest := sha256.Sum256(pub)
	var id PeerID
	id[0] = multihashSHA256Code
	id[1] = multihashSHA256Len
	copy(id[2:], digest[:])
	return id
}

// PeerIDFromBytes constructs a PeerID from raw 34-byte multihash bytes.
func PeerIDFromBytes(b []byte) (PeerID, error) {
	if len(b) != PeerIDLen {
		return PeerID{}, fmt.Errorf("invalid peer ID length: got %d, want %d", len(b), PeerIDLen)
	}
	if b[0] != multihashSHA256Code || b[1] != multihashSHA256Len {
		return PeerID{}, fmt.Errorf("invalid peer ID multihash prefix: [0x%02x, 0x%02x]", b[0], b[1])
	}
	var id PeerID
	copy(id[:], b)
	return id, nil
}

// PeerIDFromString parses a base58-encoded PeerID string.
func PeerIDFromString(s string) (PeerID, error) {
	b, err := base58.Decode(s)
	if err != nil {
		return PeerID{}, fmt.Errorf("invalid base58 encoding: %w", err)
	}
	return PeerIDFromBytes(b)
}

// String returns the base58 (Bitcoin alphabet) encoding of the PeerID.
func (p PeerID) String() string {
	return base58.Encode(p[:])
}

// MarshalText implements encoding.TextMarshaler.
func (p PeerID) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *PeerID) UnmarshalText(text []byte) error {
	parsed, err := PeerIDFromString(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}
