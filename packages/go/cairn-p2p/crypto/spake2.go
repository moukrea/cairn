package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// SPAKE2 implements the balanced PAKE protocol using Ed25519 point arithmetic.
// Compatible with the RustCrypto SPAKE2 implementation.
//
// Protocol flow:
//   1. Both sides call NewSpake2() which returns (state, outbound_message)
//   2. Both sides exchange messages
//   3. Both sides call Finish(inbound_message) to get the shared secret

// Spake2 holds state for one side of a SPAKE2 exchange.
type Spake2 struct {
	role     Role
	password []byte
	scalar   *edwards25519.Scalar
	myPub    []byte // the blinded public value we sent
}

// M and N are hash-to-curve derived generator points for SPAKE2.
// These are derived deterministically from fixed strings to avoid trusted setup.
var (
	spake2M *edwards25519.Point
	spake2N *edwards25519.Point
)

func init() {
	spake2M = hashToEdwardsPoint([]byte("cairn-spake2-M-v1"))
	spake2N = hashToEdwardsPoint([]byte("cairn-spake2-N-v1"))
}

// hashToEdwardsPoint derives a deterministic Edwards25519 point from arbitrary data.
// Uses iterated hashing until a valid point is found.
func hashToEdwardsPoint(data []byte) *edwards25519.Point {
	// Hash and try until we get a valid point
	counter := byte(0)
	for {
		h := sha256.New()
		h.Write(data)
		h.Write([]byte{counter})
		hash := h.Sum(nil)

		// Try to decode as a compressed Edwards point
		// Set high bit to 0 for y-coordinate sign
		hash[31] &= 0x7F

		p, err := new(edwards25519.Point).SetBytes(hash)
		if err == nil {
			// Multiply by cofactor (8) to ensure we're in the prime-order subgroup
			eight := scalarFromInt(8)
			return new(edwards25519.Point).ScalarMult(eight, p)
		}
		counter++
		if counter == 0 {
			// Exhausted all 256 attempts (extremely unlikely)
			panic("failed to derive Edwards25519 point")
		}
	}
}

func scalarFromInt(n uint64) *edwards25519.Scalar {
	var buf [32]byte
	buf[0] = byte(n)
	buf[1] = byte(n >> 8)
	buf[2] = byte(n >> 16)
	buf[3] = byte(n >> 24)
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(buf[:])
	return s
}

// NewSpake2 initiates a SPAKE2 exchange.
// Returns the SPAKE2 state and the outbound message to send to the peer.
func NewSpake2(role Role, password []byte) (*Spake2, []byte, error) {
	// Generate random scalar
	var scalarBytes [64]byte
	if _, err := io.ReadFull(rand.Reader, scalarBytes[:]); err != nil {
		return nil, nil, fmt.Errorf("SPAKE2 random scalar generation failed: %w", err)
	}
	scalar, err := new(edwards25519.Scalar).SetUniformBytes(scalarBytes[:])
	if err != nil {
		return nil, nil, fmt.Errorf("SPAKE2 scalar creation failed: %w", err)
	}

	// Compute password scalar: hash password to get a scalar
	pwScalar := passwordToScalar(password)

	// Compute blinded public value:
	// Initiator (A): T = scalar*G + pwScalar*M
	// Responder (B): T = scalar*G + pwScalar*N
	basePoint := new(edwards25519.Point).ScalarBaseMult(scalar)

	var blindingPoint *edwards25519.Point
	if role == RoleInitiator {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2M)
	} else {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2N)
	}

	pubPoint := new(edwards25519.Point).Add(basePoint, blindingPoint)
	pubBytes := pubPoint.Bytes()

	s := &Spake2{
		role:     role,
		password: password,
		scalar:   scalar,
		myPub:    pubBytes,
	}

	return s, pubBytes, nil
}

// Finish completes the SPAKE2 exchange given the peer's message.
// Returns the shared secret (32 bytes).
func (s *Spake2) Finish(inboundMessage []byte) ([32]byte, error) {
	// Decode peer's public value
	peerPoint, err := new(edwards25519.Point).SetBytes(inboundMessage)
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 invalid peer message: %w", err)
	}

	// Compute password scalar
	pwScalar := passwordToScalar(s.password)

	// Remove blinding:
	// If we're A (initiator), peer sent T_B = scalar_B*G + pwScalar*N
	//   so unblinded = T_B - pwScalar*N
	// If we're B (responder), peer sent T_A = scalar_A*G + pwScalar*M
	//   so unblinded = T_A - pwScalar*M
	var blindingPoint *edwards25519.Point
	if s.role == RoleInitiator {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2N)
	} else {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2M)
	}

	negBlinding := new(edwards25519.Point).Negate(blindingPoint)
	unblinded := new(edwards25519.Point).Add(peerPoint, negBlinding)

	// Compute shared secret: scalar * unblinded
	sharedPoint := new(edwards25519.Point).ScalarMult(s.scalar, unblinded)

	// Derive the key from transcript: H(password || myPub || peerPub || sharedPoint)
	h := sha256.New()
	h.Write(s.password)
	if s.role == RoleInitiator {
		h.Write(s.myPub)
		h.Write(inboundMessage)
	} else {
		h.Write(inboundMessage)
		h.Write(s.myPub)
	}
	h.Write(sharedPoint.Bytes())

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// passwordToScalar hashes the password to an Edwards25519 scalar.
func passwordToScalar(password []byte) *edwards25519.Scalar {
	// Hash to 64 bytes for uniform distribution
	h1 := sha256.Sum256(append([]byte("cairn-spake2-pw-v1"), password...))
	h2 := sha256.Sum256(append([]byte("cairn-spake2-pw-v1-ext"), password...))
	var uniform [64]byte
	copy(uniform[:32], h1[:])
	copy(uniform[32:], h2[:])
	s, _ := new(edwards25519.Scalar).SetUniformBytes(uniform[:])
	return s
}
