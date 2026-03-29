package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

// SPAKE2 implements the balanced PAKE protocol using Ed25519 point arithmetic.
// Wire-compatible with the RustCrypto spake2 crate v0.4 using Ed25519Group.
//
// Protocol flow:
//   1. Both sides call NewSpake2() which returns (state, outbound_message)
//      outbound message is 33 bytes: 1-byte side prefix + 32-byte point
//   2. Both sides exchange messages
//   3. Both sides call Finish(inbound_message) to get the shared secret

// Spake2 holds state for one side of a SPAKE2 exchange.
type Spake2 struct {
	role           Role
	password       []byte
	scalar         *edwards25519.Scalar
	passwordScalar *edwards25519.Scalar
	myMsg          []byte // 32-byte compressed point (without side prefix)
}

// M and N are the standard SPAKE2 generator points for Ed25519Group,
// matching the RustCrypto spake2 crate and Python spake2 library.
var (
	spake2M *edwards25519.Point
	spake2N *edwards25519.Point
)

func init() {
	var err error
	// M: 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
	spake2M, err = new(edwards25519.Point).SetBytes([]byte{
		0x15, 0xcf, 0xd1, 0x8e, 0x38, 0x59, 0x52, 0x98,
		0x2b, 0x6a, 0x8f, 0x8c, 0x78, 0x54, 0x96, 0x3b,
		0x58, 0xe3, 0x43, 0x88, 0xc8, 0xe6, 0xda, 0xe8,
		0x91, 0xdb, 0x75, 0x64, 0x81, 0xa0, 0x23, 0x12,
	})
	if err != nil {
		panic("failed to decode SPAKE2 M point: " + err.Error())
	}

	// N: f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
	spake2N, err = new(edwards25519.Point).SetBytes([]byte{
		0xf0, 0x4f, 0x2e, 0x7e, 0xb7, 0x34, 0xb2, 0xa8,
		0xf8, 0xb4, 0x72, 0xea, 0xf9, 0xc3, 0xc6, 0x32,
		0x57, 0x6a, 0xc6, 0x4a, 0xea, 0x65, 0x0b, 0x49,
		0x6a, 0x8a, 0x20, 0xff, 0x00, 0xe5, 0x83, 0xc3,
	})
	if err != nil {
		panic("failed to decode SPAKE2 N point: " + err.Error())
	}
}

// NewSpake2 initiates a SPAKE2 exchange.
// Returns the SPAKE2 state and the 33-byte outbound message (side prefix + point).
func NewSpake2(role Role, password []byte) (*Spake2, []byte, error) {
	// Generate random scalar (64 uniform bytes reduced mod L)
	var scalarBytes [64]byte
	if _, err := io.ReadFull(rand.Reader, scalarBytes[:]); err != nil {
		return nil, nil, fmt.Errorf("SPAKE2 random scalar generation failed: %w", err)
	}
	scalar, err := new(edwards25519.Scalar).SetUniformBytes(scalarBytes[:])
	if err != nil {
		return nil, nil, fmt.Errorf("SPAKE2 scalar creation failed: %w", err)
	}

	pwScalar := passwordToScalar(password)

	// T = scalar*G + pwScalar*(M or N)
	basePoint := new(edwards25519.Point).ScalarBaseMult(scalar)

	var blindingPoint *edwards25519.Point
	if role == RoleInitiator {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2M)
	} else {
		blindingPoint = new(edwards25519.Point).ScalarMult(pwScalar, spake2N)
	}

	pubPoint := new(edwards25519.Point).Add(basePoint, blindingPoint)
	pubBytes := pubPoint.Bytes() // 32 bytes

	// Prepend side byte: 0x41 ('A') for initiator, 0x42 ('B') for responder
	var sideByte byte
	if role == RoleInitiator {
		sideByte = 0x41
	} else {
		sideByte = 0x42
	}
	outbound := make([]byte, 33)
	outbound[0] = sideByte
	copy(outbound[1:], pubBytes)

	s := &Spake2{
		role:           role,
		password:       append([]byte(nil), password...),
		scalar:         scalar,
		passwordScalar: pwScalar,
		myMsg:          pubBytes,
	}

	return s, outbound, nil
}

// Finish completes the SPAKE2 exchange given the peer's 33-byte message.
// Returns the shared secret (32 bytes).
func (s *Spake2) Finish(inboundMessage []byte) ([32]byte, error) {
	if len(inboundMessage) != 33 {
		return [32]byte{}, fmt.Errorf("SPAKE2 invalid peer message length: expected 33, got %d", len(inboundMessage))
	}

	// Validate side byte
	peerSide := inboundMessage[0]
	if s.role == RoleInitiator && peerSide != 0x42 {
		return [32]byte{}, fmt.Errorf("SPAKE2 bad side byte: expected 0x42, got 0x%02x", peerSide)
	}
	if s.role == RoleResponder && peerSide != 0x41 {
		return [32]byte{}, fmt.Errorf("SPAKE2 bad side byte: expected 0x41, got 0x%02x", peerSide)
	}

	peerPoint, err := new(edwards25519.Point).SetBytes(inboundMessage[1:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 invalid peer message: %w", err)
	}

	// Remove blinding: unblinded = peer_T - pwScalar * (N or M)
	var blindingPoint *edwards25519.Point
	if s.role == RoleInitiator {
		blindingPoint = new(edwards25519.Point).ScalarMult(s.passwordScalar, spake2N)
	} else {
		blindingPoint = new(edwards25519.Point).ScalarMult(s.passwordScalar, spake2M)
	}

	negBlinding := new(edwards25519.Point).Negate(blindingPoint)
	unblinded := new(edwards25519.Point).Add(peerPoint, negBlinding)

	// K = scalar * unblinded
	sharedPoint := new(edwards25519.Point).ScalarMult(s.scalar, unblinded)
	kBytes := sharedPoint.Bytes()

	// Transcript hash matching RustCrypto spake2:
	// SHA256(SHA256(pw) || SHA256(idA) || SHA256(idB) || X_msg || Y_msg || K_bytes)
	var transcript [192]byte

	pwHash := sha256.Sum256(s.password)
	copy(transcript[0:32], pwHash[:])

	idAHash := sha256.Sum256([]byte("cairn-initiator"))
	copy(transcript[32:64], idAHash[:])

	idBHash := sha256.Sum256([]byte("cairn-responder"))
	copy(transcript[64:96], idBHash[:])

	peerMsg := inboundMessage[1:]
	if s.role == RoleInitiator {
		copy(transcript[96:128], s.myMsg)
		copy(transcript[128:160], peerMsg)
	} else {
		copy(transcript[96:128], peerMsg)
		copy(transcript[128:160], s.myMsg)
	}
	copy(transcript[160:192], kBytes)

	result := sha256.Sum256(transcript[:])
	return result, nil
}

// passwordToScalar derives an Ed25519 scalar from a password using HKDF-SHA256,
// matching the RustCrypto spake2 crate's hash_to_scalar.
func passwordToScalar(password []byte) *edwards25519.Scalar {
	// HKDF: salt=empty, ikm=password, info="SPAKE2 pw", len=48
	h := hkdf.New(sha256.New, password, []byte{}, []byte("SPAKE2 pw"))
	okm := make([]byte, 48)
	if _, err := io.ReadFull(h, okm); err != nil {
		panic("HKDF expand failed: " + err.Error())
	}

	// Reverse 48-byte big-endian HKDF output into 64-byte little-endian buffer,
	// then reduce mod L (matching Rust's from_bytes_mod_order_wide)
	var reducible [64]byte
	for i := 0; i < 48; i++ {
		reducible[47-i] = okm[i]
	}

	s, _ := new(edwards25519.Scalar).SetUniformBytes(reducible[:])
	return s
}
