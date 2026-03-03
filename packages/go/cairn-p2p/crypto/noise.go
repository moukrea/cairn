package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// ProtocolName is the Noise protocol name used to initialize the handshake hash.
const ProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

const (
	dhKeySize     = 32
	ed25519PubLen = 32
	tagSize       = 16 // ChaCha20-Poly1305 tag
)

var zeroNonce [12]byte

// EmojiTable is the 64-entry table for emoji SAS derivation.
var EmojiTable = [64]string{
	"dog", "cat", "fish", "bird", "bear", "lion", "wolf", "fox",
	"deer", "owl", "bee", "ant", "star", "moon", "sun", "fire",
	"tree", "leaf", "rose", "wave", "rain", "snow", "bolt", "wind",
	"rock", "gem", "bell", "key", "lock", "flag", "book", "pen",
	"cup", "hat", "shoe", "ring", "cake", "gift", "lamp", "gear",
	"ship", "car", "bike", "drum", "horn", "harp", "dice", "coin",
	"map", "tent", "crown", "sword", "shield", "bow", "axe", "hammer",
	"anchor", "wheel", "clock", "heart", "skull", "ghost", "robot", "alien",
}

// Role identifies the handshake role.
type Role int

const (
	RoleInitiator Role = iota
	RoleResponder
)

type handshakeState int

const (
	stateInitiatorStart handshakeState = iota
	stateResponderWaitMsg1
	stateInitiatorWaitMsg2
	stateResponderWaitMsg3
	stateComplete
)

// HandshakeResult is the output of a completed Noise XX handshake.
type HandshakeResult struct {
	SessionKey     [32]byte
	RemoteStatic   ed25519.PublicKey
	TranscriptHash [32]byte
}

// StepOutput is the output of a single handshake step.
type StepOutput struct {
	Message  []byte           // non-nil if we need to send
	Complete *HandshakeResult // non-nil if handshake finished
}

// NoiseXXHandshake implements the Noise XX pattern state machine.
type NoiseXXHandshake struct {
	role  Role
	state handshakeState

	localIdentity      *IdentityKeypair
	localStaticX25519  [32]byte // private key
	localEphemeral     *[32]byte
	localEphemeralPub  *[32]byte
	remoteEphemeral    *[32]byte
	remoteStatic       ed25519.PublicKey
	chainingKey        [32]byte
	handshakeHash      [32]byte
	currentKey         *[32]byte
	pakeSecret         *[32]byte
	cachedResult       *HandshakeResult
}

// NewNoiseXX creates a new Noise XX handshake state machine.
func NewNoiseXX(role Role, identity *IdentityKeypair, pakeSecret []byte) *NoiseXXHandshake {
	// Convert Ed25519 signing key to X25519 private key
	localStaticX25519 := ed25519PrivateToX25519(identity.privateKey)

	// Initialize handshake hash from protocol name (Noise spec section 5.2).
	// If protocol name <= 32 bytes, pad with zeros. If > 32, hash it.
	var handshakeHash [32]byte
	if len(ProtocolName) <= 32 {
		copy(handshakeHash[:], ProtocolName)
	} else {
		handshakeHash = sha256.Sum256([]byte(ProtocolName))
	}

	chainingKey := handshakeHash

	state := stateInitiatorStart
	if role == RoleResponder {
		state = stateResponderWaitMsg1
	}

	h := &NoiseXXHandshake{
		role:              role,
		state:             state,
		localIdentity:     identity,
		localStaticX25519: localStaticX25519,
		chainingKey:       chainingKey,
		handshakeHash:     handshakeHash,
	}

	if len(pakeSecret) == 32 {
		var ps [32]byte
		copy(ps[:], pakeSecret)
		h.pakeSecret = &ps
	}

	return h
}

// Step processes the next handshake step.
func (h *NoiseXXHandshake) Step(input []byte) (*StepOutput, error) {
	switch h.state {
	case stateInitiatorStart:
		if input != nil {
			return nil, fmt.Errorf("initiator start expects no input")
		}
		return h.initiatorSendMsg1()
	case stateResponderWaitMsg1:
		if input == nil {
			return nil, fmt.Errorf("responder expects message 1 input")
		}
		return h.responderRecvMsg1SendMsg2(input)
	case stateInitiatorWaitMsg2:
		if input == nil {
			return nil, fmt.Errorf("initiator expects message 2 input")
		}
		return h.initiatorRecvMsg2SendMsg3(input)
	case stateResponderWaitMsg3:
		if input == nil {
			return nil, fmt.Errorf("responder expects message 3 input")
		}
		return h.responderRecvMsg3(input)
	case stateComplete:
		return nil, fmt.Errorf("handshake already complete")
	default:
		return nil, fmt.Errorf("invalid handshake state")
	}
}

// Result returns the cached handshake result for the initiator after msg3 is sent.
func (h *NoiseXXHandshake) Result() (*HandshakeResult, error) {
	if h.cachedResult == nil {
		return nil, fmt.Errorf("handshake not yet complete")
	}
	return h.cachedResult, nil
}

// --- Message 1: -> e ---

func (h *NoiseXXHandshake) initiatorSendMsg1() (*StepOutput, error) {
	ephPriv, ephPub, err := generateX25519Keypair()
	if err != nil {
		return nil, err
	}

	h.mixHash(ephPub[:])
	h.localEphemeral = &ephPriv
	h.localEphemeralPub = &ephPub

	msg := make([]byte, 32)
	copy(msg, ephPub[:])

	h.state = stateInitiatorWaitMsg2
	return &StepOutput{Message: msg}, nil
}

// --- Message 2: <- e, ee, s, es ---

func (h *NoiseXXHandshake) responderRecvMsg1SendMsg2(msg1 []byte) (*StepOutput, error) {
	if len(msg1) != dhKeySize {
		return nil, fmt.Errorf("message 1 invalid length: expected %d, got %d", dhKeySize, len(msg1))
	}

	var remoteE [32]byte
	copy(remoteE[:], msg1)
	h.mixHash(remoteE[:])
	h.remoteEphemeral = &remoteE

	// e: generate responder ephemeral
	ephPriv, ephPub, err := generateX25519Keypair()
	if err != nil {
		return nil, err
	}
	h.mixHash(ephPub[:])
	h.localEphemeral = &ephPriv
	h.localEphemeralPub = &ephPub

	var msg2 []byte
	msg2 = append(msg2, ephPub[:]...)

	// ee: DH(responder_ephemeral, initiator_ephemeral)
	eeShared, err := x25519DH(ephPriv, remoteE)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(eeShared); err != nil {
		return nil, err
	}

	// s: encrypt and send our static Ed25519 public key
	staticPubBytes := []byte(h.localIdentity.PublicKey())
	encryptedStatic, err := h.encryptAndHash(staticPubBytes)
	if err != nil {
		return nil, err
	}
	msg2 = append(msg2, encryptedStatic...)

	// es: DH(responder_static_x25519, initiator_ephemeral)
	esShared, err := x25519DH(h.localStaticX25519, remoteE)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(esShared); err != nil {
		return nil, err
	}

	// Encrypt empty payload
	encryptedPayload, err := h.encryptAndHash(nil)
	if err != nil {
		return nil, err
	}
	msg2 = append(msg2, encryptedPayload...)

	h.state = stateResponderWaitMsg3
	return &StepOutput{Message: msg2}, nil
}

// --- Initiator: recv message 2, send message 3 ---

func (h *NoiseXXHandshake) initiatorRecvMsg2SendMsg3(msg2 []byte) (*StepOutput, error) {
	minLen := dhKeySize + (ed25519PubLen + tagSize) + tagSize
	if len(msg2) < minLen {
		return nil, fmt.Errorf("message 2 too short: expected at least %d, got %d", minLen, len(msg2))
	}

	offset := 0

	// e: responder ephemeral
	var remoteE [32]byte
	copy(remoteE[:], msg2[offset:offset+dhKeySize])
	h.mixHash(remoteE[:])
	offset += dhKeySize
	h.remoteEphemeral = &remoteE

	// ee: DH(initiator_ephemeral, responder_ephemeral)
	if h.localEphemeral == nil {
		return nil, fmt.Errorf("missing local ephemeral for ee DH")
	}
	eeShared, err := x25519DH(*h.localEphemeral, remoteE)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(eeShared); err != nil {
		return nil, err
	}

	// s: decrypt responder's static public key
	encryptedStatic := msg2[offset : offset+ed25519PubLen+tagSize]
	staticPubBytes, err := h.decryptAndHash(encryptedStatic)
	if err != nil {
		return nil, err
	}
	offset += ed25519PubLen + tagSize

	if len(staticPubBytes) != ed25519PubLen {
		return nil, fmt.Errorf("decrypted static key wrong size")
	}

	remoteStaticPub := ed25519.PublicKey(staticPubBytes)
	h.remoteStatic = remoteStaticPub

	// Convert remote Ed25519 public key to X25519 for DH
	remoteStaticX25519 := ed25519PublicToX25519(remoteStaticPub)

	// es: DH(initiator_ephemeral, responder_static_x25519)
	esShared, err := x25519DH(*h.localEphemeral, remoteStaticX25519)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(esShared); err != nil {
		return nil, err
	}

	// Decrypt payload from message 2
	encryptedPayload := msg2[offset:]
	if _, err := h.decryptAndHash(encryptedPayload); err != nil {
		return nil, err
	}

	// Now build message 3: -> s, se
	var msg3 []byte

	// s: encrypt initiator's static Ed25519 public key
	ourStaticPub := []byte(h.localIdentity.PublicKey())
	encryptedOurStatic, err := h.encryptAndHash(ourStaticPub)
	if err != nil {
		return nil, err
	}
	msg3 = append(msg3, encryptedOurStatic...)

	// se: DH(initiator_static_x25519, responder_ephemeral)
	seShared, err := x25519DH(h.localStaticX25519, remoteE)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(seShared); err != nil {
		return nil, err
	}

	// Mix in PAKE secret if present
	if h.pakeSecret != nil {
		if err := h.mixKey(*h.pakeSecret); err != nil {
			return nil, err
		}
	}

	// Encrypt empty payload for message 3
	encPayload, err := h.encryptAndHash(nil)
	if err != nil {
		return nil, err
	}
	msg3 = append(msg3, encPayload...)

	// Derive session key
	sessionKey, err := h.deriveSessionKey()
	if err != nil {
		return nil, err
	}

	h.state = stateComplete
	h.cachedResult = &HandshakeResult{
		SessionKey:     sessionKey,
		RemoteStatic:   remoteStaticPub,
		TranscriptHash: h.handshakeHash,
	}

	return &StepOutput{Message: msg3}, nil
}

// --- Message 3: responder receives -> s, se ---

func (h *NoiseXXHandshake) responderRecvMsg3(msg3 []byte) (*StepOutput, error) {
	minLen := (ed25519PubLen + tagSize) + tagSize
	if len(msg3) < minLen {
		return nil, fmt.Errorf("message 3 too short: expected at least %d, got %d", minLen, len(msg3))
	}

	offset := 0

	// s: decrypt initiator's static public key
	encryptedStatic := msg3[offset : offset+ed25519PubLen+tagSize]
	staticPubBytes, err := h.decryptAndHash(encryptedStatic)
	if err != nil {
		return nil, err
	}
	offset += ed25519PubLen + tagSize

	if len(staticPubBytes) != ed25519PubLen {
		return nil, fmt.Errorf("decrypted static key wrong size")
	}

	remoteStaticPub := ed25519.PublicKey(staticPubBytes)
	h.remoteStatic = remoteStaticPub

	// Convert remote Ed25519 to X25519
	remoteStaticX25519 := ed25519PublicToX25519(remoteStaticPub)

	// se: DH(responder_ephemeral, initiator_static_x25519)
	if h.localEphemeral == nil {
		return nil, fmt.Errorf("missing local ephemeral for se DH")
	}
	seShared, err := x25519DH(*h.localEphemeral, remoteStaticX25519)
	if err != nil {
		return nil, err
	}
	if err := h.mixKey(seShared); err != nil {
		return nil, err
	}

	// Mix in PAKE secret if present
	if h.pakeSecret != nil {
		if err := h.mixKey(*h.pakeSecret); err != nil {
			return nil, err
		}
	}

	// Decrypt payload
	encryptedPayload := msg3[offset:]
	if _, err := h.decryptAndHash(encryptedPayload); err != nil {
		return nil, err
	}

	// Derive session key
	sessionKey, err := h.deriveSessionKey()
	if err != nil {
		return nil, err
	}

	h.state = stateComplete
	return &StepOutput{
		Complete: &HandshakeResult{
			SessionKey:     sessionKey,
			RemoteStatic:   remoteStaticPub,
			TranscriptHash: h.handshakeHash,
		},
	}, nil
}

// --- Noise symmetric state operations ---

func (h *NoiseXXHandshake) mixKey(inputKeyMaterial [32]byte) error {
	output, err := HkdfSHA256(inputKeyMaterial[:], h.chainingKey[:], []byte(""), 64)
	if err != nil {
		return err
	}
	copy(h.chainingKey[:], output[:32])
	var derivedKey [32]byte
	copy(derivedKey[:], output[32:64])
	h.currentKey = &derivedKey
	return nil
}

func (h *NoiseXXHandshake) mixHash(data []byte) {
	hasher := sha256.New()
	hasher.Write(h.handshakeHash[:])
	hasher.Write(data)
	copy(h.handshakeHash[:], hasher.Sum(nil))
}

func (h *NoiseXXHandshake) encryptAndHash(plaintext []byte) ([]byte, error) {
	if h.currentKey == nil {
		return nil, fmt.Errorf("no encryption key available (mixKey not called)")
	}
	ciphertext, err := AeadEncrypt(CipherChaCha20Poly1305, *h.currentKey, zeroNonce, plaintext, h.handshakeHash[:])
	if err != nil {
		return nil, err
	}
	h.mixHash(ciphertext)
	return ciphertext, nil
}

func (h *NoiseXXHandshake) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if h.currentKey == nil {
		return nil, fmt.Errorf("no decryption key available (mixKey not called)")
	}
	hBefore := h.handshakeHash
	h.mixHash(ciphertext)
	return AeadDecrypt(CipherChaCha20Poly1305, *h.currentKey, zeroNonce, ciphertext, hBefore[:])
}

func (h *NoiseXXHandshake) deriveSessionKey() ([32]byte, error) {
	out, err := HkdfSHA256(h.chainingKey[:], nil, HkdfInfoSessionKey, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], out)
	return key, nil
}

// --- Key conversion helpers ---

// ed25519PrivateToX25519 converts an Ed25519 private key to an X25519 private key.
// This mirrors the Rust `SigningKey.to_scalar_bytes()` operation.
func ed25519PrivateToX25519(priv ed25519.PrivateKey) [32]byte {
	// Ed25519 private key seed is the first 32 bytes. Hash it with SHA-512
	// and clamp to get the X25519 scalar, same as ed25519-dalek's to_scalar_bytes().
	h := sha512Sum(priv.Seed())
	// Clamp for X25519
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	var result [32]byte
	copy(result[:], h[:32])
	return result
}

// sha512Sum computes SHA-512. Ed25519 key derivation uses SHA-512.
func sha512Sum(data []byte) [64]byte {
	return sha512.Sum512(data)
}

// ed25519PublicToX25519 converts an Ed25519 public key to an X25519 public key.
// This mirrors the Rust `VerifyingKey.to_montgomery()` operation.
func ed25519PublicToX25519(pub ed25519.PublicKey) [32]byte {
	// Use filippo.io/edwards25519 for the conversion
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		// Should not happen with a valid Ed25519 public key
		var zero [32]byte
		return zero
	}
	montgomery := p.BytesMontgomery()
	var result [32]byte
	copy(result[:], montgomery)
	return result
}

// --- X25519 helpers ---

func generateX25519Keypair() (priv [32]byte, pub [32]byte, err error) {
	kp, err := GenerateX25519()
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return kp.PrivateKeyBytes(), kp.PublicKeyBytes(), nil
}

func x25519DH(priv, peerPub [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("X25519 DH failed: %w", err)
	}
	var result [32]byte
	copy(result[:], shared)
	return result, nil
}

// --- SAS Derivation ---

// NumericSAS derives a 6-digit numeric SAS from the handshake transcript hash.
func NumericSAS(transcriptHash [32]byte) (string, error) {
	derived, err := HkdfSHA256(transcriptHash[:], nil, HkdfInfoSAS, 4)
	if err != nil {
		return "", err
	}
	value := uint32(derived[0])<<24 | uint32(derived[1])<<16 | uint32(derived[2])<<8 | uint32(derived[3])
	value = value % 1_000_000
	return fmt.Sprintf("%06d", value), nil
}

// EmojiSAS derives a 4-emoji SAS from the handshake transcript hash.
func EmojiSAS(transcriptHash [32]byte) ([]string, error) {
	derived, err := HkdfSHA256(transcriptHash[:], nil, HkdfInfoSAS, 4)
	if err != nil {
		return nil, err
	}
	emojis := make([]string, 4)
	for i := 0; i < 4; i++ {
		emojis[i] = EmojiTable[derived[i]%64]
	}
	return emojis, nil
}
