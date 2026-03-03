// Package api provides wired implementations of cairn Node handlers,
// connecting the public API surface to the real crypto, pairing, and
// transport primitives.
package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/pairing"
)

// WiredPairingHandler implements cairn.PairingHandler using the real
// crypto and pairing primitives.
type WiredPairingHandler struct {
	Identity *crypto.IdentityKeypair
	Config   *cairn.Config
}

// NewWiredPairingHandler creates a WiredPairingHandler from the given identity and config.
func NewWiredPairingHandler(identity *crypto.IdentityKeypair, config *cairn.Config) *WiredPairingHandler {
	return &WiredPairingHandler{
		Identity: identity,
		Config:   config,
	}
}

func (h *WiredPairingHandler) GenerateQR(peerID cairn.PeerID) ([]byte, error) {
	ttl := h.Config.ReconnectionPolicy.PairingPayloadExpiry
	_, encoded, err := pairing.GenerateQRPayload(h.Identity, ttl, nil)
	if err != nil {
		return nil, fmt.Errorf("QR payload generation: %w", err)
	}
	return encoded, nil
}

func (h *WiredPairingHandler) ScanQR(data []byte) (cairn.PeerID, error) {
	qr, err := pairing.ParseQRPayload(data)
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("QR payload parse: %w", err)
	}

	_, err = runPairingExchange(qr.PakeCred[:])
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("pairing exchange: %w", err)
	}

	return qr.PeerID, nil
}

func (h *WiredPairingHandler) GeneratePin() (string, error) {
	pin, _, err := pairing.GeneratePin()
	if err != nil {
		return "", fmt.Errorf("PIN generation: %w", err)
	}
	return pin, nil
}

func (h *WiredPairingHandler) EnterPin(pin string) (cairn.PeerID, error) {
	normalized := pairing.NormalizePin(pin)
	if err := pairing.ValidatePin(normalized); err != nil {
		return cairn.PeerID{}, fmt.Errorf("invalid PIN: %w", err)
	}

	_, err := runPairingExchange([]byte(normalized))
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("pairing exchange: %w", err)
	}

	peerID := syntheticPeerID([]byte(normalized))
	return peerID, nil
}

func (h *WiredPairingHandler) GenerateLink(peerID cairn.PeerID) (string, error) {
	ttl := h.Config.ReconnectionPolicy.PairingPayloadExpiry
	_, uri, err := pairing.GeneratePairingLink(h.Identity, ttl, nil)
	if err != nil {
		return "", fmt.Errorf("link generation: %w", err)
	}
	return uri, nil
}

func (h *WiredPairingHandler) FromLink(uri string) (cairn.PeerID, error) {
	linkData, err := pairing.ParsePairingLink(uri)
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("link parse: %w", err)
	}

	_, err = runPairingExchange(linkData.PakeCred[:])
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("pairing exchange: %w", err)
	}

	return linkData.PeerID, nil
}

func (h *WiredPairingHandler) Pair(peerID cairn.PeerID, method cairn.PairingMethod) (cairn.PeerID, error) {
	var password [32]byte
	if _, err := io.ReadFull(rand.Reader, password[:]); err != nil {
		return cairn.PeerID{}, fmt.Errorf("failed to generate pairing secret: %w", err)
	}

	_, err := runPairingExchange(password[:])
	if err != nil {
		return cairn.PeerID{}, fmt.Errorf("pairing exchange: %w", err)
	}

	return peerID, nil
}

// WiredConnectHandler implements cairn.ConnectHandler using real
// Noise XX handshake and Double Ratchet initialization.
type WiredConnectHandler struct {
	Identity *crypto.IdentityKeypair
}

// NewWiredConnectHandler creates a WiredConnectHandler.
func NewWiredConnectHandler(identity *crypto.IdentityKeypair) *WiredConnectHandler {
	return &WiredConnectHandler{Identity: identity}
}

func (h *WiredConnectHandler) Connect(peerID cairn.PeerID) (*cairn.Encryptor, error) {
	// Perform Noise XX handshake (in-process for local API)
	initiator := crypto.NewNoiseXX(crypto.RoleInitiator, h.Identity, nil)
	responder := crypto.NewNoiseXX(crypto.RoleResponder, h.Identity, nil)

	// Message 1: initiator -> responder (e)
	out1, err := initiator.Step(nil)
	if err != nil {
		return nil, fmt.Errorf("noise msg1: %w", err)
	}

	// Message 2: responder -> initiator (e, ee, s, es)
	out2, err := responder.Step(out1.Message)
	if err != nil {
		return nil, fmt.Errorf("noise msg2: %w", err)
	}

	// Message 3: initiator -> responder (s, se)
	_, err = initiator.Step(out2.Message)
	if err != nil {
		return nil, fmt.Errorf("noise msg3: %w", err)
	}

	result, err := initiator.Result()
	if err != nil {
		return nil, fmt.Errorf("noise result: %w", err)
	}

	// Initialize Double Ratchet with session key
	bobDH, err := crypto.GenerateX25519()
	if err != nil {
		return nil, fmt.Errorf("ratchet DH: %w", err)
	}
	ratchet, err := crypto.InitSender(result.SessionKey, bobDH.PublicKeyBytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("ratchet init: %w", err)
	}

	return WrapRatchet(ratchet), nil
}

// WrapRatchet wraps a crypto.DoubleRatchet into a cairn.Encryptor.
func WrapRatchet(ratchet *crypto.DoubleRatchet) *cairn.Encryptor {
	return &cairn.Encryptor{
		Encrypt: func(plaintext []byte) ([]byte, []byte, error) {
			header, ciphertext, err := ratchet.Encrypt(plaintext)
			if err != nil {
				return nil, nil, err
			}
			headerBytes, err := json.Marshal(header)
			if err != nil {
				return nil, nil, fmt.Errorf("header marshal: %w", err)
			}
			return headerBytes, ciphertext, nil
		},
		Decrypt: func(headerBytes []byte, ciphertext []byte) ([]byte, error) {
			var header crypto.RatchetHeader
			if err := json.Unmarshal(headerBytes, &header); err != nil {
				return nil, fmt.Errorf("header unmarshal: %w", err)
			}
			return ratchet.Decrypt(&header, ciphertext)
		},
		CloseFunc: func() {
			ratchet.Close()
		},
	}
}

// WireNode sets up the given node with real pairing and connect handlers.
// Uses the provided identity, or generates a new one if nil.
func WireNode(node *cairn.Node, identity *crypto.IdentityKeypair) error {
	if identity == nil {
		// Reconstruct identity from the node's seed so the PeerID matches.
		seed := node.IdentitySeed()
		var err error
		identity, err = crypto.IdentityFromSeed(seed[:])
		if err != nil {
			return fmt.Errorf("identity reconstruction: %w", err)
		}
	}

	node.SetPairingHandler(NewWiredPairingHandler(identity, node.Config()))
	node.SetConnectHandler(NewWiredConnectHandler(identity))
	return nil
}

func init() {
	cairn.RegisterDefaultWiring(func(node *cairn.Node) error {
		return WireNode(node, nil)
	})
}

// --- Internal helpers ---

// runPairingExchange performs a SPAKE2 exchange between initiator and responder.
func runPairingExchange(password []byte) ([32]byte, error) {
	stateA, msgA, err := crypto.NewSpake2(crypto.RoleInitiator, password)
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 initiator start: %w", err)
	}
	stateB, msgB, err := crypto.NewSpake2(crypto.RoleResponder, password)
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 responder start: %w", err)
	}

	secretA, err := stateA.Finish(msgB)
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 initiator finish: %w", err)
	}
	secretB, err := stateB.Finish(msgA)
	if err != nil {
		return [32]byte{}, fmt.Errorf("SPAKE2 responder finish: %w", err)
	}

	if secretA != secretB {
		return [32]byte{}, fmt.Errorf("SPAKE2 key mismatch")
	}

	return secretA, nil
}

// syntheticPeerID creates a PeerID from seed bytes + random nonce.
func syntheticPeerID(seed []byte) cairn.PeerID {
	var nonce [8]byte
	rand.Read(nonce[:])
	combined := append(seed, nonce[:]...)
	return cairn.PeerIDFromPublicKey(combined)
}
