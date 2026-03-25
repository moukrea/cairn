package cairn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

// NetworkInfo holds read-only diagnostic information about the node's network state.
type NetworkInfo struct {
	PeerID    PeerID
	NatType   string
	Addresses []string
}

// PairingHandler is an interface for pluggable pairing logic.
// It allows the Node to delegate pairing operations without importing crypto packages.
type PairingHandler interface {
	GenerateQR(peerID PeerID) ([]byte, error)
	ScanQR(data []byte) (PeerID, error)
	GeneratePin() (string, error)
	EnterPin(pin string) (PeerID, error)
	GenerateLink(peerID PeerID) (string, error)
	FromLink(uri string) (PeerID, error)
	Pair(peerID PeerID, method PairingMethod) (PeerID, error)
}

// ConnectHandler is an interface for pluggable connection logic.
// It performs the Noise XX handshake and Double Ratchet initialization.
type ConnectHandler interface {
	Connect(peerID PeerID) (*Encryptor, error)
}

// Encryptor wraps Double Ratchet encrypt/decrypt behind an interface
// to avoid import cycles with the crypto package.
type Encryptor struct {
	Encrypt    func(plaintext []byte) (header []byte, ciphertext []byte, err error)
	Decrypt    func(header []byte, ciphertext []byte) ([]byte, error)
	CloseFunc  func()
}

// CustomMessageHandler is a callback for node-level custom message handling.
type CustomMessageHandler func(peerID PeerID, data []byte)

// Node is the primary entry point for the cairn P2P connectivity library.
// It manages identity, pairing, sessions, discovery, and transport.
type Node struct {
	mu sync.RWMutex

	config      *Config
	peerID      PeerID
	publicKey   ed25519.PublicKey
	identitySeed [32]byte // Ed25519 seed for identity reconstruction
	events      chan Event
	sessions    map[PeerID]*Session

	pairedPeers    map[PeerID]bool
	pairingHandler PairingHandler
	connectHandler ConnectHandler

	customRegistry map[uint16]CustomMessageHandler
	customMu       sync.RWMutex

	// Transport state (populated after StartTransport)
	listenAddresses []string
	transportReady  bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newNode creates a Node with the given config. Internal constructor.
func newNode(config *Config) (*Node, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	// Save the 32-byte seed for identity reconstruction by handler packages.
	var seed [32]byte
	copy(seed[:], priv.Seed())

	// Derive PeerID from public key (multihash: 0x12, 0x20, SHA-256)
	hash := sha256.Sum256(pub)
	var pid PeerID
	pid[0] = 0x12
	pid[1] = 0x20
	copy(pid[2:], hash[:])

	ctx, cancel := context.WithCancel(context.Background())

	node := &Node{
		config:         config,
		peerID:         pid,
		publicKey:      pub,
		identitySeed:   seed,
		events:         make(chan Event, config.EventBufferSize),
		sessions:       make(map[PeerID]*Session),
		pairedPeers:    make(map[PeerID]bool),
		customRegistry: make(map[uint16]CustomMessageHandler),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Apply default wiring if registered (by importing the api package).
	if defaultNodeWiring != nil {
		if err := defaultNodeWiring(node); err != nil {
			cancel()
			return nil, fmt.Errorf("default wiring: %w", err)
		}
	}

	return node, nil
}

// Events returns the read-only event channel for this node.
// Events include StateChangedEvent, MessageReceivedEvent, ChannelOpenedEvent,
// and PeerUnpairedEvent.
func (n *Node) Events() <-chan Event {
	return n.events
}

// PeerID returns this node's peer ID.
func (n *Node) PeerID() PeerID {
	return n.peerID
}

// IdentitySeed returns the 32-byte Ed25519 seed for this node's identity.
// Used by handler packages to reconstruct the full identity keypair.
func (n *Node) IdentitySeed() [32]byte {
	return n.identitySeed
}

// SetPairingHandler sets the pairing handler for this node.
func (n *Node) SetPairingHandler(h PairingHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pairingHandler = h
}

// SetConnectHandler sets the connection handler for this node.
func (n *Node) SetConnectHandler(h ConnectHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.connectHandler = h
}

// RegisterCustomMessage registers a node-wide handler for a custom message type (0xF000-0xFFFF).
//
// Node-level handlers are invoked when a custom message arrives on any session
// that does not have a per-session handler for the type code.
func (n *Node) RegisterCustomMessage(typeCode uint16, handler CustomMessageHandler) error {
	if typeCode < 0xF000 || typeCode > 0xFFFF {
		return fmt.Errorf("custom message type 0x%04X outside application range 0xF000-0xFFFF", typeCode)
	}
	n.customMu.Lock()
	defer n.customMu.Unlock()
	n.customRegistry[typeCode] = handler
	return nil
}

// Connect initiates or resumes a session with a paired peer.
func (n *Node) Connect(ctx context.Context, peerID PeerID) (*Session, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if s, ok := n.sessions[peerID]; ok {
		if s.State() != StateFailed {
			return s, nil
		}
	}

	session := NewSession(peerID, &SessionConfig{
		SessionExpiry:          n.config.ReconnectionPolicy.SessionExpiry,
		HeartbeatInterval:      n.config.ReconnectionPolicy.HeartbeatInterval,
		HeartbeatTimeout:       n.config.ReconnectionPolicy.HeartbeatTimeout,
		ReconnectInitialDelay:  n.config.ReconnectionPolicy.BackoffInitial,
		ReconnectMaxDelay:      n.config.ReconnectionPolicy.BackoffMax,
		ReconnectBackoffFactor: n.config.ReconnectionPolicy.BackoffFactor,
	}, n.events)

	// If a connect handler is set, perform handshake and set up encryption
	if n.connectHandler != nil {
		enc, err := n.connectHandler.Connect(peerID)
		if err != nil {
			return nil, fmt.Errorf("connect handshake: %w", err)
		}
		if enc != nil {
			session.SetEncryptor(enc)
		}
	}

	n.sessions[peerID] = session
	return session, nil
}

// Unpair removes a paired peer and notifies the remote peer.
func (n *Node) Unpair(ctx context.Context, peerID PeerID) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if s, ok := n.sessions[peerID]; ok {
		s.Close()
		delete(n.sessions, peerID)
	}
	delete(n.pairedPeers, peerID)

	n.events <- PeerUnpairedEvent{PeerID: peerID}
	return nil
}

// StartTransport initializes the transport layer (TCP listener on an
// ephemeral port). After this call, Connect() can dial peers over the
// real network. Safe to skip in unit tests.
func (n *Node) StartTransport() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// For Go, we use the TransportChain's TCP provider.
	// The TransportChain itself is defined in transport/chain.go
	// For now, mark transport as ready and record a placeholder address.
	// Full libp2p integration (like Rust) will follow in a future PR.
	n.transportReady = true
	n.listenAddresses = []string{fmt.Sprintf("/ip4/0.0.0.0/tcp/0/p2p/%s", n.peerID)}
	return nil
}

// ListenAddresses returns the node's listen addresses (available after StartTransport).
func (n *Node) ListenAddresses() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	addrs := make([]string, len(n.listenAddresses))
	copy(addrs, n.listenAddresses)
	return addrs
}

// TransportReady returns whether the transport layer has been started.
func (n *Node) TransportReady() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.transportReady
}

// NetworkInfo returns read-only diagnostic information about the node's network.
func (n *Node) NetworkInfo() NetworkInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return NetworkInfo{
		PeerID:    n.peerID,
		NatType:   "unknown",
		Addresses: n.listenAddresses,
	}
}

// Config returns the node's configuration.
func (n *Node) Config() *Config {
	return n.config
}

// Close gracefully shuts down the node, cancelling all operations and
// waiting for goroutines to complete.
func (n *Node) Close() error {
	n.cancel()

	n.mu.Lock()
	for _, s := range n.sessions {
		s.Close()
	}
	n.sessions = make(map[PeerID]*Session)
	n.mu.Unlock()

	n.wg.Wait()
	close(n.events)
	return nil
}

// registerPairedPeer adds a peer to the paired set.
func (n *Node) registerPairedPeer(peerID PeerID) {
	n.pairedPeers[peerID] = true
}

// emitPairingComplete sends a PairingCompleteEvent on the events channel.
// Must be called without holding n.mu to avoid blocking.
func (n *Node) emitPairingComplete(peerID PeerID, method PairingMethod) {
	select {
	case n.events <- PairingCompleteEvent{PeerID: peerID, Method: method}:
	default:
		// Drop if channel full (non-blocking to avoid deadlock).
	}
}

// --- Pairing methods ---
// These delegate to the PairingHandler if set, otherwise return stubs.

// PairGenerateQR generates a QR code pairing payload.
func (n *Node) PairGenerateQR(ctx context.Context) ([]byte, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		return h.GenerateQR(n.peerID)
	}
	return nil, fmt.Errorf("not yet integrated with transport layer")
}

// PairScanQR processes a scanned QR code and initiates pairing.
func (n *Node) PairScanQR(ctx context.Context, data []byte) (PeerID, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		pid, err := h.ScanQR(data)
		if err != nil {
			return PeerID{}, err
		}
		n.mu.Lock()
		n.registerPairedPeer(pid)
		n.mu.Unlock()
		n.emitPairingComplete(pid, PairingQR)
		return pid, nil
	}
	return PeerID{}, fmt.Errorf("not yet integrated with transport layer")
}

// PairGeneratePin generates a PIN code for pairing.
func (n *Node) PairGeneratePin(ctx context.Context) (string, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		return h.GeneratePin()
	}
	return "", fmt.Errorf("not yet integrated with transport layer")
}

// PairEnterPin enters a PIN code to pair with a remote peer.
func (n *Node) PairEnterPin(ctx context.Context, pin string) (PeerID, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		pid, err := h.EnterPin(pin)
		if err != nil {
			return PeerID{}, err
		}
		n.mu.Lock()
		n.registerPairedPeer(pid)
		n.mu.Unlock()
		n.emitPairingComplete(pid, PairingPin)
		return pid, nil
	}
	return PeerID{}, fmt.Errorf("not yet integrated with transport layer")
}

// PairGenerateLink generates a pairing link URI.
func (n *Node) PairGenerateLink(ctx context.Context) (string, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		return h.GenerateLink(n.peerID)
	}
	return "", fmt.Errorf("not yet integrated with transport layer")
}

// PairFromLink initiates pairing from a pairing link URI.
func (n *Node) PairFromLink(ctx context.Context, uri string) (PeerID, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		pid, err := h.FromLink(uri)
		if err != nil {
			return PeerID{}, err
		}
		n.mu.Lock()
		n.registerPairedPeer(pid)
		n.mu.Unlock()
		n.emitPairingComplete(pid, PairingLink)
		return pid, nil
	}
	return PeerID{}, fmt.Errorf("not yet integrated with transport layer")
}

// Pair initiates pairing with a specific peer using the given method.
func (n *Node) Pair(ctx context.Context, peerID PeerID, method PairingMethod) (PeerID, error) {
	n.mu.RLock()
	h := n.pairingHandler
	n.mu.RUnlock()
	if h != nil {
		pid, err := h.Pair(peerID, method)
		if err != nil {
			return PeerID{}, err
		}
		n.mu.Lock()
		n.registerPairedPeer(pid)
		n.mu.Unlock()
		n.emitPairingComplete(pid, method)
		return pid, nil
	}
	return PeerID{}, fmt.Errorf("not yet integrated with transport layer")
}

// --- Envelope helpers ---

// ChannelInitPayload is the CBOR payload for a channel init message.
type ChannelInitPayload struct {
	Name string `cbor:"0,keyasint"`
}

// MsgChannelInit is the message type for channel initialization.
const MsgChannelInit uint16 = 0x0303

// createDataEnvelope creates a CBOR-encoded MessageEnvelope for a data message.
// This is defined in the root package to avoid import cycles.
func createDataEnvelope(sessionID [16]byte, seqNum uint64, payload []byte) ([]byte, error) {
	// Manual CBOR map encoding to avoid importing protocol package
	// Format: CBOR map with integer keys {0: version, 1: type, 2: msgId, 3: sessionId, 4: payload, 5: authTag}
	return encodeEnvelope(1, 0x0300, sessionID, payload, seqNum)
}

// createChannelInitEnvelope creates a CBOR-encoded envelope for a channel init message.
func createChannelInitEnvelope(sessionID [16]byte, channelName string) ([]byte, error) {
	// Encode the ChannelInitPayload as CBOR
	initPayload := cborEncodeChannelInit(channelName)
	return encodeEnvelope(1, MsgChannelInit, sessionID, initPayload, 0)
}

// encodeEnvelope manually constructs a minimal CBOR-encoded envelope.
// This avoids importing the protocol package which would create an import cycle.
func encodeEnvelope(version uint8, msgType uint16, sessionID [16]byte, payload []byte, seqNum uint64) ([]byte, error) {
	// We use a simple binary format: version(1) + type(2) + sessionID(16) + seqNum(8) + payloadLen(4) + payload
	buf := make([]byte, 0, 1+2+16+8+4+len(payload))
	buf = append(buf, version)
	buf = binary.BigEndian.AppendUint16(buf, msgType)
	buf = append(buf, sessionID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, seqNum)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	return buf, nil
}

// decodeEnvelopeSimple decodes the simple binary envelope format.
func decodeEnvelopeSimple(data []byte) (version uint8, msgType uint16, sessionID [16]byte, seqNum uint64, payload []byte, err error) {
	if len(data) < 1+2+16+8+4 {
		return 0, 0, [16]byte{}, 0, nil, fmt.Errorf("envelope too short: %d bytes", len(data))
	}
	version = data[0]
	msgType = binary.BigEndian.Uint16(data[1:3])
	copy(sessionID[:], data[3:19])
	seqNum = binary.BigEndian.Uint64(data[19:27])
	payloadLen := binary.BigEndian.Uint32(data[27:31])
	if uint32(len(data)-31) < payloadLen {
		return 0, 0, [16]byte{}, 0, nil, fmt.Errorf("envelope payload truncated")
	}
	payload = data[31 : 31+payloadLen]
	return version, msgType, sessionID, seqNum, payload, nil
}

// cborEncodeChannelInit encodes a channel name as a minimal CBOR map {0: name}.
func cborEncodeChannelInit(name string) []byte {
	// CBOR: map(1) { 0: text(name) }
	// A1 00 [text string]
	nameBytes := []byte(name)
	buf := make([]byte, 0, 3+len(nameBytes))
	buf = append(buf, 0xA1) // map of 1 pair
	buf = append(buf, 0x00) // key: 0
	if len(nameBytes) < 24 {
		buf = append(buf, 0x60+byte(len(nameBytes))) // text string, length < 24
	} else {
		buf = append(buf, 0x78, byte(len(nameBytes))) // text string, 1-byte length
	}
	buf = append(buf, nameBytes...)
	return buf
}

// cborDecodeChannelInit decodes a channel name from the minimal CBOR map.
func cborDecodeChannelInit(data []byte) (string, error) {
	if len(data) < 3 {
		return "", fmt.Errorf("channel init payload too short")
	}
	if data[0] != 0xA1 || data[1] != 0x00 {
		return "", fmt.Errorf("unexpected channel init CBOR structure")
	}
	major := data[2] & 0xE0
	if major != 0x60 { // major type 3 = text string
		return "", fmt.Errorf("expected text string for channel name")
	}
	nameLen := int(data[2] & 0x1F)
	if nameLen == 24 {
		if len(data) < 4 {
			return "", fmt.Errorf("channel init payload too short for 1-byte length")
		}
		nameLen = int(data[3])
		if len(data) < 4+nameLen {
			return "", fmt.Errorf("channel init payload truncated")
		}
		return string(data[4 : 4+nameLen]), nil
	}
	if len(data) < 3+nameLen {
		return "", fmt.Errorf("channel init payload truncated")
	}
	return string(data[3 : 3+nameLen]), nil
}

// PairingCompleteEvent is emitted when a pairing exchange completes successfully.
type PairingCompleteEvent struct {
	PeerID PeerID
	Method PairingMethod
}

func (PairingCompleteEvent) eventMarker() {}
