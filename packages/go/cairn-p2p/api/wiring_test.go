package api

import (
	"context"
	"encoding/binary"
	"testing"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createWiredNode(t *testing.T) *cairn.Node {
	t.Helper()
	node, err := cairn.Create()
	require.NoError(t, err)
	err = WireNode(node, nil)
	require.NoError(t, err)
	return node
}

// --- Pairing tests ---

func TestPairGenerateQR(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	payload, err := node.PairGenerateQR(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestPairScanQRRoundtrip(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	payload, err := node.PairGenerateQR(context.Background())
	require.NoError(t, err)

	peerID, err := node.PairScanQR(context.Background(), payload)
	require.NoError(t, err)
	assert.NotEqual(t, cairn.PeerID{}, peerID)
}

func TestPairScanQRRejectsInvalidCBOR(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	_, err := node.PairScanQR(context.Background(), []byte{0xFF, 0xFF})
	assert.Error(t, err)
}

func TestPairGeneratePin(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pin, err := node.PairGeneratePin(context.Background())
	require.NoError(t, err)
	assert.Len(t, pin, 9) // XXXX-XXXX
	assert.Equal(t, byte('-'), pin[4])
}

func TestPairEnterPinValid(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	peerID, err := node.PairEnterPin(context.Background(), "ABCD-EFGH")
	require.NoError(t, err)
	assert.NotEqual(t, cairn.PeerID{}, peerID)
}

func TestPairEnterPinInvalidChars(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	_, err := node.PairEnterPin(context.Background(), "!!!")
	assert.Error(t, err)
}

func TestPairGenerateLink(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	uri, err := node.PairGenerateLink(context.Background())
	require.NoError(t, err)
	assert.Contains(t, uri, "cairn://pair?")
	assert.Contains(t, uri, "pid=")
}

func TestPairFromLinkRoundtrip(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	uri, err := node.PairGenerateLink(context.Background())
	require.NoError(t, err)

	peerID, err := node.PairFromLink(context.Background(), uri)
	require.NoError(t, err)
	assert.NotEqual(t, cairn.PeerID{}, peerID)
}

func TestPairFromLinkRejectsInvalidURI(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	_, err := node.PairFromLink(context.Background(), "https://example.com")
	assert.Error(t, err)
}

func TestPairGenericMethod(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xAA}
	peerID, err := node.Pair(context.Background(), pid, cairn.PairingQR)
	require.NoError(t, err)
	assert.Equal(t, pid, peerID)
}

// --- Connect with encryption tests ---

func TestConnectWithEncryptor(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xBB}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)
	assert.Equal(t, pid, session.PeerID())
	assert.Equal(t, cairn.StateConnected, session.State())
	assert.True(t, session.HasEncryptor())
}

func TestSendWithEncryptor(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xCC}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	ch, err := session.OpenChannel(context.Background(), "data")
	require.NoError(t, err)

	err = session.Send(context.Background(), ch, []byte("hello world"))
	require.NoError(t, err)

	outbox := session.Outbox()
	// Should have ChannelInit envelope + data envelope
	assert.Len(t, outbox, 2)

	// Verify data envelope structure
	dataEnv := outbox[1]
	assert.True(t, len(dataEnv) > 31)

	// Parse the envelope
	version := dataEnv[0]
	msgType := binary.BigEndian.Uint16(dataEnv[1:3])
	assert.Equal(t, uint8(1), version)
	assert.Equal(t, uint16(0x0300), msgType)
}

func TestOpenChannelProducesChannelInitEnvelope(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xDD}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	_, err = session.OpenChannel(context.Background(), "chat")
	require.NoError(t, err)

	outbox := session.Outbox()
	require.Len(t, outbox, 1)

	// Parse envelope
	msgType := binary.BigEndian.Uint16(outbox[0][1:3])
	assert.Equal(t, uint16(0x0303), msgType)
}

// --- Message queuing during disconnection ---

func TestSendQueuesWhenDisconnected(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xEE}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)

	ch, err := session.OpenChannel(context.Background(), "data")
	require.NoError(t, err)

	// Clear outbox from channel init
	session.Outbox()

	// Transition to disconnected
	require.NoError(t, session.Transition(cairn.StateDisconnected))

	// Send should queue
	err = session.Send(context.Background(), ch, []byte("queued message"))
	require.NoError(t, err)

	// Outbox should be empty (message was queued, not enveloped)
	assert.Empty(t, session.Outbox())

	// Drain queue should return the message
	queued := session.DrainMessageQueue()
	require.Len(t, queued, 1)
	assert.Equal(t, []byte("queued message"), queued[0])
}

// --- Dispatch incoming ---

func TestDispatchIncomingChannelInit(t *testing.T) {
	events := make(chan cairn.Event, 10)
	session := cairn.NewSession(cairn.PeerID{}, nil, events)

	// Manually create a channel init envelope
	name := "remote-data"
	var sid [16]byte
	envBytes, err := createTestChannelInitEnvelope(sid, name)
	require.NoError(t, err)

	err = session.DispatchIncoming(envBytes)
	require.NoError(t, err)

	ch := session.GetChannel("remote-data")
	assert.NotNil(t, ch)
	assert.True(t, ch.IsOpen())
}

func TestDispatchIncomingCustomMessage(t *testing.T) {
	events := make(chan cairn.Event, 10)
	session := cairn.NewSession(cairn.PeerID{}, nil, events)

	var received []byte
	session.OnCustomMessage(0xF100, func(data []byte) {
		received = data
	})

	// Create a custom message envelope
	payload := []byte("custom-data")
	var sid [16]byte
	envBytes := encodeTestEnvelope(1, 0xF100, sid, payload, 0)

	err := session.DispatchIncoming(envBytes)
	require.NoError(t, err)
	assert.Equal(t, []byte("custom-data"), received)
}

func TestDispatchIncomingDataMessage(t *testing.T) {
	events := make(chan cairn.Event, 10)
	session := cairn.NewSession(cairn.PeerID{}, nil, events)

	// Create a data message envelope (no encryptor, so raw payload)
	payload := []byte("hello")
	var sid [16]byte
	envBytes := encodeTestEnvelope(1, 0x0300, sid, payload, 1)

	err := session.DispatchIncoming(envBytes)
	require.NoError(t, err)

	select {
	case ev := <-events:
		mre, ok := ev.(cairn.MessageReceivedEvent)
		require.True(t, ok)
		assert.Equal(t, []byte("hello"), mre.Data)
	default:
		t.Fatal("expected MessageReceivedEvent")
	}
}

// --- WrapRatchet tests ---

func TestWrapRatchetEncryptDecrypt(t *testing.T) {
	// Set up a sender/receiver ratchet pair
	sharedSecret := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	bobKP, err := crypto.GenerateX25519()
	require.NoError(t, err)

	sender, err := crypto.InitSender(sharedSecret, bobKP.PublicKeyBytes(), nil)
	require.NoError(t, err)

	receiver, err := crypto.InitReceiver(sharedSecret, bobKP, nil)
	require.NoError(t, err)

	senderEnc := WrapRatchet(sender)
	receiverEnc := WrapRatchet(receiver)

	// Encrypt with sender
	headerBytes, ciphertext, err := senderEnc.Encrypt([]byte("test message"))
	require.NoError(t, err)

	// Decrypt with receiver
	plaintext, err := receiverEnc.Decrypt(headerBytes, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte("test message"), plaintext)
}

// --- Helper functions for test envelope creation ---

func createTestChannelInitEnvelope(sessionID [16]byte, channelName string) ([]byte, error) {
	// CBOR: map(1) { 0: text(name) }
	nameBytes := []byte(channelName)
	payload := make([]byte, 0, 3+len(nameBytes))
	payload = append(payload, 0xA1)
	payload = append(payload, 0x00)
	if len(nameBytes) < 24 {
		payload = append(payload, 0x60+byte(len(nameBytes)))
	} else {
		payload = append(payload, 0x78, byte(len(nameBytes)))
	}
	payload = append(payload, nameBytes...)

	return encodeTestEnvelope(1, 0x0303, sessionID, payload, 0), nil
}

func encodeTestEnvelope(version uint8, msgType uint16, sessionID [16]byte, payload []byte, seqNum uint64) []byte {
	buf := make([]byte, 0, 1+2+16+8+4+len(payload))
	buf = append(buf, version)
	buf = binary.BigEndian.AppendUint16(buf, msgType)
	buf = append(buf, sessionID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, seqNum)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	return buf
}

// --- PairingCompleteEvent tests ---

func TestPairScanQREmitsPairingCompleteEvent(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	payload, err := node.PairGenerateQR(context.Background())
	require.NoError(t, err)

	pid, err := node.PairScanQR(context.Background(), payload)
	require.NoError(t, err)

	select {
	case ev := <-node.Events():
		pce, ok := ev.(cairn.PairingCompleteEvent)
		require.True(t, ok, "expected PairingCompleteEvent, got %T", ev)
		assert.Equal(t, pid, pce.PeerID)
		assert.Equal(t, cairn.PairingQR, pce.Method)
	default:
		t.Fatal("expected PairingCompleteEvent on events channel")
	}
}

func TestPairEnterPinEmitsPairingCompleteEvent(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid, err := node.PairEnterPin(context.Background(), "ABCD-EFGH")
	require.NoError(t, err)

	select {
	case ev := <-node.Events():
		pce, ok := ev.(cairn.PairingCompleteEvent)
		require.True(t, ok, "expected PairingCompleteEvent, got %T", ev)
		assert.Equal(t, pid, pce.PeerID)
		assert.Equal(t, cairn.PairingPin, pce.Method)
	default:
		t.Fatal("expected PairingCompleteEvent on events channel")
	}
}

func TestPairFromLinkEmitsPairingCompleteEvent(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	uri, err := node.PairGenerateLink(context.Background())
	require.NoError(t, err)

	pid, err := node.PairFromLink(context.Background(), uri)
	require.NoError(t, err)

	select {
	case ev := <-node.Events():
		pce, ok := ev.(cairn.PairingCompleteEvent)
		require.True(t, ok, "expected PairingCompleteEvent, got %T", ev)
		assert.Equal(t, pid, pce.PeerID)
		assert.Equal(t, cairn.PairingLink, pce.Method)
	default:
		t.Fatal("expected PairingCompleteEvent on events channel")
	}
}

func TestPairGenericEmitsPairingCompleteEvent(t *testing.T) {
	node := createWiredNode(t)
	defer node.Close()

	pid := cairn.PeerID{0x12, 0x20, 0xAA}
	_, err := node.Pair(context.Background(), pid, cairn.PairingPSK)
	require.NoError(t, err)

	select {
	case ev := <-node.Events():
		pce, ok := ev.(cairn.PairingCompleteEvent)
		require.True(t, ok, "expected PairingCompleteEvent, got %T", ev)
		assert.Equal(t, pid, pce.PeerID)
		assert.Equal(t, cairn.PairingPSK, pce.Method)
	default:
		t.Fatal("expected PairingCompleteEvent on events channel")
	}
}

// --- Auto-wiring tests ---

func TestAutoWiringViaInit(t *testing.T) {
	// The api package's init() registers default wiring.
	// Create() should return a fully wired node.
	node, err := cairn.Create()
	require.NoError(t, err)
	defer node.Close()

	// PairGenerateQR should work without manually calling WireNode
	payload, err := node.PairGenerateQR(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, payload)

	// Connect should work with encryption
	pid := cairn.PeerID{0x12, 0x20, 0xFF}
	session, err := node.Connect(context.Background(), pid)
	require.NoError(t, err)
	assert.True(t, session.HasEncryptor())
}
