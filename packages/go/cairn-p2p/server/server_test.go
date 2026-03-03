package server

import (
	"testing"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPeerID(b byte) cairn.PeerID {
	pid := cairn.PeerID{}
	pid[0] = 0x12
	pid[1] = 0x20
	pid[2] = b
	return pid
}

func testMsgID(b byte) [16]byte {
	var id [16]byte
	id[0] = b
	return id
}

// --- RetentionConfig tests ---

func TestDefaultRetentionConfig(t *testing.T) {
	cfg := DefaultRetentionConfig()
	assert.Equal(t, 7*24*time.Hour, cfg.MaxAge)
	assert.Equal(t, 1000, cfg.MaxPerPeer)
	assert.Equal(t, int64(1<<30), cfg.MaxTotalSize)
}

// --- MessageStore tests ---

func TestNewMessageStoreEmpty(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	assert.Equal(t, 0, ms.TotalMessages())
}

func TestStoreAndRetrieve(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)
	msgID := testMsgID(1)

	err := ms.Store(sender, recipient, msgID, []byte("encrypted-payload"))
	require.NoError(t, err)

	assert.Equal(t, 1, ms.TotalMessages())

	msgs := ms.Retrieve(recipient)
	assert.Len(t, msgs, 1)
	assert.Equal(t, sender, msgs[0].Sender)
	assert.Equal(t, recipient, msgs[0].Recipient)
	assert.Equal(t, msgID, msgs[0].MessageID)
	assert.Equal(t, []byte("encrypted-payload"), msgs[0].Envelope)
}

func TestStoreMultipleMessages(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)

	for i := byte(0); i < 5; i++ {
		err := ms.Store(sender, recipient, testMsgID(i), []byte{i})
		require.NoError(t, err)
	}

	assert.Equal(t, 5, ms.TotalMessages())
	msgs := ms.Retrieve(recipient)
	assert.Len(t, msgs, 5)
}

func TestStoreDuplicateIsIdempotent(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)
	msgID := testMsgID(1)

	require.NoError(t, ms.Store(sender, recipient, msgID, []byte("data")))
	require.NoError(t, ms.Store(sender, recipient, msgID, []byte("data"))) // duplicate

	assert.Equal(t, 1, ms.TotalMessages())
}

func TestStoreExceedsPerPeerLimit(t *testing.T) {
	cfg := DefaultRetentionConfig()
	cfg.MaxPerPeer = 3
	ms := NewMessageStore(cfg)

	sender := testPeerID(1)
	recipient := testPeerID(2)

	for i := byte(0); i < 3; i++ {
		require.NoError(t, ms.Store(sender, recipient, testMsgID(i), []byte{i}))
	}

	err := ms.Store(sender, recipient, testMsgID(10), []byte("overflow"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "per-peer limit")
}

func TestStorePerPeerOverride(t *testing.T) {
	cfg := DefaultRetentionConfig()
	cfg.MaxPerPeer = 100
	specialPeer := testPeerID(99)
	cfg.PerPeerOverrides[specialPeer] = RetentionOverride{MaxPerPeer: 2}
	ms := NewMessageStore(cfg)

	sender := testPeerID(1)

	require.NoError(t, ms.Store(sender, specialPeer, testMsgID(1), []byte("a")))
	require.NoError(t, ms.Store(sender, specialPeer, testMsgID(2), []byte("b")))

	err := ms.Store(sender, specialPeer, testMsgID(3), []byte("c"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "per-peer limit")
}

func TestRetrieveEmptyQueue(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	msgs := ms.Retrieve(testPeerID(1))
	assert.Nil(t, msgs)
}

func TestPurgeRemovesMessages(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)

	ms.Store(sender, recipient, testMsgID(1), []byte("a"))
	ms.Store(sender, recipient, testMsgID(2), []byte("b"))
	ms.Store(sender, recipient, testMsgID(3), []byte("c"))

	ms.Purge(recipient, [][16]byte{testMsgID(1), testMsgID(3)})

	msgs := ms.Retrieve(recipient)
	assert.Len(t, msgs, 1)
	assert.Equal(t, testMsgID(2), msgs[0].MessageID)
}

func TestPurgeAllClearsQueue(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)

	ms.Store(sender, recipient, testMsgID(1), []byte("a"))
	ms.Store(sender, recipient, testMsgID(2), []byte("b"))

	ms.Purge(recipient, [][16]byte{testMsgID(1), testMsgID(2)})

	assert.Equal(t, 0, ms.TotalMessages())
	msgs := ms.Retrieve(recipient)
	assert.Nil(t, msgs)
}

func TestStats(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	recipient := testPeerID(2)

	ms.Store(sender, recipient, testMsgID(1), []byte("hello"))
	ms.Store(sender, recipient, testMsgID(2), []byte("world!"))

	count, size := ms.Stats(recipient)
	assert.Equal(t, 2, count)
	assert.Equal(t, int64(11), size) // 5 + 6 bytes
}

func TestStatsEmptyPeer(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	count, size := ms.Stats(testPeerID(1))
	assert.Equal(t, 0, count)
	assert.Equal(t, int64(0), size)
}

func TestMultiplePeersIndependent(t *testing.T) {
	ms := NewMessageStore(DefaultRetentionConfig())
	sender := testPeerID(1)
	r1 := testPeerID(2)
	r2 := testPeerID(3)

	ms.Store(sender, r1, testMsgID(1), []byte("for-r1"))
	ms.Store(sender, r2, testMsgID(2), []byte("for-r2"))

	msgs1 := ms.Retrieve(r1)
	msgs2 := ms.Retrieve(r2)
	assert.Len(t, msgs1, 1)
	assert.Len(t, msgs2, 1)
	assert.Equal(t, []byte("for-r1"), msgs1[0].Envelope)
	assert.Equal(t, []byte("for-r2"), msgs2[0].Envelope)
}

// --- ServerConfig tests ---

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	assert.True(t, cfg.StoreForwardEnabled)
	assert.True(t, cfg.Headless)
	assert.Equal(t, 7*24*time.Hour, cfg.Retention.MaxAge)
}
