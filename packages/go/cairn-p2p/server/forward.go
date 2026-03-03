package server

import (
	"fmt"
	"sync"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// StoredMessage represents an opaque encrypted message stored for later delivery.
// The server never decrypts stored messages; it stores complete Double Ratchet
// headers as-is for recipient reconstruction.
type StoredMessage struct {
	MessageID [16]byte     // UUID v7 message ID for deduplication
	Sender    cairn.PeerID
	Recipient cairn.PeerID
	Envelope  []byte       // opaque encrypted blob
	Size      int64
}

// MessageStore implements store-and-forward encrypted mailbox.
// Messages are stored per-recipient as opaque encrypted blobs.
// Trust requirement: server must be paired with both sender and recipient.
type MessageStore struct {
	mu       sync.Mutex
	config   RetentionConfig
	messages map[cairn.PeerID][]StoredMessage
	// Track seen message IDs for deduplication
	seen map[[16]byte]bool
}

// NewMessageStore creates a store with the given retention configuration.
func NewMessageStore(config RetentionConfig) *MessageStore {
	return &MessageStore{
		config:   config,
		messages: make(map[cairn.PeerID][]StoredMessage),
		seen:     make(map[[16]byte]bool),
	}
}

// Store stores an opaque encrypted message for later delivery.
// Returns an error if retention limits would be exceeded.
func (ms *MessageStore) Store(sender, recipient cairn.PeerID, messageID [16]byte, envelope []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Deduplication via UUID v7 message ID
	if ms.seen[messageID] {
		return nil // already stored, idempotent
	}

	queue := ms.messages[recipient]

	// Check per-peer limit
	limit := ms.config.MaxPerPeer
	if override, ok := ms.config.PerPeerOverrides[recipient]; ok {
		limit = override.MaxPerPeer
	}
	if len(queue) >= limit {
		return fmt.Errorf("store-and-forward: per-peer limit reached (%d messages for %s)", limit, recipient)
	}

	// Check total size limit
	var totalSize int64
	for _, msgs := range ms.messages {
		for _, m := range msgs {
			totalSize += m.Size
		}
	}
	if ms.config.MaxTotalSize > 0 && totalSize+int64(len(envelope)) > ms.config.MaxTotalSize {
		return fmt.Errorf("store-and-forward: total storage limit reached")
	}

	msg := StoredMessage{
		MessageID: messageID,
		Sender:    sender,
		Recipient: recipient,
		Envelope:  envelope,
		Size:      int64(len(envelope)),
	}

	ms.messages[recipient] = append(queue, msg)
	ms.seen[messageID] = true
	return nil
}

// Retrieve returns all queued messages for a recipient in sequence order.
// Does not remove the messages — caller must Purge after successful delivery.
func (ms *MessageStore) Retrieve(recipient cairn.PeerID) []StoredMessage {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	queue := ms.messages[recipient]
	if len(queue) == 0 {
		return nil
	}

	result := make([]StoredMessage, len(queue))
	copy(result, queue)
	return result
}

// Purge removes delivered messages by their message IDs.
func (ms *MessageStore) Purge(recipient cairn.PeerID, messageIDs [][16]byte) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	toRemove := make(map[[16]byte]bool, len(messageIDs))
	for _, id := range messageIDs {
		toRemove[id] = true
	}

	queue := ms.messages[recipient]
	filtered := queue[:0]
	for _, m := range queue {
		if !toRemove[m.MessageID] {
			filtered = append(filtered, m)
		} else {
			delete(ms.seen, m.MessageID)
		}
	}

	if len(filtered) == 0 {
		delete(ms.messages, recipient)
	} else {
		ms.messages[recipient] = filtered
	}
}

// Stats returns the message count and total size for a peer.
func (ms *MessageStore) Stats(peer cairn.PeerID) (count int, totalSize int64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	queue := ms.messages[peer]
	for _, m := range queue {
		totalSize += m.Size
	}
	return len(queue), totalSize
}

// TotalMessages returns the total number of stored messages across all peers.
func (ms *MessageStore) TotalMessages() int {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	total := 0
	for _, queue := range ms.messages {
		total += len(queue)
	}
	return total
}
