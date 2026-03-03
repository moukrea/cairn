//! Message queuing during disconnection (spec/07-reconnection-sessions.md section 5).
//!
//! Messages are buffered locally while in Disconnected, Reconnecting, or Suspended states.
//! On session resumption, queued messages are retransmitted in sequence order.
//! On session re-establishment (after expiry), all queued messages are discarded.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Queue overflow strategy (spec section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueStrategy {
    /// Oldest first; reject new messages when full.
    Fifo,
    /// Newest first; discard oldest messages to make room.
    Lifo,
}

impl std::fmt::Display for QueueStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueStrategy::Fifo => write!(f, "FIFO"),
            QueueStrategy::Lifo => write!(f, "LIFO"),
        }
    }
}

/// Message queue configuration (spec section 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Whether to buffer messages at all. Default: true.
    pub enabled: bool,
    /// Maximum messages to buffer. Default: 1000.
    pub max_size: usize,
    /// Maximum age before discard. Default: 1 hour.
    pub max_age: Duration,
    /// Overflow strategy. Default: FIFO (reject new when full).
    pub strategy: QueueStrategy,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 1000,
            max_age: Duration::from_secs(3600),
            strategy: QueueStrategy::Fifo,
        }
    }
}

/// A queued message with metadata for age tracking.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// The sequence number assigned to this message.
    pub sequence: u64,
    /// The opaque message payload.
    pub payload: Vec<u8>,
    /// When the message was enqueued.
    pub enqueued_at: Instant,
}

/// Result of attempting to enqueue a message.
#[derive(Debug, PartialEq, Eq)]
pub enum EnqueueResult {
    /// Message was enqueued successfully.
    Enqueued,
    /// Message rejected: queue is disabled.
    Disabled,
    /// Message rejected: queue is full (FIFO strategy).
    Full,
    /// Message enqueued, but an older message was evicted (LIFO strategy).
    EnqueuedWithEviction,
}

/// Message queue for buffering during disconnection.
///
/// Behavior per spec:
/// - FIFO: reject new messages when full.
/// - LIFO: discard oldest messages to make room for new ones.
/// - Messages exceeding `max_age` are discarded on access.
pub struct MessageQueue {
    config: QueueConfig,
    messages: VecDeque<QueuedMessage>,
}

impl MessageQueue {
    /// Create a new message queue with the given configuration.
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            messages: VecDeque::new(),
        }
    }

    /// Enqueue a message.
    ///
    /// Returns the enqueue result indicating whether the message was accepted.
    pub fn enqueue(&mut self, sequence: u64, payload: Vec<u8>) -> EnqueueResult {
        if !self.config.enabled {
            return EnqueueResult::Disabled;
        }

        // Expire stale messages first
        self.expire_stale();

        let msg = QueuedMessage {
            sequence,
            payload,
            enqueued_at: Instant::now(),
        };

        if self.messages.len() >= self.config.max_size {
            match self.config.strategy {
                QueueStrategy::Fifo => {
                    return EnqueueResult::Full;
                }
                QueueStrategy::Lifo => {
                    // Discard oldest to make room
                    self.messages.pop_front();
                    self.messages.push_back(msg);
                    return EnqueueResult::EnqueuedWithEviction;
                }
            }
        }

        self.messages.push_back(msg);
        EnqueueResult::Enqueued
    }

    /// Drain all queued messages in sequence order for retransmission.
    ///
    /// Called on successful session resumption. Returns messages oldest-first.
    pub fn drain(&mut self) -> Vec<QueuedMessage> {
        self.expire_stale();
        self.messages.drain(..).collect()
    }

    /// Discard all queued messages.
    ///
    /// Called on session re-establishment (after expiry) since sequence numbers restart.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the number of currently queued messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Get the remaining capacity.
    pub fn remaining_capacity(&self) -> usize {
        self.config.max_size.saturating_sub(self.messages.len())
    }

    /// Peek at the next message without removing it.
    pub fn peek(&self) -> Option<&QueuedMessage> {
        self.messages.front()
    }

    /// Get a reference to the queue configuration.
    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    /// Remove messages older than `max_age`.
    fn expire_stale(&mut self) {
        let max_age = self.config.max_age;
        self.messages
            .retain(|msg| msg.enqueued_at.elapsed() < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_queue() -> MessageQueue {
        MessageQueue::new(QueueConfig::default())
    }

    // --- QueueConfig tests ---

    #[test]
    fn test_default_config() {
        let config = QueueConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_size, 1000);
        assert_eq!(config.max_age, Duration::from_secs(3600));
        assert_eq!(config.strategy, QueueStrategy::Fifo);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = QueueConfig {
            enabled: false,
            max_size: 500,
            max_age: Duration::from_secs(1800),
            strategy: QueueStrategy::Lifo,
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: QueueConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.enabled, config.enabled);
        assert_eq!(decoded.max_size, config.max_size);
        assert_eq!(decoded.max_age, config.max_age);
        assert_eq!(decoded.strategy, config.strategy);
    }

    #[test]
    fn test_queue_strategy_display() {
        assert_eq!(QueueStrategy::Fifo.to_string(), "FIFO");
        assert_eq!(QueueStrategy::Lifo.to_string(), "LIFO");
    }

    // --- MessageQueue basic tests ---

    #[test]
    fn test_queue_starts_empty() {
        let queue = default_queue();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.remaining_capacity(), 1000);
    }

    #[test]
    fn test_enqueue_success() {
        let mut queue = default_queue();
        let result = queue.enqueue(1, vec![1, 2, 3]);
        assert_eq!(result, EnqueueResult::Enqueued);
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_enqueue_multiple() {
        let mut queue = default_queue();
        queue.enqueue(1, vec![1]);
        queue.enqueue(2, vec![2]);
        queue.enqueue(3, vec![3]);
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.remaining_capacity(), 997);
    }

    #[test]
    fn test_peek() {
        let mut queue = default_queue();
        assert!(queue.peek().is_none());

        queue.enqueue(1, vec![10, 20]);
        let msg = queue.peek().unwrap();
        assert_eq!(msg.sequence, 1);
        assert_eq!(msg.payload, vec![10, 20]);
        // Peek doesn't consume
        assert_eq!(queue.len(), 1);
    }

    // --- Disabled queue ---

    #[test]
    fn test_enqueue_disabled() {
        let config = QueueConfig {
            enabled: false,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);
        let result = queue.enqueue(1, vec![1]);
        assert_eq!(result, EnqueueResult::Disabled);
        assert!(queue.is_empty());
    }

    // --- FIFO overflow ---

    #[test]
    fn test_fifo_rejects_when_full() {
        let config = QueueConfig {
            max_size: 3,
            strategy: QueueStrategy::Fifo,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);

        assert_eq!(queue.enqueue(1, vec![1]), EnqueueResult::Enqueued);
        assert_eq!(queue.enqueue(2, vec![2]), EnqueueResult::Enqueued);
        assert_eq!(queue.enqueue(3, vec![3]), EnqueueResult::Enqueued);

        // Queue full — FIFO rejects new
        assert_eq!(queue.enqueue(4, vec![4]), EnqueueResult::Full);
        assert_eq!(queue.len(), 3);

        // Verify oldest is still there
        assert_eq!(queue.peek().unwrap().sequence, 1);
    }

    // --- LIFO overflow ---

    #[test]
    fn test_lifo_evicts_oldest_when_full() {
        let config = QueueConfig {
            max_size: 3,
            strategy: QueueStrategy::Lifo,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);

        queue.enqueue(1, vec![1]);
        queue.enqueue(2, vec![2]);
        queue.enqueue(3, vec![3]);

        // Queue full — LIFO evicts oldest
        let result = queue.enqueue(4, vec![4]);
        assert_eq!(result, EnqueueResult::EnqueuedWithEviction);
        assert_eq!(queue.len(), 3);

        // Oldest (seq 1) evicted, now seq 2 is first
        assert_eq!(queue.peek().unwrap().sequence, 2);
    }

    #[test]
    fn test_lifo_multiple_evictions() {
        let config = QueueConfig {
            max_size: 2,
            strategy: QueueStrategy::Lifo,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);

        queue.enqueue(1, vec![1]);
        queue.enqueue(2, vec![2]);
        queue.enqueue(3, vec![3]); // evicts 1
        queue.enqueue(4, vec![4]); // evicts 2

        assert_eq!(queue.len(), 2);
        let msgs = queue.drain();
        assert_eq!(msgs[0].sequence, 3);
        assert_eq!(msgs[1].sequence, 4);
    }

    // --- Drain ---

    #[test]
    fn test_drain_returns_in_order() {
        let mut queue = default_queue();
        queue.enqueue(1, vec![10]);
        queue.enqueue(2, vec![20]);
        queue.enqueue(3, vec![30]);

        let msgs = queue.drain();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].sequence, 1);
        assert_eq!(msgs[1].sequence, 2);
        assert_eq!(msgs[2].sequence, 3);

        // Queue is now empty
        assert!(queue.is_empty());
    }

    // --- Clear ---

    #[test]
    fn test_clear_discards_all() {
        let mut queue = default_queue();
        queue.enqueue(1, vec![1]);
        queue.enqueue(2, vec![2]);
        assert_eq!(queue.len(), 2);

        queue.clear();
        assert!(queue.is_empty());
        assert_eq!(queue.remaining_capacity(), 1000);
    }

    // --- Stale message expiry ---

    #[test]
    fn test_expire_stale_with_zero_max_age() {
        let config = QueueConfig {
            max_age: Duration::ZERO,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);
        queue.enqueue(1, vec![1]);

        // With zero max_age, message is immediately stale
        // Enqueuing another triggers expiry of previous
        queue.enqueue(2, vec![2]);

        // Both messages should be expired on drain
        let msgs = queue.drain();
        assert!(msgs.is_empty());
    }

    // --- Sequence ordering ---

    #[test]
    fn test_messages_maintain_insertion_order() {
        let mut queue = default_queue();
        for seq in (0..10).rev() {
            queue.enqueue(seq, vec![seq as u8]);
        }

        let msgs = queue.drain();
        // Should maintain insertion order (9, 8, 7, ..., 0)
        for (i, msg) in msgs.iter().enumerate() {
            assert_eq!(msg.sequence, (9 - i) as u64);
        }
    }

    // --- Payload integrity ---

    #[test]
    fn test_payload_preserved() {
        let mut queue = default_queue();
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        queue.enqueue(42, payload.clone());

        let msgs = queue.drain();
        assert_eq!(msgs[0].payload, payload);
        assert_eq!(msgs[0].sequence, 42);
    }

    // --- Remaining capacity ---

    #[test]
    fn test_remaining_capacity_decreases() {
        let config = QueueConfig {
            max_size: 5,
            ..Default::default()
        };
        let mut queue = MessageQueue::new(config);
        assert_eq!(queue.remaining_capacity(), 5);

        queue.enqueue(1, vec![]);
        assert_eq!(queue.remaining_capacity(), 4);

        queue.enqueue(2, vec![]);
        queue.enqueue(3, vec![]);
        assert_eq!(queue.remaining_capacity(), 2);
    }
}
