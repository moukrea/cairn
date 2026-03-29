use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::headless::PeerQuota;
use crate::identity::PeerId;

// ---------------------------------------------------------------------------
// Control channel name
// ---------------------------------------------------------------------------

/// Reserved control channel for store-and-forward directives.
pub const FORWARD_CHANNEL: &str = "__cairn_forward";

// ---------------------------------------------------------------------------
// Forward message types (0x07xx)
// ---------------------------------------------------------------------------

/// 0x0700 — Sender asks the server to store a message for an offline recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub msg_id: Uuid,
    pub recipient: PeerId,
    #[serde(with = "serde_bytes")]
    pub encrypted_payload: Vec<u8>,
    pub sequence_number: u64,
}

/// 0x0701 — Server acknowledges (or rejects) a ForwardRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardAck {
    pub msg_id: Uuid,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
}

/// 0x0702 — Server delivers a stored message to the recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardDeliver {
    pub msg_id: Uuid,
    pub sender: PeerId,
    #[serde(with = "serde_bytes")]
    pub encrypted_payload: Vec<u8>,
    pub sequence_number: u64,
}

/// 0x0703 — Server purges delivered messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardPurge {
    pub msg_ids: Vec<Uuid>,
}

// ---------------------------------------------------------------------------
// Retention policy
// ---------------------------------------------------------------------------

/// Per-peer or default retention policy for stored messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub max_age: Duration,
    pub max_messages: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(7 * 24 * 3600), // 7 days
            max_messages: 1_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Stored message
// ---------------------------------------------------------------------------

/// A message held in the server's per-peer queue.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub msg_id: Uuid,
    pub sender: PeerId,
    pub encrypted_payload: Vec<u8>,
    pub sequence_number: u64,
    pub stored_at: SystemTime,
}

// ---------------------------------------------------------------------------
// Message queue
// ---------------------------------------------------------------------------

/// Max skip threshold for Double Ratchet message reconstruction.
pub const MAX_SKIP_THRESHOLD: u64 = 1_000;

/// In-memory store-and-forward message queue with per-peer retention and dedup.
#[derive(Debug)]
pub struct MessageQueue {
    queues: HashMap<PeerId, VecDeque<StoredMessage>>,
    /// Tracks seen message IDs for deduplication.
    seen_ids: HashSet<Uuid>,
    per_peer_overrides: HashMap<PeerId, RetentionPolicy>,
    default_policy: RetentionPolicy,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            seen_ids: HashSet::new(),
            per_peer_overrides: HashMap::new(),
            default_policy: RetentionPolicy::default(),
        }
    }

    pub fn with_policy(default_policy: RetentionPolicy) -> Self {
        Self {
            default_policy,
            ..Self::new()
        }
    }

    /// Set a per-peer retention override.
    pub fn set_peer_override(&mut self, peer_id: PeerId, policy: RetentionPolicy) {
        self.per_peer_overrides.insert(peer_id, policy);
    }

    /// Get the effective retention policy for a peer.
    fn policy_for(&self, peer_id: &PeerId) -> &RetentionPolicy {
        self.per_peer_overrides
            .get(peer_id)
            .unwrap_or(&self.default_policy)
    }

    /// Enqueue a message for a recipient. Returns a `ForwardAck`.
    ///
    /// Validates:
    /// - sender and recipient are both in `paired_peers` set
    /// - message is not a duplicate (UUID v7 dedup)
    /// - quota is not exceeded (if provided)
    /// - sequence gap does not exceed MAX_SKIP_THRESHOLD
    /// - per-peer queue is not at capacity
    pub fn enqueue(
        &mut self,
        request: &ForwardRequest,
        sender: &PeerId,
        paired_peers: &HashSet<PeerId>,
        quota: Option<&PeerQuota>,
    ) -> ForwardAck {
        // Trust validation: server must be paired with both sender and recipient.
        if !paired_peers.contains(sender) {
            return ForwardAck {
                msg_id: request.msg_id,
                accepted: false,
                rejection_reason: Some("sender is not a paired peer".into()),
            };
        }
        if !paired_peers.contains(&request.recipient) {
            return ForwardAck {
                msg_id: request.msg_id,
                accepted: false,
                rejection_reason: Some("recipient is not a paired peer".into()),
            };
        }

        // UUID v7 deduplication.
        if self.seen_ids.contains(&request.msg_id) {
            return ForwardAck {
                msg_id: request.msg_id,
                accepted: false,
                rejection_reason: Some("duplicate message ID".into()),
            };
        }

        // Check quota before retention enforcement.
        if let Some(q) = quota {
            let current_count = self.queues.get(&request.recipient).map_or(0, |q| q.len()) as u32;
            if !q.check_store_quota(current_count) {
                return ForwardAck {
                    msg_id: request.msg_id,
                    accepted: false,
                    rejection_reason: Some("quota exceeded".into()),
                };
            }
        }

        // Enforce retention limits.
        let policy = self.policy_for(&request.recipient).clone();
        let queue = self.queues.entry(request.recipient.clone()).or_default();

        // Expire old messages first.
        let now = SystemTime::now();
        while let Some(front) = queue.front() {
            if let Ok(age) = now.duration_since(front.stored_at) {
                if age > policy.max_age {
                    if let Some(removed) = queue.pop_front() {
                        self.seen_ids.remove(&removed.msg_id);
                    }
                    continue;
                }
            }
            break;
        }

        // Check capacity.
        if queue.len() >= policy.max_messages as usize {
            return ForwardAck {
                msg_id: request.msg_id,
                accepted: false,
                rejection_reason: Some(format!(
                    "recipient queue full ({} messages)",
                    policy.max_messages
                )),
            };
        }

        // Validate sequence gap (max skip threshold).
        if let Some(last) = queue.back() {
            let gap = request.sequence_number.saturating_sub(last.sequence_number);
            if gap > MAX_SKIP_THRESHOLD {
                return ForwardAck {
                    msg_id: request.msg_id,
                    accepted: false,
                    rejection_reason: Some(format!(
                        "sequence gap {} exceeds max skip threshold {}",
                        gap, MAX_SKIP_THRESHOLD
                    )),
                };
            }
        }

        // Store message.
        queue.push_back(StoredMessage {
            msg_id: request.msg_id,
            sender: sender.clone(),
            encrypted_payload: request.encrypted_payload.clone(),
            sequence_number: request.sequence_number,
            stored_at: now,
        });
        self.seen_ids.insert(request.msg_id);

        ForwardAck {
            msg_id: request.msg_id,
            accepted: true,
            rejection_reason: None,
        }
    }

    /// Drain all queued messages for a recipient, producing `ForwardDeliver` items
    /// in sequence order. Returns the delivered messages and a `ForwardPurge`.
    pub fn deliver(&mut self, recipient: &PeerId) -> (Vec<ForwardDeliver>, ForwardPurge) {
        let queue = self.queues.entry(recipient.clone()).or_default();

        // Expire old messages before delivering.
        let now = SystemTime::now();
        let policy = self
            .per_peer_overrides
            .get(recipient)
            .unwrap_or(&self.default_policy)
            .clone();
        while let Some(front) = queue.front() {
            if let Ok(age) = now.duration_since(front.stored_at) {
                if age > policy.max_age {
                    if let Some(removed) = queue.pop_front() {
                        self.seen_ids.remove(&removed.msg_id);
                    }
                    continue;
                }
            }
            break;
        }

        let messages: Vec<StoredMessage> = queue.drain(..).collect();
        let mut purge_ids = Vec::with_capacity(messages.len());
        let mut delivers = Vec::with_capacity(messages.len());

        for msg in messages {
            purge_ids.push(msg.msg_id);
            self.seen_ids.remove(&msg.msg_id);
            delivers.push(ForwardDeliver {
                msg_id: msg.msg_id,
                sender: msg.sender,
                encrypted_payload: msg.encrypted_payload,
                sequence_number: msg.sequence_number,
            });
        }

        let purge = ForwardPurge { msg_ids: purge_ids };
        (delivers, purge)
    }

    /// Number of queued messages for a given peer.
    pub fn queue_depth(&self, peer_id: &PeerId) -> usize {
        self.queues.get(peer_id).map_or(0, |q| q.len())
    }

    /// Total number of messages across all queues.
    pub fn total_messages(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Return per-peer queue statistics: (peer_id, pending_messages, oldest_message_age_secs, total_bytes).
    pub fn queue_stats(&self) -> Vec<(PeerId, usize, Option<u64>, usize)> {
        let now = SystemTime::now();
        self.queues
            .iter()
            .map(|(peer_id, queue)| {
                let pending = queue.len();
                let oldest_age = queue
                    .front()
                    .and_then(|msg| now.duration_since(msg.stored_at).ok().map(|d| d.as_secs()));
                let total_bytes: usize = queue.iter().map(|msg| msg.encrypted_payload.len()).sum();
                (peer_id.clone(), pending, oldest_age, total_bytes)
            })
            .collect()
    }

    /// Run retention expiry across all queues.
    pub fn expire_all(&mut self) {
        let now = SystemTime::now();
        for (peer_id, queue) in &mut self.queues {
            let policy = self
                .per_peer_overrides
                .get(peer_id)
                .unwrap_or(&self.default_policy);
            while let Some(front) = queue.front() {
                if let Ok(age) = now.duration_since(front.stored_at) {
                    if age > policy.max_age {
                        if let Some(removed) = queue.pop_front() {
                            self.seen_ids.remove(&removed.msg_id);
                        }
                        continue;
                    }
                }
                break;
            }
        }
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Dedup tracker (recipient side)
// ---------------------------------------------------------------------------

/// Tracks received message IDs for recipient-side deduplication.
/// Bounded to prevent unbounded memory growth.
#[derive(Debug)]
pub struct DeduplicationTracker {
    seen: HashSet<Uuid>,
    order: VecDeque<Uuid>,
    capacity: usize,
}

impl DeduplicationTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns `true` if this is a new (non-duplicate) message ID.
    pub fn check_and_insert(&mut self, msg_id: Uuid) -> bool {
        if self.seen.contains(&msg_id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(msg_id);
        self.order.push_back(msg_id);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_peer(seed: u8) -> PeerId {
        let key = SigningKey::from_bytes(&[seed; 32]);
        PeerId::from_public_key(&key.verifying_key())
    }

    fn make_paired_set(peers: &[PeerId]) -> HashSet<PeerId> {
        peers.iter().cloned().collect()
    }

    fn make_request(recipient: &PeerId, seq: u64) -> ForwardRequest {
        ForwardRequest {
            msg_id: Uuid::now_v7(),
            recipient: recipient.clone(),
            encrypted_payload: vec![0xAB; 64],
            sequence_number: seq,
        }
    }

    // -- ForwardRequest / ForwardAck --

    #[test]
    fn enqueue_accepted() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);
        let req = make_request(&recipient, 1);
        let ack = queue.enqueue(&req, &sender, &paired, None);
        assert!(ack.accepted);
        assert!(ack.rejection_reason.is_none());
        assert_eq!(queue.queue_depth(&recipient), 1);
    }

    #[test]
    fn enqueue_rejects_unpaired_sender() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(std::slice::from_ref(&recipient)); // sender not paired
        let req = make_request(&recipient, 1);
        let ack = queue.enqueue(&req, &sender, &paired, None);
        assert!(!ack.accepted);
        assert!(ack.rejection_reason.unwrap().contains("sender"));
    }

    #[test]
    fn enqueue_rejects_unpaired_recipient() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(std::slice::from_ref(&sender)); // recipient not paired
        let req = make_request(&recipient, 1);
        let ack = queue.enqueue(&req, &sender, &paired, None);
        assert!(!ack.accepted);
        assert!(ack.rejection_reason.unwrap().contains("recipient"));
    }

    #[test]
    fn enqueue_rejects_duplicate_msg_id() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);
        let req = make_request(&recipient, 1);
        queue.enqueue(&req, &sender, &paired, None);
        let ack2 = queue.enqueue(&req, &sender, &paired, None);
        assert!(!ack2.accepted);
        assert!(ack2.rejection_reason.unwrap().contains("duplicate"));
    }

    #[test]
    fn enqueue_rejects_queue_full() {
        let policy = RetentionPolicy {
            max_age: Duration::from_secs(86400),
            max_messages: 3,
        };
        let mut queue = MessageQueue::with_policy(policy);
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        for seq in 1..=3 {
            let req = make_request(&recipient, seq);
            let ack = queue.enqueue(&req, &sender, &paired, None);
            assert!(ack.accepted);
        }

        let req4 = make_request(&recipient, 4);
        let ack = queue.enqueue(&req4, &sender, &paired, None);
        assert!(!ack.accepted);
        assert!(ack.rejection_reason.unwrap().contains("queue full"));
    }

    #[test]
    fn enqueue_rejects_sequence_gap_exceeding_threshold() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        let req1 = make_request(&recipient, 1);
        queue.enqueue(&req1, &sender, &paired, None);

        // Gap of 1001 exceeds MAX_SKIP_THRESHOLD (1000)
        let req_far = make_request(&recipient, 1002);
        let ack = queue.enqueue(&req_far, &sender, &paired, None);
        assert!(!ack.accepted);
        assert!(ack.rejection_reason.unwrap().contains("skip threshold"));
    }

    #[test]
    fn enqueue_allows_sequence_gap_within_threshold() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        let req1 = make_request(&recipient, 1);
        queue.enqueue(&req1, &sender, &paired, None);

        // Gap of exactly 1000 is within threshold
        let req_ok = make_request(&recipient, 1001);
        let ack = queue.enqueue(&req_ok, &sender, &paired, None);
        assert!(ack.accepted);
    }

    // -- Delivery --

    #[test]
    fn deliver_returns_messages_in_order() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        for seq in 1..=5 {
            let req = make_request(&recipient, seq);
            queue.enqueue(&req, &sender, &paired, None);
        }

        let (delivers, purge) = queue.deliver(&recipient);
        assert_eq!(delivers.len(), 5);
        assert_eq!(purge.msg_ids.len(), 5);
        for (i, d) in delivers.iter().enumerate() {
            assert_eq!(d.sequence_number, (i + 1) as u64);
            assert_eq!(d.sender, sender);
        }
        assert_eq!(queue.queue_depth(&recipient), 0);
    }

    #[test]
    fn deliver_empty_queue() {
        let mut queue = MessageQueue::new();
        let recipient = make_peer(2);
        let (delivers, purge) = queue.deliver(&recipient);
        assert!(delivers.is_empty());
        assert!(purge.msg_ids.is_empty());
    }

    #[test]
    fn deliver_clears_dedup_entries() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        let req = make_request(&recipient, 1);
        let msg_id = req.msg_id;
        queue.enqueue(&req, &sender, &paired, None);
        queue.deliver(&recipient);

        // Same msg_id should be accepted again after delivery purge
        let req2 = ForwardRequest {
            msg_id,
            recipient: recipient.clone(),
            encrypted_payload: vec![0xCD; 32],
            sequence_number: 2,
        };
        let ack = queue.enqueue(&req2, &sender, &paired, None);
        assert!(ack.accepted);
    }

    // -- Retention --

    #[test]
    fn expired_messages_pruned_on_enqueue() {
        let policy = RetentionPolicy {
            max_age: Duration::from_secs(0), // immediate expiry
            max_messages: 1_000,
        };
        let mut queue = MessageQueue::with_policy(policy);
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        let req = make_request(&recipient, 1);
        queue.enqueue(&req, &sender, &paired, None);

        // Force enough time to pass (SystemTime::now already past stored_at)
        // The next enqueue will prune expired messages
        std::thread::sleep(Duration::from_millis(10));
        let req2 = make_request(&recipient, 2);
        queue.enqueue(&req2, &sender, &paired, None);

        // Only the newest should remain (first expired before second enqueue)
        assert_eq!(queue.queue_depth(&recipient), 1);
    }

    #[test]
    fn per_peer_override() {
        let default_policy = RetentionPolicy {
            max_age: Duration::from_secs(86400),
            max_messages: 2,
        };
        let mut queue = MessageQueue::with_policy(default_policy);
        let sender = make_peer(1);
        let priority_peer = make_peer(2);
        let regular_peer = make_peer(3);
        let paired =
            make_paired_set(&[sender.clone(), priority_peer.clone(), regular_peer.clone()]);

        // Give priority_peer a higher quota
        queue.set_peer_override(
            priority_peer.clone(),
            RetentionPolicy {
                max_age: Duration::from_secs(86400),
                max_messages: 100,
            },
        );

        // Regular peer should hit cap at 2
        for seq in 1..=3 {
            let req = make_request(&regular_peer, seq);
            queue.enqueue(&req, &sender, &paired, None);
        }
        assert_eq!(queue.queue_depth(&regular_peer), 2); // capped

        // Priority peer should accept all 3
        for seq in 1..=3 {
            let req = make_request(&priority_peer, seq);
            queue.enqueue(&req, &sender, &paired, None);
        }
        assert_eq!(queue.queue_depth(&priority_peer), 3);
    }

    // -- Total messages --

    #[test]
    fn total_messages_across_peers() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let r1 = make_peer(2);
        let r2 = make_peer(3);
        let paired = make_paired_set(&[sender.clone(), r1.clone(), r2.clone()]);

        for seq in 1..=3 {
            queue.enqueue(&make_request(&r1, seq), &sender, &paired, None);
        }
        for seq in 1..=2 {
            queue.enqueue(&make_request(&r2, seq), &sender, &paired, None);
        }
        assert_eq!(queue.total_messages(), 5);
    }

    // -- DeduplicationTracker --

    #[test]
    fn dedup_tracker_new_message() {
        let mut tracker = DeduplicationTracker::new(100);
        let id = Uuid::now_v7();
        assert!(tracker.check_and_insert(id));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn dedup_tracker_rejects_duplicate() {
        let mut tracker = DeduplicationTracker::new(100);
        let id = Uuid::now_v7();
        assert!(tracker.check_and_insert(id));
        assert!(!tracker.check_and_insert(id));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn dedup_tracker_evicts_oldest() {
        let mut tracker = DeduplicationTracker::new(3);
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let id3 = Uuid::now_v7();
        let id4 = Uuid::now_v7();

        tracker.check_and_insert(id1);
        tracker.check_and_insert(id2);
        tracker.check_and_insert(id3);
        assert_eq!(tracker.len(), 3);

        // Adding id4 should evict id1
        tracker.check_and_insert(id4);
        assert_eq!(tracker.len(), 3);

        // id1 should now be accepted again
        assert!(tracker.check_and_insert(id1));
    }

    #[test]
    fn dedup_tracker_is_empty() {
        let tracker = DeduplicationTracker::new(10);
        assert!(tracker.is_empty());
    }

    // -- Forward message types --

    #[test]
    fn forward_request_fields() {
        let recipient = make_peer(1);
        let req = ForwardRequest {
            msg_id: Uuid::now_v7(),
            recipient: recipient.clone(),
            encrypted_payload: vec![1, 2, 3],
            sequence_number: 42,
        };
        assert_eq!(req.recipient, recipient);
        assert_eq!(req.sequence_number, 42);
        assert_eq!(req.encrypted_payload, vec![1, 2, 3]);
    }

    #[test]
    fn forward_ack_accepted() {
        let ack = ForwardAck {
            msg_id: Uuid::now_v7(),
            accepted: true,
            rejection_reason: None,
        };
        assert!(ack.accepted);
    }

    #[test]
    fn forward_ack_rejected() {
        let ack = ForwardAck {
            msg_id: Uuid::now_v7(),
            accepted: false,
            rejection_reason: Some("test reason".into()),
        };
        assert!(!ack.accepted);
        assert_eq!(ack.rejection_reason.as_deref(), Some("test reason"));
    }

    #[test]
    fn forward_deliver_fields() {
        let sender = make_peer(1);
        let deliver = ForwardDeliver {
            msg_id: Uuid::now_v7(),
            sender: sender.clone(),
            encrypted_payload: vec![0xDE, 0xAD],
            sequence_number: 99,
        };
        assert_eq!(deliver.sender, sender);
        assert_eq!(deliver.sequence_number, 99);
    }

    #[test]
    fn forward_purge_fields() {
        let ids = vec![Uuid::now_v7(), Uuid::now_v7()];
        let purge = ForwardPurge {
            msg_ids: ids.clone(),
        };
        assert_eq!(purge.msg_ids.len(), 2);
    }

    #[test]
    fn channel_name_constant() {
        assert_eq!(FORWARD_CHANNEL, "__cairn_forward");
    }

    #[test]
    fn max_skip_threshold_is_1000() {
        assert_eq!(MAX_SKIP_THRESHOLD, 1_000);
    }

    #[test]
    fn default_retention_policy() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.max_age, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(policy.max_messages, 1_000);
    }

    // -- Quota enforcement --

    #[test]
    fn enqueue_with_quota_allows_within_limit() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);
        let quota = PeerQuota {
            max_stored_messages: Some(5),
            ..PeerQuota::default()
        };

        let req = make_request(&recipient, 1);
        let ack = queue.enqueue(&req, &sender, &paired, Some(&quota));
        assert!(ack.accepted);
    }

    #[test]
    fn enqueue_with_quota_rejects_at_limit() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);
        let quota = PeerQuota {
            max_stored_messages: Some(2),
            ..PeerQuota::default()
        };

        // Fill up to the quota limit
        for seq in 1..=2 {
            let req = make_request(&recipient, seq);
            let ack = queue.enqueue(&req, &sender, &paired, Some(&quota));
            assert!(ack.accepted);
        }

        // Third message should be rejected by quota
        let req3 = make_request(&recipient, 3);
        let ack = queue.enqueue(&req3, &sender, &paired, Some(&quota));
        assert!(!ack.accepted);
        assert_eq!(ack.rejection_reason.as_deref(), Some("quota exceeded"));
    }

    #[test]
    fn enqueue_with_none_quota_allows_unlimited() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);

        // No quota — should only be limited by retention policy
        for seq in 1..=100 {
            let req = make_request(&recipient, seq);
            let ack = queue.enqueue(&req, &sender, &paired, None);
            assert!(ack.accepted);
        }
    }

    #[test]
    fn enqueue_with_unlimited_quota_allows_all() {
        let mut queue = MessageQueue::new();
        let sender = make_peer(1);
        let recipient = make_peer(2);
        let paired = make_paired_set(&[sender.clone(), recipient.clone()]);
        // None means unlimited for that resource
        let quota = PeerQuota {
            max_stored_messages: None,
            ..PeerQuota::default()
        };

        for seq in 1..=10 {
            let req = make_request(&recipient, seq);
            let ack = queue.enqueue(&req, &sender, &paired, Some(&quota));
            assert!(ack.accepted);
        }
    }
}
