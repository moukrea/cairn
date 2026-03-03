"""Store-and-forward message queue for offline recipients."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORWARD_CHANNEL: str = "__cairn_forward"
MAX_SKIP_THRESHOLD: int = 1_000


# ---------------------------------------------------------------------------
# Forward message types (0x07xx)
# ---------------------------------------------------------------------------


@dataclass
class ForwardRequest:
    """0x0700 -- Sender asks the server to store a message."""

    msg_id: bytes
    recipient: bytes
    encrypted_payload: bytes
    sequence_number: int


@dataclass
class ForwardAck:
    """0x0701 -- Server acknowledges (or rejects) a ForwardRequest."""

    msg_id: bytes
    accepted: bool
    rejection_reason: str | None = None


@dataclass
class ForwardDeliver:
    """0x0702 -- Server delivers a stored message to the recipient."""

    msg_id: bytes
    sender: bytes
    encrypted_payload: bytes
    sequence_number: int


@dataclass
class ForwardPurge:
    """0x0703 -- Server purges delivered messages."""

    msg_ids: list[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Retention policy
# ---------------------------------------------------------------------------


@dataclass
class RetentionPolicy:
    """Per-peer or default retention policy for stored messages."""

    max_age: float = 7 * 24 * 3600.0  # 7 days in seconds
    max_messages: int = 1_000


# ---------------------------------------------------------------------------
# Stored message
# ---------------------------------------------------------------------------


@dataclass
class StoredMessage:
    """A message held in the server's per-peer queue."""

    msg_id: bytes
    sender: bytes
    encrypted_payload: bytes
    sequence_number: int
    stored_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Message queue
# ---------------------------------------------------------------------------


class MessageQueue:
    """In-memory store-and-forward message queue with per-peer retention and dedup."""

    def __init__(
        self, default_policy: RetentionPolicy | None = None
    ) -> None:
        self._queues: dict[bytes, deque[StoredMessage]] = {}
        self._seen_ids: set[bytes] = set()
        self._per_peer_overrides: dict[bytes, RetentionPolicy] = {}
        self._default_policy = default_policy or RetentionPolicy()

    @property
    def default_policy(self) -> RetentionPolicy:
        return self._default_policy

    def set_peer_override(
        self, peer_id: bytes, policy: RetentionPolicy
    ) -> None:
        """Set a per-peer retention override."""
        self._per_peer_overrides[peer_id] = policy

    def _policy_for(self, peer_id: bytes) -> RetentionPolicy:
        return self._per_peer_overrides.get(
            peer_id, self._default_policy
        )

    def enqueue(
        self,
        request: ForwardRequest,
        sender: bytes,
        paired_peers: set[bytes],
    ) -> ForwardAck:
        """Enqueue a message for a recipient. Returns a ForwardAck.

        Validates:
        - sender and recipient are both in paired_peers set
        - message is not a duplicate (UUID dedup)
        - sequence gap does not exceed MAX_SKIP_THRESHOLD
        - per-peer queue is not at capacity
        """
        # Trust validation: server must be paired with both.
        if sender not in paired_peers:
            return ForwardAck(
                msg_id=request.msg_id,
                accepted=False,
                rejection_reason="sender is not a paired peer",
            )
        if request.recipient not in paired_peers:
            return ForwardAck(
                msg_id=request.msg_id,
                accepted=False,
                rejection_reason="recipient is not a paired peer",
            )

        # UUID deduplication.
        if request.msg_id in self._seen_ids:
            return ForwardAck(
                msg_id=request.msg_id,
                accepted=False,
                rejection_reason="duplicate message ID",
            )

        # Enforce retention limits.
        policy = self._policy_for(request.recipient)
        queue = self._queues.setdefault(
            request.recipient, deque()
        )

        # Expire old messages first.
        now = time.time()
        while queue and now - queue[0].stored_at > policy.max_age:
            removed = queue.popleft()
            self._seen_ids.discard(removed.msg_id)

        # Check capacity.
        if len(queue) >= policy.max_messages:
            return ForwardAck(
                msg_id=request.msg_id,
                accepted=False,
                rejection_reason=(
                    f"recipient queue full ({policy.max_messages} messages)"
                ),
            )

        # Validate sequence gap (max skip threshold).
        if queue:
            last = queue[-1]
            gap = request.sequence_number - last.sequence_number
            if gap > MAX_SKIP_THRESHOLD:
                return ForwardAck(
                    msg_id=request.msg_id,
                    accepted=False,
                    rejection_reason=(
                        f"sequence gap {gap} exceeds max skip "
                        f"threshold {MAX_SKIP_THRESHOLD}"
                    ),
                )

        # Store message.
        queue.append(
            StoredMessage(
                msg_id=request.msg_id,
                sender=sender,
                encrypted_payload=request.encrypted_payload,
                sequence_number=request.sequence_number,
                stored_at=now,
            )
        )
        self._seen_ids.add(request.msg_id)

        return ForwardAck(
            msg_id=request.msg_id,
            accepted=True,
        )

    def deliver(
        self, recipient: bytes
    ) -> tuple[list[ForwardDeliver], ForwardPurge]:
        """Drain all queued messages for a recipient.

        Returns (delivers, purge).
        """
        queue = self._queues.setdefault(recipient, deque())

        # Expire old messages before delivering.
        now = time.time()
        policy = self._policy_for(recipient)
        while queue and now - queue[0].stored_at > policy.max_age:
            removed = queue.popleft()
            self._seen_ids.discard(removed.msg_id)

        messages = list(queue)
        queue.clear()

        delivers = []
        purge_ids = []
        for msg in messages:
            purge_ids.append(msg.msg_id)
            self._seen_ids.discard(msg.msg_id)
            delivers.append(
                ForwardDeliver(
                    msg_id=msg.msg_id,
                    sender=msg.sender,
                    encrypted_payload=msg.encrypted_payload,
                    sequence_number=msg.sequence_number,
                )
            )

        return delivers, ForwardPurge(msg_ids=purge_ids)

    def queue_depth(self, peer_id: bytes) -> int:
        """Number of queued messages for a given peer."""
        queue = self._queues.get(peer_id)
        return len(queue) if queue else 0

    def total_messages(self) -> int:
        """Total number of messages across all queues."""
        return sum(len(q) for q in self._queues.values())

    def queue_stats(
        self,
    ) -> list[tuple[bytes, int, float | None, int]]:
        """Per-peer queue statistics.

        Returns list of (peer_id, pending, oldest_age_secs, total_bytes).
        """
        now = time.time()
        result = []
        for peer_id, queue in self._queues.items():
            pending = len(queue)
            oldest_age = None
            if queue:
                oldest_age = now - queue[0].stored_at
            total_bytes = sum(
                len(msg.encrypted_payload) for msg in queue
            )
            result.append(
                (peer_id, pending, oldest_age, total_bytes)
            )
        return result

    def expire_all(self) -> None:
        """Run retention expiry across all queues."""
        now = time.time()
        for peer_id, queue in self._queues.items():
            policy = self._policy_for(peer_id)
            while (
                queue and now - queue[0].stored_at > policy.max_age
            ):
                removed = queue.popleft()
                self._seen_ids.discard(removed.msg_id)


# ---------------------------------------------------------------------------
# Deduplication tracker (recipient side)
# ---------------------------------------------------------------------------


class DeduplicationTracker:
    """Tracks received message IDs for recipient-side dedup.

    Bounded to prevent unbounded memory growth.
    """

    def __init__(self, capacity: int) -> None:
        self._seen: set[bytes] = set()
        self._order: deque[bytes] = deque()
        self._capacity = capacity

    def check_and_insert(self, msg_id: bytes) -> bool:
        """Returns True if this is a new (non-duplicate) message ID."""
        if msg_id in self._seen:
            return False
        if len(self._order) >= self._capacity:
            oldest = self._order.popleft()
            self._seen.discard(oldest)
        self._seen.add(msg_id)
        self._order.append(msg_id)
        return True

    def __len__(self) -> int:
        return len(self._seen)

    @property
    def is_empty(self) -> bool:
        return len(self._seen) == 0
