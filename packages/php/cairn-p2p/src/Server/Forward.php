<?php

declare(strict_types=1);

namespace Cairn\Server;

use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;

/**
 * Reserved control channel for store-and-forward directives.
 */
const FORWARD_CHANNEL = '__cairn_forward';

/**
 * Max skip threshold for Double Ratchet message reconstruction.
 */
const MAX_SKIP_THRESHOLD = 1000;

// Also define as global constants for unqualified access from any namespace.
if (!defined('FORWARD_CHANNEL')) {
    define('FORWARD_CHANNEL', FORWARD_CHANNEL);
}
if (!defined('MAX_SKIP_THRESHOLD')) {
    define('MAX_SKIP_THRESHOLD', MAX_SKIP_THRESHOLD);
}

// ---------------------------------------------------------------------------
// Forward message types (0x07xx)
// ---------------------------------------------------------------------------

/**
 * 0x0700 -- Sender asks the server to store a message for an offline recipient.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs ForwardRequest.
 */
final class ForwardRequest
{
    public function __construct(
        public readonly string $msgId,
        public readonly PeerId $recipient,
        public readonly string $encryptedPayload,
        public readonly int $sequenceNumber,
    ) {
    }
}

/**
 * 0x0701 -- Server acknowledges (or rejects) a ForwardRequest.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs ForwardAck.
 */
final class ForwardAck
{
    public function __construct(
        public readonly string $msgId,
        public readonly bool $accepted,
        public readonly ?string $rejectionReason = null,
    ) {
    }
}

/**
 * 0x0702 -- Server delivers a stored message to the recipient.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs ForwardDeliver.
 */
final class ForwardDeliver
{
    public function __construct(
        public readonly string $msgId,
        public readonly PeerId $sender,
        public readonly string $encryptedPayload,
        public readonly int $sequenceNumber,
    ) {
    }
}

/**
 * 0x0703 -- Server purges delivered messages.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs ForwardPurge.
 */
final class ForwardPurge
{
    /**
     * @param list<string> $msgIds
     */
    public function __construct(
        public readonly array $msgIds,
    ) {
    }
}

// ---------------------------------------------------------------------------
// Retention policy
// ---------------------------------------------------------------------------

/**
 * Per-peer or default retention policy for stored messages.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs RetentionPolicy.
 */
final class RetentionPolicy
{
    public function __construct(
        /** Maximum message age in seconds. Default: 7 days. */
        public readonly int $maxAge = 604800,
        /** Maximum messages per peer queue. Default: 1000. */
        public readonly int $maxMessages = 1000,
    ) {
    }
}

// ---------------------------------------------------------------------------
// Stored message
// ---------------------------------------------------------------------------

/**
 * A message held in the server's per-peer queue.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs StoredMessage.
 */
final class StoredMessage
{
    public function __construct(
        public readonly string $msgId,
        public readonly PeerId $sender,
        public readonly string $encryptedPayload,
        public readonly int $sequenceNumber,
        public readonly float $storedAt,
    ) {
    }
}

// ---------------------------------------------------------------------------
// Message queue
// ---------------------------------------------------------------------------

/**
 * In-memory store-and-forward message queue with per-peer retention and dedup.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs MessageQueue.
 */
final class MessageQueue
{
    /** @var array<string, list<StoredMessage>> Queues: peer_id_string -> messages */
    private array $queues = [];

    /** @var array<string, true> Seen message IDs for deduplication */
    private array $seenIds = [];

    /** @var array<string, RetentionPolicy> Per-peer retention overrides */
    private array $peerOverrides = [];

    public function __construct(
        private readonly RetentionPolicy $defaultPolicy = new RetentionPolicy(),
    ) {
    }

    /**
     * Set a per-peer retention override.
     */
    public function setPeerOverride(PeerId $peerId, RetentionPolicy $policy): void
    {
        $this->peerOverrides[(string) $peerId] = $policy;
    }

    /**
     * Get the effective retention policy for a peer.
     */
    private function policyFor(PeerId $peerId): RetentionPolicy
    {
        return $this->peerOverrides[(string) $peerId] ?? $this->defaultPolicy;
    }

    /**
     * Enqueue a message for a recipient. Returns a ForwardAck.
     *
     * Validates:
     * - sender and recipient are both in pairedPeers set
     * - message is not a duplicate (UUID dedup)
     * - sequence gap does not exceed MAX_SKIP_THRESHOLD
     * - per-peer queue is not at capacity
     *
     * @param array<string, true> $pairedPeers Set of paired peer ID strings
     */
    public function enqueue(
        ForwardRequest $request,
        PeerId $sender,
        array $pairedPeers,
    ): ForwardAck {
        $senderKey = (string) $sender;
        $recipientKey = (string) $request->recipient;

        // Trust validation: server must be paired with both sender and recipient.
        if (!isset($pairedPeers[$senderKey])) {
            return new ForwardAck(
                msgId: $request->msgId,
                accepted: false,
                rejectionReason: 'sender is not a paired peer',
            );
        }

        if (!isset($pairedPeers[$recipientKey])) {
            return new ForwardAck(
                msgId: $request->msgId,
                accepted: false,
                rejectionReason: 'recipient is not a paired peer',
            );
        }

        // UUID deduplication.
        if (isset($this->seenIds[$request->msgId])) {
            return new ForwardAck(
                msgId: $request->msgId,
                accepted: false,
                rejectionReason: 'duplicate message ID',
            );
        }

        // Enforce retention limits.
        $policy = $this->policyFor($request->recipient);
        if (!isset($this->queues[$recipientKey])) {
            $this->queues[$recipientKey] = [];
        }
        $queue = &$this->queues[$recipientKey];

        // Expire old messages first.
        $now = microtime(true);
        while ($queue !== [] && ($now - $queue[0]->storedAt) > $policy->maxAge) {
            $removed = array_shift($queue);
            unset($this->seenIds[$removed->msgId]);
        }

        // Check capacity.
        if (count($queue) >= $policy->maxMessages) {
            return new ForwardAck(
                msgId: $request->msgId,
                accepted: false,
                rejectionReason: sprintf('recipient queue full (%d messages)', $policy->maxMessages),
            );
        }

        // Validate sequence gap (max skip threshold).
        if ($queue !== []) {
            $last = $queue[count($queue) - 1];
            $gap = $request->sequenceNumber - $last->sequenceNumber;
            if ($gap > MAX_SKIP_THRESHOLD) {
                return new ForwardAck(
                    msgId: $request->msgId,
                    accepted: false,
                    rejectionReason: sprintf(
                        'sequence gap %d exceeds max skip threshold %d',
                        $gap,
                        MAX_SKIP_THRESHOLD,
                    ),
                );
            }
        }

        // Store message.
        $queue[] = new StoredMessage(
            msgId: $request->msgId,
            sender: $sender,
            encryptedPayload: $request->encryptedPayload,
            sequenceNumber: $request->sequenceNumber,
            storedAt: $now,
        );
        $this->seenIds[$request->msgId] = true;

        return new ForwardAck(
            msgId: $request->msgId,
            accepted: true,
        );
    }

    /**
     * Drain all queued messages for a recipient, producing ForwardDeliver items.
     *
     * @return array{list<ForwardDeliver>, ForwardPurge}
     */
    public function deliver(PeerId $recipient): array
    {
        $key = (string) $recipient;
        if (!isset($this->queues[$key])) {
            $this->queues[$key] = [];
        }
        $queue = &$this->queues[$key];

        // Expire old messages before delivering.
        $now = microtime(true);
        $policy = $this->policyFor($recipient);
        while ($queue !== [] && ($now - $queue[0]->storedAt) > $policy->maxAge) {
            $removed = array_shift($queue);
            unset($this->seenIds[$removed->msgId]);
        }

        $delivers = [];
        $purgeIds = [];

        foreach ($queue as $msg) {
            $purgeIds[] = $msg->msgId;
            unset($this->seenIds[$msg->msgId]);
            $delivers[] = new ForwardDeliver(
                msgId: $msg->msgId,
                sender: $msg->sender,
                encryptedPayload: $msg->encryptedPayload,
                sequenceNumber: $msg->sequenceNumber,
            );
        }

        $this->queues[$key] = [];

        return [$delivers, new ForwardPurge($purgeIds)];
    }

    /**
     * Number of queued messages for a given peer.
     */
    public function queueDepth(PeerId $peerId): int
    {
        $key = (string) $peerId;
        return count($this->queues[$key] ?? []);
    }

    /**
     * Total number of messages across all queues.
     */
    public function totalMessages(): int
    {
        $total = 0;
        foreach ($this->queues as $queue) {
            $total += count($queue);
        }
        return $total;
    }

    /**
     * Run retention expiry across all queues.
     */
    public function expireAll(): void
    {
        $now = microtime(true);
        foreach ($this->queues as $peerKey => &$queue) {
            $policy = $this->peerOverrides[$peerKey] ?? $this->defaultPolicy;
            while ($queue !== [] && ($now - $queue[0]->storedAt) > $policy->maxAge) {
                $removed = array_shift($queue);
                unset($this->seenIds[$removed->msgId]);
            }
        }
        unset($queue);
    }
}

// ---------------------------------------------------------------------------
// Dedup tracker (recipient side)
// ---------------------------------------------------------------------------

/**
 * Tracks received message IDs for recipient-side deduplication.
 * Bounded to prevent unbounded memory growth.
 *
 * Matches packages/rs/cairn-p2p/src/server/store_forward.rs DeduplicationTracker.
 */
final class DeduplicationTracker
{
    /** @var array<string, true> */
    private array $seen = [];

    /** @var list<string> */
    private array $order = [];

    public function __construct(
        private readonly int $capacity,
    ) {
    }

    /**
     * Returns true if this is a new (non-duplicate) message ID.
     */
    public function checkAndInsert(string $msgId): bool
    {
        if (isset($this->seen[$msgId])) {
            return false;
        }

        if (count($this->order) >= $this->capacity) {
            $oldest = array_shift($this->order);
            if ($oldest !== null) {
                unset($this->seen[$oldest]);
            }
        }

        $this->seen[$msgId] = true;
        $this->order[] = $msgId;
        return true;
    }

    public function count(): int
    {
        return count($this->seen);
    }

    public function isEmpty(): bool
    {
        return $this->seen === [];
    }
}
