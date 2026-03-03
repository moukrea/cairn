// Store-and-forward message queue (spec/10 section 10.3)

/** Reserved control channel for store-and-forward directives. */
export const FORWARD_CHANNEL = '__cairn_forward';

/** Max skip threshold for Double Ratchet message reconstruction. */
export const MAX_SKIP_THRESHOLD = 1000;

// --- Forward message types (0x07xx) ---

/** 0x0700 — Sender asks the server to store a message for an offline recipient. */
export interface ForwardRequest {
  msgId: string;
  recipient: string;
  encryptedPayload: Uint8Array;
  sequenceNumber: number;
}

/** 0x0701 — Server acknowledges (or rejects) a ForwardRequest. */
export interface ForwardAck {
  msgId: string;
  accepted: boolean;
  rejectionReason?: string;
}

/** 0x0702 — Server delivers a stored message to the recipient. */
export interface ForwardDeliver {
  msgId: string;
  sender: string;
  encryptedPayload: Uint8Array;
  sequenceNumber: number;
}

/** 0x0703 — Server purges delivered messages. */
export interface ForwardPurge {
  msgIds: string[];
}

// --- Stored message ---

/** A message held in the server's per-peer queue. */
export interface StoredMessage {
  msgId: string;
  sender: string;
  encryptedPayload: Uint8Array;
  sequenceNumber: number;
  storedAt: number;
}

// --- Retention policy ---

/** Retention policy for stored messages. */
export interface RetentionPolicy {
  /** Max age in milliseconds. Default: 7 days. */
  maxAgeMs: number;
  /** Max messages per peer. Default: 1000. */
  maxMessages: number;
}

/** Default retention policy: 7 days, 1000 messages per peer. */
export function defaultRetentionPolicy(): RetentionPolicy {
  return {
    maxAgeMs: 7 * 24 * 60 * 60 * 1000,
    maxMessages: 1000,
  };
}

// --- Message store ---

/**
 * In-memory store-and-forward message queue with per-peer retention and dedup.
 */
export class MessageStore {
  private readonly _queues = new Map<string, StoredMessage[]>();
  private readonly _seenIds = new Set<string>();
  private readonly _defaultPolicy: RetentionPolicy;
  private readonly _peerOverrides = new Map<string, RetentionPolicy>();

  constructor(policy?: RetentionPolicy) {
    this._defaultPolicy = policy ?? defaultRetentionPolicy();
  }

  /** Set a per-peer retention override. */
  setPeerOverride(peerId: string, policy: RetentionPolicy): void {
    this._peerOverrides.set(peerId, policy);
  }

  /** Get the effective retention policy for a peer. */
  private policyFor(peerId: string): RetentionPolicy {
    return this._peerOverrides.get(peerId) ?? this._defaultPolicy;
  }

  /**
   * Enqueue a message for a recipient.
   *
   * Validates:
   * - sender and recipient are both in pairedPeers set
   * - message is not a duplicate (UUID dedup)
   * - sequence gap does not exceed MAX_SKIP_THRESHOLD
   * - per-peer queue is not at capacity
   */
  enqueue(
    request: ForwardRequest,
    sender: string,
    pairedPeers: Set<string>,
  ): ForwardAck {
    // Trust validation: server must be paired with both sender and recipient.
    if (!pairedPeers.has(sender)) {
      return { msgId: request.msgId, accepted: false, rejectionReason: 'sender is not a paired peer' };
    }
    if (!pairedPeers.has(request.recipient)) {
      return { msgId: request.msgId, accepted: false, rejectionReason: 'recipient is not a paired peer' };
    }

    // UUID deduplication.
    if (this._seenIds.has(request.msgId)) {
      return { msgId: request.msgId, accepted: false, rejectionReason: 'duplicate message ID' };
    }

    // Get or create queue, expire old messages.
    const policy = this.policyFor(request.recipient);
    let queue = this._queues.get(request.recipient);
    if (!queue) {
      queue = [];
      this._queues.set(request.recipient, queue);
    }

    this.expireQueue(queue, policy);

    // Check capacity.
    if (queue.length >= policy.maxMessages) {
      return {
        msgId: request.msgId,
        accepted: false,
        rejectionReason: `recipient queue full (${policy.maxMessages} messages)`,
      };
    }

    // Validate sequence gap.
    if (queue.length > 0) {
      const last = queue[queue.length - 1];
      const gap = request.sequenceNumber - last.sequenceNumber;
      if (gap > MAX_SKIP_THRESHOLD) {
        return {
          msgId: request.msgId,
          accepted: false,
          rejectionReason: `sequence gap ${gap} exceeds max skip threshold ${MAX_SKIP_THRESHOLD}`,
        };
      }
    }

    // Store message.
    queue.push({
      msgId: request.msgId,
      sender,
      encryptedPayload: request.encryptedPayload,
      sequenceNumber: request.sequenceNumber,
      storedAt: Date.now(),
    });
    this._seenIds.add(request.msgId);

    return { msgId: request.msgId, accepted: true };
  }

  /**
   * Deliver all queued messages for a recipient.
   * Returns delivered messages and a purge directive.
   */
  deliver(recipient: string): { delivers: ForwardDeliver[]; purge: ForwardPurge } {
    let queue = this._queues.get(recipient);
    if (!queue) {
      queue = [];
      this._queues.set(recipient, queue);
    }

    const policy = this.policyFor(recipient);
    this.expireQueue(queue, policy);

    const delivers: ForwardDeliver[] = [];
    const purgeIds: string[] = [];

    for (const msg of queue) {
      purgeIds.push(msg.msgId);
      this._seenIds.delete(msg.msgId);
      delivers.push({
        msgId: msg.msgId,
        sender: msg.sender,
        encryptedPayload: msg.encryptedPayload,
        sequenceNumber: msg.sequenceNumber,
      });
    }

    queue.length = 0; // clear

    return { delivers, purge: { msgIds: purgeIds } };
  }

  /** Number of queued messages for a given peer. */
  queueDepth(peerId: string): number {
    return this._queues.get(peerId)?.length ?? 0;
  }

  /** Total number of messages across all queues. */
  get totalMessages(): number {
    let count = 0;
    for (const q of this._queues.values()) {
      count += q.length;
    }
    return count;
  }

  /** Run retention expiry across all queues. */
  expireAll(): void {
    for (const [peerId, queue] of this._queues) {
      const policy = this.policyFor(peerId);
      this.expireQueue(queue, policy);
    }
  }

  /** Expire old messages from a queue. */
  private expireQueue(queue: StoredMessage[], policy: RetentionPolicy): void {
    const now = Date.now();
    while (queue.length > 0 && (now - queue[0].storedAt) >= policy.maxAgeMs) {
      const removed = queue.shift()!;
      this._seenIds.delete(removed.msgId);
    }
  }
}

// --- Deduplication tracker (recipient side) ---

/**
 * Tracks received message IDs for recipient-side deduplication.
 * Bounded to prevent unbounded memory growth.
 */
export class DeduplicationTracker {
  private readonly _seen = new Set<string>();
  private readonly _order: string[] = [];
  private readonly _capacity: number;

  constructor(capacity: number) {
    this._capacity = capacity;
  }

  /** Returns true if this is a new (non-duplicate) message ID. */
  checkAndInsert(msgId: string): boolean {
    if (this._seen.has(msgId)) {
      return false;
    }
    if (this._order.length >= this._capacity) {
      const oldest = this._order.shift()!;
      this._seen.delete(oldest);
    }
    this._seen.add(msgId);
    this._order.push(msgId);
    return true;
  }

  get length(): number {
    return this._seen.size;
  }

  get isEmpty(): boolean {
    return this._seen.size === 0;
  }
}
