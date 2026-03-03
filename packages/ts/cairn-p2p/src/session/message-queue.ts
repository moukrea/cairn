// Message queuing during disconnection (spec/07 section 5)

/** Queue overflow strategy. */
export type QueueStrategy = 'fifo' | 'lifo';

/** Message queue configuration. */
export interface QueueConfig {
  /** Whether to buffer messages at all. Default: true. */
  enabled: boolean;
  /** Maximum messages to buffer. Default: 1000. */
  maxSize: number;
  /** Maximum age before discard (ms). Default: 3600000 (1 hour). */
  maxAgeMs: number;
  /** Overflow strategy. Default: 'fifo'. */
  strategy: QueueStrategy;
}

/** Default queue config. */
export function defaultQueueConfig(): QueueConfig {
  return {
    enabled: true,
    maxSize: 1000,
    maxAgeMs: 3_600_000,
    strategy: 'fifo',
  };
}

/** A queued message with metadata for age tracking. */
export interface QueuedMessage {
  sequence: number;
  payload: Uint8Array;
  enqueuedAt: number;
}

/** Result of attempting to enqueue a message. */
export type EnqueueResult = 'enqueued' | 'disabled' | 'full' | 'enqueued_with_eviction';

/**
 * Message queue for buffering during disconnection.
 *
 * Messages are buffered locally while in Disconnected, Reconnecting, or Suspended states.
 * On session resumption, retransmit in sequence order.
 * On session re-establishment (after expiry), discard entire queue.
 *
 * FIFO: when queue is full, reject new messages.
 * LIFO: when queue is full, discard oldest message to make room.
 */
export class MessageQueue {
  private readonly _config: QueueConfig;
  private _messages: QueuedMessage[] = [];

  constructor(config?: Partial<QueueConfig>) {
    const defaults = defaultQueueConfig();
    this._config = {
      enabled: config?.enabled ?? defaults.enabled,
      maxSize: config?.maxSize ?? defaults.maxSize,
      maxAgeMs: config?.maxAgeMs ?? defaults.maxAgeMs,
      strategy: config?.strategy ?? defaults.strategy,
    };
  }

  /** Enqueue a message. Returns the enqueue result. */
  enqueue(sequence: number, payload: Uint8Array): EnqueueResult {
    if (!this._config.enabled) {
      return 'disabled';
    }

    this.expireStale();

    const msg: QueuedMessage = {
      sequence,
      payload,
      enqueuedAt: Date.now(),
    };

    if (this._messages.length >= this._config.maxSize) {
      if (this._config.strategy === 'fifo') {
        return 'full';
      }
      // LIFO: discard oldest to make room
      this._messages.shift();
      this._messages.push(msg);
      return 'enqueued_with_eviction';
    }

    this._messages.push(msg);
    return 'enqueued';
  }

  /** Drain all queued messages in sequence order for retransmission. */
  drain(): QueuedMessage[] {
    this.expireStale();
    const msgs = [...this._messages];
    this._messages = [];
    return msgs;
  }

  /** Discard all queued messages (e.g., on session re-establishment). */
  clear(): void {
    this._messages = [];
  }

  /** Get the number of currently queued messages. */
  get length(): number {
    return this._messages.length;
  }

  /** Check whether the queue is empty. */
  get isEmpty(): boolean {
    return this._messages.length === 0;
  }

  /** Get the remaining capacity. */
  get remainingCapacity(): number {
    return Math.max(0, this._config.maxSize - this._messages.length);
  }

  /** Peek at the next message without removing it. */
  peek(): QueuedMessage | undefined {
    return this._messages[0];
  }

  /** Get the queue configuration. */
  get config(): QueueConfig {
    return this._config;
  }

  /** Remove messages older than maxAge. */
  private expireStale(): void {
    const now = Date.now();
    this._messages = this._messages.filter((msg) => now - msg.enqueuedAt < this._config.maxAgeMs);
  }
}
