// Discovery manager — coordinates multiple backends (spec/08 section 5)

import type { RendezvousId } from './rendezvous.js';

/** A pluggable discovery backend. */
export interface DiscoveryBackend {
  /** Human-readable name (e.g., "mdns", "dht", "bittorrent", "signaling"). */
  readonly name: string;

  /** Publish reachability information at the given rendezvous ID. */
  publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void>;

  /** Query for a peer's reachability at the given rendezvous ID. */
  query(rendezvousId: RendezvousId): Promise<Uint8Array | null>;

  /** Stop publishing and querying. Clean up resources. */
  stop(): Promise<void>;
}

/** Result of a discovery query indicating which backend found the peer. */
export interface DiscoveryResult {
  backend: string;
  payload: Uint8Array;
}

/** Result of a publish operation per backend. */
export interface PublishResult {
  backend: string;
  success: boolean;
  error?: Error;
}

/**
 * Coordinates discovery across all configured backends.
 *
 * Publishes to and queries from all backends simultaneously.
 * First successful query result wins.
 */
export class DiscoveryManager {
  private readonly _backends: DiscoveryBackend[] = [];

  /** Add a discovery backend. */
  addBackend(backend: DiscoveryBackend): void {
    this._backends.push(backend);
  }

  /** Number of configured backends. */
  get backendCount(): number {
    return this._backends.length;
  }

  /** List backend names. */
  get backendNames(): string[] {
    return this._backends.map((b) => b.name);
  }

  /**
   * Publish reachability to all backends simultaneously.
   * Returns per-backend results. Non-critical failures are captured, not thrown.
   */
  async publishAll(rendezvousId: RendezvousId, payload: Uint8Array): Promise<PublishResult[]> {
    const results = await Promise.allSettled(
      this._backends.map(async (backend) => {
        await backend.publish(rendezvousId, payload);
        return backend.name;
      }),
    );

    return results.map((result, i) => {
      if (result.status === 'fulfilled') {
        return { backend: result.value, success: true };
      }
      return {
        backend: this._backends[i].name,
        success: false,
        error: result.reason instanceof Error ? result.reason : new Error(String(result.reason)),
      };
    });
  }

  /**
   * Query all backends simultaneously. Returns the first successful result.
   *
   * All backends are queried in parallel via Promise.allSettled. The first
   * non-null result (in backend registration order) wins.
   */
  async queryFirst(rendezvousId: RendezvousId): Promise<DiscoveryResult | null> {
    const results = await Promise.allSettled(
      this._backends.map(async (backend) => {
        const payload = await backend.query(rendezvousId);
        return { backend: backend.name, payload };
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.payload !== null) {
        return {
          backend: result.value.backend,
          payload: result.value.payload,
        };
      }
    }

    return null;
  }

  /** Stop all backends. */
  async stopAll(): Promise<void> {
    await Promise.allSettled(this._backends.map((b) => b.stop()));
  }
}

/**
 * In-memory discovery backend for testing and local development.
 *
 * All instances share records through the records map passed in constructor.
 */
export class InMemoryBackend implements DiscoveryBackend {
  readonly name: string;
  private readonly _records: Map<string, Uint8Array>;

  constructor(name: string, records?: Map<string, Uint8Array>) {
    this.name = name;
    this._records = records ?? new Map();
  }

  async publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void> {
    this._records.set(rendezvousId.toHex(), new Uint8Array(payload));
  }

  async query(rendezvousId: RendezvousId): Promise<Uint8Array | null> {
    return this._records.get(rendezvousId.toHex()) ?? null;
  }

  async stop(): Promise<void> {
    this._records.clear();
  }
}
