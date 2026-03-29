// Kademlia DHT discovery backend — distributed peer discovery (spec/08 section 5.2)

import type { RendezvousId } from './rendezvous.js';
import type { DiscoveryBackend } from './manager.js';

/**
 * Kademlia DHT-based discovery backend.
 *
 * Uses libp2p's kad-dht service for distributed peer discovery.
 * Records are published as DHT provider records keyed by the
 * rendezvous ID, and queries use DHT GET to find records.
 *
 * The libp2p node must have the kad-dht service enabled
 * (configured in transport/libp2p-node.ts).
 */
export class DhtBackend implements DiscoveryBackend {
  readonly name = 'kademlia';

  /** Local records (fallback when DHT is not available). */
  private readonly _records = new Map<string, Uint8Array>();

  /** Reference to the libp2p node (set via setNode after transport starts). */
  private _libp2pNode: any = null;

  /**
   * Attach a running libp2p node with kad-dht service enabled.
   *
   * Call this after `createCairnNode()` + `node.start()` to wire
   * DHT operations through the libp2p network.
   */
  setNode(libp2pNode: unknown): void {
    this._libp2pNode = libp2pNode;
  }

  async publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void> {
    const key = rendezvousId.toHex();
    this._records.set(key, new Uint8Array(payload));

    // Attempt to publish via DHT content routing if available
    if (this._libp2pNode) {
      try {
        const contentRouting = (this._libp2pNode as any).contentRouting;
        if (contentRouting?.put) {
          // Store as a DHT record keyed by the rendezvous ID hex.
          // The key is prefixed with /cairn/rv/ to namespace it.
          const dhtKey = new TextEncoder().encode(`/cairn/rv/${key}`);
          await contentRouting.put(dhtKey, payload);
          return;
        }
      } catch {
        // DHT put failed — fall through to local storage only
      }
    }
  }

  async query(rendezvousId: RendezvousId): Promise<Uint8Array | null> {
    const key = rendezvousId.toHex();

    // Try DHT lookup first if the node is available
    if (this._libp2pNode) {
      try {
        const contentRouting = (this._libp2pNode as any).contentRouting;
        if (contentRouting?.get) {
          const dhtKey = new TextEncoder().encode(`/cairn/rv/${key}`);
          const result = await contentRouting.get(dhtKey);
          if (result) {
            return result instanceof Uint8Array ? result : new Uint8Array(result);
          }
        }
      } catch {
        // DHT lookup failed — fall through to local records
      }
    }

    // Fallback to local records
    return this._records.get(key) ?? null;
  }

  async stop(): Promise<void> {
    this._records.clear();
    this._libp2pNode = null;
  }

  /** Number of locally stored records. */
  get recordCount(): number {
    return this._records.size;
  }
}
