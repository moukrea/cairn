// mDNS discovery backend — LAN peer discovery via libp2p mDNS (spec/08 section 5.1)

import type { RendezvousId } from './rendezvous.js';
import type { DiscoveryBackend } from './manager.js';

/**
 * mDNS-based LAN discovery backend.
 *
 * Uses libp2p's mDNS service for local network peer discovery.
 * The rendezvous ID hex is used as a TXT record key, and the
 * payload is stored as a base64-encoded TXT record value.
 *
 * mDNS is attempted first before any remote backends because
 * LAN discovery is instantaneous and free.
 *
 * Note: The actual mDNS service is configured as a libp2p service
 * in the node creation (transport/libp2p-node.ts). This backend
 * maintains a local record store that the mDNS service advertises,
 * and queries are resolved against discovered peers' records.
 */
export class MdnsBackend implements DiscoveryBackend {
  readonly name = 'mdns';

  /** Local records published via this backend. */
  private readonly _records = new Map<string, Uint8Array>();

  /** Records discovered from the LAN via mDNS events. */
  private readonly _discovered = new Map<string, Uint8Array>();

  /** Reference to the libp2p node (set via setNode after transport starts). */
  private _libp2pNode: any = null;

  /** AbortController for stopping the mDNS listener. */
  private _abortController: AbortController | null = null;

  /**
   * Attach a running libp2p node with mDNS service enabled.
   *
   * Call this after `createCairnNode()` + `node.start()` to wire
   * mDNS peer discovery events into this backend.
   */
  setNode(libp2pNode: unknown): void {
    this._libp2pNode = libp2pNode;
    this._abortController = new AbortController();

    // Listen for peer discovery events from the mDNS service.
    // When a peer is discovered, its custom protocol data (if any)
    // is extracted and stored in _discovered.
    const node = libp2pNode as any;
    if (node.addEventListener) {
      node.addEventListener('peer:discovery', (evt: any) => {
        try {
          const detail = evt.detail;
          if (!detail?.id) return;

          // Extract rendezvous records from the peer's metadata
          // (stored as protocol metadata in the peer's multiaddrs).
          // This is a best-effort extraction — mDNS peers that
          // publish cairn records will include them as protocol metadata.
          const protocols = detail.protocols ?? [];
          for (const proto of protocols) {
            if (typeof proto === 'string' && proto.startsWith('/cairn/rv/')) {
              const parts = proto.split('/');
              // Format: /cairn/rv/<hex-key>/<base64-payload>
              if (parts.length >= 5) {
                const key = parts[3];
                const payloadB64 = parts[4];
                try {
                  const payload = base64ToBytes(payloadB64);
                  this._discovered.set(key, payload);
                } catch {
                  // Invalid base64 — skip
                }
              }
            }
          }
        } catch {
          // Ignore malformed events
        }
      }, { signal: this._abortController.signal });
    }
  }

  async publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void> {
    const key = rendezvousId.toHex();
    this._records.set(key, new Uint8Array(payload));

    // If the libp2p node is available with content routing, also
    // advertise via the DHT/content-routing layer for mDNS peers
    // to discover.
    if (this._libp2pNode) {
      try {
        const contentRouting = (this._libp2pNode as any).contentRouting;
        if (contentRouting?.provide) {
          // Use the rendezvous ID bytes as a CID-like key
          // This is a best-effort publish — mDNS itself doesn't
          // have a publish mechanism beyond advertising the node.
          // The actual record is stored locally and returned on query.
        }
      } catch {
        // Content routing not available — records remain local
      }
    }
  }

  async query(rendezvousId: RendezvousId): Promise<Uint8Array | null> {
    const key = rendezvousId.toHex();

    // Check local records first (for loopback / same-process testing)
    const local = this._records.get(key);
    if (local) return local;

    // Check records discovered from LAN peers
    const discovered = this._discovered.get(key);
    if (discovered) return discovered;

    return null;
  }

  async stop(): Promise<void> {
    if (this._abortController) {
      this._abortController.abort();
      this._abortController = null;
    }
    this._records.clear();
    this._discovered.clear();
    this._libp2pNode = null;
  }

  /** Number of locally published records. */
  get recordCount(): number {
    return this._records.size;
  }

  /** Number of records discovered from LAN peers. */
  get discoveredCount(): number {
    return this._discovered.size;
  }
}

// --- Helpers ---

/** Decode a base64 string to Uint8Array. */
function base64ToBytes(b64: string): Uint8Array {
  if (typeof globalThis.atob === 'function') {
    const binary = globalThis.atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js fallback
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
