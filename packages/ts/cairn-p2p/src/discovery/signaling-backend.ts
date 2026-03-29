// WebSocket signaling discovery backend (spec/08 section 5.4)
//
// Connects to one or more signaling servers via WebSocket and uses
// JSON messages to publish/query rendezvous records.
//
// Protocol:
//   Publish: {"type":"publish","topic":"<hex>","payload":"<base64>"}
//   Query:   {"type":"query","topic":"<hex>"}
//   Result:  {"type":"result","topic":"<hex>","payload":"<base64>"} | {"type":"result","topic":"<hex>","payload":null}

import type { RendezvousId } from './rendezvous.js';
import type { DiscoveryBackend } from './manager.js';

/** Signaling server configuration. */
export interface SignalingConfig {
  /** WebSocket URL(s) of signaling server(s). */
  urls: string[];
  /** Connection timeout in ms (default: 10000). */
  connectTimeoutMs?: number;
}

/**
 * WebSocket signaling-based discovery backend.
 *
 * Publishes and queries rendezvous records through a signaling server
 * over WebSocket. The signaling server is a simple pub/sub relay that
 * stores records keyed by topic (rendezvous ID hex).
 *
 * Falls back to local records when no signaling server is reachable.
 */
export class SignalingBackend implements DiscoveryBackend {
  readonly name = 'signaling';

  private readonly _urls: string[];
  private readonly _connectTimeoutMs: number;

  /** Local record store (fallback and cache). */
  private readonly _records = new Map<string, Uint8Array>();

  /** Active WebSocket connections, keyed by URL. */
  private readonly _connections = new Map<string, WebSocket>();

  /** Pending query resolvers, keyed by topic hex. */
  private readonly _pendingQueries = new Map<string, {
    resolve: (value: Uint8Array | null) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(config: SignalingConfig) {
    this._urls = [...config.urls];
    this._connectTimeoutMs = config.connectTimeoutMs ?? 10_000;
  }

  async publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void> {
    const topic = rendezvousId.toHex();
    this._records.set(topic, new Uint8Array(payload));

    const message = JSON.stringify({
      type: 'publish',
      topic,
      payload: bytesToBase64(payload),
    });

    // Publish to all connected signaling servers
    const ws = await this._getOrConnect();
    if (ws) {
      try {
        ws.send(message);
      } catch {
        // Connection lost — record is still stored locally
      }
    }
  }

  async query(rendezvousId: RendezvousId): Promise<Uint8Array | null> {
    const topic = rendezvousId.toHex();

    // Check local cache first
    const cached = this._records.get(topic);
    if (cached) return cached;

    // Query via signaling server
    const ws = await this._getOrConnect();
    if (!ws) return null;

    return new Promise<Uint8Array | null>((resolve) => {
      const timer = setTimeout(() => {
        this._pendingQueries.delete(topic);
        resolve(null);
      }, this._connectTimeoutMs);

      this._pendingQueries.set(topic, { resolve, timer });

      try {
        ws.send(JSON.stringify({ type: 'query', topic }));
      } catch {
        clearTimeout(timer);
        this._pendingQueries.delete(topic);
        resolve(null);
      }
    });
  }

  async stop(): Promise<void> {
    // Clear pending queries
    for (const [, pending] of this._pendingQueries) {
      clearTimeout(pending.timer);
      pending.resolve(null);
    }
    this._pendingQueries.clear();

    // Close all connections
    for (const [, ws] of this._connections) {
      try {
        ws.close(1000, 'backend stopped');
      } catch {
        // Already closed
      }
    }
    this._connections.clear();
    this._records.clear();
  }

  /** Number of locally cached records. */
  get recordCount(): number {
    return this._records.size;
  }

  /** Number of active signaling server connections. */
  get connectionCount(): number {
    let count = 0;
    for (const [, ws] of this._connections) {
      if (ws.readyState === WebSocket.OPEN) count++;
    }
    return count;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /**
   * Get an existing open connection or establish a new one.
   * Returns the first successfully connected WebSocket, or null.
   */
  private async _getOrConnect(): Promise<WebSocket | null> {
    // Try existing connections first
    for (const [, ws] of this._connections) {
      if (ws.readyState === WebSocket.OPEN) return ws;
    }

    // Try to connect to each URL in order
    for (const url of this._urls) {
      try {
        const ws = await this._connect(url);
        this._connections.set(url, ws);
        return ws;
      } catch {
        // Try next URL
      }
    }

    return null;
  }

  /** Connect to a signaling server with timeout. */
  private _connect(url: string): Promise<WebSocket> {
    return new Promise<WebSocket>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`connection timeout: ${url}`));
      }, this._connectTimeoutMs);

      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch (err) {
        clearTimeout(timer);
        reject(err);
        return;
      }

      ws.onopen = () => {
        clearTimeout(timer);
        resolve(ws);
      };

      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error(`WebSocket error: ${url}`));
      };

      ws.onclose = () => {
        this._connections.delete(url);
      };

      ws.onmessage = (event: MessageEvent) => {
        this._handleMessage(event.data);
      };
    });
  }

  /** Handle an incoming message from the signaling server. */
  private _handleMessage(data: unknown): void {
    try {
      const text = typeof data === 'string' ? data : String(data);
      const msg = JSON.parse(text) as {
        type: string;
        topic?: string;
        payload?: string | null;
      };

      if (msg.type === 'result' && msg.topic) {
        const pending = this._pendingQueries.get(msg.topic);
        if (pending) {
          clearTimeout(pending.timer);
          this._pendingQueries.delete(msg.topic);

          if (msg.payload) {
            try {
              const bytes = base64ToBytes(msg.payload);
              // Cache the result locally
              this._records.set(msg.topic, bytes);
              pending.resolve(bytes);
            } catch {
              pending.resolve(null);
            }
          } else {
            pending.resolve(null);
          }
        }
      }
    } catch {
      // Ignore malformed messages
    }
  }
}

// --- Helpers ---

/** Encode Uint8Array to base64 string. */
function bytesToBase64(bytes: Uint8Array): string {
  if (typeof globalThis.btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return globalThis.btoa(binary);
  }
  // Node.js fallback
  return Buffer.from(bytes).toString('base64');
}

/** Decode base64 string to Uint8Array. */
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
