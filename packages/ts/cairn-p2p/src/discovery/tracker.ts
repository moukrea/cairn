// BitTorrent tracker client for peer discovery (spec/08 section 5.3)
// Supports BEP 3 (HTTP) and BEP 15 (UDP) tracker protocols.

import type { RendezvousId } from './rendezvous.js';
import type { DiscoveryBackend } from './manager.js';

/** Tracker protocol type. */
export type TrackerProtocol = 'http' | 'udp';

/** Tracker configuration. */
export interface TrackerConfig {
  /** Tracker announce URL. */
  url: string;
  /** Protocol (inferred from URL if not specified). */
  protocol?: TrackerProtocol;
}

/** Peer info returned from tracker announce. */
export interface TrackerPeer {
  /** IP address. */
  ip: string;
  /** Port number. */
  port: number;
}

/** Default minimum re-announce interval (15 minutes). */
export const MIN_REANNOUNCE_INTERVAL_MS = 15 * 60 * 1000;

/**
 * Parse a tracker URL to determine its protocol.
 */
export function parseTrackerProtocol(url: string): TrackerProtocol {
  if (url.startsWith('udp://')) return 'udp';
  return 'http';
}

/**
 * Encode bytes as URL-safe percent-encoded string for tracker requests.
 */
export function urlEncodeBytes(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => '%' + b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
}

/**
 * Build an HTTP tracker announce URL (BEP 3).
 *
 * @param announceUrl - Base tracker announce URL
 * @param infoHash - 20-byte info_hash
 * @param peerId - 20-byte peer_id
 * @param port - Listening port
 * @param event - Tracker event (started, stopped, completed)
 */
export function buildHttpAnnounceUrl(
  announceUrl: string,
  infoHash: Uint8Array,
  peerId: Uint8Array,
  port: number,
  event?: 'started' | 'stopped' | 'completed',
): string {
  const separator = announceUrl.includes('?') ? '&' : '?';
  let url =
    announceUrl +
    separator +
    `info_hash=${urlEncodeBytes(infoHash)}` +
    `&peer_id=${urlEncodeBytes(peerId)}` +
    `&port=${port}` +
    `&uploaded=0` +
    `&downloaded=0` +
    `&left=0` +
    `&compact=1`;

  if (event) {
    url += `&event=${event}`;
  }
  return url;
}

/**
 * Build a UDP tracker connect request (BEP 15).
 *
 * Returns a 16-byte buffer:
 * - 8 bytes: protocol_id (0x41727101980)
 * - 4 bytes: action (0 = connect)
 * - 4 bytes: transaction_id
 */
export function buildUdpConnectRequest(transactionId: number): Uint8Array {
  const buf = new Uint8Array(16);
  const view = new DataView(buf.buffer);
  // Magic protocol ID for BitTorrent UDP tracker
  view.setBigUint64(0, 0x41727101980n, false);
  view.setUint32(8, 0, false); // action: connect
  view.setUint32(12, transactionId, false);
  return buf;
}

/**
 * Parse a UDP tracker connect response (BEP 15).
 *
 * Expects 16 bytes:
 * - 4 bytes: action (0 = connect)
 * - 4 bytes: transaction_id
 * - 8 bytes: connection_id
 *
 * Returns the connection_id or null if invalid.
 */
export function parseUdpConnectResponse(
  data: Uint8Array,
  expectedTransactionId: number,
): bigint | null {
  if (data.length < 16) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const action = view.getUint32(0, false);
  const txnId = view.getUint32(4, false);
  if (action !== 0 || txnId !== expectedTransactionId) return null;
  return view.getBigUint64(8, false);
}

/**
 * Build a UDP tracker announce request (BEP 15).
 *
 * Returns a 98-byte buffer.
 */
export function buildUdpAnnounceRequest(
  connectionId: bigint,
  transactionId: number,
  infoHash: Uint8Array,
  peerId: Uint8Array,
  port: number,
  event: number = 0, // 0=none, 1=completed, 2=started, 3=stopped
): Uint8Array {
  const buf = new Uint8Array(98);
  const view = new DataView(buf.buffer);

  view.setBigUint64(0, connectionId, false);
  view.setUint32(8, 1, false); // action: announce
  view.setUint32(12, transactionId, false);
  buf.set(infoHash.slice(0, 20), 16); // info_hash
  buf.set(peerId.slice(0, 20), 36); // peer_id
  // downloaded (8 bytes) at offset 56 — left as 0
  // left (8 bytes) at offset 64 — left as 0
  // uploaded (8 bytes) at offset 72 — left as 0
  view.setUint32(80, event, false); // event
  // IP address (4 bytes) at offset 84 — 0 = default
  // key (4 bytes) at offset 88 — 0
  view.setInt32(92, -1, false); // num_want = -1 (default)
  view.setUint16(96, port, false);

  return buf;
}

/**
 * Parse a UDP tracker announce response (BEP 15).
 *
 * Returns peer list or null if invalid.
 */
export function parseUdpAnnounceResponse(
  data: Uint8Array,
  expectedTransactionId: number,
): { interval: number; peers: TrackerPeer[] } | null {
  if (data.length < 20) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const action = view.getUint32(0, false);
  const txnId = view.getUint32(4, false);
  if (action !== 1 || txnId !== expectedTransactionId) return null;

  const interval = view.getUint32(8, false);
  // leechers at offset 12, seeders at offset 16 — skip

  const peers: TrackerPeer[] = [];
  for (let offset = 20; offset + 6 <= data.length; offset += 6) {
    const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    const port = view.getUint16(offset + 4, false);
    peers.push({ ip, port });
  }

  return { interval, peers };
}

/**
 * Generate a random 20-byte peer ID (BEP 20 style).
 * Format: "-CR0001-" followed by 12 random bytes.
 */
export function generatePeerId(): Uint8Array {
  const id = new Uint8Array(20);
  const prefix = new TextEncoder().encode('-CR0001-');
  id.set(prefix, 0);
  // Fill remaining 12 bytes with random data
  const random = new Uint8Array(12);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(random);
  } else {
    for (let i = 0; i < 12; i++) {
      random[i] = Math.floor(Math.random() * 256);
    }
  }
  id.set(random, 8);
  return id;
}

/**
 * BitTorrent tracker discovery backend.
 *
 * Uses rendezvous ID as info_hash to publish and query peers via
 * BitTorrent tracker infrastructure.
 *
 * This is a local record-based implementation suitable for unit testing.
 * Real tracker communication requires platform-specific HTTP/UDP clients.
 */
export class TrackerBackend implements DiscoveryBackend {
  readonly name = 'bittorrent';
  readonly minReannounceIntervalMs = MIN_REANNOUNCE_INTERVAL_MS;
  private readonly _records = new Map<string, Uint8Array>();
  private readonly _trackers: TrackerConfig[];

  constructor(trackers: TrackerConfig[] = []) {
    this._trackers = trackers;
  }

  /** Get configured trackers. */
  get trackers(): TrackerConfig[] {
    return [...this._trackers];
  }

  /** Convert a RendezvousId to a 20-byte info_hash. */
  static toInfoHash(rendezvousId: RendezvousId): Uint8Array {
    return rendezvousId.toInfoHash();
  }

  async publish(rendezvousId: RendezvousId, payload: Uint8Array): Promise<void> {
    const key = bytesToHex(TrackerBackend.toInfoHash(rendezvousId));
    this._records.set(key, new Uint8Array(payload));
  }

  async query(rendezvousId: RendezvousId): Promise<Uint8Array | null> {
    const key = bytesToHex(TrackerBackend.toInfoHash(rendezvousId));
    return this._records.get(key) ?? null;
  }

  async stop(): Promise<void> {
    this._records.clear();
  }
}

/** Hex encoding utility. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
