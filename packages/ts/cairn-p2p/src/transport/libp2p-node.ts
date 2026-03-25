import type { Libp2p } from 'libp2p';

import type { FallbackTransportType } from './fallback.js';

// ---------------------------------------------------------------------------
// Transport config
// ---------------------------------------------------------------------------

/** Per-transport enable/disable flags and timeout settings. */
export interface TransportConfig {
  /** Enable QUIC v1 — priority 1 in the fallback chain. (Node.js only) */
  quicEnabled: boolean;
  /** Enable TCP — priority 3 in the fallback chain. (Node.js only) */
  tcpEnabled: boolean;
  /** Enable WebSocket over TLS — priority 6 in the fallback chain. */
  websocketEnabled: boolean;
  /** Enable WebTransport over HTTP/3 — priority 7 in the fallback chain. */
  webtransportEnabled: boolean;
  /** Enable WebRTC — browser environment. */
  webrtcEnabled: boolean;
  /** Enable Circuit Relay v2 — priority 8. */
  circuitRelayEnabled: boolean;
  /** Per-transport connection timeout in ms. */
  perTransportTimeoutMs: number;
  /** STUN server URLs for NAT detection. */
  stunServers: string[];
  /** TURN server URLs (enables priorities 4-5). */
  turnServers: string[];
}

/** Default transport configuration. */
export function defaultTransportConfig(): TransportConfig {
  return {
    quicEnabled: true,
    tcpEnabled: true,
    websocketEnabled: true,
    webtransportEnabled: true,
    webrtcEnabled: true,
    circuitRelayEnabled: true,
    perTransportTimeoutMs: 10_000,
    stunServers: [
      'stun:stun.l.google.com:19302',
      'stun:stun1.l.google.com:19302',
    ],
    turnServers: [],
  };
}

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

/** Detect whether we are running in a Node.js environment. */
export function isNodeEnvironment(): boolean {
  return (
    typeof globalThis.process !== 'undefined' &&
    typeof globalThis.process.versions !== 'undefined' &&
    typeof globalThis.process.versions.node !== 'undefined'
  );
}

/** Detect whether we are running in a browser environment. */
export function isBrowserEnvironment(): boolean {
  return typeof globalThis.window !== 'undefined' && typeof globalThis.document !== 'undefined';
}

// ---------------------------------------------------------------------------
// libp2p node creation
// ---------------------------------------------------------------------------

/** Options for creating a cairn libp2p node. */
export interface CreateNodeOptions {
  config?: Partial<TransportConfig>;
}

/**
 * Create a libp2p node with environment-conditional transports.
 *
 * - Node.js: TCP, WebSocket, Circuit Relay v2 (yamux + noise)
 * - Browser: WebRTC, WebSocket, WebTransport, Circuit Relay v2 (yamux + noise)
 *
 * Uses dynamic `import()` so browser bundles don't include Node.js-only packages.
 */
export async function createCairnNode(options?: CreateNodeOptions): Promise<Libp2p> {
  const config = { ...defaultTransportConfig(), ...options?.config };
  const { createLibp2p } = await import('libp2p');
  const { yamux } = await import('@libp2p/yamux');
  const { noise } = await import('@chainsafe/libp2p-noise');

  const transports: unknown[] = [];

  if (isNodeEnvironment()) {
    // Node.js transports
    if (config.tcpEnabled) {
      const { tcp } = await import('@libp2p/tcp');
      transports.push(tcp());
    }
    if (config.websocketEnabled) {
      const { webSockets } = await import('@libp2p/websockets');
      transports.push(webSockets());
    }
  } else {
    // Browser transports
    if (config.webrtcEnabled) {
      const { webRTC } = await import('@libp2p/webrtc');
      transports.push(webRTC());
    }
    if (config.websocketEnabled) {
      const { webSockets } = await import('@libp2p/websockets');
      transports.push(webSockets());
    }
    if (config.webtransportEnabled) {
      const { webTransport } = await import('@libp2p/webtransport');
      transports.push(webTransport());
    }
  }

  if (config.circuitRelayEnabled) {
    const { circuitRelayTransport } = await import('@libp2p/circuit-relay-v2');
    transports.push(circuitRelayTransport());
  }

  const node = await createLibp2p({
    transports: transports as any[],
    streamMuxers: [yamux()],
    connectionEncrypters: [noise()],
  });

  return node;
}

// ---------------------------------------------------------------------------
// Cairn protocol framing — length-prefixed CBOR envelopes
// ---------------------------------------------------------------------------

/** Cairn application-level protocol identifier. */
export const CAIRN_PROTOCOL = '/cairn/1.0.0';

/** Maximum frame payload size (1 MiB). */
const MAX_FRAME_SIZE = 1_048_576;

/**
 * Encode a payload into a length-prefixed frame.
 *
 * Wire format: [4 bytes big-endian length][payload bytes]
 * Matches the Rust CairnCodec framing exactly.
 */
export function encodeFrame(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(4 + payload.length);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  view.setUint32(0, payload.length);
  frame.set(payload, 4);
  return frame;
}

/**
 * Decode a length-prefixed frame from a buffer.
 *
 * Returns the payload bytes. Throws if the buffer is too short or the
 * declared length exceeds the safety cap.
 */
export function decodeFrame(data: Uint8Array): Uint8Array {
  if (data.length < 4) {
    throw new Error('frame too short: missing length prefix');
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const len = view.getUint32(0);
  if (len > MAX_FRAME_SIZE) {
    throw new Error(`frame too large: ${len} bytes exceeds ${MAX_FRAME_SIZE} cap`);
  }
  if (data.length < 4 + len) {
    throw new Error(`frame truncated: expected ${4 + len} bytes, got ${data.length}`);
  }
  return data.slice(4, 4 + len);
}

/**
 * Read a complete length-prefixed frame from a libp2p stream.
 *
 * libp2p streams expose an async iterable of Uint8ArrayList chunks.
 * This function buffers until a complete frame is available.
 */
export async function readFrame(source: AsyncIterable<any>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let totalLen = 0;

  for await (const chunk of source) {
    // libp2p streams yield Uint8ArrayList objects that have a .subarray() method
    const bytes: Uint8Array = chunk.subarray ? chunk.subarray() : new Uint8Array(chunk);
    chunks.push(bytes);
    totalLen += bytes.length;

    // Need at least 4 bytes for the length prefix
    if (totalLen < 4) continue;

    const buf = concatChunks(chunks, totalLen);
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const payloadLen = view.getUint32(0);

    if (payloadLen > MAX_FRAME_SIZE) {
      throw new Error(`frame too large: ${payloadLen} bytes exceeds ${MAX_FRAME_SIZE} cap`);
    }

    if (totalLen >= 4 + payloadLen) {
      return buf.slice(4, 4 + payloadLen);
    }
  }

  throw new Error('stream ended before complete frame was received');
}

/**
 * Write a length-prefixed frame to a libp2p stream sink.
 */
export async function writeFrame(sink: { write: (data: Uint8Array) => void | Promise<void> }, payload: Uint8Array): Promise<void> {
  const frame = encodeFrame(payload);
  await sink.write(frame);
}

/** Concatenate buffered chunks into a single Uint8Array. */
function concatChunks(chunks: Uint8Array[], totalLen: number): Uint8Array {
  if (chunks.length === 1) return chunks[0];
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Browser transport chain (3 levels)
// ---------------------------------------------------------------------------

/** Browser transport chain: WebRTC -> WebSocket -> WebTransport. */
export const BROWSER_TRANSPORT_CHAIN: FallbackTransportType[] = [
  'quic', // WebRTC direct maps conceptually to the "best effort direct" slot
  'websocket-tls',
  'webtransport',
];

// ---------------------------------------------------------------------------
// Node.js transport chain (9 levels)
// ---------------------------------------------------------------------------

/** Node.js transport chain: full 9-level priority. */
export const NODEJS_TRANSPORT_CHAIN: FallbackTransportType[] = [
  'quic',
  'stun-udp',
  'tcp',
  'turn-udp',
  'turn-tcp',
  'websocket-tls',
  'webtransport',
  'circuit-relay-v2',
  'https-long-polling',
];
