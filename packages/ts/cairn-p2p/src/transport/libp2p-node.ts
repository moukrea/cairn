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
