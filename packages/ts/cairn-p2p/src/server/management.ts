// Management API for server-mode peers (spec 10.5, 10.7).
//
// Opt-in REST/JSON HTTP API bound to 127.0.0.1:9090 by default.
// Bearer token authentication with constant-time comparison.

import { createServer, IncomingMessage, ServerResponse, Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Management API configuration. */
export interface ManagementConfig {
  /** Whether the management API is enabled. Default: false. */
  enabled: boolean;
  /** Bind address. Default: '127.0.0.1'. */
  bindAddress: string;
  /** Port. Default: 9090. */
  port: number;
  /** Bearer token for authentication. */
  authToken: string;
}

/** Default management API configuration. */
export function defaultManagementConfig(): ManagementConfig {
  return {
    enabled: false,
    bindAddress: '127.0.0.1',
    port: 9090,
    authToken: '',
  };
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/** Information about a paired peer. */
export interface PeerInfo {
  peerId: string;
  name: string;
  connected: boolean;
  lastSeen: string | null;
}

/** Per-peer store-and-forward queue info. */
export interface QueueInfo {
  peerId: string;
  pendingMessages: number;
  oldestMessageAgeSecs: number | null;
  totalBytes: number;
}

/** Per-peer relay statistics. */
export interface PeerRelayStats {
  peerId: string;
  bytesRelayed: number;
  activeStreams: number;
}

/** Relay statistics overview. */
export interface RelayStats {
  activeConnections: number;
  perPeer: PeerRelayStats[];
}

/** Response for GET /peers. */
export interface PeersResponse {
  peers: PeerInfo[];
}

/** Response for GET /queues. */
export interface QueuesResponse {
  queues: QueueInfo[];
}

/** Response for GET /relay/stats. */
export interface RelayStatsResponse {
  relay: RelayStats;
}

/** Response for GET /health. */
export interface HealthResponse {
  status: 'healthy' | 'degraded';
  uptimeSecs: number;
  connectedPeers: number;
  totalPeers: number;
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/** Shared state accessible by all management API handlers. */
export class ManagementState {
  readonly authTokenBytes: Buffer;
  peers: PeerInfo[] = [];
  queues: QueueInfo[] = [];
  relayStats: RelayStats = { activeConnections: 0, perPeer: [] };
  readonly startedAt: number;

  constructor(authToken: string) {
    this.authTokenBytes = Buffer.from(authToken, 'utf-8');
    this.startedAt = Date.now();
  }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Validate a bearer token using constant-time comparison.
 * Returns true if the token matches.
 */
function validateToken(provided: string, expected: Buffer): boolean {
  const providedBytes = Buffer.from(provided, 'utf-8');
  if (providedBytes.length !== expected.length) {
    // Still do a comparison against expected to avoid timing leak on length.
    timingSafeEqual(expected, expected);
    return false;
  }
  return timingSafeEqual(providedBytes, expected);
}

/**
 * Extract bearer token from Authorization header.
 * Returns the token string or null if not present/malformed.
 */
function extractBearerToken(req: IncomingMessage): string | null {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return null;
  }
  return header.slice(7);
}

// ---------------------------------------------------------------------------
// Route handling
// ---------------------------------------------------------------------------

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function handlePeers(state: ManagementState, res: ServerResponse): void {
  const response: PeersResponse = { peers: state.peers };
  sendJson(res, 200, response);
}

function handleQueues(state: ManagementState, res: ServerResponse): void {
  const response: QueuesResponse = { queues: state.queues };
  sendJson(res, 200, response);
}

function handleRelayStats(state: ManagementState, res: ServerResponse): void {
  const response: RelayStatsResponse = { relay: state.relayStats };
  sendJson(res, 200, response);
}

function handleHealth(state: ManagementState, res: ServerResponse): void {
  const totalPeers = state.peers.length;
  const connectedPeers = state.peers.filter((p) => p.connected).length;
  const uptimeSecs = Math.floor((Date.now() - state.startedAt) / 1000);
  const status = connectedPeers > 0 ? 'healthy' : 'degraded';

  const response: HealthResponse = {
    status,
    uptimeSecs,
    connectedPeers,
    totalPeers,
  };
  sendJson(res, 200, response);
}

function handlePairingQr(res: ServerResponse): void {
  sendJson(res, 503, {
    error: 'pairing QR generation not yet available (pending headless pairing integration)',
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * Create and start the management API HTTP server.
 *
 * Returns a handle with `close()` to stop the server.
 *
 * @throws Error if authToken is empty.
 */
export function createManagementServer(
  config: ManagementConfig,
  state: ManagementState,
): ManagementServer {
  if (config.authToken === '') {
    throw new Error('management API auth token is empty');
  }

  // Warn on non-loopback bind address.
  if (config.bindAddress !== '127.0.0.1' && config.bindAddress !== '::1') {
    console.warn(
      `Management API exposed on non-loopback interface ${config.bindAddress} without TLS. This is insecure.`,
    );
  }

  const server = createServer((req, res) => {
    // Authentication.
    const token = extractBearerToken(req);
    if (token === null || !validateToken(token, state.authTokenBytes)) {
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }

    // Routing.
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    if (method !== 'GET') {
      sendJson(res, 405, { error: 'method not allowed' });
      return;
    }

    switch (url) {
      case '/peers':
        handlePeers(state, res);
        break;
      case '/queues':
        handleQueues(state, res);
        break;
      case '/relay/stats':
        handleRelayStats(state, res);
        break;
      case '/health':
        handleHealth(state, res);
        break;
      case '/pairing/qr':
        handlePairingQr(res);
        break;
      default:
        sendJson(res, 404, { error: 'not found' });
        break;
    }
  });

  return new ManagementServer(server, config);
}

/** Handle to a running management API server. */
export class ManagementServer {
  private readonly _server: Server;
  private readonly _config: ManagementConfig;

  constructor(server: Server, config: ManagementConfig) {
    this._server = server;
    this._config = config;
  }

  /** Start listening. Returns a promise that resolves when the server is ready. */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this._server.listen(this._config.port, this._config.bindAddress, () => {
        resolve();
      });
    });
  }

  /** Stop the server. */
  async close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this._server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /** The underlying http.Server (for testing). */
  get httpServer(): Server {
    return this._server;
  }
}
