import { describe, it, expect, afterEach } from 'vitest';
import {
  FORWARD_CHANNEL,
  MAX_SKIP_THRESHOLD,
  defaultRetentionPolicy,
  MessageStore,
  DeduplicationTracker,
} from '../../src/server/store-forward.js';
import type {
  ForwardRequest,
  ForwardAck,
  ForwardDeliver,
  ForwardPurge,
  RetentionPolicy,
} from '../../src/server/store-forward.js';
import { defaultServerConfig } from '../../src/server/index.js';
import type { ServerConfig } from '../../src/server/index.js';
import {
  ManagementState,
  createManagementServer,
  defaultManagementConfig,
} from '../../src/server/management.js';
import type {
  ManagementConfig,
  PeersResponse,
  QueuesResponse,
  RelayStatsResponse,
  HealthResponse,
} from '../../src/server/management.js';

// Helper to generate unique IDs
let idCounter = 0;
function makeId(): string {
  return `msg-${++idCounter}-${Date.now()}`;
}

function makeRequest(recipient: string, seq: number): ForwardRequest {
  return {
    msgId: makeId(),
    recipient,
    encryptedPayload: new Uint8Array([0xab, 0xcd]),
    sequenceNumber: seq,
  };
}

// --- Constants ---

describe('constants', () => {
  it('FORWARD_CHANNEL', () => {
    expect(FORWARD_CHANNEL).toBe('__cairn_forward');
  });

  it('MAX_SKIP_THRESHOLD', () => {
    expect(MAX_SKIP_THRESHOLD).toBe(1000);
  });
});

// --- RetentionPolicy ---

describe('RetentionPolicy', () => {
  it('default values', () => {
    const p = defaultRetentionPolicy();
    expect(p.maxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(p.maxMessages).toBe(1000);
  });
});

// --- ServerConfig ---

describe('ServerConfig', () => {
  it('default values', () => {
    const cfg = defaultServerConfig();
    expect(cfg.meshEnabled).toBe(true);
    expect(cfg.relayWilling).toBe(true);
    expect(cfg.relayCapacity).toBe(100);
    expect(cfg.storeForwardEnabled).toBe(true);
    expect(cfg.storeForwardMaxPerPeer).toBe(1000);
    expect(cfg.storeForwardMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(cfg.storeForwardMaxTotalSize).toBe(1_073_741_824);
    expect(cfg.sessionExpiryMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(cfg.heartbeatIntervalMs).toBe(60_000);
    expect(cfg.reconnectMaxDurationMs).toBeNull();
    expect(cfg.headless).toBe(true);
  });
});

// --- Forward message types ---

describe('ForwardRequest', () => {
  it('fields', () => {
    const req: ForwardRequest = {
      msgId: 'test-id',
      recipient: 'peer-b',
      encryptedPayload: new Uint8Array([1, 2, 3]),
      sequenceNumber: 42,
    };
    expect(req.recipient).toBe('peer-b');
    expect(req.sequenceNumber).toBe(42);
    expect(req.encryptedPayload).toEqual(new Uint8Array([1, 2, 3]));
  });
});

describe('ForwardAck', () => {
  it('accepted', () => {
    const ack: ForwardAck = { msgId: 'id', accepted: true };
    expect(ack.accepted).toBe(true);
    expect(ack.rejectionReason).toBeUndefined();
  });

  it('rejected', () => {
    const ack: ForwardAck = { msgId: 'id', accepted: false, rejectionReason: 'test reason' };
    expect(ack.accepted).toBe(false);
    expect(ack.rejectionReason).toBe('test reason');
  });
});

describe('ForwardDeliver', () => {
  it('fields', () => {
    const d: ForwardDeliver = {
      msgId: 'id',
      sender: 'peer-a',
      encryptedPayload: new Uint8Array([0xde, 0xad]),
      sequenceNumber: 99,
    };
    expect(d.sender).toBe('peer-a');
    expect(d.sequenceNumber).toBe(99);
  });
});

describe('ForwardPurge', () => {
  it('fields', () => {
    const p: ForwardPurge = { msgIds: ['id1', 'id2'] };
    expect(p.msgIds.length).toBe(2);
  });
});

// --- MessageStore ---

describe('MessageStore', () => {
  const paired = new Set(['sender', 'recipient']);

  it('enqueue accepted', () => {
    const store = new MessageStore();
    const req = makeRequest('recipient', 1);
    const ack = store.enqueue(req, 'sender', paired);
    expect(ack.accepted).toBe(true);
    expect(ack.rejectionReason).toBeUndefined();
    expect(store.queueDepth('recipient')).toBe(1);
  });

  it('rejects unpaired sender', () => {
    const store = new MessageStore();
    const req = makeRequest('recipient', 1);
    const ack = store.enqueue(req, 'unknown-sender', paired);
    expect(ack.accepted).toBe(false);
    expect(ack.rejectionReason).toContain('sender');
  });

  it('rejects unpaired recipient', () => {
    const store = new MessageStore();
    const req = makeRequest('unknown-recipient', 1);
    const ack = store.enqueue(req, 'sender', paired);
    expect(ack.accepted).toBe(false);
    expect(ack.rejectionReason).toContain('recipient');
  });

  it('rejects duplicate message ID', () => {
    const store = new MessageStore();
    const req = makeRequest('recipient', 1);
    store.enqueue(req, 'sender', paired);
    const ack2 = store.enqueue(req, 'sender', paired);
    expect(ack2.accepted).toBe(false);
    expect(ack2.rejectionReason).toContain('duplicate');
  });

  it('rejects queue full', () => {
    const store = new MessageStore({ maxAgeMs: 86_400_000, maxMessages: 3 });
    for (let seq = 1; seq <= 3; seq++) {
      const ack = store.enqueue(makeRequest('recipient', seq), 'sender', paired);
      expect(ack.accepted).toBe(true);
    }
    const ack = store.enqueue(makeRequest('recipient', 4), 'sender', paired);
    expect(ack.accepted).toBe(false);
    expect(ack.rejectionReason).toContain('queue full');
  });

  it('rejects sequence gap exceeding threshold', () => {
    const store = new MessageStore();
    store.enqueue(makeRequest('recipient', 1), 'sender', paired);
    const req = makeRequest('recipient', 1002); // gap of 1001
    const ack = store.enqueue(req, 'sender', paired);
    expect(ack.accepted).toBe(false);
    expect(ack.rejectionReason).toContain('skip threshold');
  });

  it('allows sequence gap within threshold', () => {
    const store = new MessageStore();
    store.enqueue(makeRequest('recipient', 1), 'sender', paired);
    const req = makeRequest('recipient', 1001); // gap of exactly 1000
    const ack = store.enqueue(req, 'sender', paired);
    expect(ack.accepted).toBe(true);
  });

  it('deliver returns messages in order', () => {
    const store = new MessageStore();
    for (let seq = 1; seq <= 5; seq++) {
      store.enqueue(makeRequest('recipient', seq), 'sender', paired);
    }

    const { delivers, purge } = store.deliver('recipient');
    expect(delivers.length).toBe(5);
    expect(purge.msgIds.length).toBe(5);
    for (let i = 0; i < delivers.length; i++) {
      expect(delivers[i].sequenceNumber).toBe(i + 1);
      expect(delivers[i].sender).toBe('sender');
    }
    expect(store.queueDepth('recipient')).toBe(0);
  });

  it('deliver empty queue', () => {
    const store = new MessageStore();
    const { delivers, purge } = store.deliver('nobody');
    expect(delivers.length).toBe(0);
    expect(purge.msgIds.length).toBe(0);
  });

  it('deliver clears dedup entries', () => {
    const store = new MessageStore();
    const req = makeRequest('recipient', 1);
    const msgId = req.msgId;
    store.enqueue(req, 'sender', paired);
    store.deliver('recipient');

    // Same msg_id should be accepted again after delivery purge
    const req2: ForwardRequest = {
      msgId,
      recipient: 'recipient',
      encryptedPayload: new Uint8Array([0xcd]),
      sequenceNumber: 2,
    };
    const ack = store.enqueue(req2, 'sender', paired);
    expect(ack.accepted).toBe(true);
  });

  it('expired messages pruned on enqueue', () => {
    const store = new MessageStore({ maxAgeMs: 0, maxMessages: 1000 });
    store.enqueue(makeRequest('recipient', 1), 'sender', paired);
    // With maxAge=0, the message is immediately expired on next enqueue
    store.enqueue(makeRequest('recipient', 2), 'sender', paired);
    // Only the newest should remain (first expired before second check)
    expect(store.queueDepth('recipient')).toBeLessThanOrEqual(1);
  });

  it('per-peer override', () => {
    const store = new MessageStore({ maxAgeMs: 86_400_000, maxMessages: 2 });
    const allPaired = new Set(['sender', 'priority', 'regular']);

    store.setPeerOverride('priority', { maxAgeMs: 86_400_000, maxMessages: 100 });

    // Regular peer hits cap at 2
    for (let seq = 1; seq <= 3; seq++) {
      store.enqueue(makeRequest('regular', seq), 'sender', allPaired);
    }
    expect(store.queueDepth('regular')).toBe(2);

    // Priority peer accepts all 3
    for (let seq = 1; seq <= 3; seq++) {
      store.enqueue(makeRequest('priority', seq), 'sender', allPaired);
    }
    expect(store.queueDepth('priority')).toBe(3);
  });

  it('total messages across peers', () => {
    const store = new MessageStore();
    const allPaired = new Set(['sender', 'r1', 'r2']);
    for (let seq = 1; seq <= 3; seq++) {
      store.enqueue(makeRequest('r1', seq), 'sender', allPaired);
    }
    for (let seq = 1; seq <= 2; seq++) {
      store.enqueue(makeRequest('r2', seq), 'sender', allPaired);
    }
    expect(store.totalMessages).toBe(5);
  });

  it('queue depth for unknown peer is 0', () => {
    const store = new MessageStore();
    expect(store.queueDepth('unknown')).toBe(0);
  });

  it('expire all', () => {
    const store = new MessageStore({ maxAgeMs: 0, maxMessages: 1000 });
    store.enqueue(makeRequest('recipient', 1), 'sender', paired);
    store.expireAll();
    expect(store.queueDepth('recipient')).toBe(0);
  });
});

// --- DeduplicationTracker ---

describe('DeduplicationTracker', () => {
  it('new message accepted', () => {
    const tracker = new DeduplicationTracker(100);
    expect(tracker.checkAndInsert('msg-1')).toBe(true);
    expect(tracker.length).toBe(1);
  });

  it('duplicate rejected', () => {
    const tracker = new DeduplicationTracker(100);
    tracker.checkAndInsert('msg-1');
    expect(tracker.checkAndInsert('msg-1')).toBe(false);
    expect(tracker.length).toBe(1);
  });

  it('evicts oldest when at capacity', () => {
    const tracker = new DeduplicationTracker(3);
    tracker.checkAndInsert('id1');
    tracker.checkAndInsert('id2');
    tracker.checkAndInsert('id3');
    expect(tracker.length).toBe(3);

    // Adding id4 should evict id1
    tracker.checkAndInsert('id4');
    expect(tracker.length).toBe(3);

    // id1 should now be accepted again
    expect(tracker.checkAndInsert('id1')).toBe(true);
  });

  it('isEmpty', () => {
    const tracker = new DeduplicationTracker(10);
    expect(tracker.isEmpty).toBe(true);
    tracker.checkAndInsert('x');
    expect(tracker.isEmpty).toBe(false);
  });
});

// --- ManagementConfig ---

describe('ManagementConfig', () => {
  it('defaults', () => {
    const cfg = defaultManagementConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.bindAddress).toBe('127.0.0.1');
    expect(cfg.port).toBe(9090);
    expect(cfg.authToken).toBe('');
  });
});

// --- Management API ---

describe('Management API', () => {
  let serverInstance: ReturnType<typeof createManagementServer> | null = null;

  afterEach(async () => {
    if (serverInstance) {
      await serverInstance.close().catch(() => {});
      serverInstance = null;
    }
  });

  function makeConfig(overrides?: Partial<ManagementConfig>): ManagementConfig {
    return {
      ...defaultManagementConfig(),
      enabled: true,
      authToken: 'test-secret-token',
      ...overrides,
    };
  }

  async function request(
    server: ReturnType<typeof createManagementServer>,
    path: string,
    token?: string,
  ): Promise<{ status: number; body: unknown }> {
    await server.start();

    const addr = server.httpServer.address();
    if (!addr || typeof addr === 'string') throw new Error('no address');

    const url = `http://127.0.0.1:${addr.port}${path}`;
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(url, { headers });
    const body = await resp.json();
    return { status: resp.status, body };
  }

  it('rejects empty auth token', () => {
    const state = new ManagementState('');
    expect(() => createManagementServer(makeConfig({ authToken: '' }), state)).toThrow('empty');
  });

  it('rejects missing authorization header', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status } = await request(serverInstance, '/health');
    expect(status).toBe(401);
  });

  it('rejects wrong token', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status } = await request(serverInstance, '/health', 'wrong-token');
    expect(status).toBe(401);
  });

  it('accepts correct token', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status } = await request(serverInstance, '/health', 'test-secret-token');
    expect(status).toBe(200);
  });

  it('GET /health returns degraded with no peers', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status, body } = await request(serverInstance, '/health', 'test-secret-token');
    expect(status).toBe(200);
    const health = body as HealthResponse;
    expect(health.status).toBe('degraded');
    expect(health.connectedPeers).toBe(0);
    expect(health.totalPeers).toBe(0);
    expect(health.uptimeSecs).toBeGreaterThanOrEqual(0);
  });

  it('GET /health returns healthy with connected peer', async () => {
    const state = new ManagementState('test-secret-token');
    state.peers = [
      { peerId: 'peer-1', name: 'alpha', connected: true, lastSeen: '2026-03-01T12:00:00Z' },
      { peerId: 'peer-2', name: 'beta', connected: false, lastSeen: null },
    ];
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { body } = await request(serverInstance, '/health', 'test-secret-token');
    const health = body as HealthResponse;
    expect(health.status).toBe('healthy');
    expect(health.connectedPeers).toBe(1);
    expect(health.totalPeers).toBe(2);
  });

  it('GET /peers returns empty list', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { body } = await request(serverInstance, '/peers', 'test-secret-token');
    const resp = body as PeersResponse;
    expect(resp.peers).toEqual([]);
  });

  it('GET /peers returns peer list', async () => {
    const state = new ManagementState('test-secret-token');
    state.peers = [
      { peerId: 'peer-1', name: 'alpha', connected: true, lastSeen: '2026-03-01T12:00:00Z' },
    ];
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { body } = await request(serverInstance, '/peers', 'test-secret-token');
    const resp = body as PeersResponse;
    expect(resp.peers).toHaveLength(1);
    expect(resp.peers[0].name).toBe('alpha');
    expect(resp.peers[0].connected).toBe(true);
  });

  it('GET /queues returns empty list', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { body } = await request(serverInstance, '/queues', 'test-secret-token');
    const resp = body as QueuesResponse;
    expect(resp.queues).toEqual([]);
  });

  it('GET /relay/stats returns defaults', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { body } = await request(serverInstance, '/relay/stats', 'test-secret-token');
    const resp = body as RelayStatsResponse;
    expect(resp.relay.activeConnections).toBe(0);
    expect(resp.relay.perPeer).toEqual([]);
  });

  it('GET /pairing/qr returns 503', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status } = await request(serverInstance, '/pairing/qr', 'test-secret-token');
    expect(status).toBe(503);
  });

  it('unknown path returns 404', async () => {
    const state = new ManagementState('test-secret-token');
    serverInstance = createManagementServer(makeConfig({ port: 0 }), state);
    const { status } = await request(serverInstance, '/unknown', 'test-secret-token');
    expect(status).toBe(404);
  });
});
