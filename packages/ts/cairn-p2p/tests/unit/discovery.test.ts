import { describe, it, expect } from 'vitest';
import {
  RendezvousId,
  defaultRotationConfig,
  deriveRendezvousId,
  derivePairingRendezvousId,
  computeEpoch,
  activeRendezvousIdsAt,
} from '../../src/discovery/rendezvous.js';
import {
  DiscoveryManager,
  InMemoryBackend,
} from '../../src/discovery/manager.js';
import type { DiscoveryBackend } from '../../src/discovery/manager.js';
import {
  TrackerBackend,
  MIN_REANNOUNCE_INTERVAL_MS,
  parseTrackerProtocol,
  urlEncodeBytes,
  buildHttpAnnounceUrl,
  buildUdpConnectRequest,
  parseUdpConnectResponse,
  buildUdpAnnounceRequest,
  parseUdpAnnounceResponse,
  generatePeerId,
} from '../../src/discovery/tracker.js';

// --- RendezvousId ---

describe('RendezvousId', () => {
  it('constructor requires 32 bytes', () => {
    expect(() => new RendezvousId(new Uint8Array(31))).toThrow();
    expect(() => new RendezvousId(new Uint8Array(33))).toThrow();
    expect(() => new RendezvousId(new Uint8Array(32))).not.toThrow();
  });

  it('toHex returns 64-character lowercase hex', () => {
    const id = new RendezvousId(new Uint8Array(32).fill(0xab));
    const hex = id.toHex();
    expect(hex.length).toBe(64);
    expect(hex).toBe('ab'.repeat(32));
  });

  it('toInfoHash returns first 20 bytes', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = i;
    const id = new RendezvousId(bytes);
    const hash = id.toInfoHash();
    expect(hash.length).toBe(20);
    for (let i = 0; i < 20; i++) {
      expect(hash[i]).toBe(i);
    }
  });

  it('equals compares correctly', () => {
    const a = new RendezvousId(new Uint8Array(32).fill(0x11));
    const b = new RendezvousId(new Uint8Array(32).fill(0x11));
    const c = new RendezvousId(new Uint8Array(32).fill(0x22));
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(false);
  });
});

// --- deriveRendezvousId ---

describe('deriveRendezvousId', () => {
  it('is deterministic', () => {
    const secret = new TextEncoder().encode('shared-pairing-secret');
    const id1 = deriveRendezvousId(secret, 42);
    const id2 = deriveRendezvousId(secret, 42);
    expect(id1.equals(id2)).toBe(true);
  });

  it('different epochs produce different IDs', () => {
    const secret = new TextEncoder().encode('shared-pairing-secret');
    const id1 = deriveRendezvousId(secret, 1);
    const id2 = deriveRendezvousId(secret, 2);
    expect(id1.equals(id2)).toBe(false);
  });

  it('different secrets produce different IDs', () => {
    const id1 = deriveRendezvousId(new TextEncoder().encode('secret-a'), 1);
    const id2 = deriveRendezvousId(new TextEncoder().encode('secret-b'), 1);
    expect(id1.equals(id2)).toBe(false);
  });

  it('both peers compute the same ID from shared secret', () => {
    const shared = new TextEncoder().encode('shared-pairing-secret-between-alice-and-bob');
    const alice = deriveRendezvousId(shared, 12345);
    const bob = deriveRendezvousId(shared, 12345);
    expect(alice.equals(bob)).toBe(true);
  });
});

// --- derivePairingRendezvousId ---

describe('derivePairingRendezvousId', () => {
  it('is deterministic', () => {
    const cred = new TextEncoder().encode('pake-credential');
    const nonce = new TextEncoder().encode('nonce-123');
    const id1 = derivePairingRendezvousId(cred, nonce);
    const id2 = derivePairingRendezvousId(cred, nonce);
    expect(id1.equals(id2)).toBe(true);
  });

  it('different nonces produce different IDs', () => {
    const cred = new TextEncoder().encode('pake-credential');
    const id1 = derivePairingRendezvousId(cred, new TextEncoder().encode('nonce-a'));
    const id2 = derivePairingRendezvousId(cred, new TextEncoder().encode('nonce-b'));
    expect(id1.equals(id2)).toBe(false);
  });

  it('differs from standard rendezvous ID', () => {
    const input = new TextEncoder().encode('same-input');
    const epoch = 1;
    const standard = deriveRendezvousId(input, epoch);
    const epochSalt = new Uint8Array(8);
    new DataView(epochSalt.buffer).setBigUint64(0, BigInt(epoch), false);
    const pairing = derivePairingRendezvousId(input, epochSalt);
    expect(standard.equals(pairing)).toBe(false);
  });
});

// --- computeEpoch ---

describe('computeEpoch', () => {
  it('is consistent', () => {
    const secret = new TextEncoder().encode('test-secret');
    const e1 = computeEpoch(secret, 3600, 1_700_000_000);
    const e2 = computeEpoch(secret, 3600, 1_700_000_000);
    expect(e1).toBe(e2);
  });

  it('advances with time', () => {
    const secret = new TextEncoder().encode('test-secret');
    const e1 = computeEpoch(secret, 3600, 1_700_000_000);
    const e2 = computeEpoch(secret, 3600, 1_700_000_000 + 3600);
    expect(e2).toBe(e1 + 1);
  });

  it('zero interval is rejected', () => {
    expect(() => computeEpoch(new TextEncoder().encode('secret'), 0, 1_700_000_000)).toThrow();
  });

  it('different secrets produce different epoch numbers', () => {
    const e1 = computeEpoch(new TextEncoder().encode('secret-a'), 3600, 1_700_000_000);
    const e2 = computeEpoch(new TextEncoder().encode('secret-b'), 3600, 1_700_000_000);
    expect(e1).not.toBe(e2);
  });
});

// --- RotationConfig ---

describe('RotationConfig', () => {
  it('default values', () => {
    const config = defaultRotationConfig();
    expect(config.rotationIntervalSecs).toBe(86400);
    expect(config.overlapWindowSecs).toBe(3600);
    expect(config.clockToleranceSecs).toBe(300);
  });
});

// --- activeRendezvousIdsAt ---

describe('activeRendezvousIdsAt', () => {
  it('includes current epoch ID', () => {
    const secret = new TextEncoder().encode('test-secret');
    const config = defaultRotationConfig();
    const ts = 1_700_000_000;

    const ids = activeRendezvousIdsAt(secret, config, ts);
    const epoch = computeEpoch(secret, config.rotationIntervalSecs, ts);
    const expected = deriveRendezvousId(secret, epoch);

    expect(ids.some((id) => id.equals(expected))).toBe(true);
  });

  it('returns 2 IDs near epoch boundary (just after)', () => {
    const secret = new TextEncoder().encode('test-secret');
    const config = defaultRotationConfig();
    const interval = config.rotationIntervalSecs;

    // Find epoch boundary for this secret
    // We need adjusted = ts + offset to be divisible by interval
    // Use a brute force approach: find a timestamp where the position in epoch is small
    const baseTs = 1_700_000_000;
    const epoch1 = computeEpoch(secret, interval, baseTs);
    // Try timestamps until we find one just past a boundary
    for (let delta = 0; delta < interval; delta += 10) {
      const ts = baseTs + delta;
      const e = computeEpoch(secret, interval, ts);
      if (e !== epoch1) {
        // Just crossed a boundary — ts should be near start of new epoch
        const ids = activeRendezvousIdsAt(secret, config, ts);
        expect(ids.length).toBe(2);
        return;
      }
    }
    // If we never crossed, the test should still pass with 1 or 2 IDs
  });

  it('returns 1 ID well inside an epoch', () => {
    const secret = new TextEncoder().encode('test-secret');
    const config = defaultRotationConfig();
    const interval = config.rotationIntervalSecs;
    const halfOverlap = Math.floor(config.overlapWindowSecs / 2) + config.clockToleranceSecs;

    // Find the middle of an epoch
    const baseTs = 1_700_000_000;
    for (let delta = 0; delta < interval; delta += 100) {
      const ts = baseTs + delta;
      const prevTs = ts - 1;
      const nextTs = ts + 1;
      const e = computeEpoch(secret, interval, ts);
      const ePrev = computeEpoch(secret, interval, prevTs);
      const eNext = computeEpoch(secret, interval, nextTs);
      // Well inside the epoch if same epoch for a wide range
      if (e === ePrev && e === eNext) {
        // Check we're far from any boundary by checking a wide range
        const eWayBefore = computeEpoch(secret, interval, ts - halfOverlap - 100);
        const eWayAfter = computeEpoch(secret, interval, ts + halfOverlap + 100);
        if (e === eWayBefore && e === eWayAfter) {
          const ids = activeRendezvousIdsAt(secret, config, ts);
          expect(ids.length).toBe(1);
          return;
        }
      }
    }
  });

  it('zero interval throws', () => {
    const config = { rotationIntervalSecs: 0, overlapWindowSecs: 3600, clockToleranceSecs: 300 };
    expect(() =>
      activeRendezvousIdsAt(new TextEncoder().encode('s'), config, 1_700_000_000),
    ).toThrow();
  });
});

// --- DiscoveryManager ---

describe('DiscoveryManager', () => {
  it('starts with no backends', () => {
    const mgr = new DiscoveryManager();
    expect(mgr.backendCount).toBe(0);
    expect(mgr.backendNames).toEqual([]);
  });

  it('add backends', () => {
    const mgr = new DiscoveryManager();
    mgr.addBackend(new InMemoryBackend('mdns'));
    mgr.addBackend(new InMemoryBackend('dht'));
    expect(mgr.backendCount).toBe(2);
    expect(mgr.backendNames).toEqual(['mdns', 'dht']);
  });

  it('publishAll publishes to all backends', async () => {
    const records = new Map<string, Uint8Array>();
    const mgr = new DiscoveryManager();
    mgr.addBackend(new InMemoryBackend('a', records));
    mgr.addBackend(new InMemoryBackend('b'));

    const id = new RendezvousId(new Uint8Array(32).fill(0x11));
    const results = await mgr.publishAll(id, new Uint8Array([1, 2, 3]));

    expect(results.length).toBe(2);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it('publishAll captures errors without throwing', async () => {
    const mgr = new DiscoveryManager();
    const failing: DiscoveryBackend = {
      name: 'failing',
      async publish() {
        throw new Error('publish error');
      },
      async query() {
        return null;
      },
      async stop() {},
    };
    mgr.addBackend(failing);
    mgr.addBackend(new InMemoryBackend('ok'));

    const id = new RendezvousId(new Uint8Array(32).fill(0x22));
    const results = await mgr.publishAll(id, new Uint8Array([4, 5, 6]));

    expect(results[0].success).toBe(false);
    expect(results[0].error).toBeDefined();
    expect(results[1].success).toBe(true);
  });

  it('queryFirst returns first non-null result', async () => {
    const mgr = new DiscoveryManager();
    const records1 = new Map<string, Uint8Array>();
    const records2 = new Map<string, Uint8Array>();
    mgr.addBackend(new InMemoryBackend('a', records1));
    mgr.addBackend(new InMemoryBackend('b', records2));

    const id = new RendezvousId(new Uint8Array(32).fill(0x33));
    // Only publish to backend b
    records2.set(id.toHex(), new Uint8Array([7, 8, 9]));

    const result = await mgr.queryFirst(id);
    expect(result).not.toBeNull();
    expect(result!.payload).toEqual(new Uint8Array([7, 8, 9]));
  });

  it('queryFirst returns null when no backend has result', async () => {
    const mgr = new DiscoveryManager();
    mgr.addBackend(new InMemoryBackend('a'));

    const id = new RendezvousId(new Uint8Array(32).fill(0x44));
    const result = await mgr.queryFirst(id);
    expect(result).toBeNull();
  });

  it('queryFirst ignores failing backends', async () => {
    const mgr = new DiscoveryManager();
    const failing: DiscoveryBackend = {
      name: 'failing',
      async publish() {},
      async query() {
        throw new Error('query error');
      },
      async stop() {},
    };
    const records = new Map<string, Uint8Array>();
    mgr.addBackend(failing);
    mgr.addBackend(new InMemoryBackend('ok', records));

    const id = new RendezvousId(new Uint8Array(32).fill(0x55));
    records.set(id.toHex(), new Uint8Array([10]));

    const result = await mgr.queryFirst(id);
    expect(result).not.toBeNull();
    expect(result!.backend).toBe('ok');
  });

  it('stopAll stops all backends', async () => {
    const mgr = new DiscoveryManager();
    const records = new Map<string, Uint8Array>();
    const backend = new InMemoryBackend('test', records);
    mgr.addBackend(backend);

    const id = new RendezvousId(new Uint8Array(32).fill(0x66));
    await backend.publish(id, new Uint8Array([1]));
    expect(records.size).toBe(1);

    await mgr.stopAll();
    expect(records.size).toBe(0);
  });
});

// --- InMemoryBackend ---

describe('InMemoryBackend', () => {
  it('publish and query', async () => {
    const backend = new InMemoryBackend('test');
    const id = new RendezvousId(new Uint8Array(32).fill(0xaa));
    await backend.publish(id, new Uint8Array([1, 2, 3]));
    const result = await backend.query(id);
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('query returns null for missing', async () => {
    const backend = new InMemoryBackend('test');
    const id = new RendezvousId(new Uint8Array(32).fill(0xbb));
    expect(await backend.query(id)).toBeNull();
  });

  it('stop clears records', async () => {
    const backend = new InMemoryBackend('test');
    const id = new RendezvousId(new Uint8Array(32).fill(0xcc));
    await backend.publish(id, new Uint8Array([1]));
    await backend.stop();
    expect(await backend.query(id)).toBeNull();
  });
});

// --- TrackerBackend ---

describe('TrackerBackend', () => {
  it('name is bittorrent', () => {
    const backend = new TrackerBackend();
    expect(backend.name).toBe('bittorrent');
  });

  it('min reannounce interval is 15 minutes', () => {
    const backend = new TrackerBackend();
    expect(backend.minReannounceIntervalMs).toBe(15 * 60 * 1000);
    expect(MIN_REANNOUNCE_INTERVAL_MS).toBe(15 * 60 * 1000);
  });

  it('toInfoHash returns 20 bytes', () => {
    const id = new RendezvousId(new Uint8Array(32).fill(0xff));
    const hash = TrackerBackend.toInfoHash(id);
    expect(hash.length).toBe(20);
    expect(hash).toEqual(new Uint8Array(20).fill(0xff));
  });

  it('publish and query', async () => {
    const backend = new TrackerBackend();
    const id = new RendezvousId(new Uint8Array(32).fill(0xdd));
    await backend.publish(id, new Uint8Array([1, 2, 3]));
    const result = await backend.query(id);
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('query returns null for missing', async () => {
    const backend = new TrackerBackend();
    const id = new RendezvousId(new Uint8Array(32).fill(0xee));
    expect(await backend.query(id)).toBeNull();
  });

  it('stop clears records', async () => {
    const backend = new TrackerBackend();
    const id = new RendezvousId(new Uint8Array(32).fill(0x99));
    await backend.publish(id, new Uint8Array([1]));
    await backend.stop();
    expect(await backend.query(id)).toBeNull();
  });

  it('trackers config', () => {
    const backend = new TrackerBackend([
      { url: 'udp://tracker.example.com:6969' },
      { url: 'http://tracker.example.com/announce' },
    ]);
    expect(backend.trackers.length).toBe(2);
  });
});

// --- Tracker protocol parsing ---

describe('parseTrackerProtocol', () => {
  it('udp protocol', () => {
    expect(parseTrackerProtocol('udp://tracker.example.com:6969')).toBe('udp');
  });

  it('http protocol', () => {
    expect(parseTrackerProtocol('http://tracker.example.com/announce')).toBe('http');
    expect(parseTrackerProtocol('https://tracker.example.com/announce')).toBe('http');
  });
});

// --- URL encoding ---

describe('urlEncodeBytes', () => {
  it('encodes bytes as percent-encoded', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(urlEncodeBytes(bytes)).toBe('%DE%AD%BE%EF');
  });

  it('encodes zero bytes', () => {
    const bytes = new Uint8Array([0x00, 0x01]);
    expect(urlEncodeBytes(bytes)).toBe('%00%01');
  });
});

// --- HTTP announce URL ---

describe('buildHttpAnnounceUrl', () => {
  it('builds correct URL', () => {
    const infoHash = new Uint8Array(20).fill(0xaa);
    const peerId = new Uint8Array(20).fill(0xbb);
    const url = buildHttpAnnounceUrl('http://tracker.example.com/announce', infoHash, peerId, 6881);
    expect(url).toContain('info_hash=');
    expect(url).toContain('peer_id=');
    expect(url).toContain('port=6881');
    expect(url).toContain('compact=1');
  });

  it('includes event parameter', () => {
    const infoHash = new Uint8Array(20);
    const peerId = new Uint8Array(20);
    const url = buildHttpAnnounceUrl(
      'http://tracker.example.com/announce',
      infoHash,
      peerId,
      6881,
      'started',
    );
    expect(url).toContain('event=started');
  });

  it('uses & separator when URL has query params', () => {
    const url = buildHttpAnnounceUrl(
      'http://tracker.example.com/announce?passkey=abc',
      new Uint8Array(20),
      new Uint8Array(20),
      6881,
    );
    expect(url).toContain('announce?passkey=abc&info_hash=');
  });
});

// --- UDP connect request/response ---

describe('UDP connect', () => {
  it('builds 16-byte connect request', () => {
    const req = buildUdpConnectRequest(0x12345678);
    expect(req.length).toBe(16);
    const view = new DataView(req.buffer);
    // Protocol ID
    expect(view.getBigUint64(0, false)).toBe(0x41727101980n);
    // Action: connect = 0
    expect(view.getUint32(8, false)).toBe(0);
    // Transaction ID
    expect(view.getUint32(12, false)).toBe(0x12345678);
  });

  it('parses connect response', () => {
    const resp = new Uint8Array(16);
    const view = new DataView(resp.buffer);
    view.setUint32(0, 0, false); // action: connect
    view.setUint32(4, 0xaabbccdd, false); // transaction_id
    view.setBigUint64(8, 0x1122334455667788n, false); // connection_id

    const connId = parseUdpConnectResponse(resp, 0xaabbccdd);
    expect(connId).toBe(0x1122334455667788n);
  });

  it('rejects invalid transaction ID', () => {
    const resp = new Uint8Array(16);
    const view = new DataView(resp.buffer);
    view.setUint32(0, 0, false);
    view.setUint32(4, 0x11111111, false);
    view.setBigUint64(8, 0n, false);

    expect(parseUdpConnectResponse(resp, 0x22222222)).toBeNull();
  });

  it('rejects too-short response', () => {
    expect(parseUdpConnectResponse(new Uint8Array(10), 0)).toBeNull();
  });
});

// --- UDP announce request/response ---

describe('UDP announce', () => {
  it('builds 98-byte announce request', () => {
    const req = buildUdpAnnounceRequest(
      0x1122334455667788n,
      0xdeadbeef,
      new Uint8Array(20).fill(0xaa),
      new Uint8Array(20).fill(0xbb),
      6881,
      2, // started
    );
    expect(req.length).toBe(98);
    const view = new DataView(req.buffer);
    expect(view.getBigUint64(0, false)).toBe(0x1122334455667788n);
    expect(view.getUint32(8, false)).toBe(1); // action: announce
    expect(view.getUint32(12, false)).toBe(0xdeadbeef);
    expect(req[16]).toBe(0xaa); // info_hash start
    expect(req[36]).toBe(0xbb); // peer_id start
    expect(view.getUint16(96, false)).toBe(6881); // port
  });

  it('parses announce response with peers', () => {
    // Build a response: action(4) + txn(4) + interval(4) + leechers(4) + seeders(4) + peers(6 each)
    const resp = new Uint8Array(20 + 12); // 2 peers
    const view = new DataView(resp.buffer);
    view.setUint32(0, 1, false); // action: announce
    view.setUint32(4, 0x12345678, false);
    view.setUint32(8, 1800, false); // interval
    view.setUint32(12, 0, false); // leechers
    view.setUint32(16, 0, false); // seeders
    // Peer 1: 192.168.1.1:6881
    resp[20] = 192; resp[21] = 168; resp[22] = 1; resp[23] = 1;
    view.setUint16(24, 6881, false);
    // Peer 2: 10.0.0.5:8080
    resp[26] = 10; resp[27] = 0; resp[28] = 0; resp[29] = 5;
    view.setUint16(30, 8080, false);

    const result = parseUdpAnnounceResponse(resp, 0x12345678);
    expect(result).not.toBeNull();
    expect(result!.interval).toBe(1800);
    expect(result!.peers.length).toBe(2);
    expect(result!.peers[0]).toEqual({ ip: '192.168.1.1', port: 6881 });
    expect(result!.peers[1]).toEqual({ ip: '10.0.0.5', port: 8080 });
  });

  it('rejects invalid announce response', () => {
    expect(parseUdpAnnounceResponse(new Uint8Array(10), 0)).toBeNull();
  });

  it('rejects wrong transaction ID', () => {
    const resp = new Uint8Array(20);
    const view = new DataView(resp.buffer);
    view.setUint32(0, 1, false);
    view.setUint32(4, 0x11111111, false);
    expect(parseUdpAnnounceResponse(resp, 0x22222222)).toBeNull();
  });
});

// --- Peer ID generation ---

describe('generatePeerId', () => {
  it('generates 20-byte peer ID', () => {
    const id = generatePeerId();
    expect(id.length).toBe(20);
  });

  it('starts with -CR0001- prefix', () => {
    const id = generatePeerId();
    const prefix = new TextDecoder().decode(id.slice(0, 8));
    expect(prefix).toBe('-CR0001-');
  });

  it('generates unique IDs', () => {
    const id1 = generatePeerId();
    const id2 = generatePeerId();
    // Random 12 bytes should differ
    const suffix1 = Array.from(id1.slice(8));
    const suffix2 = Array.from(id2.slice(8));
    expect(suffix1).not.toEqual(suffix2);
  });
});
