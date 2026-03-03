import { describe, it, expect, vi } from 'vitest';
import {
  // Fallback chain
  transportPriority,
  transportDisplayName,
  isTier0Available,
  allTransportsInOrder,
  FallbackChain,
  DEFAULT_TRANSPORT_TIMEOUT_MS,
  defaultConnectionQuality,
  defaultQualityThresholds,
  ConnectionQualityMonitor,
  TransportMigrator,
  // NAT detection
  buildBindingRequest,
  parseBindingResponse,
  classifyNat,
  NatDetector,
  defaultNetworkInfo,
  DEFAULT_STUN_SERVERS,
  // libp2p node
  defaultTransportConfig,
  isNodeEnvironment,
  isBrowserEnvironment,
  BROWSER_TRANSPORT_CHAIN,
  NODEJS_TRANSPORT_CHAIN,
} from '../../src/transport/index.js';
import type {
  FallbackTransportType,
  ConnectionQuality,
  DegradationEvent,
  MigrationEvent,
  StunMappedAddress,
} from '../../src/transport/index.js';
import { TransportExhaustedError, CairnError } from '../../src/errors.js';

// --- FallbackTransportType ---

describe('FallbackTransportType', () => {
  it('has 9 transport types in order', () => {
    const all = allTransportsInOrder();
    expect(all.length).toBe(9);
  });

  it('priorities are sequential 1-9', () => {
    const all = allTransportsInOrder();
    for (let i = 0; i < all.length; i++) {
      expect(transportPriority(all[i])).toBe(i + 1);
    }
  });

  it('tier0 availability', () => {
    expect(isTier0Available('quic')).toBe(true);
    expect(isTier0Available('stun-udp')).toBe(true);
    expect(isTier0Available('tcp')).toBe(true);
    expect(isTier0Available('turn-udp')).toBe(false);
    expect(isTier0Available('turn-tcp')).toBe(false);
    expect(isTier0Available('websocket-tls')).toBe(false);
    expect(isTier0Available('webtransport')).toBe(false);
    expect(isTier0Available('circuit-relay-v2')).toBe(true);
    expect(isTier0Available('https-long-polling')).toBe(false);
  });

  it('display names', () => {
    expect(transportDisplayName('quic')).toBe('Direct QUIC v1');
    expect(transportDisplayName('tcp')).toBe('Direct TCP');
    expect(transportDisplayName('https-long-polling')).toBe('HTTPS long-polling (443)');
  });
});

// --- FallbackChain construction ---

describe('FallbackChain', () => {
  it('tier0 chain has correct availability', () => {
    const chain = FallbackChain.tier0();
    const transports = chain.transports;
    expect(transports.length).toBe(9);

    // Priorities 1-3, 8 should be available
    expect(transports[0].available).toBe(true);  // quic
    expect(transports[1].available).toBe(true);  // stun-udp
    expect(transports[2].available).toBe(true);  // tcp
    expect(transports[3].available).toBe(false); // turn-udp
    expect(transports[4].available).toBe(false); // turn-tcp
    expect(transports[5].available).toBe(false); // websocket-tls
    expect(transports[6].available).toBe(false); // webtransport
    expect(transports[7].available).toBe(true);  // circuit-relay-v2
    expect(transports[8].available).toBe(false); // https-long-polling
  });

  it('full chain with TURN and relay', () => {
    const chain = FallbackChain.create(10_000, true, true, false);
    expect(chain.transports.every((t) => t.available)).toBe(true);
  });

  it('default timeout is 10s', () => {
    expect(DEFAULT_TRANSPORT_TIMEOUT_MS).toBe(10_000);
  });

  it('tier0 has sequential mode', () => {
    const chain = FallbackChain.tier0();
    expect(chain.parallelMode).toBe(false);
  });

  it('can create with parallel mode', () => {
    const chain = FallbackChain.create(5000, false, false, true);
    expect(chain.parallelMode).toBe(true);
  });
});

// --- FallbackChain execution ---

describe('FallbackChain execution', () => {
  it('sequential: first transport succeeds', async () => {
    const chain = FallbackChain.tier0(5000);
    const result = await chain.execute(async (tt) => {
      if (tt === 'quic') return 42;
      throw new Error('not implemented');
    });
    expect(result.transportType).toBe('quic');
    expect(result.value).toBe(42);
  });

  it('sequential: falls back to tcp', async () => {
    const chain = FallbackChain.tier0(5000);
    const result = await chain.execute(async (tt) => {
      if (tt === 'tcp') return 'tcp_connected';
      throw new Error(`${tt} failed`);
    });
    expect(result.transportType).toBe('tcp');
    expect(result.value).toBe('tcp_connected');
  });

  it('sequential: skips unavailable transports', async () => {
    const chain = FallbackChain.tier0(5000);
    const attempted: FallbackTransportType[] = [];
    try {
      await chain.execute(async (tt) => {
        attempted.push(tt);
        throw new Error(`${tt} failed`);
      });
    } catch {
      // expected
    }
    // Should not attempt turn-udp, turn-tcp, websocket-tls, webtransport, https-long-polling
    expect(attempted).not.toContain('turn-udp');
    expect(attempted).not.toContain('turn-tcp');
    expect(attempted).not.toContain('websocket-tls');
    expect(attempted).not.toContain('webtransport');
    expect(attempted).not.toContain('https-long-polling');
    // Should attempt quic, stun-udp, tcp, circuit-relay-v2
    expect(attempted).toContain('quic');
    expect(attempted).toContain('stun-udp');
    expect(attempted).toContain('tcp');
    expect(attempted).toContain('circuit-relay-v2');
  });

  it('sequential: all fail returns TransportExhaustedError', async () => {
    const chain = FallbackChain.tier0(1000);
    try {
      await chain.execute(async (tt) => {
        throw new Error(`${tt} failed`);
      });
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(TransportExhaustedError);
      const err = e as TransportExhaustedError;
      expect(err.code).toBe('TRANSPORT_EXHAUSTED');
      expect(err.details).toBeDefined();
      expect(typeof err.details!.details).toBe('string');
      expect(typeof err.details!.suggestion).toBe('string');
      // Should mention skipped transports and suggest infrastructure
      expect(err.details!.details).toContain('skipped');
      expect(err.details!.suggestion).toContain('deploy companion infrastructure');
    }
  });

  it('sequential: error includes transport names in details', async () => {
    const chain = FallbackChain.tier0(1000);
    try {
      await chain.execute(async (tt) => {
        throw new Error(`${tt} failed`);
      });
    } catch (e) {
      const err = e as TransportExhaustedError;
      const details = err.details!.details as string;
      expect(details).toContain('Direct QUIC v1');
      expect(details).toContain('Direct TCP');
    }
  });

  it('parallel: first success wins', async () => {
    const chain = FallbackChain.create(5000, false, false, true);
    const result = await chain.execute(async (tt) => {
      if (tt === 'tcp') {
        // TCP "connects" instantly
        return 'tcp_connected';
      }
      if (tt === 'quic') {
        // QUIC is slower
        await new Promise((r) => setTimeout(r, 50));
        return 'quic_connected';
      }
      throw new Error(`${tt} failed`);
    });
    // One of the fast ones should win
    expect(['quic', 'tcp']).toContain(result.transportType);
  });

  it('parallel: all fail returns TransportExhaustedError', async () => {
    const chain = FallbackChain.create(1000, false, false, true);
    try {
      await chain.execute(async (tt) => {
        throw new Error(`${tt} failed`);
      });
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(TransportExhaustedError);
    }
  });

  it('all transports have infrastructure suggestion', async () => {
    // When ALL transports are available and all fail, suggestion is about connectivity
    const chain = FallbackChain.create(1000, true, true, false);
    try {
      await chain.execute(async (tt) => {
        throw new Error(`${tt} failed`);
      });
    } catch (e) {
      const err = e as TransportExhaustedError;
      expect(err.details!.suggestion).toContain('check network connectivity');
    }
  });
});

// --- ConnectionQuality ---

describe('ConnectionQuality', () => {
  it('default quality metrics', () => {
    const q = defaultConnectionQuality();
    expect(q.latencyMs).toBe(0);
    expect(q.jitterMs).toBe(0);
    expect(q.packetLossRatio).toBe(0);
  });

  it('default quality thresholds', () => {
    const t = defaultQualityThresholds();
    expect(t.maxLatencyMs).toBe(500);
    expect(t.maxJitterMs).toBe(100);
    expect(t.maxPacketLoss).toBe(0.05);
  });
});

// --- ConnectionQualityMonitor ---

describe('ConnectionQualityMonitor', () => {
  it('creates with default thresholds', () => {
    const monitor = new ConnectionQualityMonitor();
    expect(monitor.thresholds.maxLatencyMs).toBe(500);
  });

  it('detects high latency', () => {
    const monitor = new ConnectionQualityMonitor();
    const good: ConnectionQuality = { latencyMs: 100, jitterMs: 10, packetLossRatio: 0.01 };
    expect(monitor.isDegraded(good)).toBe(false);

    const bad: ConnectionQuality = { latencyMs: 600, jitterMs: 10, packetLossRatio: 0.01 };
    expect(monitor.isDegraded(bad)).toBe(true);
  });

  it('detects high jitter', () => {
    const monitor = new ConnectionQualityMonitor();
    const bad: ConnectionQuality = { latencyMs: 100, jitterMs: 150, packetLossRatio: 0.01 };
    expect(monitor.isDegraded(bad)).toBe(true);
  });

  it('detects high packet loss', () => {
    const monitor = new ConnectionQualityMonitor();
    const bad: ConnectionQuality = { latencyMs: 100, jitterMs: 10, packetLossRatio: 0.10 };
    expect(monitor.isDegraded(bad)).toBe(true);
  });

  it('emits degradation event for high latency', () => {
    const monitor = new ConnectionQualityMonitor();
    const events: DegradationEvent[] = [];
    monitor.onDegradation((e) => events.push(e));

    const bad: ConnectionQuality = { latencyMs: 600, jitterMs: 10, packetLossRatio: 0.01 };
    monitor.reportSample(bad);

    expect(events.length).toBe(1);
    expect(events[0].reason).toBe('high_latency');
  });

  it('emits multiple degradation events', () => {
    const monitor = new ConnectionQualityMonitor();
    const events: DegradationEvent[] = [];
    monitor.onDegradation((e) => events.push(e));

    const bad: ConnectionQuality = { latencyMs: 600, jitterMs: 150, packetLossRatio: 0.10 };
    monitor.reportSample(bad);

    expect(events.length).toBe(3); // latency + jitter + packet loss
  });

  it('no event for good quality', () => {
    const monitor = new ConnectionQualityMonitor();
    const events: DegradationEvent[] = [];
    monitor.onDegradation((e) => events.push(e));

    const good: ConnectionQuality = { latencyMs: 50, jitterMs: 5, packetLossRatio: 0.001 };
    monitor.reportSample(good);

    expect(events.length).toBe(0);
  });

  it('custom thresholds', () => {
    const monitor = new ConnectionQualityMonitor({
      maxLatencyMs: 200,
      maxJitterMs: 50,
      maxPacketLoss: 0.02,
    });

    const mid: ConnectionQuality = { latencyMs: 250, jitterMs: 30, packetLossRatio: 0.01 };
    expect(monitor.isDegraded(mid)).toBe(true); // latency exceeds 200

    const ok: ConnectionQuality = { latencyMs: 150, jitterMs: 30, packetLossRatio: 0.01 };
    expect(monitor.isDegraded(ok)).toBe(false);
  });

  it('sample interval', () => {
    const monitor = new ConnectionQualityMonitor(undefined, 2000);
    expect(monitor.sampleIntervalMs).toBe(2000);
  });
});

// --- TransportMigrator ---

describe('TransportMigrator', () => {
  it('probes better transports', () => {
    const migrator = new TransportMigrator(30_000, 'websocket-tls'); // priority 6
    const toProbe = migrator.transportsToProbe();
    // Should probe priorities 1-5
    expect(toProbe.length).toBe(5);
    expect(toProbe[0]).toBe('quic');
    expect(toProbe[4]).toBe('turn-tcp');
  });

  it('quic has nothing better', () => {
    const migrator = new TransportMigrator(30_000, 'quic'); // priority 1
    expect(migrator.transportsToProbe().length).toBe(0);
  });

  it('emits migration event', () => {
    const migrator = new TransportMigrator(30_000, 'tcp'); // priority 3
    const events: MigrationEvent[] = [];
    migrator.onMigration((e) => events.push(e));

    migrator.reportBetterTransport('quic');

    expect(events.length).toBe(1);
    expect(events[0].from).toBe('tcp');
    expect(events[0].to).toBe('quic');
  });

  it('rejects worse transport', () => {
    const migrator = new TransportMigrator(30_000, 'tcp'); // priority 3
    expect(() => migrator.reportBetterTransport('websocket-tls')).toThrow();
  });

  it('rejects same priority transport', () => {
    const migrator = new TransportMigrator(30_000, 'tcp');
    expect(() => migrator.reportBetterTransport('tcp')).toThrow();
  });

  it('set current updates probes', () => {
    const migrator = new TransportMigrator(30_000, 'https-long-polling'); // priority 9
    expect(migrator.transportsToProbe().length).toBe(8);

    migrator.setCurrentTransport('quic');
    expect(migrator.currentTransport).toBe('quic');
    expect(migrator.transportsToProbe().length).toBe(0);
  });

  it('probe interval', () => {
    const migrator = new TransportMigrator(60_000, 'tcp');
    expect(migrator.probeIntervalMs).toBe(60_000);
  });
});

// --- STUN protocol ---

describe('STUN protocol', () => {
  it('builds binding request (20 bytes)', () => {
    const txnId = new Uint8Array(12).fill(0xAA);
    const req = buildBindingRequest(txnId);
    expect(req.length).toBe(20);

    const view = new DataView(req.buffer);
    // Type: Binding Request (0x0001)
    expect(view.getUint16(0)).toBe(0x0001);
    // Length: 0
    expect(view.getUint16(2)).toBe(0);
    // Magic Cookie
    expect(view.getUint32(4)).toBe(0x2112_A442);
    // Transaction ID
    for (let i = 0; i < 12; i++) {
      expect(req[8 + i]).toBe(0xAA);
    }
  });

  it('rejects invalid transaction ID length', () => {
    expect(() => buildBindingRequest(new Uint8Array(10))).toThrow();
  });

  it('parses binding response with XOR-MAPPED-ADDRESS IPv4', () => {
    const txnId = new Uint8Array(12).fill(0xAA);
    const MAGIC = 0x2112_A442;

    // Build a response
    const buf = new Uint8Array(32);
    const view = new DataView(buf.buffer);
    // Header
    view.setUint16(0, 0x0101); // Binding Response
    view.setUint16(2, 12);     // message length (attr header 4 + data 8)
    view.setUint32(4, MAGIC);
    buf.set(txnId, 8);

    // XOR-MAPPED-ADDRESS attribute
    view.setUint16(20, 0x0020); // attr type
    view.setUint16(22, 8);      // attr len
    buf[24] = 0x00; // reserved
    buf[25] = 0x01; // IPv4
    // XOR'd port: 12345 ^ (magic >> 16)
    const port = 12345;
    const xorPort = port ^ (MAGIC >>> 16);
    view.setUint16(26, xorPort);
    // XOR'd IP: 192.168.1.100 ^ magic
    const ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    const xorIp = ip ^ MAGIC;
    view.setUint32(28, xorIp);

    const addr = parseBindingResponse(buf, txnId);
    expect(addr.port).toBe(12345);
    expect(addr.ip).toBe('192.168.1.100');
    expect(addr.family).toBe('IPv4');
  });

  it('rejects short STUN response', () => {
    const txnId = new Uint8Array(12);
    expect(() => parseBindingResponse(new Uint8Array(10), txnId)).toThrow('too short');
  });

  it('rejects wrong message type', () => {
    const txnId = new Uint8Array(12);
    const buf = new Uint8Array(20);
    const view = new DataView(buf.buffer);
    view.setUint16(0, 0x0111); // wrong type
    view.setUint32(4, 0x2112_A442);
    buf.set(txnId, 8);
    expect(() => parseBindingResponse(buf, txnId)).toThrow('unexpected STUN message type');
  });

  it('rejects wrong transaction ID', () => {
    const txnId = new Uint8Array(12).fill(0xBB);
    const wrongId = new Uint8Array(12).fill(0xCC);
    const buf = new Uint8Array(20);
    const view = new DataView(buf.buffer);
    view.setUint16(0, 0x0101);
    view.setUint32(4, 0x2112_A442);
    buf.set(wrongId, 8);
    expect(() => parseBindingResponse(buf, txnId)).toThrow('transaction ID mismatch');
  });

  it('rejects invalid magic cookie', () => {
    const txnId = new Uint8Array(12);
    const buf = new Uint8Array(20);
    const view = new DataView(buf.buffer);
    view.setUint16(0, 0x0101);
    view.setUint32(4, 0xDEADBEEF); // wrong magic
    buf.set(txnId, 8);
    expect(() => parseBindingResponse(buf, txnId)).toThrow('invalid STUN magic cookie');
  });

  it('rejects response with no mapped address', () => {
    const txnId = new Uint8Array(12);
    const buf = new Uint8Array(20);
    const view = new DataView(buf.buffer);
    view.setUint16(0, 0x0101);
    view.setUint16(2, 0); // no attributes
    view.setUint32(4, 0x2112_A442);
    buf.set(txnId, 8);
    expect(() => parseBindingResponse(buf, txnId)).toThrow('no mapped address');
  });
});

// --- NAT classification ---

describe('NAT classification', () => {
  it('empty is unknown', () => {
    expect(classifyNat([])).toBe('unknown');
  });

  it('single server is unknown', () => {
    expect(classifyNat([
      { server: '1.1.1.1:3478', mapped: { ip: '203.0.113.50', port: 54321, family: 'IPv4' } },
    ])).toBe('unknown');
  });

  it('same mapping is port_restricted_cone', () => {
    const mapped: StunMappedAddress = { ip: '203.0.113.50', port: 54321, family: 'IPv4' };
    expect(classifyNat([
      { server: '1.1.1.1:3478', mapped },
      { server: '8.8.8.8:3478', mapped },
    ])).toBe('port_restricted_cone');
  });

  it('different IPs is symmetric', () => {
    expect(classifyNat([
      { server: '1.1.1.1:3478', mapped: { ip: '203.0.113.50', port: 54321, family: 'IPv4' } },
      { server: '8.8.8.8:3478', mapped: { ip: '203.0.113.51', port: 54321, family: 'IPv4' } },
    ])).toBe('symmetric');
  });

  it('different ports is symmetric', () => {
    expect(classifyNat([
      { server: '1.1.1.1:3478', mapped: { ip: '203.0.113.50', port: 54321, family: 'IPv4' } },
      { server: '8.8.8.8:3478', mapped: { ip: '203.0.113.50', port: 54322, family: 'IPv4' } },
    ])).toBe('symmetric');
  });
});

// --- NatDetector ---

describe('NatDetector', () => {
  it('creates with default STUN servers', () => {
    const detector = new NatDetector();
    expect(detector.stunServers.length).toBe(2);
    expect(detector.timeoutMs).toBe(3000);
  });

  it('creates with custom servers', () => {
    const detector = new NatDetector([{ host: 'custom.stun.server', port: 3478 }], 5000);
    expect(detector.stunServers.length).toBe(1);
    expect(detector.timeoutMs).toBe(5000);
  });

  it('empty servers returns unknown', async () => {
    const detector = new NatDetector([], 1000);
    const info = await detector.detect();
    expect(info.natType).toBe('unknown');
    expect(info.externalAddr).toBeUndefined();
  });

  it('default network info', () => {
    const info = defaultNetworkInfo();
    expect(info.natType).toBe('unknown');
    expect(info.externalAddr).toBeUndefined();
  });

  it('default STUN servers are configured', () => {
    expect(DEFAULT_STUN_SERVERS.length).toBe(2);
    expect(DEFAULT_STUN_SERVERS[0].host).toBe('stun.l.google.com');
  });
});

// --- Environment detection ---

describe('Environment detection', () => {
  it('detects Node.js environment', () => {
    // We're running in Node.js via vitest
    expect(isNodeEnvironment()).toBe(true);
  });

  it('detects non-browser environment', () => {
    // We're running in Node.js, not a browser
    expect(isBrowserEnvironment()).toBe(false);
  });
});

// --- Transport config ---

describe('Transport config', () => {
  it('default config', () => {
    const config = defaultTransportConfig();
    expect(config.quicEnabled).toBe(true);
    expect(config.tcpEnabled).toBe(true);
    expect(config.websocketEnabled).toBe(true);
    expect(config.webtransportEnabled).toBe(true);
    expect(config.webrtcEnabled).toBe(true);
    expect(config.circuitRelayEnabled).toBe(true);
    expect(config.perTransportTimeoutMs).toBe(10_000);
    expect(config.stunServers.length).toBe(2);
    expect(config.turnServers.length).toBe(0);
  });

  it('browser transport chain has 3 entries', () => {
    expect(BROWSER_TRANSPORT_CHAIN.length).toBe(3);
  });

  it('Node.js transport chain has 9 entries', () => {
    expect(NODEJS_TRANSPORT_CHAIN.length).toBe(9);
  });
});
