import { describe, it, expect } from 'vitest';
import {
  Node,
  NodeSession,
  NodeChannel,
  DEFAULT_RECONNECTION_POLICY,
  DEFAULT_MESH_SETTINGS,
  DEFAULT_STUN_SERVERS,
  DEFAULT_TRANSPORT_PREFERENCES,
} from '../../src/index.js';
import type { ConnectionState } from '../../src/config.js';

// --- Node creation ---

describe('Node.create', () => {
  it('creates node with defaults', async () => {
    const node = await Node.create();
    expect(node.isClosed).toBe(false);
    expect(node.config.stunServers).toEqual([...DEFAULT_STUN_SERVERS]);
    expect(node.config.transportPreferences).toEqual([...DEFAULT_TRANSPORT_PREFERENCES]);
    expect(node.config.reconnectionPolicy.connectTimeout).toBe(30_000);
    expect(node.config.reconnectionPolicy.transportTimeout).toBe(10_000);
    expect(node.config.reconnectionPolicy.reconnectMaxDuration).toBe(3_600_000);
    expect(node.config.reconnectionPolicy.rendezvousPollInterval).toBe(30_000);
    expect(node.config.reconnectionPolicy.sessionExpiry).toBe(86_400_000);
    expect(node.config.reconnectionPolicy.pairingPayloadExpiry).toBe(300_000);
    expect(node.config.reconnectionPolicy.reconnectBackoff.initialDelay).toBe(1_000);
    expect(node.config.reconnectionPolicy.reconnectBackoff.maxDelay).toBe(60_000);
    expect(node.config.reconnectionPolicy.reconnectBackoff.factor).toBe(2.0);
    expect(node.config.meshSettings.meshEnabled).toBe(false);
    expect(node.config.meshSettings.maxHops).toBe(3);
    expect(node.config.meshSettings.relayWilling).toBe(false);
    expect(node.config.meshSettings.relayCapacity).toBe(10);
    expect(node.config.storageBackend).toBe('memory');
  });

  it('overrides specific fields', async () => {
    const node = await Node.create({
      stunServers: ['stun:custom.example.com:3478'],
      reconnectionPolicy: { connectTimeout: 60_000 },
    });
    expect(node.config.stunServers).toEqual(['stun:custom.example.com:3478']);
    expect(node.config.reconnectionPolicy.connectTimeout).toBe(60_000);
    // Other reconnection defaults preserved
    expect(node.config.reconnectionPolicy.transportTimeout).toBe(10_000);
  });

  it('overrides mesh settings', async () => {
    const node = await Node.create({ meshSettings: { meshEnabled: true, relayWilling: true } });
    expect(node.config.meshSettings.meshEnabled).toBe(true);
    expect(node.config.meshSettings.relayWilling).toBe(true);
    expect(node.config.meshSettings.maxHops).toBe(3); // default
  });
});

describe('Node.createServer', () => {
  it('creates server with server-mode defaults', async () => {
    const node = await Node.createServer();
    expect(node.config.meshSettings.meshEnabled).toBe(true);
    expect(node.config.meshSettings.relayWilling).toBe(true);
    expect(node.config.meshSettings.relayCapacity).toBe(100);
    expect(node.config.reconnectionPolicy.sessionExpiry).toBe(7 * 24 * 60 * 60 * 1000);
    expect(node.config.reconnectionPolicy.reconnectMaxDuration).toBe(Infinity);
  });

  it('server config can be overridden', async () => {
    const node = await Node.createServer({
      meshSettings: { relayCapacity: 500 },
    });
    expect(node.config.meshSettings.relayCapacity).toBe(500);
    expect(node.config.meshSettings.meshEnabled).toBe(true); // server default preserved
  });
});

// --- Node pairing methods ---

describe('Node pairing', () => {
  it('pairGenerateQr returns payload', async () => {
    const node = await Node.create();
    const data = await node.pairGenerateQr();
    expect(data.expiresIn).toBe(node.config.reconnectionPolicy.pairingPayloadExpiry);
  });

  it('pairScanQr rejects invalid CBOR', async () => {
    const node = await Node.create();
    await expect(node.pairScanQr(new Uint8Array([1, 2]))).rejects.toThrow();
  });

  it('pairScanQr roundtrip', async () => {
    const node = await Node.create();
    const qr = await node.pairGenerateQr();
    const peerId = await node.pairScanQr(qr.payload);
    expect(peerId).toBeTruthy();
  });

  it('pairGeneratePin returns pin', async () => {
    const node = await Node.create();
    const data = await node.pairGeneratePin();
    expect(data.pin).toBeTruthy();
    expect(data.pin.length).toBe(9); // XXXX-XXXX
    expect(data.pin[4]).toBe('-');
    expect(data.expiresIn).toBe(node.config.reconnectionPolicy.pairingPayloadExpiry);
  });

  it('pairEnterPin succeeds with valid pin', async () => {
    const node = await Node.create();
    const peerId = await node.pairEnterPin('ABCD-EFGH');
    expect(peerId).toBeTruthy();
  });

  it('pairEnterPin rejects invalid characters', async () => {
    const node = await Node.create();
    await expect(node.pairEnterPin('!!!')).rejects.toThrow();
  });

  it('pairGenerateLink returns real URI', async () => {
    const node = await Node.create();
    const data = await node.pairGenerateLink();
    expect(data.uri).toContain('cairn://pair?');
    expect(data.uri).toContain('pid=');
    expect(data.expiresIn).toBe(node.config.reconnectionPolicy.pairingPayloadExpiry);
  });

  it('pairFromLink roundtrip', async () => {
    const node = await Node.create();
    const link = await node.pairGenerateLink();
    const peerId = await node.pairFromLink(link.uri);
    expect(peerId).toBeTruthy();
  });

  it('pairFromLink rejects invalid URI', async () => {
    const node = await Node.create();
    await expect(node.pairFromLink('https://example.com')).rejects.toThrow();
  });
});

// --- Node connection ---

describe('Node connection', () => {
  it('connect creates session', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-abc');
    expect(session.peerId).toBe('peer-abc');
    expect(session.state).toBe('connected');
  });

  it('unpair removes session and emits event', async () => {
    const node = await Node.create();
    const unpaired: string[] = [];
    node.onPeerUnpaired((id) => unpaired.push(id));
    await node.connect('peer-1');
    await node.unpair('peer-1');
    expect(unpaired).toEqual(['peer-1']);
  });

  it('networkInfo returns NAT type', async () => {
    const node = await Node.create();
    const info = await node.networkInfo();
    expect(info.natType).toBe('unknown');
  });

  it('setNatType updates NAT type', async () => {
    const node = await Node.create();
    node.setNatType('full_cone');
    const info = await node.networkInfo();
    expect(info.natType).toBe('full_cone');
  });

  it('close stops node', async () => {
    const node = await Node.create();
    await node.connect('peer-1');
    await node.close();
    expect(node.isClosed).toBe(true);
  });
});

// --- NodeSession ---

describe('NodeSession', () => {
  it('open channel', () => {
    const session = new NodeSession('peer-1');
    const ch = session.openChannel('data');
    expect(ch.name).toBe('data');
    expect(ch.isOpen).toBe(true);
  });

  it('open channel rejects empty name', () => {
    const session = new NodeSession('peer-1');
    expect(() => session.openChannel('')).toThrow('cannot be empty');
  });

  it('open channel rejects reserved prefix', () => {
    const session = new NodeSession('peer-1');
    expect(() => session.openChannel('__cairn_internal')).toThrow('reserved');
  });

  it('send on open channel', () => {
    const session = new NodeSession('peer-1');
    const ch = session.openChannel('data');
    expect(() => session.send(ch, new Uint8Array([1, 2, 3]))).not.toThrow();
  });

  it('send on closed channel throws', () => {
    const session = new NodeSession('peer-1');
    const ch = session.openChannel('data');
    ch.close();
    expect(() => session.send(ch, new Uint8Array([1]))).toThrow('not open');
  });

  it('close transitions to disconnected', () => {
    const session = new NodeSession('peer-1');
    session.close();
    expect(session.state).toBe('disconnected');
  });

  it('state change listener', () => {
    const session = new NodeSession('peer-1');
    const changes: Array<{ prev: ConnectionState; current: ConnectionState }> = [];
    session.onStateChange((prev, current) => changes.push({ prev, current }));
    session.close();
    expect(changes.length).toBe(1);
    expect(changes[0].prev).toBe('connected');
    expect(changes[0].current).toBe('disconnected');
  });

  it('channel opened listener', () => {
    const session = new NodeSession('peer-1');
    const opened: string[] = [];
    session.onChannelOpened((ch) => opened.push(ch.name));
    session.openChannel('chat');
    session.openChannel('video');
    expect(opened).toEqual(['chat', 'video']);
  });

  it('on message handler', () => {
    const session = new NodeSession('peer-1');
    const ch = session.openChannel('data');
    let received = false;
    session.onMessage(ch, () => { received = true; });
    // Handler registered but not invoked here (no real transport)
    expect(received).toBe(false);
  });

  it('custom message handler valid range', () => {
    const session = new NodeSession('peer-1');
    expect(() => session.onCustomMessage(0xf000, () => {})).not.toThrow();
    expect(() => session.onCustomMessage(0xffff, () => {})).not.toThrow();
  });

  it('custom message handler invalid range', () => {
    const session = new NodeSession('peer-1');
    expect(() => session.onCustomMessage(0x0100, () => {})).toThrow('outside application range');
    expect(() => session.onCustomMessage(0xefff, () => {})).toThrow('outside application range');
  });

  it('multiple channels', () => {
    const session = new NodeSession('peer-1');
    const ch1 = session.openChannel('chat');
    const ch2 = session.openChannel('video');
    expect(ch1.name).toBe('chat');
    expect(ch2.name).toBe('video');
    expect(ch1.isOpen).toBe(true);
    expect(ch2.isOpen).toBe(true);
  });
});

// --- NodeChannel ---

describe('NodeChannel', () => {
  it('lifecycle', () => {
    const ch = new NodeChannel('test');
    expect(ch.isOpen).toBe(true);
    expect(ch.name).toBe('test');
    ch.close();
    expect(ch.isOpen).toBe(false);
  });
});

// --- Default constants ---

describe('default constants', () => {
  it('DEFAULT_RECONNECTION_POLICY', () => {
    expect(DEFAULT_RECONNECTION_POLICY.connectTimeout).toBe(30_000);
    expect(DEFAULT_RECONNECTION_POLICY.transportTimeout).toBe(10_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectMaxDuration).toBe(3_600_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.initialDelay).toBe(1_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.maxDelay).toBe(60_000);
    expect(DEFAULT_RECONNECTION_POLICY.reconnectBackoff.factor).toBe(2.0);
    expect(DEFAULT_RECONNECTION_POLICY.rendezvousPollInterval).toBe(30_000);
    expect(DEFAULT_RECONNECTION_POLICY.sessionExpiry).toBe(86_400_000);
    expect(DEFAULT_RECONNECTION_POLICY.pairingPayloadExpiry).toBe(300_000);
  });

  it('DEFAULT_MESH_SETTINGS', () => {
    expect(DEFAULT_MESH_SETTINGS.meshEnabled).toBe(false);
    expect(DEFAULT_MESH_SETTINGS.maxHops).toBe(3);
    expect(DEFAULT_MESH_SETTINGS.relayWilling).toBe(false);
    expect(DEFAULT_MESH_SETTINGS.relayCapacity).toBe(10);
  });

  it('DEFAULT_STUN_SERVERS', () => {
    expect(DEFAULT_STUN_SERVERS.length).toBe(3);
    expect(DEFAULT_STUN_SERVERS[0]).toContain('google.com');
  });

  it('DEFAULT_TRANSPORT_PREFERENCES', () => {
    expect(DEFAULT_TRANSPORT_PREFERENCES.length).toBe(5);
    expect(DEFAULT_TRANSPORT_PREFERENCES[0]).toBe('quic');
  });
});
