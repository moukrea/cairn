import { describe, it, expect } from 'vitest';
import { Node, NodeSession, NodeChannel } from '../../src/node.js';
import type { ConnectionState } from '../../src/config.js';
import { IdentityKeypair, peerIdFromPublicKey } from '../../src/crypto/identity.js';
import { Spake2 } from '../../src/crypto/spake2.js';
import { NoiseXXHandshake } from '../../src/crypto/noise.js';
import { DoubleRatchet } from '../../src/crypto/double-ratchet.js';
import { X25519Keypair } from '../../src/crypto/exchange.js';
import { hkdfSha256, HKDF_INFO_SESSION_KEY } from '../../src/crypto/hkdf.js';
import { aeadEncrypt, aeadDecrypt } from '../../src/crypto/aead.js';
import { generatePin, normalizePin, decodeCrockford } from '../../src/pairing/pin.js';
import {
  generateQrPayload,
  consumeQrPayload,
} from '../../src/pairing/qr.js';
import {
  generatePairingLink,
  parsePairingLink,
} from '../../src/pairing/link.js';
import { generateNonce } from '../../src/pairing/payload.js';
import type { PairingPayload } from '../../src/pairing/payload.js';

// --- Integration: Zero-config node creation ---

describe('integration: Node creation', () => {
  it('zero-config node creation', async () => {
    const node = await Node.create();
    expect(node.isClosed).toBe(false);
    expect(node.config.reconnectionPolicy.connectTimeout).toBe(30_000);
    await node.close();
    expect(node.isClosed).toBe(true);
  });

  it('server-mode node creation', async () => {
    const server = await Node.createServer();
    expect(server.config.meshSettings.meshEnabled).toBe(true);
    expect(server.config.meshSettings.relayWilling).toBe(true);
    await server.close();
  });

  it('all 6 pairing API methods exist', async () => {
    const node = await Node.create();
    // Generation methods return data
    const qr = await node.pairGenerateQr();
    expect(qr.expiresIn).toBeGreaterThan(0);

    const pin = await node.pairGeneratePin();
    expect(pin.pin).toBeTruthy();

    const link = await node.pairGenerateLink();
    expect(link.uri).toContain('cairn://');

    // Scan/enter methods are not yet wired
    await expect(node.pairScanQr(new Uint8Array(10))).rejects.toThrow();
    await expect(node.pairEnterPin('ABCD')).rejects.toThrow();
    await expect(node.pairFromLink('cairn://pair?data=x')).rejects.toThrow();

    await node.close();
  });
});

// --- Integration: Session + data exchange + channels ---

describe('integration: Session lifecycle', () => {
  it('connect creates session with correct state', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-abc');
    expect(session.peerId).toBe('peer-abc');
    expect(session.state).toBe('connected');
    await node.close();
  });

  it('session state transitions emit events', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-1');

    const transitions: Array<{ prev: ConnectionState; current: ConnectionState }> = [];
    session.onStateChange((prev, current) => transitions.push({ prev, current }));

    session.close();
    expect(transitions.length).toBe(1);
    expect(transitions[0]).toEqual({ prev: 'connected', current: 'disconnected' });
    await node.close();
  });

  it('channel multiplexing: open multiple channels', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-1');

    const opened: string[] = [];
    session.onChannelOpened((ch) => opened.push(ch.name));

    const chat = session.openChannel('chat');
    const video = session.openChannel('video');
    const files = session.openChannel('files');

    expect(opened).toEqual(['chat', 'video', 'files']);
    expect(chat.isOpen).toBe(true);
    expect(video.isOpen).toBe(true);
    expect(files.isOpen).toBe(true);

    // Send data on channels
    session.send(chat, new Uint8Array([1, 2, 3]));
    session.send(video, new Uint8Array([4, 5, 6]));

    // Close individual channels
    chat.close();
    expect(chat.isOpen).toBe(false);
    expect(video.isOpen).toBe(true);

    // Send on closed channel throws
    expect(() => session.send(chat, new Uint8Array([7]))).toThrow();

    await node.close();
  });

  it('reserved channel names rejected', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-1');
    expect(() => session.openChannel('__cairn_forward')).toThrow('reserved');
    expect(() => session.openChannel('__cairn_anything')).toThrow('reserved');
    expect(() => session.openChannel('')).toThrow('empty');
    await node.close();
  });

  it('unpair emits event', async () => {
    const node = await Node.create();
    const unpaired: string[] = [];
    node.onPeerUnpaired((id) => unpaired.push(id));

    await node.connect('peer-1');
    await node.unpair('peer-1');
    expect(unpaired).toEqual(['peer-1']);
    await node.close();
  });
});

// --- Integration: Full crypto pipeline ---

describe('integration: Crypto pipeline', () => {
  it('SPAKE2 -> Noise XX -> HKDF -> Double Ratchet -> encrypted message', async () => {
    // 1. SPAKE2 mutual authentication
    const password = new TextEncoder().encode('test-password');
    const alice = Spake2.startA(password);
    const bob = Spake2.startB(password);

    const aliceSecret = alice.finish(bob.outboundMsg);
    const bobSecret = bob.finish(alice.outboundMsg);
    expect(aliceSecret).toEqual(bobSecret);

    // 2. Noise XX handshake
    const aliceId = await IdentityKeypair.generate();
    const bobId = await IdentityKeypair.generate();

    const aliceNoise = new NoiseXXHandshake('initiator', aliceId);
    const bobNoise = new NoiseXXHandshake('responder', bobId);

    const step1 = aliceNoise.step();
    expect(step1.type).toBe('send_message');
    const msg1 = (step1 as { type: 'send_message'; data: Uint8Array }).data;

    const step2 = bobNoise.step(msg1);
    expect(step2.type).toBe('send_message');
    const msg2 = (step2 as { type: 'send_message'; data: Uint8Array }).data;

    const step3 = aliceNoise.step(msg2);
    expect(step3.type).toBe('send_message');
    const msg3 = (step3 as { type: 'send_message'; data: Uint8Array }).data;

    const step4 = bobNoise.step(msg3);
    expect(step4.type).toBe('complete');

    const aliceResult = aliceNoise.getResult();
    const bobResult = (step4 as { type: 'complete'; result: typeof aliceResult }).result;
    expect(aliceResult.sessionKey).toEqual(bobResult.sessionKey);

    // 3. HKDF session key derivation
    const sessionKey = hkdfSha256(aliceResult.sessionKey, undefined, HKDF_INFO_SESSION_KEY, 32);
    expect(sessionKey.length).toBe(32);

    // 4. Double Ratchet for forward-secure messaging
    // Bob creates a DH keypair for the initial ratchet setup
    const bobDhKp = X25519Keypair.generate();
    const aliceRatchet = DoubleRatchet.initSender(aliceResult.sessionKey, bobDhKp.publicKeyBytes());
    const bobRatchet = DoubleRatchet.initReceiver(aliceResult.sessionKey, bobDhKp);

    const plaintext = new TextEncoder().encode('Hello from Alice!');
    const { header, ciphertext } = aliceRatchet.encrypt(plaintext);
    const decrypted = bobRatchet.decrypt(header, ciphertext);
    expect(decrypted).toEqual(plaintext);

    // 5. Bidirectional messaging
    const bobPlaintext = new TextEncoder().encode('Hello from Bob!');
    const bobEncrypted = bobRatchet.encrypt(bobPlaintext);
    const aliceDecrypted = aliceRatchet.decrypt(bobEncrypted.header, bobEncrypted.ciphertext);
    expect(aliceDecrypted).toEqual(bobPlaintext);
  });

  it('AEAD encrypt/decrypt round-trip with tamper detection', () => {
    const key = new Uint8Array(32);
    key.fill(0x42);
    const nonce = new Uint8Array(12);
    nonce.fill(0x01);
    const plaintext = new TextEncoder().encode('secret message');
    const aad = new TextEncoder().encode('associated data');

    const encrypted = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);
    const decrypted = aeadDecrypt('aes-256-gcm', key, nonce, encrypted, aad);
    expect(decrypted).toEqual(plaintext);

    // Tamper with ciphertext
    const tampered = new Uint8Array(encrypted);
    tampered[0] ^= 0xff;
    expect(() => aeadDecrypt('aes-256-gcm', key, nonce, tampered, aad)).toThrow();

    // Wrong key
    const wrongKey = new Uint8Array(32);
    wrongKey.fill(0x99);
    expect(() => aeadDecrypt('aes-256-gcm', wrongKey, nonce, encrypted, aad)).toThrow();

    // Wrong AAD
    const wrongAad = new TextEncoder().encode('wrong aad');
    expect(() => aeadDecrypt('aes-256-gcm', key, nonce, encrypted, wrongAad)).toThrow();
  });
});

// --- Integration: Pairing flows ---

describe('integration: Pairing flows', () => {
  it('PIN code generation and normalization', () => {
    const pin = generatePin();
    expect(pin.length).toBe(8);

    // Normalize handles confusable characters
    const withConfusables = pin.replace(/1/g, 'l').replace(/0/g, 'O');
    const normalized = normalizePin(withConfusables);
    expect(normalized).toBe(normalizePin(pin));
  });

  it('QR payload round-trip', async () => {
    const keypair = await IdentityKeypair.generate();
    const now = Math.floor(Date.now() / 1000);
    const payload: PairingPayload = {
      peerId: peerIdFromPublicKey(keypair.publicKey()),
      nonce: generateNonce(),
      pakeCredential: new Uint8Array(32).fill(0xAB),
      createdAt: now,
      expiresAt: now + 300,
    };

    const qrBytes = generateQrPayload(payload);
    expect(qrBytes.length).toBeLessThanOrEqual(256);

    const parsed = consumeQrPayload(qrBytes);
    expect(parsed.peerId).toEqual(payload.peerId);
    expect(parsed.nonce).toEqual(payload.nonce);
    expect(parsed.pakeCredential).toEqual(payload.pakeCredential);
  });

  it('Pairing link round-trip', async () => {
    const keypair = await IdentityKeypair.generate();
    const now = Math.floor(Date.now() / 1000);
    const payload: PairingPayload = {
      peerId: peerIdFromPublicKey(keypair.publicKey()),
      nonce: generateNonce(),
      pakeCredential: new Uint8Array(32).fill(0xCD),
      createdAt: now,
      expiresAt: now + 300,
    };

    const uri = generatePairingLink(payload);
    expect(uri).toContain('cairn://pair?');

    const parsed = parsePairingLink(uri);
    expect(parsed.peerId).toEqual(payload.peerId);
    expect(parsed.nonce).toEqual(payload.nonce);
    expect(parsed.pakeCredential).toEqual(payload.pakeCredential);
  });
});

// --- Integration: Reconnection backoff sequence ---

describe('integration: Reconnection', () => {
  it('backoff sequence: 1s -> 2s -> 4s -> 8s -> 16s -> 32s -> 60s', async () => {
    const { ExponentialBackoff } = await import('../../src/session/backoff.js');
    const backoff = new ExponentialBackoff();

    const expected = [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000];
    for (const delay of expected) {
      expect(backoff.nextDelay()).toBe(delay);
    }
  });
});

// --- Integration: Error propagation ---

describe('integration: Error propagation', () => {
  it('CairnError has code and details', async () => {
    const { CairnError } = await import('../../src/errors.js');
    const err = new CairnError('TEST_CODE', 'test message', { key: 'value' });
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test message');
    expect(err.details).toEqual({ key: 'value' });
  });

  it('all error subclasses have correct codes', async () => {
    const errors = await import('../../src/errors.js');
    expect(new errors.TransportExhaustedError('msg').code).toBe('TRANSPORT_EXHAUSTED');
    expect(new errors.SessionExpiredError('msg').code).toBe('SESSION_EXPIRED');
    expect(new errors.PeerUnreachableError('msg').code).toBe('PEER_UNREACHABLE');
    expect(new errors.AuthenticationFailedError('msg').code).toBe('AUTHENTICATION_FAILED');
    expect(new errors.PairingRejectedError('msg').code).toBe('PAIRING_REJECTED');
    expect(new errors.PairingExpiredError('msg').code).toBe('PAIRING_EXPIRED');
    expect(new errors.MeshRouteNotFoundError('msg').code).toBe('MESH_ROUTE_NOT_FOUND');
    expect(new errors.VersionMismatchError('msg').code).toBe('VERSION_MISMATCH');
  });
});
