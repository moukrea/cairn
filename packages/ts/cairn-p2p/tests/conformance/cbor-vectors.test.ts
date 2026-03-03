import { describe, it, expect } from 'vitest';
import {
  encodeEnvelope,
  decodeEnvelope,
  encodeEnvelopeDeterministic,
} from '../../src/protocol/envelope.js';
import type { MessageEnvelope } from '../../src/protocol/envelope.js';
import * as MSG from '../../src/protocol/message-types.js';
import { IdentityKeypair, peerIdFromPublicKey, verifySignature } from '../../src/crypto/identity.js';
import { hkdfSha256, HKDF_INFO_SESSION_KEY } from '../../src/crypto/hkdf.js';
import { deriveRendezvousId, derivePairingRendezvousId } from '../../src/discovery/rendezvous.js';

// --- CBOR envelope conformance ---

describe('conformance: CBOR envelope encoding', () => {
  it('round-trip minimal envelope', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: MSG.HEARTBEAT,
      msgId: new Uint8Array(16).fill(0x01),
      payload: new Uint8Array(0),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.version).toBe(1);
    expect(decoded.type).toBe(MSG.HEARTBEAT);
    expect(decoded.msgId).toEqual(envelope.msgId);
    expect(decoded.payload).toEqual(new Uint8Array(0));
    expect(decoded.sessionId).toBeUndefined();
    expect(decoded.authTag).toBeUndefined();
  });

  it('round-trip full envelope', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: MSG.DATA_MESSAGE,
      msgId: new Uint8Array(16).fill(0xAB),
      sessionId: new Uint8Array(32).fill(0xCD),
      payload: new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]),
      authTag: new Uint8Array([0xDE, 0xAD]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.version).toBe(envelope.version);
    expect(decoded.type).toBe(envelope.type);
    expect(decoded.msgId).toEqual(envelope.msgId);
    expect(decoded.sessionId).toEqual(envelope.sessionId);
    expect(decoded.payload).toEqual(envelope.payload);
    expect(decoded.authTag).toEqual(envelope.authTag);
  });

  it('optional fields absent when not set', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: MSG.PAIR_REQUEST,
      msgId: new Uint8Array(16).fill(0x02),
      payload: new Uint8Array([0x01]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.sessionId).toBeUndefined();
    expect(decoded.authTag).toBeUndefined();
  });

  it('deterministic encoding produces identical bytes', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: MSG.HEARTBEAT,
      msgId: new Uint8Array(16).fill(0x01),
      sessionId: new Uint8Array(32).fill(0x02),
      payload: new Uint8Array([0xFF]),
      authTag: new Uint8Array([0x00, 0x01]),
    };

    const enc1 = encodeEnvelopeDeterministic(envelope);
    const enc2 = encodeEnvelopeDeterministic(envelope);
    expect(enc1).toEqual(enc2);
  });

  it('deterministic encoding is stable across calls', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: MSG.HEARTBEAT,
      msgId: new Uint8Array(16),
      payload: new Uint8Array(0),
    };

    const results = [];
    for (let i = 0; i < 10; i++) {
      results.push(encodeEnvelopeDeterministic(envelope));
    }

    for (let i = 1; i < results.length; i++) {
      expect(results[i]).toEqual(results[0]);
    }
  });

  it('decode rejects invalid CBOR', () => {
    expect(() => decodeEnvelope(new Uint8Array([0xFF, 0xFF, 0xFF]))).toThrow();
  });

  it('version field preserved for all values', () => {
    for (const v of [0, 1, 255]) {
      const envelope: MessageEnvelope = {
        version: v,
        type: MSG.HEARTBEAT,
        msgId: new Uint8Array(16),
        payload: new Uint8Array(0),
      };
      const decoded = decodeEnvelope(encodeEnvelope(envelope));
      expect(decoded.version).toBe(v);
    }
  });

  it('all message type codes are valid uint16', () => {
    const messageTypeNames = [
      'PAIR_REQUEST', 'PAIR_CHALLENGE', 'PAIR_RESPONSE', 'PAIR_CONFIRM', 'PAIR_REJECT', 'PAIR_REVOKE',
      'SESSION_RESUME', 'SESSION_RESUME_ACK', 'SESSION_EXPIRED', 'SESSION_CLOSE',
      'DATA_MESSAGE', 'DATA_ACK', 'DATA_NACK',
      'HEARTBEAT', 'HEARTBEAT_ACK', 'TRANSPORT_MIGRATE', 'TRANSPORT_MIGRATE_ACK',
      'ROUTE_REQUEST', 'ROUTE_RESPONSE', 'RELAY_DATA', 'RELAY_ACK',
      'RENDEZVOUS_PUBLISH', 'RENDEZVOUS_QUERY', 'RENDEZVOUS_RESPONSE',
      'FORWARD_REQUEST', 'FORWARD_ACK', 'FORWARD_DELIVER', 'FORWARD_PURGE',
      'VERSION_NEGOTIATE',
    ] as const;

    for (const name of messageTypeNames) {
      const code = MSG[name];
      expect(code).toBeGreaterThanOrEqual(0);
      expect(code).toBeLessThanOrEqual(0xFFFF);
    }
  });

  it('message types match Rust constants', () => {
    // Core protocol messages
    expect(MSG.HEARTBEAT).toBe(0x0400);
    expect(MSG.DATA_MESSAGE).toBe(0x0300);

    // Pairing messages (0x01xx)
    expect(MSG.PAIR_REQUEST).toBe(0x0100);
    expect(MSG.PAIR_REJECT).toBe(0x0104);

    // Session messages (0x02xx)
    expect(MSG.SESSION_RESUME).toBe(0x0200);

    // Mesh messages (0x05xx)
    expect(MSG.ROUTE_REQUEST).toBe(0x0500);
    expect(MSG.ROUTE_RESPONSE).toBe(0x0501);
    expect(MSG.RELAY_DATA).toBe(0x0502);
    expect(MSG.RELAY_ACK).toBe(0x0503);

    // Forward messages (0x07xx)
    expect(MSG.FORWARD_REQUEST).toBe(0x0700);
    expect(MSG.FORWARD_ACK).toBe(0x0701);
    expect(MSG.FORWARD_DELIVER).toBe(0x0702);
    expect(MSG.FORWARD_PURGE).toBe(0x0703);
  });
});

// --- Crypto conformance ---

describe('conformance: Crypto', () => {
  it('Ed25519 PeerId is deterministic from public key', async () => {
    const kp = await IdentityKeypair.generate();
    const id1 = peerIdFromPublicKey(kp.publicKey());
    const id2 = peerIdFromPublicKey(kp.publicKey());
    expect(id1).toEqual(id2);
  });

  it('PeerId is 32 bytes (SHA-256 of public key)', async () => {
    const kp = await IdentityKeypair.generate();
    const id = peerIdFromPublicKey(kp.publicKey());
    expect(id.length).toBe(32);
  });

  it('different keys produce different PeerIds', async () => {
    const kp1 = await IdentityKeypair.generate();
    const kp2 = await IdentityKeypair.generate();
    const id1 = peerIdFromPublicKey(kp1.publicKey());
    const id2 = peerIdFromPublicKey(kp2.publicKey());
    expect(id1).not.toEqual(id2);
  });

  it('HKDF output has correct length', () => {
    const ikm = new Uint8Array(32).fill(0x01);
    for (const len of [16, 32, 48, 64]) {
      const output = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, len);
      expect(output.length).toBe(len);
    }
  });

  it('HKDF is deterministic', () => {
    const ikm = new Uint8Array(32).fill(0x42);
    const salt = new Uint8Array(16).fill(0x01);
    const info = HKDF_INFO_SESSION_KEY;

    const out1 = hkdfSha256(ikm, salt, info, 32);
    const out2 = hkdfSha256(ikm, salt, info, 32);
    expect(out1).toEqual(out2);
  });

  it('HKDF different inputs produce different outputs', () => {
    const info = HKDF_INFO_SESSION_KEY;
    const out1 = hkdfSha256(new Uint8Array(32).fill(0x01), undefined, info, 32);
    const out2 = hkdfSha256(new Uint8Array(32).fill(0x02), undefined, info, 32);
    expect(out1).not.toEqual(out2);
  });

  it('Ed25519 sign/verify round-trip', async () => {
    const kp = await IdentityKeypair.generate();
    const message = new TextEncoder().encode('test message');
    const signature = await kp.sign(message);
    expect(signature.length).toBe(64);

    // Valid signature should not throw
    await verifySignature(kp.publicKey(), message, signature);

    // Tampered message should throw
    const tampered = new TextEncoder().encode('wrong message');
    await expect(verifySignature(kp.publicKey(), tampered, signature)).rejects.toThrow();
  });
});

// --- Rendezvous conformance ---

describe('conformance: Rendezvous', () => {
  it('rendezvous ID derivation is deterministic and cross-peer consistent', () => {
    const secret = new TextEncoder().encode('shared-secret');

    const alice = deriveRendezvousId(secret, 42);
    const bob = deriveRendezvousId(secret, 42);
    expect(alice.toHex()).toBe(bob.toHex());
  });

  it('pairing rendezvous differs from standard rendezvous', () => {
    const input = new TextEncoder().encode('same-input');
    const epoch = 1;
    const standard = deriveRendezvousId(input, epoch);
    const epochBytes = new Uint8Array(8);
    new DataView(epochBytes.buffer).setBigUint64(0, BigInt(epoch), false);
    const pairing = derivePairingRendezvousId(input, epochBytes);
    expect(standard.toHex()).not.toBe(pairing.toHex());
  });
});
