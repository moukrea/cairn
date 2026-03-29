import { describe, it, expect } from 'vitest';
import { NoiseXXHandshake } from '../../src/crypto/noise.js';
import type { HandshakeResult, StepOutput } from '../../src/crypto/noise.js';
import { IdentityKeypair } from '../../src/crypto/identity.js';
import { deriveNumericSas, deriveEmojiSas, EMOJI_TABLE } from '../../src/crypto/sas.js';
import { Spake2 } from '../../src/crypto/spake2.js';
import { CairnError } from '../../src/errors.js';

/** Run a complete Noise XX handshake and return both results. */
async function runHandshake(
  pakeSecret?: Uint8Array,
): Promise<[HandshakeResult, HandshakeResult]> {
  const alice = await IdentityKeypair.generate();
  const bob = await IdentityKeypair.generate();
  return runHandshakeWithIdentities(alice, bob, pakeSecret);
}

async function runHandshakeWithIdentities(
  alice: IdentityKeypair,
  bob: IdentityKeypair,
  pakeSecret?: Uint8Array,
): Promise<[HandshakeResult, HandshakeResult]> {
  const initiator = new NoiseXXHandshake('initiator', alice, pakeSecret);
  const responder = new NoiseXXHandshake('responder', bob, pakeSecret);

  // Initiator sends msg1
  const out1 = initiator.step();
  expect(out1.type).toBe('send_message');
  const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;

  // Responder receives msg1, sends msg2
  const out2 = responder.step(msg1);
  expect(out2.type).toBe('send_message');
  const msg2 = (out2 as { type: 'send_message'; data: Uint8Array }).data;

  // Initiator receives msg2, sends msg3
  const out3 = initiator.step(msg2);
  expect(out3.type).toBe('send_message');
  const msg3 = (out3 as { type: 'send_message'; data: Uint8Array }).data;

  // Initiator result is available via getResult()
  const initiatorResult = initiator.getResult();

  // Responder receives msg3 -> complete
  const out4 = responder.step(msg3);
  expect(out4.type).toBe('complete');
  const responderResult = (out4 as { type: 'complete'; result: HandshakeResult }).result;

  return [initiatorResult, responderResult];
}

describe('Noise XX Handshake', () => {
  it('produces matching session keys', async () => {
    const [initResult, respResult] = await runHandshake();
    expect(initResult.sessionKey).toEqual(respResult.sessionKey);
  });

  it('reveals remote static keys', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();
    const alicePub = alice.publicKey();
    const bobPub = bob.publicKey();

    const [initResult, respResult] = await runHandshakeWithIdentities(alice, bob);

    expect(initResult.remoteStatic).toEqual(bobPub);
    expect(respResult.remoteStatic).toEqual(alicePub);
  });

  it('transcript hashes match', async () => {
    const [initResult, respResult] = await runHandshake();
    expect(initResult.transcriptHash).toEqual(respResult.transcriptHash);
  });

  it('different handshakes produce different session keys', async () => {
    const [result1] = await runHandshake();
    const [result2] = await runHandshake();
    expect(result1.sessionKey).not.toEqual(result2.sessionKey);
  });

  it('message 1 is 32 bytes (ephemeral public key)', async () => {
    const alice = await IdentityKeypair.generate();
    const initiator = new NoiseXXHandshake('initiator', alice);
    const out = initiator.step();
    expect(out.type).toBe('send_message');
    expect((out as { type: 'send_message'; data: Uint8Array }).data.length).toBe(32);
  });

  it('session key is 32 bytes', async () => {
    const [initResult] = await runHandshake();
    expect(initResult.sessionKey.length).toBe(32);
  });

  it('transcript hash is 32 bytes', async () => {
    const [initResult] = await runHandshake();
    expect(initResult.transcriptHash.length).toBe(32);
  });
});

describe('Noise XX with PAKE secret', () => {
  it('completes with matching PAKE secrets', async () => {
    const pake = new Uint8Array(32).fill(42);
    const [initResult, respResult] = await runHandshake(pake);
    expect(initResult.sessionKey).toEqual(respResult.sessionKey);
  });

  it('mismatched PAKE secrets cause failure', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice, new Uint8Array(32).fill(1));
    const responder = new NoiseXXHandshake('responder', bob, new Uint8Array(32).fill(2));

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    const msg2 = (responder.step(msg1) as { type: 'send_message'; data: Uint8Array }).data;
    const msg3 = (initiator.step(msg2) as { type: 'send_message'; data: Uint8Array }).data;

    // Responder should fail to decrypt msg3 because PAKE secrets differ
    expect(() => responder.step(msg3)).toThrow(CairnError);
  });
});

describe('Noise XX error handling', () => {
  it('initiator rejects input at start', async () => {
    const alice = await IdentityKeypair.generate();
    const initiator = new NoiseXXHandshake('initiator', alice);
    expect(() => initiator.step(new Uint8Array(32))).toThrow(CairnError);
  });

  it('responder rejects no input', async () => {
    const bob = await IdentityKeypair.generate();
    const responder = new NoiseXXHandshake('responder', bob);
    expect(() => responder.step()).toThrow(CairnError);
  });

  it('message 1 wrong length rejected', async () => {
    const bob = await IdentityKeypair.generate();
    const responder = new NoiseXXHandshake('responder', bob);
    expect(() => responder.step(new Uint8Array(16))).toThrow(CairnError);
  });

  it('message 2 too short rejected', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice);
    const responder = new NoiseXXHandshake('responder', bob);

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    responder.step(msg1);

    expect(() => initiator.step(new Uint8Array(10))).toThrow(CairnError);
  });

  it('message 3 too short rejected', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice);
    const responder = new NoiseXXHandshake('responder', bob);

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    responder.step(msg1);

    expect(() => responder.step(new Uint8Array(5))).toThrow(CairnError);
  });

  it('tampered message 2 rejected', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice);
    const responder = new NoiseXXHandshake('responder', bob);

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    const msg2 = (responder.step(msg1) as { type: 'send_message'; data: Uint8Array }).data;

    // Tamper with encrypted portion
    if (msg2.length > 40) msg2[40] ^= 0xff;
    expect(() => initiator.step(msg2)).toThrow(CairnError);
  });

  it('tampered message 3 rejected', async () => {
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice);
    const responder = new NoiseXXHandshake('responder', bob);

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    const msg2 = (responder.step(msg1) as { type: 'send_message'; data: Uint8Array }).data;
    const msg3 = (initiator.step(msg2) as { type: 'send_message'; data: Uint8Array }).data;

    msg3[0] ^= 0xff;
    expect(() => responder.step(msg3)).toThrow(CairnError);
  });

  it('step after complete rejected', async () => {
    const [, respResult] = await runHandshake();
    // Create a new completed handshake and test further steps
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', alice);
    const responder = new NoiseXXHandshake('responder', bob);

    const msg1 = (initiator.step() as { type: 'send_message'; data: Uint8Array }).data;
    const msg2 = (responder.step(msg1) as { type: 'send_message'; data: Uint8Array }).data;
    const msg3 = (initiator.step(msg2) as { type: 'send_message'; data: Uint8Array }).data;
    responder.step(msg3);

    expect(() => responder.step()).toThrow(CairnError);
  });
});

describe('SAS derivation', () => {
  it('numeric SAS matches between peers', async () => {
    const [initResult, respResult] = await runHandshake();
    const initSas = deriveNumericSas(initResult.transcriptHash);
    const respSas = deriveNumericSas(respResult.transcriptHash);
    expect(initSas).toBe(respSas);
  });

  it('emoji SAS matches between peers', async () => {
    const [initResult, respResult] = await runHandshake();
    const initEmoji = deriveEmojiSas(initResult.transcriptHash);
    const respEmoji = deriveEmojiSas(respResult.transcriptHash);
    expect(initEmoji).toEqual(respEmoji);
  });

  it('numeric SAS is 6 digits', () => {
    const hash = new Uint8Array(32).fill(42);
    const sas = deriveNumericSas(hash);
    expect(sas.length).toBe(6);
    expect(sas).toMatch(/^\d{6}$/);
  });

  it('numeric SAS is zero-padded', () => {
    // We can't easily force a specific result, but let's verify format
    for (let i = 0; i < 10; i++) {
      const hash = new Uint8Array(32).fill(i);
      const sas = deriveNumericSas(hash);
      expect(sas.length).toBe(6);
      expect(sas).toMatch(/^\d{6}$/);
    }
  });

  it('numeric SAS is deterministic', () => {
    const hash = new Uint8Array(32).fill(99);
    expect(deriveNumericSas(hash)).toBe(deriveNumericSas(hash));
  });

  it('different transcripts produce different SAS', () => {
    const hash1 = new Uint8Array(32).fill(1);
    const hash2 = new Uint8Array(32).fill(2);
    expect(deriveNumericSas(hash1)).not.toBe(deriveNumericSas(hash2));
  });

  it('emoji SAS returns 4 entries', () => {
    const hash = new Uint8Array(32).fill(42);
    const emojis = deriveEmojiSas(hash);
    expect(emojis.length).toBe(4);
  });

  it('emoji SAS is deterministic', () => {
    const hash = new Uint8Array(32).fill(99);
    expect(deriveEmojiSas(hash)).toEqual(deriveEmojiSas(hash));
  });

  it('emoji SAS entries are from table', () => {
    const hash = new Uint8Array(32).fill(77);
    const emojis = deriveEmojiSas(hash);
    for (const emoji of emojis) {
      expect(EMOJI_TABLE).toContain(emoji);
    }
  });

  it('emoji table has 64 entries', () => {
    expect(EMOJI_TABLE.length).toBe(64);
  });
});

describe('SPAKE2', () => {
  it('same password produces matching keys', () => {
    const password = new TextEncoder().encode('test-password-42');
    const alice = Spake2.startA(password);
    const bob = Spake2.startB(password);

    const aliceKey = alice.finish(bob.outboundMsg);
    const bobKey = bob.finish(alice.outboundMsg);

    expect(aliceKey).toEqual(bobKey);
  });

  it('different passwords produce different keys', () => {
    const alice = Spake2.startA(new TextEncoder().encode('password-1'));
    const bob = Spake2.startB(new TextEncoder().encode('password-2'));

    const aliceKey = alice.finish(bob.outboundMsg);
    const bobKey = bob.finish(alice.outboundMsg);

    expect(aliceKey).not.toEqual(bobKey);
  });

  it('output key is 32 bytes', () => {
    const password = new TextEncoder().encode('test');
    const alice = Spake2.startA(password);
    const bob = Spake2.startB(password);
    const key = alice.finish(bob.outboundMsg);
    expect(key.length).toBe(32);
  });

  it('outbound message is 33 bytes (side prefix + compressed Ed25519 point)', () => {
    const password = new TextEncoder().encode('test');
    const alice = Spake2.startA(password);
    expect(alice.outboundMsg.length).toBe(33);
  });

  it('different sessions produce different outbound messages', () => {
    const password = new TextEncoder().encode('same-password');
    const a1 = Spake2.startA(password);
    const a2 = Spake2.startA(password);
    expect(a1.outboundMsg).not.toEqual(a2.outboundMsg);
  });

  it('SPAKE2 key integrates with Noise XX as PAKE secret', async () => {
    const password = new TextEncoder().encode('pairing-pin-42');

    // Both sides run SPAKE2 to derive a shared key
    const spakeA = Spake2.startA(password);
    const spakeB = Spake2.startB(password);

    const pakeKeyA = spakeA.finish(spakeB.outboundMsg);
    const pakeKeyB = spakeB.finish(spakeA.outboundMsg);

    expect(pakeKeyA).toEqual(pakeKeyB);

    // Use the SPAKE2 key as PAKE secret in Noise XX
    const alice = await IdentityKeypair.generate();
    const bob = await IdentityKeypair.generate();

    const [initResult, respResult] = await runHandshakeWithIdentities(alice, bob, pakeKeyA);

    expect(initResult.sessionKey).toEqual(respResult.sessionKey);
  });
});
