import { describe, it, expect } from 'vitest';
import { DoubleRatchet } from '../../src/crypto/double-ratchet.js';
import { X25519Keypair } from '../../src/crypto/exchange.js';
import { CairnError } from '../../src/errors.js';

function setupPair(config?: { maxSkip?: number; cipher?: 'aes-256-gcm' | 'chacha20-poly1305' }) {
  const sharedSecret = new Uint8Array(32).fill(0x42);
  const bobKp = X25519Keypair.generate();

  const alice = DoubleRatchet.initSender(sharedSecret, bobKp.publicKeyBytes(), config);
  const bob = DoubleRatchet.initReceiver(sharedSecret, bobKp, config);

  return { alice, bob };
}

describe('DoubleRatchet', () => {
  it('alice sends bob receives', () => {
    const { alice, bob } = setupPair();

    const plaintext = new TextEncoder().encode('hello bob');
    const { header, ciphertext } = alice.encrypt(plaintext);
    const decrypted = bob.decrypt(header, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  it('multiple messages one direction', () => {
    const { alice, bob } = setupPair();

    for (let i = 0; i < 10; i++) {
      const msg = new TextEncoder().encode(`message ${i}`);
      const { header, ciphertext } = alice.encrypt(msg);
      const pt = bob.decrypt(header, ciphertext);
      expect(pt).toEqual(msg);
    }
  });

  it('bidirectional messages', () => {
    const { alice, bob } = setupPair();

    // Alice -> Bob
    const { header: h1, ciphertext: ct1 } = alice.encrypt(new TextEncoder().encode('hello bob'));
    expect(bob.decrypt(h1, ct1)).toEqual(new TextEncoder().encode('hello bob'));

    // Bob -> Alice
    const { header: h2, ciphertext: ct2 } = bob.encrypt(new TextEncoder().encode('hello alice'));
    expect(alice.decrypt(h2, ct2)).toEqual(new TextEncoder().encode('hello alice'));

    // Alice -> Bob again (second ratchet step)
    const { header: h3, ciphertext: ct3 } = alice.encrypt(new TextEncoder().encode('how are you?'));
    expect(bob.decrypt(h3, ct3)).toEqual(new TextEncoder().encode('how are you?'));
  });

  it('out-of-order messages', () => {
    const { alice, bob } = setupPair();

    const { header: h1, ciphertext: ct1 } = alice.encrypt(new TextEncoder().encode('msg 0'));
    const { header: h2, ciphertext: ct2 } = alice.encrypt(new TextEncoder().encode('msg 1'));
    const { header: h3, ciphertext: ct3 } = alice.encrypt(new TextEncoder().encode('msg 2'));

    // Deliver out of order: 2, 0, 1
    expect(bob.decrypt(h3, ct3)).toEqual(new TextEncoder().encode('msg 2'));
    expect(bob.decrypt(h1, ct1)).toEqual(new TextEncoder().encode('msg 0'));
    expect(bob.decrypt(h2, ct2)).toEqual(new TextEncoder().encode('msg 1'));
  });

  it('max skip threshold respected', () => {
    const sharedSecret = new Uint8Array(32).fill(0x42);
    const bobKp = X25519Keypair.generate();

    const alice = DoubleRatchet.initSender(sharedSecret, bobKp.publicKeyBytes(), { maxSkip: 2 });
    const bob = DoubleRatchet.initReceiver(sharedSecret, bobKp, { maxSkip: 2 });

    alice.encrypt(new TextEncoder().encode('skip 0'));
    alice.encrypt(new TextEncoder().encode('skip 1'));
    alice.encrypt(new TextEncoder().encode('skip 2'));
    const { header: h4, ciphertext: ct4 } = alice.encrypt(new TextEncoder().encode('msg 3'));

    // Should fail: need to skip 3 keys but maxSkip is 2
    expect(() => bob.decrypt(h4, ct4)).toThrow('max skip threshold exceeded');
  });

  it('state export/import roundtrip', () => {
    const { alice, bob } = setupPair();

    // Exchange some messages
    const { header: h1, ciphertext: ct1 } = alice.encrypt(new TextEncoder().encode('before persist'));
    expect(bob.decrypt(h1, ct1)).toEqual(new TextEncoder().encode('before persist'));

    // Export and reimport Alice's state
    const exported = alice.exportState();
    const alice2 = DoubleRatchet.importState(exported);

    // Alice2 should continue sending
    const { header: h2, ciphertext: ct2 } = alice2.encrypt(new TextEncoder().encode('after persist'));
    expect(bob.decrypt(h2, ct2)).toEqual(new TextEncoder().encode('after persist'));
  });

  it('multiple ratchet turns', () => {
    const { alice, bob } = setupPair();

    for (let round = 0; round < 5; round++) {
      const msgAb = new TextEncoder().encode(`alice round ${round}`);
      const { header: ha, ciphertext: cta } = alice.encrypt(msgAb);
      expect(bob.decrypt(ha, cta)).toEqual(msgAb);

      const msgBa = new TextEncoder().encode(`bob round ${round}`);
      const { header: hb, ciphertext: ctb } = bob.encrypt(msgBa);
      expect(alice.decrypt(hb, ctb)).toEqual(msgBa);
    }
  });

  it('tampered ciphertext rejected', () => {
    const { alice, bob } = setupPair();

    const { header, ciphertext } = alice.encrypt(new TextEncoder().encode('tamper test'));
    ciphertext[0] ^= 0xff;
    expect(() => bob.decrypt(header, ciphertext)).toThrow(CairnError);
  });

  it('chacha20 cipher suite', () => {
    const { alice, bob } = setupPair({ cipher: 'chacha20-poly1305' });

    const { header, ciphertext } = alice.encrypt(new TextEncoder().encode('chacha20 test'));
    expect(bob.decrypt(header, ciphertext)).toEqual(new TextEncoder().encode('chacha20 test'));
  });

  it('empty plaintext', () => {
    const { alice, bob } = setupPair();

    const { header, ciphertext } = alice.encrypt(new Uint8Array(0));
    expect(bob.decrypt(header, ciphertext)).toEqual(new Uint8Array(0));
  });

  it('message numbers increment', () => {
    const { alice } = setupPair();

    const { header: h1 } = alice.encrypt(new TextEncoder().encode('msg0'));
    const { header: h2 } = alice.encrypt(new TextEncoder().encode('msg1'));
    const { header: h3 } = alice.encrypt(new TextEncoder().encode('msg2'));

    expect(h1.msgNum).toBe(0);
    expect(h2.msgNum).toBe(1);
    expect(h3.msgNum).toBe(2);
  });

  it('DH public key changes on ratchet', () => {
    const { alice, bob } = setupPair();

    const { header: h1, ciphertext: ct1 } = alice.encrypt(new TextEncoder().encode('from alice'));
    const alicePk1 = h1.dhPublic;
    bob.decrypt(h1, ct1);

    // Bob replies -> Alice will DH ratchet
    const { header: h2, ciphertext: ct2 } = bob.encrypt(new TextEncoder().encode('from bob'));
    alice.decrypt(h2, ct2);

    // Alice sends again -> should have a new DH key
    const { header: h3 } = alice.encrypt(new TextEncoder().encode('from alice again'));
    const alicePk2 = h3.dhPublic;

    expect(alicePk1).not.toEqual(alicePk2);
  });

  it('import state with invalid data throws CairnError', () => {
    expect(() => DoubleRatchet.importState(new TextEncoder().encode('not valid json'))).toThrow(CairnError);
  });

  it('header dhPublic is 32 bytes', () => {
    const { alice } = setupPair();
    const { header } = alice.encrypt(new TextEncoder().encode('test'));
    expect(header.dhPublic.length).toBe(32);
  });

  it('nonce construction: first 8 bytes from messageKey, last 4 from msgNum', () => {
    // Indirectly tested: messages at different msgNum positions decrypt correctly
    const { alice, bob } = setupPair();

    for (let i = 0; i < 5; i++) {
      const msg = new TextEncoder().encode(`msg ${i}`);
      const { header, ciphertext } = alice.encrypt(msg);
      expect(header.msgNum).toBe(i);
      expect(bob.decrypt(header, ciphertext)).toEqual(msg);
    }
  });
});
