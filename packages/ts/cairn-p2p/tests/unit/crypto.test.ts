import { describe, it, expect } from 'vitest';
import {
  IdentityKeypair,
  peerIdFromPublicKey,
  verifySignature,
} from '../../src/crypto/identity.js';
import { X25519Keypair } from '../../src/crypto/exchange.js';
import {
  hkdfSha256,
  HKDF_INFO_SESSION_KEY,
  HKDF_INFO_RENDEZVOUS,
  HKDF_INFO_SAS,
  HKDF_INFO_CHAIN_KEY,
  HKDF_INFO_MESSAGE_KEY,
} from '../../src/crypto/hkdf.js';
import {
  aeadEncrypt,
  aeadDecrypt,
  NONCE_SIZE,
  KEY_SIZE,
  TAG_SIZE,
} from '../../src/crypto/aead.js';
import { CairnError } from '../../src/errors.js';

describe('IdentityKeypair', () => {
  it('generates and round-trips a keypair', async () => {
    const kp = await IdentityKeypair.generate();
    const secret = kp.secretBytes();
    const restored = await IdentityKeypair.fromBytes(secret);
    expect(restored.publicKey()).toEqual(kp.publicKey());
  });

  it('signs and verifies a message', async () => {
    const kp = await IdentityKeypair.generate();
    const message = new TextEncoder().encode('hello cairn');
    const sig = await kp.sign(message);
    await expect(kp.verify(message, sig)).resolves.toBeUndefined();
  });

  it('rejects verification with wrong message', async () => {
    const kp = await IdentityKeypair.generate();
    const sig = await kp.sign(new TextEncoder().encode('correct message'));
    await expect(kp.verify(new TextEncoder().encode('wrong message'), sig)).rejects.toThrow(CairnError);
  });

  it('rejects verification with wrong key', async () => {
    const kp1 = await IdentityKeypair.generate();
    const kp2 = await IdentityKeypair.generate();
    const sig = await kp1.sign(new TextEncoder().encode('hello'));
    await expect(kp2.verify(new TextEncoder().encode('hello'), sig)).rejects.toThrow(CairnError);
  });

  it('signature is 64 bytes', async () => {
    const kp = await IdentityKeypair.generate();
    const sig = await kp.sign(new TextEncoder().encode('test'));
    expect(sig.length).toBe(64);
  });

  it('signature is deterministic', async () => {
    const kp = await IdentityKeypair.generate();
    const msg = new TextEncoder().encode('deterministic');
    const sig1 = await kp.sign(msg);
    const sig2 = await kp.sign(msg);
    expect(sig1).toEqual(sig2);
  });

  it('public key is 32 bytes', async () => {
    const kp = await IdentityKeypair.generate();
    expect(kp.publicKey().length).toBe(32);
  });

  it('secret key is 32 bytes', async () => {
    const kp = await IdentityKeypair.generate();
    expect(kp.secretBytes().length).toBe(32);
  });
});

describe('peerIdFromPublicKey', () => {
  it('peer ID is deterministic', async () => {
    const kp = await IdentityKeypair.generate();
    const id1 = kp.peerId();
    const id2 = kp.peerId();
    expect(id1).toEqual(id2);
  });

  it('peer ID matches peerIdFromPublicKey', async () => {
    const kp = await IdentityKeypair.generate();
    const idFromKp = kp.peerId();
    const idFromPub = peerIdFromPublicKey(kp.publicKey());
    expect(idFromKp).toEqual(idFromPub);
  });

  it('different keys produce different peer IDs', async () => {
    const kp1 = await IdentityKeypair.generate();
    const kp2 = await IdentityKeypair.generate();
    expect(kp1.peerId()).not.toEqual(kp2.peerId());
  });

  it('peer ID is 32 bytes (SHA-256 output)', async () => {
    const kp = await IdentityKeypair.generate();
    expect(kp.peerId().length).toBe(32);
  });
});

describe('verifySignature (standalone)', () => {
  it('verifies valid signature', async () => {
    const kp = await IdentityKeypair.generate();
    const message = new TextEncoder().encode('standalone verify');
    const sig = await kp.sign(message);
    await expect(verifySignature(kp.publicKey(), message, sig)).resolves.toBeUndefined();
  });

  it('rejects tampered message', async () => {
    const kp = await IdentityKeypair.generate();
    const sig = await kp.sign(new TextEncoder().encode('original'));
    await expect(
      verifySignature(kp.publicKey(), new TextEncoder().encode('tampered'), sig),
    ).rejects.toThrow(CairnError);
  });
});

describe('X25519Keypair', () => {
  it('shared secret matches both sides', () => {
    const alice = X25519Keypair.generate();
    const bob = X25519Keypair.generate();

    const aliceShared = alice.diffieHellman(bob.publicKeyBytes());
    const bobShared = bob.diffieHellman(alice.publicKeyBytes());

    expect(aliceShared).toEqual(bobShared);
  });

  it('different peers produce different shared secrets', () => {
    const alice = X25519Keypair.generate();
    const bob = X25519Keypair.generate();
    const charlie = X25519Keypair.generate();

    const ab = alice.diffieHellman(bob.publicKeyBytes());
    const ac = alice.diffieHellman(charlie.publicKeyBytes());

    expect(ab).not.toEqual(ac);
  });

  it('public key is 32 bytes', () => {
    const kp = X25519Keypair.generate();
    expect(kp.publicKeyBytes().length).toBe(32);
  });

  it('shared secret is 32 bytes', () => {
    const alice = X25519Keypair.generate();
    const bob = X25519Keypair.generate();
    const shared = alice.diffieHellman(bob.publicKeyBytes());
    expect(shared.length).toBe(32);
  });

  it('round-trips from bytes', () => {
    const kp = X25519Keypair.generate();
    const restored = X25519Keypair.fromBytes(kp.secretBytes());
    expect(restored.publicKeyBytes()).toEqual(kp.publicKeyBytes());
  });
});

describe('HKDF-SHA256', () => {
  it('produces deterministic output', () => {
    const ikm = new TextEncoder().encode('shared-secret-material');
    const out1 = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 32);
    const out2 = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 32);
    expect(out1).toEqual(out2);
  });

  it('domain separation produces different keys', () => {
    const ikm = new TextEncoder().encode('same-input-keying-material');
    const sessionKey = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 32);
    const rendezvousKey = hkdfSha256(ikm, undefined, HKDF_INFO_RENDEZVOUS, 32);
    expect(sessionKey).not.toEqual(rendezvousKey);
  });

  it('salt changes output', () => {
    const ikm = new TextEncoder().encode('input-keying-material');
    const salt = new TextEncoder().encode('some-salt-value');
    const withSalt = hkdfSha256(ikm, salt, HKDF_INFO_SESSION_KEY, 32);
    const withoutSalt = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 32);
    expect(withSalt).not.toEqual(withoutSalt);
  });

  it('can produce various output lengths', () => {
    const ikm = new TextEncoder().encode('key-material');
    const short = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 16);
    const long = hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 64);
    expect(short.length).toBe(16);
    expect(long.length).toBe(64);
  });

  it('rejects too-long output', () => {
    const ikm = new TextEncoder().encode('key-material');
    // HKDF-SHA256 max output is 255 * 32 = 8160 bytes
    expect(() => hkdfSha256(ikm, undefined, HKDF_INFO_SESSION_KEY, 8161)).toThrow(CairnError);
  });

  it('all domain separation constants are unique', () => {
    const constants = [
      HKDF_INFO_SESSION_KEY,
      HKDF_INFO_RENDEZVOUS,
      HKDF_INFO_SAS,
      HKDF_INFO_CHAIN_KEY,
      HKDF_INFO_MESSAGE_KEY,
    ];
    const strs = constants.map((c) => new TextDecoder().decode(c));
    const unique = new Set(strs);
    expect(unique.size).toBe(constants.length);
  });
});

describe('AEAD', () => {
  function testKey(): Uint8Array {
    const key = new Uint8Array(32);
    key[0] = 0x42;
    key[31] = 0xff;
    return key;
  }

  function testNonce(): Uint8Array {
    const nonce = new Uint8Array(12);
    nonce[0] = 0x01;
    return nonce;
  }

  it('constants are correct', () => {
    expect(NONCE_SIZE).toBe(12);
    expect(KEY_SIZE).toBe(32);
    expect(TAG_SIZE).toBe(16);
  });

  describe('AES-256-GCM', () => {
    it('encrypt/decrypt round-trip', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('hello cairn aes-gcm');
      const aad = new TextEncoder().encode('associated-data');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('aes-256-gcm', key, nonce, ct, aad);

      expect(pt).toEqual(plaintext);
    });

    it('ciphertext includes tag', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('hello');
      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, new Uint8Array(0));
      expect(ct.length).toBe(plaintext.length + TAG_SIZE);
    });

    it('rejects tampered ciphertext', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('sensitive data');
      const aad = new TextEncoder().encode('aad');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);
      ct[0] ^= 0xff;

      expect(() => aeadDecrypt('aes-256-gcm', key, nonce, ct, aad)).toThrow(CairnError);
    });

    it('rejects wrong AAD', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, new TextEncoder().encode('correct-aad'));
      expect(() =>
        aeadDecrypt('aes-256-gcm', key, nonce, ct, new TextEncoder().encode('wrong-aad')),
      ).toThrow(CairnError);
    });

    it('rejects wrong key', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data');
      const aad = new TextEncoder().encode('aad');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);

      const wrongKey = new Uint8Array(key);
      wrongKey[0] ^= 0x01;
      expect(() => aeadDecrypt('aes-256-gcm', wrongKey, nonce, ct, aad)).toThrow(CairnError);
    });

    it('rejects wrong nonce', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data');
      const aad = new TextEncoder().encode('aad');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);

      const wrongNonce = new Uint8Array(nonce);
      wrongNonce[0] ^= 0x01;
      expect(() => aeadDecrypt('aes-256-gcm', key, wrongNonce, ct, aad)).toThrow(CairnError);
    });

    it('handles empty plaintext', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new Uint8Array(0);
      const aad = new TextEncoder().encode('some-context');

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('aes-256-gcm', key, nonce, ct, aad);
      expect(pt).toEqual(plaintext);
    });

    it('handles empty AAD', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data with no aad');
      const aad = new Uint8Array(0);

      const ct = aeadEncrypt('aes-256-gcm', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('aes-256-gcm', key, nonce, ct, aad);
      expect(pt).toEqual(plaintext);
    });
  });

  describe('ChaCha20-Poly1305', () => {
    it('encrypt/decrypt round-trip', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('hello cairn chacha20');
      const aad = new TextEncoder().encode('associated-data');

      const ct = aeadEncrypt('chacha20-poly1305', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('chacha20-poly1305', key, nonce, ct, aad);

      expect(pt).toEqual(plaintext);
    });

    it('ciphertext includes tag', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('hello');
      const ct = aeadEncrypt('chacha20-poly1305', key, nonce, plaintext, new Uint8Array(0));
      expect(ct.length).toBe(plaintext.length + TAG_SIZE);
    });

    it('rejects tampered ciphertext', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('sensitive data');
      const aad = new TextEncoder().encode('aad');

      const ct = aeadEncrypt('chacha20-poly1305', key, nonce, plaintext, aad);
      ct[0] ^= 0xff;

      expect(() => aeadDecrypt('chacha20-poly1305', key, nonce, ct, aad)).toThrow(CairnError);
    });

    it('rejects wrong AAD', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data');

      const ct = aeadEncrypt(
        'chacha20-poly1305', key, nonce, plaintext, new TextEncoder().encode('correct-aad'),
      );
      expect(() =>
        aeadDecrypt('chacha20-poly1305', key, nonce, ct, new TextEncoder().encode('wrong-aad')),
      ).toThrow(CairnError);
    });

    it('handles empty plaintext', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new Uint8Array(0);
      const aad = new TextEncoder().encode('some-context');

      const ct = aeadEncrypt('chacha20-poly1305', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('chacha20-poly1305', key, nonce, ct, aad);
      expect(pt).toEqual(plaintext);
    });

    it('handles empty AAD', () => {
      const key = testKey();
      const nonce = testNonce();
      const plaintext = new TextEncoder().encode('data with no aad');
      const aad = new Uint8Array(0);

      const ct = aeadEncrypt('chacha20-poly1305', key, nonce, plaintext, aad);
      const pt = aeadDecrypt('chacha20-poly1305', key, nonce, ct, aad);
      expect(pt).toEqual(plaintext);
    });
  });

  it('throws CairnError for wrong key size', () => {
    expect(() =>
      aeadEncrypt('aes-256-gcm', new Uint8Array(16), new Uint8Array(12), new Uint8Array(0), new Uint8Array(0)),
    ).toThrow(CairnError);
  });

  it('throws CairnError for wrong nonce size', () => {
    expect(() =>
      aeadEncrypt('aes-256-gcm', new Uint8Array(32), new Uint8Array(8), new Uint8Array(0), new Uint8Array(0)),
    ).toThrow(CairnError);
  });
});
