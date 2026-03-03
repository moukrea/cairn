import { gcm } from '@noble/ciphers/aes';
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305';
import { CairnError } from '../errors.js';
import type { CipherSuite } from '../config.js';

/** Nonce size for both ciphers: 12 bytes. */
export const NONCE_SIZE = 12;
/** Key size for both ciphers: 32 bytes. */
export const KEY_SIZE = 32;
/** Authentication tag size for both ciphers: 16 bytes. */
export const TAG_SIZE = 16;

/**
 * Encrypt plaintext with associated data using the specified cipher.
 *
 * Returns ciphertext with appended authentication tag.
 */
export function aeadEncrypt(
  cipher: CipherSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_SIZE) {
    throw new CairnError('CRYPTO', `AEAD key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new CairnError('CRYPTO', `AEAD nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  try {
    if (cipher === 'aes-256-gcm') {
      const aes = gcm(key, nonce, aad);
      return aes.encrypt(plaintext);
    } else {
      const chacha = new ChaCha20Poly1305(key);
      return chacha.seal(nonce, plaintext, aad);
    }
  } catch (e) {
    throw new CairnError('CRYPTO', `AEAD encrypt error: ${e}`);
  }
}

/**
 * Decrypt ciphertext with associated data using the specified cipher.
 *
 * Returns plaintext on success. Throws CairnError if authentication fails.
 */
export function aeadDecrypt(
  cipher: CipherSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_SIZE) {
    throw new CairnError('CRYPTO', `AEAD key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new CairnError('CRYPTO', `AEAD nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  try {
    if (cipher === 'aes-256-gcm') {
      const aes = gcm(key, nonce, aad);
      return aes.decrypt(ciphertext);
    } else {
      const chacha = new ChaCha20Poly1305(key);
      const result = chacha.open(nonce, ciphertext, aad);
      if (result === null) {
        throw new CairnError('CRYPTO', 'ChaCha20-Poly1305 authentication failed');
      }
      return result;
    }
  } catch (e) {
    if (e instanceof CairnError) throw e;
    throw new CairnError('CRYPTO', `AEAD decrypt error: ${e}`);
  }
}
