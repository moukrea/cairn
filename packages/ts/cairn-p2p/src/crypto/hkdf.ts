import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { CairnError } from '../errors.js';

// Domain separation info strings for HKDF derivations.
// Must match Rust constants exactly.
const encoder = new TextEncoder();
export const HKDF_INFO_SESSION_KEY = encoder.encode('cairn-session-key-v1');
export const HKDF_INFO_RENDEZVOUS = encoder.encode('cairn-rendezvous-id-v1');
export const HKDF_INFO_SAS = encoder.encode('cairn-sas-derivation-v1');
export const HKDF_INFO_CHAIN_KEY = encoder.encode('cairn-chain-key-v1');
export const HKDF_INFO_MESSAGE_KEY = encoder.encode('cairn-message-key-v1');

/**
 * Derive key material from input keying material using HKDF-SHA256 (RFC 5869).
 *
 * @param ikm - input keying material (e.g., DH shared secret)
 * @param salt - optional salt (undefined uses zero-filled salt)
 * @param info - context-specific info string for domain separation
 * @param length - number of bytes to derive
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array,
  length: number,
): Uint8Array {
  try {
    return hkdf(sha256, ikm, salt, info, length);
  } catch (e) {
    throw new CairnError('CRYPTO', `HKDF-SHA256 error: ${e}`);
  }
}
