import { CairnError } from '../errors.js';
import { hkdfSha256 } from '../crypto/hkdf.js';

/** HKDF info string for PSK rendezvous ID derivation. Must match Rust. */
const HKDF_INFO_PSK_RENDEZVOUS = new TextEncoder().encode('cairn-psk-rendezvous-v1');

/** Default minimum entropy in bytes (128 bits). */
const DEFAULT_MIN_ENTROPY_BYTES = 16;

/**
 * Validate that a pre-shared key has sufficient entropy.
 *
 * @param psk - the pre-shared key bytes
 * @param minBytes - minimum length in bytes (default: 16 = 128 bits)
 */
export function validatePskEntropy(
  psk: Uint8Array,
  minBytes: number = DEFAULT_MIN_ENTROPY_BYTES,
): void {
  if (psk.length === 0) {
    throw new CairnError('PAIRING', 'empty pre-shared key');
  }
  if (psk.length < minBytes) {
    throw new CairnError(
      'PAIRING',
      `insufficient PSK entropy: got ${psk.length} bytes, need at least ${minBytes} bytes (${minBytes * 8} bits)`,
    );
  }
}

/**
 * Derive a 32-byte rendezvous ID from a pre-shared key.
 *
 * Uses HKDF-SHA256 with info="cairn-psk-rendezvous-v1".
 */
export function derivePskRendezvousId(psk: Uint8Array): Uint8Array {
  validatePskEntropy(psk);
  return hkdfSha256(psk, undefined, HKDF_INFO_PSK_RENDEZVOUS, 32);
}

/**
 * Get the SPAKE2 password input from a PSK.
 * The PSK is used directly as the SPAKE2 password bytes.
 */
export function pskToPakeInput(psk: Uint8Array | string): Uint8Array {
  const bytes = typeof psk === 'string' ? new TextEncoder().encode(psk) : psk;
  validatePskEntropy(bytes);
  return bytes;
}
