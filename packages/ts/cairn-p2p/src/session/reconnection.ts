/**
 * Session resumption proof generation and verification.
 *
 * Used by the SESSION_RESUME protocol to prove that a reconnecting
 * peer previously held a valid session without replaying old data.
 *
 * The proof is HMAC-SHA256(resumptionKey, nonce || timestamp_be || sessionId).
 */

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { CairnError } from '../errors.js';

/**
 * Generate a resume proof for a SESSION_RESUME message.
 *
 * @param resumptionKey - 32 bytes from DoubleRatchet.deriveResumptionKey()
 * @param sessionId - 16-byte session identifier
 * @param nonce - 16-byte random nonce (freshness)
 * @param timestamp - Unix timestamp in seconds
 * @returns 32-byte HMAC-SHA256 proof
 */
export function generateResumeProof(
  resumptionKey: Uint8Array,
  sessionId: Uint8Array,
  nonce: Uint8Array,
  timestamp: number,
): Uint8Array {
  if (resumptionKey.length !== 32) {
    throw new CairnError('CRYPTO', 'resumption key must be 32 bytes');
  }
  if (sessionId.length !== 16) {
    throw new CairnError('CRYPTO', 'session ID must be 16 bytes');
  }
  if (nonce.length !== 16) {
    throw new CairnError('CRYPTO', 'nonce must be 16 bytes');
  }

  const message = buildProofMessage(nonce, timestamp, sessionId);
  return hmac(sha256, resumptionKey, message);
}

/**
 * Verify a resume proof received in a SESSION_RESUME message.
 *
 * @param resumptionKey - 32 bytes from DoubleRatchet.deriveResumptionKey()
 * @param sessionId - 16-byte session identifier
 * @param nonce - 16-byte nonce from the resume message
 * @param timestamp - Unix timestamp from the resume message
 * @param proof - 32-byte HMAC proof to verify
 * @returns true if the proof is valid
 */
export function verifyResumeProof(
  resumptionKey: Uint8Array,
  sessionId: Uint8Array,
  nonce: Uint8Array,
  timestamp: number,
  proof: Uint8Array,
): boolean {
  if (proof.length !== 32) return false;

  try {
    const expected = generateResumeProof(resumptionKey, sessionId, nonce, timestamp);
    return timingSafeEqual(expected, proof);
  } catch {
    return false;
  }
}

/**
 * Build the message to be HMAC'd: nonce || timestamp_be_bytes || sessionId
 */
function buildProofMessage(
  nonce: Uint8Array,
  timestamp: number,
  sessionId: Uint8Array,
): Uint8Array {
  // nonce (16) + timestamp big-endian (8) + sessionId (16) = 40 bytes
  const msg = new Uint8Array(16 + 8 + 16);
  msg.set(nonce, 0);

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  // Write timestamp as 64-bit big-endian (split into two 32-bit writes)
  view.setUint32(16, Math.floor(timestamp / 0x100000000));
  view.setUint32(20, timestamp >>> 0);

  msg.set(sessionId, 24);
  return msg;
}

/**
 * Constant-time comparison of two byte arrays.
 *
 * Prevents timing side channels when comparing HMAC values.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}
