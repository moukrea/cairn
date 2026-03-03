import { CairnError } from '../errors.js';
import { hkdfSha256 } from '../crypto/hkdf.js';

/** Crockford Base32 alphabet (excludes I, L, O, U). */
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Pin code length in characters (before formatting). */
const PIN_LENGTH = 8;

/** HKDF info string for deriving the rendezvous ID from a pin code. */
const HKDF_INFO_PIN_RENDEZVOUS = new TextEncoder().encode('cairn-pin-rendezvous-v1');

/**
 * Generate a random 8-character Crockford Base32 pin code (40 bits entropy).
 * Returns the raw 8-character string (without formatting).
 */
export function generatePin(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(5)); // 40 bits
  return encodeCrockford(bytes);
}

/**
 * Format a pin code as `XXXX-XXXX`.
 */
export function formatPin(pin: string): string {
  if (pin.length === PIN_LENGTH) {
    return `${pin.slice(0, 4)}-${pin.slice(4)}`;
  }
  return pin;
}

/**
 * Normalize a pin code input: uppercase, strip separators, apply Crockford substitutions.
 *
 * - Case-insensitive (uppercased)
 * - `I`/`L` -> `1`
 * - `O` -> `0`
 * - `U` removed (Crockford excludes U)
 * - Hyphens and spaces stripped
 */
export function normalizePin(input: string): string {
  return input
    .split('')
    .filter(c => c !== '-' && c !== ' ')
    .map(c => c.toUpperCase())
    .filter(c => c !== 'U')
    .map(c => {
      if (c === 'I' || c === 'L') return '1';
      if (c === 'O') return '0';
      return c;
    })
    .join('');
}

/**
 * Validate a normalized pin code: must be 8 Crockford Base32 characters.
 */
export function validatePin(normalized: string): void {
  if (normalized.length !== PIN_LENGTH) {
    throw new CairnError('PAIRING', `expected ${PIN_LENGTH} characters, got ${normalized.length}`);
  }
  for (const ch of normalized) {
    if (!CROCKFORD_ALPHABET.includes(ch)) {
      throw new CairnError('PAIRING', `invalid Crockford character: '${ch}'`);
    }
  }
}

/**
 * Derive a 32-byte rendezvous ID from a pin code.
 * Uses HKDF-SHA256 with info="cairn-pin-rendezvous-v1".
 */
export function derivePinRendezvousId(pinBytes: Uint8Array): Uint8Array {
  return hkdfSha256(pinBytes, new Uint8Array(0), HKDF_INFO_PIN_RENDEZVOUS, 32);
}

/** Encode 5 bytes (40 bits) to 8 Crockford Base32 characters. */
function encodeCrockford(bytes: Uint8Array): string {
  // Convert 5 bytes to a 40-bit integer (using bigint for precision)
  let bits = 0n;
  for (const b of bytes) {
    bits = (bits << 8n) | BigInt(b);
  }

  // Extract 8 x 5-bit chunks from the top
  let result = '';
  for (let i = 7; i >= 0; i--) {
    const index = Number((bits >> BigInt(i * 5)) & 0x1Fn);
    result += CROCKFORD_ALPHABET[index];
  }
  return result;
}

/** Decode a Crockford Base32 string (8 chars, normalized) to 5 bytes. */
export function decodeCrockford(input: string): Uint8Array {
  if (input.length !== PIN_LENGTH) {
    throw new CairnError('PAIRING', `expected ${PIN_LENGTH} characters, got ${input.length}`);
  }

  let bits = 0n;
  for (const ch of input) {
    const idx = CROCKFORD_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new CairnError('PAIRING', `invalid Crockford character: '${ch}'`);
    }
    bits = (bits << 5n) | BigInt(idx);
  }

  // Extract 5 bytes from the 40-bit value
  const result = new Uint8Array(5);
  for (let i = 0; i < 5; i++) {
    result[i] = Number((bits >> BigInt((4 - i) * 8)) & 0xFFn);
  }
  return result;
}
