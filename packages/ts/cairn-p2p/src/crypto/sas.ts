import { hkdfSha256, HKDF_INFO_SAS } from './hkdf.js';

/** Emoji table for SAS derivation (64 entries). Must match Rust exactly. */
export const EMOJI_TABLE: readonly string[] = [
  'dog', 'cat', 'fish', 'bird', 'bear', 'lion', 'wolf', 'fox',
  'deer', 'owl', 'bee', 'ant', 'star', 'moon', 'sun', 'fire',
  'tree', 'leaf', 'rose', 'wave', 'rain', 'snow', 'bolt', 'wind',
  'rock', 'gem', 'bell', 'key', 'lock', 'flag', 'book', 'pen',
  'cup', 'hat', 'shoe', 'ring', 'cake', 'gift', 'lamp', 'gear',
  'ship', 'car', 'bike', 'drum', 'horn', 'harp', 'dice', 'coin',
  'map', 'tent', 'crown', 'sword', 'shield', 'bow', 'axe', 'hammer',
  'anchor', 'wheel', 'clock', 'heart', 'skull', 'ghost', 'robot', 'alien',
];

/**
 * Derive a 6-digit numeric SAS from the handshake transcript hash.
 *
 * Uses HKDF-SHA256 with the SAS domain separation info to derive 4 bytes,
 * then computes `u32 % 1_000_000` formatted as zero-padded 6 digits.
 */
export function deriveNumericSas(transcriptHash: Uint8Array): string {
  const derived = hkdfSha256(transcriptHash, undefined, HKDF_INFO_SAS, 4);
  const view = new DataView(derived.buffer, derived.byteOffset, derived.byteLength);
  const value = view.getUint32(0) % 1_000_000;
  return value.toString().padStart(6, '0');
}

/**
 * Derive an emoji SAS (sequence of 4 emoji names) from the handshake transcript hash.
 *
 * Uses HKDF-SHA256 to derive 4 bytes, then indexes into the 64-entry emoji table.
 */
export function deriveEmojiSas(transcriptHash: Uint8Array): string[] {
  const derived = hkdfSha256(transcriptHash, undefined, HKDF_INFO_SAS, 4);
  return Array.from(derived).map((b) => EMOJI_TABLE[b % 64]);
}
