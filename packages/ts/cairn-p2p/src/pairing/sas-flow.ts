import { deriveNumericSas, deriveEmojiSas } from '../crypto/sas.js';

/** SAS verification type. */
export type SasType = 'numeric' | 'emoji';

/** Result of SAS derivation. */
export interface SasResult {
  type: SasType;
  /** Numeric SAS: 6-digit string. Emoji SAS: 4-emoji array joined as string. */
  display: string;
  /** For emoji SAS: the individual emoji entries. */
  emojis?: string[];
}

/**
 * Derive SAS from a Noise XX handshake transcript hash.
 *
 * Both peers compute identical SAS values from their local view of the
 * transcript. Users compare them out-of-band (verbally, visually) to
 * verify the handshake was not tampered with (MITM detection).
 *
 * @param transcriptHash - 32-byte transcript hash from Noise XX handshake
 * @param type - 'numeric' (6-digit code) or 'emoji' (4-emoji sequence)
 */
export function deriveSas(transcriptHash: Uint8Array, type: SasType): SasResult {
  if (type === 'numeric') {
    const code = deriveNumericSas(transcriptHash);
    return { type: 'numeric', display: code };
  }

  const emojis = deriveEmojiSas(transcriptHash);
  return {
    type: 'emoji',
    display: emojis.join(' '),
    emojis,
  };
}

/**
 * Verify that two SAS values match.
 * Returns true if the displayed values are identical.
 */
export function verifySas(local: SasResult, remote: SasResult): boolean {
  return local.type === remote.type && local.display === remote.display;
}
