import { CairnError } from '../errors.js';
import type { PairingPayload, ConnectionHint } from './payload.js';

/** Default URI scheme. */
const DEFAULT_SCHEME = 'cairn';

/**
 * Generate a pairing link URI from a PairingPayload.
 *
 * Format: `cairn://pair?pid=<hex>&nonce=<hex>&pake=<hex>&hints=<comma-separated>&t=<created>&x=<expires>`
 *
 * Note: The spec says pid is base58. We use hex for simplicity since we don't have
 * a base58 dependency. Hints are JSON-encoded and percent-encoded in the query string.
 */
export function generatePairingLink(
  payload: PairingPayload,
  scheme: string = DEFAULT_SCHEME,
): string {
  const pid = bytesToHex(payload.peerId);
  const nonce = bytesToHex(payload.nonce);
  const pake = bytesToHex(payload.pakeCredential);

  let uri = `${scheme}://pair?pid=${pid}&nonce=${nonce}&pake=${pake}`;

  if (payload.hints && payload.hints.length > 0) {
    const hintsStr = payload.hints
      .map(h => `${h.hintType}:${h.value}`)
      .join(',');
    uri += `&hints=${encodeURIComponent(hintsStr)}`;
  }

  uri += `&t=${payload.createdAt}&x=${payload.expiresAt}`;

  return uri;
}

/**
 * Parse and validate a pairing link URI into a PairingPayload.
 */
export function parsePairingLink(
  uri: string,
  scheme: string = DEFAULT_SCHEME,
): PairingPayload {
  // Validate scheme
  if (!uri.startsWith(`${scheme}://pair?`)) {
    throw new CairnError('PAIRING', `invalid pairing link: expected ${scheme}://pair?...`);
  }

  // Extract query string
  const queryStart = uri.indexOf('?');
  if (queryStart === -1) {
    throw new CairnError('PAIRING', 'invalid pairing link: missing query string');
  }

  const params = new URLSearchParams(uri.slice(queryStart + 1));

  // pid (hex)
  const pidHex = params.get('pid');
  if (!pidHex) {
    throw new CairnError('PAIRING', "missing 'pid' parameter in pairing link");
  }
  const peerId = hexToBytes(pidHex);

  // nonce (hex)
  const nonceHex = params.get('nonce');
  if (!nonceHex) {
    throw new CairnError('PAIRING', "missing 'nonce' parameter in pairing link");
  }
  const nonce = hexToBytes(nonceHex);
  if (nonce.length !== 16) {
    throw new CairnError('PAIRING', `nonce must be 16 bytes, got ${nonce.length}`);
  }

  // pake (hex)
  const pakeHex = params.get('pake');
  if (!pakeHex) {
    throw new CairnError('PAIRING', "missing 'pake' parameter in pairing link");
  }
  const pakeCredential = hexToBytes(pakeHex);

  // hints (optional, comma-separated type:value pairs)
  let hints: ConnectionHint[] | undefined;
  const hintsStr = params.get('hints');
  if (hintsStr) {
    hints = hintsStr.split(',').map(part => {
      const colonIdx = part.indexOf(':');
      if (colonIdx === -1) {
        throw new CairnError('PAIRING', `invalid hint format: '${part}'`);
      }
      return {
        hintType: part.slice(0, colonIdx),
        value: part.slice(colonIdx + 1),
      };
    });
  }

  // timestamps
  const createdAt = parseInt(params.get('t') ?? '0', 10) || 0;
  const expiresAt = parseInt(params.get('x') ?? '0', 10) || 0;

  // Validate expiry
  const now = Math.floor(Date.now() / 1000);
  if (now > expiresAt) {
    throw new CairnError('PAIRING', 'pairing link has expired');
  }

  return { peerId, nonce, pakeCredential, hints, createdAt, expiresAt };
}

/** Convert bytes to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert hex string to bytes. */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new CairnError('PAIRING', `invalid hex string length: ${hex.length}`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
