import { CairnError } from '../errors.js';
import type { PairingPayload } from './payload.js';
import { encodePairingPayload, decodePairingPayload } from './payload.js';

/** Maximum payload size for QR code encoding (256 bytes). */
const MAX_QR_PAYLOAD_SIZE = 256;

/** Default TTL for QR code pairing payloads (5 minutes). */
const DEFAULT_TTL_MS = 300_000;

/**
 * Generate a QR code pairing payload as raw CBOR bytes.
 *
 * The caller can render this into a QR code using any library.
 * Uses binary CBOR encoding, EC Level M, max 256 bytes.
 */
export function generateQrPayload(payload: PairingPayload): Uint8Array {
  const cbor = encodePairingPayload(payload);
  if (cbor.length > MAX_QR_PAYLOAD_SIZE) {
    throw new CairnError(
      'PAIRING',
      `QR payload exceeds max size: ${cbor.length} > ${MAX_QR_PAYLOAD_SIZE} bytes`,
    );
  }
  return cbor;
}

/**
 * Decode and validate a QR code pairing payload from raw CBOR bytes.
 */
export function consumeQrPayload(raw: Uint8Array): PairingPayload {
  if (raw.length > MAX_QR_PAYLOAD_SIZE) {
    throw new CairnError(
      'PAIRING',
      `QR payload exceeds max size: ${raw.length} > ${MAX_QR_PAYLOAD_SIZE} bytes`,
    );
  }

  const payload = decodePairingPayload(raw);

  const now = Math.floor(Date.now() / 1000);
  if (now > payload.expiresAt) {
    throw new CairnError('PAIRING', 'QR pairing payload has expired');
  }

  return payload;
}

/** Default TTL in milliseconds for QR pairing. */
export { DEFAULT_TTL_MS as QR_DEFAULT_TTL_MS };
/** Maximum payload size for QR code. */
export { MAX_QR_PAYLOAD_SIZE };
