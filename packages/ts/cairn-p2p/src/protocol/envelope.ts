import { encode, decode, rfc8949EncodeOptions } from 'cborg';
import { v7 as uuidv7, parse as uuidParse } from 'uuid';
import { CairnError } from '../errors.js';

/**
 * Wire-level message envelope for all cairn protocol messages.
 *
 * Serialized as a CBOR map with integer keys 0-5.
 */
export interface MessageEnvelope {
  /** Protocol version identifier (uint8). Initial version is 1. */
  version: number;
  /** Message type code (uint16) from the message type registry. */
  type: number;
  /** UUID v7 message ID (16 bytes), timestamp-ordered. */
  msgId: Uint8Array;
  /** Session ID (32 bytes). Absent before session establishment. */
  sessionId?: Uint8Array;
  /** Type-specific CBOR-encoded payload. */
  payload: Uint8Array;
  /** HMAC or AEAD authentication tag. Absent before key establishment. */
  authTag?: Uint8Array;
}

/**
 * Generate a new UUID v7 message ID as a 16-byte Uint8Array.
 *
 * UUID v7 provides timestamp-ordering with 74 bits of randomness per RFC 9562.
 */
export function newMsgId(): Uint8Array {
  const uuid = uuidv7();
  return new Uint8Array(uuidParse(uuid));
}

/**
 * Convert a MessageEnvelope to a CBOR-friendly Map with integer keys.
 *
 * Optional fields (sessionId, authTag) are omitted when undefined.
 */
function envelopeToMap(envelope: MessageEnvelope): Map<number, unknown> {
  const map = new Map<number, unknown>();
  map.set(0, envelope.version);
  map.set(1, envelope.type);
  map.set(2, envelope.msgId);
  if (envelope.sessionId !== undefined) {
    map.set(3, envelope.sessionId);
  }
  map.set(4, envelope.payload);
  if (envelope.authTag !== undefined) {
    map.set(5, envelope.authTag);
  }
  return map;
}

/**
 * Convert a decoded CBOR Map back to a MessageEnvelope.
 */
function mapToEnvelope(map: Map<number, unknown>): MessageEnvelope {
  const version = map.get(0);
  if (version === undefined) {
    throw new CairnError('PROTOCOL', 'missing required field: version (key 0)');
  }
  const type = map.get(1);
  if (type === undefined) {
    throw new CairnError('PROTOCOL', 'missing required field: type (key 1)');
  }
  const msgId = map.get(2);
  if (msgId === undefined) {
    throw new CairnError('PROTOCOL', 'missing required field: msgId (key 2)');
  }
  if (!(msgId instanceof Uint8Array) || msgId.length !== 16) {
    throw new CairnError('PROTOCOL', 'msgId must be 16 bytes');
  }
  const payload = map.get(4);
  if (payload === undefined) {
    throw new CairnError('PROTOCOL', 'missing required field: payload (key 4)');
  }

  const sessionId = map.get(3) as Uint8Array | undefined;
  if (sessionId !== undefined && (!(sessionId instanceof Uint8Array) || sessionId.length !== 32)) {
    throw new CairnError('PROTOCOL', 'sessionId must be 32 bytes');
  }

  const authTag = map.get(5) as Uint8Array | undefined;

  return {
    version: version as number,
    type: type as number,
    msgId: msgId as Uint8Array,
    sessionId,
    payload: payload instanceof Uint8Array ? payload : new Uint8Array(payload as ArrayBuffer),
    authTag,
  };
}

/**
 * Encode a MessageEnvelope to CBOR bytes.
 *
 * Uses integer keys (0-5) for compactness. Optional fields (sessionId, authTag)
 * are omitted entirely when undefined.
 */
export function encodeEnvelope(envelope: MessageEnvelope): Uint8Array {
  try {
    return encode(envelopeToMap(envelope));
  } catch (e) {
    throw new CairnError('PROTOCOL', `CBOR encode error: ${e}`);
  }
}

/**
 * Encode a MessageEnvelope to deterministic CBOR (RFC 8949 section 4.2).
 *
 * Keys are sorted by integer value and all values use shortest encoding.
 * Used when output will be input to a signature or HMAC computation.
 */
export function encodeEnvelopeDeterministic(envelope: MessageEnvelope): Uint8Array {
  try {
    return encode(envelopeToMap(envelope), rfc8949EncodeOptions);
  } catch (e) {
    throw new CairnError('PROTOCOL', `CBOR deterministic encode error: ${e}`);
  }
}

/**
 * Decode a MessageEnvelope from CBOR bytes.
 */
export function decodeEnvelope(data: Uint8Array): MessageEnvelope {
  try {
    const decoded = decode(data, { useMaps: true });
    if (!(decoded instanceof Map)) {
      throw new CairnError('PROTOCOL', 'expected CBOR map');
    }
    return mapToEnvelope(decoded as Map<number, unknown>);
  } catch (e) {
    if (e instanceof CairnError) throw e;
    throw new CairnError('PROTOCOL', `CBOR decode error: ${e}`);
  }
}
