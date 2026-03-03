import { encode, decode } from 'cborg';
import { CairnError, VersionMismatchError } from '../errors.js';
import { MessageEnvelope, newMsgId } from './envelope.js';
import { VERSION_NEGOTIATE } from './message-types.js';

/** Current protocol version. */
export const CURRENT_PROTOCOL_VERSION = 1;

/** All protocol versions this implementation supports, highest first. */
export const SUPPORTED_VERSIONS: readonly number[] = [1];

/** Payload for VersionNegotiate messages. */
export interface VersionNegotiatePayload {
  versions: number[];
}

/**
 * Select the highest mutually supported version.
 *
 * Returns the selected version, or throws VersionMismatchError.
 */
export function selectVersion(ourVersions: readonly number[], peerVersions: number[]): number {
  for (const v of ourVersions) {
    if (peerVersions.includes(v)) {
      return v;
    }
  }
  throw new VersionMismatchError(
    `no common protocol version: local supports [${ourVersions}], remote supports [${peerVersions}]`,
    {
      localVersions: [...ourVersions],
      remoteVersions: [...peerVersions],
      suggestion: 'update the peer with the older protocol version',
    },
  );
}

/** CBOR-encode a VersionNegotiatePayload. */
function encodePayload(payload: VersionNegotiatePayload): Uint8Array {
  try {
    return encode(payload);
  } catch (e) {
    throw new CairnError('PROTOCOL', `CBOR payload encode error: ${e}`);
  }
}

/** CBOR-decode a VersionNegotiatePayload. */
function decodePayload(data: Uint8Array): VersionNegotiatePayload {
  try {
    return decode(data) as VersionNegotiatePayload;
  } catch (e) {
    throw new CairnError('PROTOCOL', `CBOR payload decode error: ${e}`);
  }
}

/** Create a VersionNegotiate message envelope advertising our supported versions. */
export function createVersionNegotiate(): MessageEnvelope {
  const payload = encodePayload({ versions: [...SUPPORTED_VERSIONS] });
  return {
    version: CURRENT_PROTOCOL_VERSION,
    type: VERSION_NEGOTIATE,
    msgId: newMsgId(),
    payload,
  };
}

/** Parse a received VersionNegotiate envelope and extract the payload. */
export function parseVersionNegotiate(envelope: MessageEnvelope): VersionNegotiatePayload {
  if (envelope.type !== VERSION_NEGOTIATE) {
    throw new CairnError(
      'PROTOCOL',
      `expected VERSION_NEGOTIATE (0x${VERSION_NEGOTIATE.toString(16).padStart(4, '0')}), got 0x${envelope.type.toString(16).padStart(4, '0')}`,
    );
  }
  return decodePayload(envelope.payload);
}

/**
 * Process a received VersionNegotiate and produce a response.
 *
 * Returns [selectedVersion, responseEnvelope]. If incompatible, throws VersionMismatchError.
 */
export function handleVersionNegotiate(
  received: MessageEnvelope,
): [number, MessageEnvelope] {
  const peerPayload = parseVersionNegotiate(received);
  const selected = selectVersion(SUPPORTED_VERSIONS, peerPayload.versions);

  const responsePayload = encodePayload({ versions: [selected] });
  const response: MessageEnvelope = {
    version: CURRENT_PROTOCOL_VERSION,
    type: VERSION_NEGOTIATE,
    msgId: newMsgId(),
    payload: responsePayload,
  };

  return [selected, response];
}
