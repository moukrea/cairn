// Protocol module — CBOR envelope encode/decode, message types, version negotiation

export type { MessageEnvelope } from './envelope.js';
export { newMsgId, encodeEnvelope, encodeEnvelopeDeterministic, decodeEnvelope } from './envelope.js';

export {
  // Pairing
  PAIR_REQUEST, PAIR_CHALLENGE, PAIR_RESPONSE, PAIR_CONFIRM, PAIR_REJECT, PAIR_REVOKE,
  // Session
  SESSION_RESUME, SESSION_RESUME_ACK, SESSION_EXPIRED, SESSION_CLOSE,
  // Data
  DATA_MESSAGE, DATA_ACK, DATA_NACK,
  // Control
  HEARTBEAT, HEARTBEAT_ACK, TRANSPORT_MIGRATE, TRANSPORT_MIGRATE_ACK,
  // Mesh
  ROUTE_REQUEST, ROUTE_RESPONSE, RELAY_DATA, RELAY_ACK,
  // Rendezvous
  RENDEZVOUS_PUBLISH, RENDEZVOUS_QUERY, RENDEZVOUS_RESPONSE,
  // Forward
  FORWARD_REQUEST, FORWARD_ACK, FORWARD_DELIVER, FORWARD_PURGE,
  // Version
  VERSION_NEGOTIATE,
  // Ranges
  CAIRN_RESERVED_START, CAIRN_RESERVED_END, APP_EXTENSION_START, APP_EXTENSION_END,
  // Helpers
  messageCategory, isApplicationType,
} from './message-types.js';

export type { VersionNegotiatePayload } from './version.js';
export {
  CURRENT_PROTOCOL_VERSION, SUPPORTED_VERSIONS,
  selectVersion, createVersionNegotiate, parseVersionNegotiate, handleVersionNegotiate,
} from './version.js';

export type { CustomMessageCallback } from './custom-handler.js';
export { CustomMessageRegistry } from './custom-handler.js';
