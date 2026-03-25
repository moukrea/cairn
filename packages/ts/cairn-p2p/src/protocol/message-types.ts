// Pairing (0x01xx)
export const PAIR_REQUEST = 0x0100;
export const PAIR_CHALLENGE = 0x0101;
export const PAIR_RESPONSE = 0x0102;
export const PAIR_CONFIRM = 0x0103;
export const PAIR_REJECT = 0x0104;
export const PAIR_REVOKE = 0x0105;

// Handshake (0x01Ex) — Noise XX over transport
export const HANDSHAKE_INIT = 0x01e0;
export const HANDSHAKE_RESPONSE = 0x01e1;
export const HANDSHAKE_FINISH = 0x01e2;
export const HANDSHAKE_ACK = 0x01e3;

// Session (0x02xx)
export const SESSION_RESUME = 0x0200;
export const SESSION_RESUME_ACK = 0x0201;
export const SESSION_EXPIRED = 0x0202;
export const SESSION_CLOSE = 0x0203;

// Data (0x03xx)
export const DATA_MESSAGE = 0x0300;
export const DATA_ACK = 0x0301;
export const DATA_NACK = 0x0302;

// Control (0x04xx)
export const HEARTBEAT = 0x0400;
export const HEARTBEAT_ACK = 0x0401;
export const TRANSPORT_MIGRATE = 0x0402;
export const TRANSPORT_MIGRATE_ACK = 0x0403;

// Mesh (0x05xx)
export const ROUTE_REQUEST = 0x0500;
export const ROUTE_RESPONSE = 0x0501;
export const RELAY_DATA = 0x0502;
export const RELAY_ACK = 0x0503;

// Rendezvous (0x06xx)
export const RENDEZVOUS_PUBLISH = 0x0600;
export const RENDEZVOUS_QUERY = 0x0601;
export const RENDEZVOUS_RESPONSE = 0x0602;

// Forward (0x07xx)
export const FORWARD_REQUEST = 0x0700;
export const FORWARD_ACK = 0x0701;
export const FORWARD_DELIVER = 0x0702;
export const FORWARD_PURGE = 0x0703;

// Version negotiation
export const VERSION_NEGOTIATE = 0x0001;

// Reserved ranges
export const CAIRN_RESERVED_START = 0x0100;
export const CAIRN_RESERVED_END = 0xefff;
export const APP_EXTENSION_START = 0xf000;
export const APP_EXTENSION_END = 0xffff;

/**
 * Returns the category name for a given message type code.
 */
export function messageCategory(msgType: number): string {
  if (msgType === 0x0001) return 'version';
  if (msgType >= 0x0100 && msgType <= 0x01ff) return 'pairing';
  if (msgType >= 0x0200 && msgType <= 0x02ff) return 'session';
  if (msgType >= 0x0300 && msgType <= 0x03ff) return 'data';
  if (msgType >= 0x0400 && msgType <= 0x04ff) return 'control';
  if (msgType >= 0x0500 && msgType <= 0x05ff) return 'mesh';
  if (msgType >= 0x0600 && msgType <= 0x06ff) return 'rendezvous';
  if (msgType >= 0x0700 && msgType <= 0x07ff) return 'forward';
  if (msgType >= 0x0800 && msgType <= 0xefff) return 'reserved';
  if (msgType >= APP_EXTENSION_START && msgType <= APP_EXTENSION_END) return 'application';
  return 'reserved';
}

/**
 * Returns true if the given type code is in the application extension range.
 */
export function isApplicationType(msgType: number): boolean {
  return msgType >= APP_EXTENSION_START && msgType <= APP_EXTENSION_END;
}

/**
 * Returns true if the given type code is a Noise XX handshake message.
 */
export function isHandshakeType(msgType: number): boolean {
  return msgType >= HANDSHAKE_INIT && msgType <= HANDSHAKE_ACK;
}
