import { describe, it, expect } from 'vitest';
import {
  type MessageEnvelope,
  newMsgId,
  encodeEnvelope,
  encodeEnvelopeDeterministic,
  decodeEnvelope,
  PAIR_REQUEST,
  PAIR_CHALLENGE,
  PAIR_RESPONSE,
  PAIR_CONFIRM,
  PAIR_REJECT,
  PAIR_REVOKE,
  SESSION_RESUME,
  SESSION_RESUME_ACK,
  SESSION_EXPIRED,
  SESSION_CLOSE,
  DATA_MESSAGE,
  DATA_ACK,
  DATA_NACK,
  HEARTBEAT,
  HEARTBEAT_ACK,
  TRANSPORT_MIGRATE,
  TRANSPORT_MIGRATE_ACK,
  ROUTE_REQUEST,
  ROUTE_RESPONSE,
  RELAY_DATA,
  RELAY_ACK,
  RENDEZVOUS_PUBLISH,
  RENDEZVOUS_QUERY,
  RENDEZVOUS_RESPONSE,
  FORWARD_REQUEST,
  FORWARD_ACK,
  FORWARD_DELIVER,
  FORWARD_PURGE,
  VERSION_NEGOTIATE,
  APP_EXTENSION_START,
  APP_EXTENSION_END,
  messageCategory,
  isApplicationType,
  CURRENT_PROTOCOL_VERSION,
  SUPPORTED_VERSIONS,
  selectVersion,
  createVersionNegotiate,
  parseVersionNegotiate,
  handleVersionNegotiate,
} from '../../src/protocol/index.js';
import { CustomMessageRegistry } from '../../src/protocol/index.js';
import { CairnError, VersionMismatchError } from '../../src/errors.js';

describe('newMsgId', () => {
  it('generates a 16-byte Uint8Array', () => {
    const id = newMsgId();
    expect(id).toBeInstanceOf(Uint8Array);
    expect(id.length).toBe(16);
  });

  it('generates unique IDs', () => {
    const id1 = newMsgId();
    const id2 = newMsgId();
    expect(id1).not.toEqual(id2);
  });
});

describe('MessageEnvelope round-trip', () => {
  it('encodes and decodes a minimal envelope', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: HEARTBEAT,
      msgId: newMsgId(),
      payload: new Uint8Array([]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.version).toBe(envelope.version);
    expect(decoded.type).toBe(envelope.type);
    expect(decoded.msgId).toEqual(envelope.msgId);
    expect(decoded.payload).toEqual(envelope.payload);
    expect(decoded.sessionId).toBeUndefined();
    expect(decoded.authTag).toBeUndefined();
  });

  it('encodes and decodes a full envelope with all optional fields', () => {
    const sessionId = new Uint8Array(32).fill(0xab);
    const envelope: MessageEnvelope = {
      version: 1,
      type: DATA_MESSAGE,
      msgId: newMsgId(),
      sessionId,
      payload: new Uint8Array([0xca, 0xfe, 0xba, 0xbe]),
      authTag: new Uint8Array([0xde, 0xad]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.version).toBe(1);
    expect(decoded.type).toBe(DATA_MESSAGE);
    expect(decoded.msgId).toEqual(envelope.msgId);
    expect(decoded.sessionId).toEqual(sessionId);
    expect(decoded.payload).toEqual(envelope.payload);
    expect(decoded.authTag).toEqual(envelope.authTag);
  });

  it('omits optional fields when undefined', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: PAIR_REQUEST,
      msgId: newMsgId(),
      payload: new Uint8Array([0x01]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);
    expect(decoded.sessionId).toBeUndefined();
    expect(decoded.authTag).toBeUndefined();
  });

  it('preserves version field values', () => {
    for (const v of [0, 1, 255]) {
      const envelope: MessageEnvelope = {
        version: v,
        type: HEARTBEAT,
        msgId: new Uint8Array(16),
        payload: new Uint8Array([]),
      };
      const decoded = decodeEnvelope(encodeEnvelope(envelope));
      expect(decoded.version).toBe(v);
    }
  });
});

describe('deterministic encoding', () => {
  it('produces stable output across multiple calls', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: HEARTBEAT,
      msgId: new Uint8Array(16).fill(1),
      sessionId: new Uint8Array(32).fill(2),
      payload: new Uint8Array([0xff]),
      authTag: new Uint8Array([0x00, 0x01]),
    };

    const enc1 = encodeEnvelopeDeterministic(envelope);
    const enc2 = encodeEnvelopeDeterministic(envelope);
    expect(enc1).toEqual(enc2);
  });

  it('deterministic output decodes correctly', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: DATA_MESSAGE,
      msgId: newMsgId(),
      payload: new Uint8Array([0xaa, 0xbb]),
    };

    const encoded = encodeEnvelopeDeterministic(envelope);
    const decoded = decodeEnvelope(encoded);
    expect(decoded.version).toBe(envelope.version);
    expect(decoded.type).toBe(envelope.type);
    expect(decoded.msgId).toEqual(envelope.msgId);
    expect(decoded.payload).toEqual(envelope.payload);
  });
});

describe('decode errors', () => {
  it('rejects invalid CBOR', () => {
    expect(() => decodeEnvelope(new Uint8Array([0xff, 0xff, 0xff]))).toThrow(CairnError);
  });

  it('rejects envelope missing version field', async () => {
    // Encode a map without key 0 (version)
    const { encode } = await import('cborg');
    const map = new Map<number, unknown>();
    map.set(1, HEARTBEAT);
    map.set(2, new Uint8Array(16));
    map.set(4, new Uint8Array([]));
    const bytes = encode(map);
    expect(() => decodeEnvelope(bytes)).toThrow('version');
  });
});

describe('message type constants', () => {
  it('pairing types are in 0x01xx range', () => {
    for (const t of [PAIR_REQUEST, PAIR_CHALLENGE, PAIR_RESPONSE, PAIR_CONFIRM, PAIR_REJECT, PAIR_REVOKE]) {
      expect(t).toBeGreaterThanOrEqual(0x0100);
      expect(t).toBeLessThanOrEqual(0x01ff);
    }
  });

  it('session types are in 0x02xx range', () => {
    for (const t of [SESSION_RESUME, SESSION_RESUME_ACK, SESSION_EXPIRED, SESSION_CLOSE]) {
      expect(t).toBeGreaterThanOrEqual(0x0200);
      expect(t).toBeLessThanOrEqual(0x02ff);
    }
  });

  it('data types are in 0x03xx range', () => {
    for (const t of [DATA_MESSAGE, DATA_ACK, DATA_NACK]) {
      expect(t).toBeGreaterThanOrEqual(0x0300);
      expect(t).toBeLessThanOrEqual(0x03ff);
    }
  });

  it('control types are in 0x04xx range', () => {
    for (const t of [HEARTBEAT, HEARTBEAT_ACK, TRANSPORT_MIGRATE, TRANSPORT_MIGRATE_ACK]) {
      expect(t).toBeGreaterThanOrEqual(0x0400);
      expect(t).toBeLessThanOrEqual(0x04ff);
    }
  });

  it('mesh types are in 0x05xx range', () => {
    for (const t of [ROUTE_REQUEST, ROUTE_RESPONSE, RELAY_DATA, RELAY_ACK]) {
      expect(t).toBeGreaterThanOrEqual(0x0500);
      expect(t).toBeLessThanOrEqual(0x05ff);
    }
  });

  it('rendezvous types are in 0x06xx range', () => {
    for (const t of [RENDEZVOUS_PUBLISH, RENDEZVOUS_QUERY, RENDEZVOUS_RESPONSE]) {
      expect(t).toBeGreaterThanOrEqual(0x0600);
      expect(t).toBeLessThanOrEqual(0x06ff);
    }
  });

  it('forward types are in 0x07xx range', () => {
    for (const t of [FORWARD_REQUEST, FORWARD_ACK, FORWARD_DELIVER, FORWARD_PURGE]) {
      expect(t).toBeGreaterThanOrEqual(0x0700);
      expect(t).toBeLessThanOrEqual(0x07ff);
    }
  });

  it('VERSION_NEGOTIATE is 0x0001', () => {
    expect(VERSION_NEGOTIATE).toBe(0x0001);
  });

  it('application range is 0xF000-0xFFFF', () => {
    expect(APP_EXTENSION_START).toBe(0xf000);
    expect(APP_EXTENSION_END).toBe(0xffff);
  });
});

describe('messageCategory', () => {
  it('categorizes all message types correctly', () => {
    expect(messageCategory(VERSION_NEGOTIATE)).toBe('version');
    expect(messageCategory(PAIR_REQUEST)).toBe('pairing');
    expect(messageCategory(PAIR_REVOKE)).toBe('pairing');
    expect(messageCategory(SESSION_RESUME)).toBe('session');
    expect(messageCategory(SESSION_CLOSE)).toBe('session');
    expect(messageCategory(DATA_MESSAGE)).toBe('data');
    expect(messageCategory(DATA_NACK)).toBe('data');
    expect(messageCategory(HEARTBEAT)).toBe('control');
    expect(messageCategory(TRANSPORT_MIGRATE_ACK)).toBe('control');
    expect(messageCategory(ROUTE_REQUEST)).toBe('mesh');
    expect(messageCategory(RELAY_ACK)).toBe('mesh');
    expect(messageCategory(RENDEZVOUS_PUBLISH)).toBe('rendezvous');
    expect(messageCategory(RENDEZVOUS_RESPONSE)).toBe('rendezvous');
    expect(messageCategory(FORWARD_REQUEST)).toBe('forward');
    expect(messageCategory(FORWARD_PURGE)).toBe('forward');
    expect(messageCategory(0xf000)).toBe('application');
    expect(messageCategory(0xffff)).toBe('application');
    expect(messageCategory(0x0800)).toBe('reserved');
  });
});

describe('isApplicationType', () => {
  it('returns true for application range', () => {
    expect(isApplicationType(0xf000)).toBe(true);
    expect(isApplicationType(0xf123)).toBe(true);
    expect(isApplicationType(0xffff)).toBe(true);
  });

  it('returns false for non-application types', () => {
    expect(isApplicationType(HEARTBEAT)).toBe(false);
    expect(isApplicationType(PAIR_REQUEST)).toBe(false);
    expect(isApplicationType(0xefff)).toBe(false);
  });
});

describe('version negotiation', () => {
  it('CURRENT_PROTOCOL_VERSION is 1', () => {
    expect(CURRENT_PROTOCOL_VERSION).toBe(1);
  });

  it('SUPPORTED_VERSIONS contains current version', () => {
    expect(SUPPORTED_VERSIONS).toContain(CURRENT_PROTOCOL_VERSION);
  });

  it('SUPPORTED_VERSIONS is ordered highest first', () => {
    for (let i = 1; i < SUPPORTED_VERSIONS.length; i++) {
      expect(SUPPORTED_VERSIONS[i - 1]).toBeGreaterThanOrEqual(SUPPORTED_VERSIONS[i]);
    }
  });

  describe('selectVersion', () => {
    it('selects highest common version', () => {
      expect(selectVersion([3, 2, 1], [2, 1])).toBe(2);
    });

    it('selects exact match', () => {
      expect(selectVersion([1], [1])).toBe(1);
    });

    it('picks highest mutual', () => {
      expect(selectVersion([5, 3, 1], [4, 3, 2, 1])).toBe(3);
    });

    it('throws VersionMismatchError when no common version', () => {
      expect(() => selectVersion([3, 2], [5, 4])).toThrow(VersionMismatchError);
    });

    it('throws on empty ours', () => {
      expect(() => selectVersion([], [1])).toThrow(VersionMismatchError);
    });

    it('throws on empty peer', () => {
      expect(() => selectVersion([1], [])).toThrow(VersionMismatchError);
    });
  });

  describe('createVersionNegotiate', () => {
    it('creates a valid envelope', () => {
      const envelope = createVersionNegotiate();
      expect(envelope.version).toBe(CURRENT_PROTOCOL_VERSION);
      expect(envelope.type).toBe(VERSION_NEGOTIATE);
      expect(envelope.sessionId).toBeUndefined();
      expect(envelope.authTag).toBeUndefined();

      const payload = parseVersionNegotiate(envelope);
      expect(payload.versions).toEqual([...SUPPORTED_VERSIONS]);
    });
  });

  describe('parseVersionNegotiate', () => {
    it('rejects wrong message type', () => {
      const envelope: MessageEnvelope = {
        version: 1,
        type: PAIR_REQUEST,
        msgId: newMsgId(),
        payload: new Uint8Array([]),
      };
      expect(() => parseVersionNegotiate(envelope)).toThrow(CairnError);
    });
  });

  describe('handleVersionNegotiate', () => {
    it('handles compatible versions', () => {
      const initiator = createVersionNegotiate();
      const [selected, response] = handleVersionNegotiate(initiator);
      expect(selected).toBe(1);
      expect(response.type).toBe(VERSION_NEGOTIATE);

      const respPayload = parseVersionNegotiate(response);
      expect(respPayload.versions).toEqual([1]);
    });

    it('rejects incompatible versions', async () => {
      const { encode } = await import('cborg');
      const payload = encode({ versions: [99] });
      const envelope: MessageEnvelope = {
        version: 99,
        type: VERSION_NEGOTIATE,
        msgId: newMsgId(),
        payload,
      };
      expect(() => handleVersionNegotiate(envelope)).toThrow(VersionMismatchError);
    });
  });

  describe('full negotiation roundtrip', () => {
    it('works end-to-end over the wire', () => {
      // Alice initiates
      const aliceOffer = createVersionNegotiate();
      const aliceWire = encodeEnvelope(aliceOffer);

      // Bob receives and responds
      const bobReceived = decodeEnvelope(aliceWire);
      const [selected, bobResponse] = handleVersionNegotiate(bobReceived);
      expect(selected).toBe(1);
      const bobWire = encodeEnvelope(bobResponse);

      // Alice processes response
      const aliceReceived = decodeEnvelope(bobWire);
      const respPayload = parseVersionNegotiate(aliceReceived);
      expect(respPayload.versions).toEqual([1]);
    });
  });
});

describe('CustomMessageRegistry', () => {
  it('registers and dispatches handlers for application types', () => {
    const registry = new CustomMessageRegistry();
    const received: Uint8Array[] = [];
    registry.onCustomMessage(0xf000, (payload) => received.push(payload));

    const data = new Uint8Array([0x01, 0x02]);
    const dispatched = registry.dispatch(0xf000, data);

    expect(dispatched).toBe(true);
    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(data);
  });

  it('supports multiple handlers for the same type', () => {
    const registry = new CustomMessageRegistry();
    let count = 0;
    registry.onCustomMessage(0xf001, () => count++);
    registry.onCustomMessage(0xf001, () => count++);

    registry.dispatch(0xf001, new Uint8Array([]));
    expect(count).toBe(2);
  });

  it('returns false when no handler is registered', () => {
    const registry = new CustomMessageRegistry();
    expect(registry.dispatch(0xf000, new Uint8Array([]))).toBe(false);
  });

  it('throws CairnError for type codes below application range', () => {
    const registry = new CustomMessageRegistry();
    expect(() => registry.onCustomMessage(0xefff, () => {})).toThrow(CairnError);
    expect(() => registry.onCustomMessage(HEARTBEAT, () => {})).toThrow(CairnError);
  });

  it('throws CairnError for type codes above application range', () => {
    const registry = new CustomMessageRegistry();
    // 0x10000 is out of uint16 range
    expect(() => registry.onCustomMessage(0x10000, () => {})).toThrow(CairnError);
  });

  it('accepts boundary values of application range', () => {
    const registry = new CustomMessageRegistry();
    expect(() => registry.onCustomMessage(0xf000, () => {})).not.toThrow();
    expect(() => registry.onCustomMessage(0xffff, () => {})).not.toThrow();
  });
});
