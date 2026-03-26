import { describe, it, expect } from 'vitest';
import {
  CAIRN_PROTOCOL,
  encodeFrame,
  decodeFrame,
  readFrame,
} from '../../src/transport/libp2p-node.js';
import {
  HANDSHAKE_INIT,
  HANDSHAKE_RESPONSE,
  HANDSHAKE_FINISH,
  HANDSHAKE_ACK,
  isHandshakeType,
  DATA_MESSAGE,
} from '../../src/protocol/message-types.js';
import { encodeEnvelope, decodeEnvelope, newMsgId } from '../../src/protocol/envelope.js';
import type { MessageEnvelope } from '../../src/protocol/envelope.js';
import { Node, NodeSession } from '../../src/node.js';
import { IdentityKeypair } from '../../src/crypto/identity.js';
import { NoiseXXHandshake } from '../../src/crypto/noise.js';
import { X25519Keypair } from '../../src/crypto/exchange.js';
import { DoubleRatchet } from '../../src/crypto/double-ratchet.js';

// --- Cairn protocol constant ---

describe('CAIRN_PROTOCOL', () => {
  it('has the expected value', () => {
    expect(CAIRN_PROTOCOL).toBe('/cairn/1.0.0');
  });
});

// --- Handshake message type constants ---

describe('handshake message types', () => {
  it('has correct hex values matching Rust', () => {
    expect(HANDSHAKE_INIT).toBe(0x01e0);
    expect(HANDSHAKE_RESPONSE).toBe(0x01e1);
    expect(HANDSHAKE_FINISH).toBe(0x01e2);
    expect(HANDSHAKE_ACK).toBe(0x01e3);
  });

  it('isHandshakeType correctly classifies', () => {
    expect(isHandshakeType(HANDSHAKE_INIT)).toBe(true);
    expect(isHandshakeType(HANDSHAKE_RESPONSE)).toBe(true);
    expect(isHandshakeType(HANDSHAKE_FINISH)).toBe(true);
    expect(isHandshakeType(HANDSHAKE_ACK)).toBe(true);
    expect(isHandshakeType(DATA_MESSAGE)).toBe(false);
    expect(isHandshakeType(0x0100)).toBe(false);
  });
});

// --- Length-prefixed framing ---

describe('encodeFrame / decodeFrame', () => {
  it('round-trips a simple payload', () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const frame = encodeFrame(payload);
    expect(frame.length).toBe(4 + 5);

    // Check length prefix is big-endian
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    expect(view.getUint32(0)).toBe(5);

    const decoded = decodeFrame(frame);
    expect(decoded).toEqual(payload);
  });

  it('round-trips an empty payload', () => {
    const payload = new Uint8Array(0);
    const frame = encodeFrame(payload);
    expect(frame.length).toBe(4);
    const decoded = decodeFrame(frame);
    expect(decoded.length).toBe(0);
  });

  it('round-trips a CBOR-encoded envelope', () => {
    const envelope: MessageEnvelope = {
      version: 1,
      type: DATA_MESSAGE,
      msgId: newMsgId(),
      payload: new TextEncoder().encode('hello cairn'),
    };
    const cborBytes = encodeEnvelope(envelope);
    const frame = encodeFrame(cborBytes);
    const decoded = decodeFrame(frame);
    const recoveredEnvelope = decodeEnvelope(decoded);
    expect(recoveredEnvelope.version).toBe(1);
    expect(recoveredEnvelope.type).toBe(DATA_MESSAGE);
    expect(new TextDecoder().decode(recoveredEnvelope.payload)).toBe('hello cairn');
  });

  it('rejects truncated frame (missing length prefix)', () => {
    expect(() => decodeFrame(new Uint8Array([1, 2]))).toThrow('frame too short');
  });

  it('rejects truncated frame (incomplete payload)', () => {
    const frame = new Uint8Array(8);
    const view = new DataView(frame.buffer);
    view.setUint32(0, 100); // claims 100 bytes but only 4 available
    expect(() => decodeFrame(frame)).toThrow('frame truncated');
  });

  it('rejects oversized frame', () => {
    const frame = new Uint8Array(8);
    const view = new DataView(frame.buffer);
    view.setUint32(0, 2_000_000); // > 1 MiB
    expect(() => decodeFrame(frame)).toThrow('frame too large');
  });
});

// --- readFrame from async iterable ---

describe('readFrame', () => {
  /** Create an async iterable from an array of Uint8Array chunks. */
  async function* chunkedSource(chunks: Uint8Array[]): AsyncIterable<Uint8Array> {
    for (const chunk of chunks) {
      yield chunk;
    }
  }

  it('reads a single-chunk frame', async () => {
    const payload = new Uint8Array([10, 20, 30]);
    const frame = encodeFrame(payload);
    const result = await readFrame(chunkedSource([frame]));
    expect(result).toEqual(payload);
  });

  it('reads a frame split across multiple chunks', async () => {
    const payload = new Uint8Array([10, 20, 30, 40, 50]);
    const frame = encodeFrame(payload);

    // Split the 9-byte frame into 3 chunks
    const chunk1 = frame.slice(0, 2);  // partial length prefix
    const chunk2 = frame.slice(2, 6);  // rest of prefix + 2 bytes payload
    const chunk3 = frame.slice(6);     // remaining 3 bytes payload

    const result = await readFrame(chunkedSource([chunk1, chunk2, chunk3]));
    expect(result).toEqual(payload);
  });

  it('reads from Uint8ArrayList-like objects', async () => {
    const payload = new Uint8Array([1, 2, 3]);
    const frame = encodeFrame(payload);
    // Simulate Uint8ArrayList with .subarray() method
    const listLike = { subarray: () => frame };

    async function* source() {
      yield listLike;
    }

    const result = await readFrame(source());
    expect(result).toEqual(payload);
  });

  it('throws on premature stream end', async () => {
    // Send only the length prefix (claiming 100 bytes) with no payload
    const partial = new Uint8Array(4);
    const view = new DataView(partial.buffer);
    view.setUint32(0, 100);

    await expect(readFrame(chunkedSource([partial]))).rejects.toThrow('stream ended');
  });

  it('throws on oversized frame from stream', async () => {
    const header = new Uint8Array(4);
    const view = new DataView(header.buffer);
    view.setUint32(0, 2_000_000);

    await expect(readFrame(chunkedSource([header]))).rejects.toThrow('frame too large');
  });
});

// --- NodeSession transport wiring ---

describe('NodeSession transport wiring', () => {
  it('hasTransport is false by default', () => {
    const session = new NodeSession('test-peer');
    expect(session.hasTransport).toBe(false);
  });

  it('hasTransport is true after _setTransport', () => {
    const session = new NodeSession('test-peer');
    const fakeNode = {};
    const fakePeerId = 'fake-peer-id';
    session._setTransport(fakeNode, fakePeerId);
    expect(session.hasTransport).toBe(true);
  });

  it('send() pushes to outbox even with transport', () => {
    const session = new NodeSession('test-peer');
    // Set up a ratchet for encryption
    const dhKp = X25519Keypair.generate();
    const sharedSecret = new Uint8Array(32).fill(0x42);
    const ratchet = DoubleRatchet.initSender(sharedSecret, dhKp.publicKeyBytes());
    session._setRatchet(ratchet);

    const channel = session.openChannel('test');
    session.send(channel, new Uint8Array([1, 2, 3]));

    // Without transport, outbox is populated but not drained
    expect(session.outbox.length).toBe(1);
  });

  it('send() with mock transport triggers drain (outbox cleared)', async () => {
    const session = new NodeSession('test-peer');
    const sharedSecret = new Uint8Array(32).fill(0x42);
    const dhKp = X25519Keypair.generate();
    const ratchet = DoubleRatchet.initSender(sharedSecret, dhKp.publicKeyBytes());
    session._setRatchet(ratchet);

    // Mock libp2p node that captures sent data
    const sentFrames: Uint8Array[] = [];
    const mockLibp2p = {
      dialProtocol: async () => ({
        sink: async (source: AsyncIterable<Uint8Array>) => {
          for await (const chunk of source) {
            sentFrames.push(chunk);
          }
        },
        source: (async function* () {
          // Empty response
        })(),
      }),
    };

    session._setTransport(mockLibp2p, 'remote-peer');

    const channel = session.openChannel('test');
    session.send(channel, new Uint8Array([1, 2, 3]));

    // Wait for async drain
    await new Promise(resolve => setTimeout(resolve, 50));

    // Outbox should be drained
    expect(session.outbox.length).toBe(0);
    // A frame should have been sent
    expect(sentFrames.length).toBe(1);

    // The sent frame should be a valid length-prefixed CBOR envelope
    const payload = decodeFrame(sentFrames[0]);
    const env = decodeEnvelope(payload);
    expect(env.type).toBe(DATA_MESSAGE);
    expect(env.version).toBe(1);
  });
});

// --- Handshake envelope construction ---

describe('handshake envelope construction', () => {
  it('HANDSHAKE_INIT envelope carries Noise msg1 in payload', async () => {
    const identity = await IdentityKeypair.generate();
    const initiator = new NoiseXXHandshake('initiator', identity);
    const out1 = initiator.step();
    expect(out1.type).toBe('send_message');
    const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;

    const env: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_INIT,
      msgId: newMsgId(),
      payload: msg1,
    };

    const encoded = encodeEnvelope(env);
    const decoded = decodeEnvelope(encoded);
    expect(decoded.type).toBe(HANDSHAKE_INIT);
    expect(decoded.payload).toEqual(msg1);
    expect(decoded.payload.length).toBe(32); // X25519 ephemeral public key
  });

  it('HANDSHAKE_RESPONSE envelope carries Noise msg2 + DH public key in authTag', async () => {
    const aliceId = await IdentityKeypair.generate();
    const bobId = await IdentityKeypair.generate();

    const initiator = new NoiseXXHandshake('initiator', aliceId);
    const responder = new NoiseXXHandshake('responder', bobId);

    const out1 = initiator.step();
    const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;

    const out2 = responder.step(msg1);
    const msg2 = (out2 as { type: 'send_message'; data: Uint8Array }).data;

    const dhKp = X25519Keypair.generate();

    const env: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_RESPONSE,
      msgId: newMsgId(),
      payload: msg2,
      authTag: dhKp.publicKeyBytes(),
    };

    const encoded = encodeEnvelope(env);
    const decoded = decodeEnvelope(encoded);
    expect(decoded.type).toBe(HANDSHAKE_RESPONSE);
    expect(decoded.authTag).toBeDefined();
    expect(decoded.authTag!.length).toBe(32);
    expect(decoded.authTag!).toEqual(dhKp.publicKeyBytes());
  });

  it('HANDSHAKE_ACK envelope has empty payload', () => {
    const env: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_ACK,
      msgId: newMsgId(),
      payload: new Uint8Array(0),
    };

    const encoded = encodeEnvelope(env);
    const decoded = decodeEnvelope(encoded);
    expect(decoded.type).toBe(HANDSHAKE_ACK);
    expect(decoded.payload.length).toBe(0);
  });
});

// --- Full in-memory handshake protocol simulation ---

describe('in-memory handshake protocol simulation', () => {
  it('2-round handshake produces matching ratchets', async () => {
    const aliceId = await IdentityKeypair.generate();
    const bobId = await IdentityKeypair.generate();

    // --- Round 1: INIT -> RESPONSE ---
    const initiator = new NoiseXXHandshake('initiator', aliceId);
    const responder = new NoiseXXHandshake('responder', bobId);

    // Alice: generate msg1
    const out1 = initiator.step();
    const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;

    // Wrap in HANDSHAKE_INIT envelope, encode as frame
    const initEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_INIT,
      msgId: newMsgId(),
      payload: msg1,
    };
    const initFrame = encodeFrame(encodeEnvelope(initEnv));

    // Bob: receive INIT, process msg1, produce msg2
    const initPayload = decodeFrame(initFrame);
    const receivedInit = decodeEnvelope(initPayload);
    expect(receivedInit.type).toBe(HANDSHAKE_INIT);

    const out2 = responder.step(receivedInit.payload);
    const msg2 = (out2 as { type: 'send_message'; data: Uint8Array }).data;

    // Bob: generate DH keypair for Double Ratchet
    const bobDhKp = X25519Keypair.generate();

    // Wrap in HANDSHAKE_RESPONSE envelope
    const responseEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_RESPONSE,
      msgId: newMsgId(),
      payload: msg2,
      authTag: bobDhKp.publicKeyBytes(),
    };
    const responseFrame = encodeFrame(encodeEnvelope(responseEnv));

    // --- Round 2: FINISH -> ACK ---

    // Alice: receive RESPONSE, extract DH public key, process msg2, produce msg3
    const responsePayload = decodeFrame(responseFrame);
    const receivedResponse = decodeEnvelope(responsePayload);
    expect(receivedResponse.type).toBe(HANDSHAKE_RESPONSE);
    expect(receivedResponse.authTag).toBeDefined();
    expect(receivedResponse.authTag!.length).toBe(32);

    const dhPublicBytes = receivedResponse.authTag!;

    const out3 = initiator.step(receivedResponse.payload);
    const msg3 = (out3 as { type: 'send_message'; data: Uint8Array }).data;

    // Wrap in HANDSHAKE_FINISH envelope
    const finishEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_FINISH,
      msgId: newMsgId(),
      payload: msg3,
    };
    const finishFrame = encodeFrame(encodeEnvelope(finishEnv));

    // Bob: receive FINISH, complete handshake
    const finishPayload = decodeFrame(finishFrame);
    const receivedFinish = decodeEnvelope(finishPayload);
    expect(receivedFinish.type).toBe(HANDSHAKE_FINISH);

    const out4 = responder.step(receivedFinish.payload);
    expect(out4.type).toBe('complete');
    const bobResult = (out4 as { type: 'complete'; result: any }).result;

    // Alice: get handshake result
    const aliceResult = initiator.getResult();

    // Session keys must match
    expect(aliceResult.sessionKey).toEqual(bobResult.sessionKey);

    // --- Create Double Ratchets ---
    const aliceRatchet = DoubleRatchet.initSender(aliceResult.sessionKey, dhPublicBytes);
    const bobRatchet = DoubleRatchet.initReceiver(bobResult.sessionKey, bobDhKp);

    // Send ACK
    const ackEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_ACK,
      msgId: newMsgId(),
      payload: new Uint8Array(0),
    };
    const ackFrame = encodeFrame(encodeEnvelope(ackEnv));
    const ackPayload = decodeFrame(ackFrame);
    const receivedAck = decodeEnvelope(ackPayload);
    expect(receivedAck.type).toBe(HANDSHAKE_ACK);

    // --- Verify ratchets produce compatible encryption ---
    const plaintext = new TextEncoder().encode('hello from Alice over the wire');
    const { header, ciphertext } = aliceRatchet.encrypt(plaintext);
    const decrypted = bobRatchet.decrypt(header, ciphertext);
    expect(decrypted).toEqual(plaintext);

    // Bidirectional
    const bobPlaintext = new TextEncoder().encode('hello from Bob over the wire');
    const bobEncrypted = bobRatchet.encrypt(bobPlaintext);
    const aliceDecrypted = aliceRatchet.decrypt(bobEncrypted.header, bobEncrypted.ciphertext);
    expect(aliceDecrypted).toEqual(bobPlaintext);
  });

  it('handshake envelopes survive frame encoding round-trip', async () => {
    const identity = await IdentityKeypair.generate();
    const initiator = new NoiseXXHandshake('initiator', identity);
    const out1 = initiator.step();
    const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;

    const envelope: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_INIT,
      msgId: newMsgId(),
      payload: msg1,
    };

    // Envelope -> CBOR -> frame -> decode frame -> decode CBOR -> envelope
    const frame = encodeFrame(encodeEnvelope(envelope));
    const framePayload = decodeFrame(frame);
    const recovered = decodeEnvelope(framePayload);

    expect(recovered.version).toBe(1);
    expect(recovered.type).toBe(HANDSHAKE_INIT);
    expect(recovered.msgId).toEqual(envelope.msgId);
    expect(recovered.payload).toEqual(msg1);
  });
});

// --- Node.connectTransport requires transport ---

describe('Node.connectTransport', () => {
  it('throws when transport is not started', async () => {
    const node = await Node.create();
    await expect(
      node.connectTransport('12D3KooWTest', ['/ip4/127.0.0.1/tcp/4001']),
    ).rejects.toThrow('transport not started');
    await node.close();
  });
});

// --- Node.getSession ---

describe('Node.getSession', () => {
  it('returns session after connect', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-abc');
    expect(node.getSession('peer-abc')).toBe(session);
    await node.close();
  });

  it('returns undefined for unknown peer', async () => {
    const node = await Node.create();
    expect(node.getSession('unknown')).toBeUndefined();
    await node.close();
  });
});

// --- Existing connect() still works (backward compatibility) ---

describe('existing connect() backward compatibility', () => {
  it('connect without transport produces session with ratchet', async () => {
    const node = await Node.create();
    const session = await node.connect('peer-1');
    expect(session.peerId).toBe('peer-1');
    expect(session.state).toBe('connected');
    expect(session.ratchet).not.toBeNull();
    expect(session.hasTransport).toBe(false);

    // Can still send (goes to outbox, not over wire)
    const channel = session.openChannel('chat');
    session.send(channel, new TextEncoder().encode('hello'));
    expect(session.outbox.length).toBe(1);

    await node.close();
  });
});

// --- Data message dispatch through full envelope path ---

describe('data message dispatch through envelope path', () => {
  it('incoming data envelope dispatches to session handlers', async () => {
    const aliceId = await IdentityKeypair.generate();
    const bobId = await IdentityKeypair.generate();

    // Set up matching ratchets
    const aliceNoise = new NoiseXXHandshake('initiator', aliceId);
    const bobNoise = new NoiseXXHandshake('responder', bobId);

    const out1 = aliceNoise.step();
    const msg1 = (out1 as { type: 'send_message'; data: Uint8Array }).data;
    const out2 = bobNoise.step(msg1);
    const msg2 = (out2 as { type: 'send_message'; data: Uint8Array }).data;
    const out3 = aliceNoise.step(msg2);
    const msg3 = (out3 as { type: 'send_message'; data: Uint8Array }).data;
    bobNoise.step(msg3);

    const aliceResult = aliceNoise.getResult();
    const bobDhKp = X25519Keypair.generate();

    const senderRatchet = DoubleRatchet.initSender(aliceResult.sessionKey, bobDhKp.publicKeyBytes());
    const receiverRatchet = DoubleRatchet.initReceiver(aliceResult.sessionKey, bobDhKp);

    // Sender creates session and sends a message
    const senderSession = new NodeSession('bob');
    senderSession._setRatchet(senderRatchet);
    const ch = senderSession.openChannel('data');
    senderSession.send(ch, new TextEncoder().encode('test message'));

    expect(senderSession.outbox.length).toBe(1);
    const outEnvelopeBytes = senderSession.outbox[0];

    // Receiver creates session and dispatches the incoming envelope
    const receiverSession = new NodeSession('alice');
    receiverSession._setRatchet(receiverRatchet);
    const receiverCh = receiverSession.openChannel('data');

    const received: Uint8Array[] = [];
    receiverSession.onMessage(receiverCh, (data) => received.push(data));

    receiverSession.dispatchIncoming(outEnvelopeBytes);

    expect(received.length).toBe(1);
    expect(new TextDecoder().decode(received[0])).toBe('test message');
  });
});
