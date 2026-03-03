import { describe, it, expect, vi } from 'vitest';
import {
  SessionStateMachine,
  isValidTransition,
} from '../../src/session/state-machine.js';
import type {
  ConnectionState,
  StateChangedEvent,
} from '../../src/session/state-machine.js';
import {
  Channel,
  ChannelManager,
  validateChannelName,
  encodeChannelInit,
  decodeChannelInit,
  createDataMessage,
  RESERVED_CHANNEL_PREFIX,
  CHANNEL_FORWARD,
  CHANNEL_INIT_TYPE,
} from '../../src/channel.js';
import type { ChannelEvent, DataMessage } from '../../src/channel.js';
import { Session, DEFAULT_SESSION_EXPIRY_MS } from '../../src/session.js';
import { CairnError } from '../../src/errors.js';

// --- isValidTransition ---

describe('isValidTransition', () => {
  it('all 10 valid transitions', () => {
    const valid: [ConnectionState, ConnectionState][] = [
      ['connected', 'unstable'],
      ['connected', 'disconnected'],
      ['unstable', 'disconnected'],
      ['unstable', 'connected'],
      ['disconnected', 'reconnecting'],
      ['reconnecting', 'reconnected'],
      ['reconnecting', 'suspended'],
      ['suspended', 'reconnecting'],
      ['suspended', 'failed'],
      ['reconnected', 'connected'],
    ];
    for (const [from, to] of valid) {
      expect(isValidTransition(from, to)).toBe(true);
    }
  });

  it('invalid transitions', () => {
    const invalid: [ConnectionState, ConnectionState][] = [
      ['connected', 'failed'],
      ['connected', 'reconnecting'],
      ['connected', 'reconnected'],
      ['connected', 'suspended'],
      ['disconnected', 'connected'],
      ['disconnected', 'failed'],
      ['reconnecting', 'connected'],
      ['reconnecting', 'failed'],
      ['reconnected', 'failed'],
      ['reconnected', 'disconnected'],
      ['failed', 'connected'],
      ['failed', 'reconnecting'],
    ];
    for (const [from, to] of invalid) {
      expect(isValidTransition(from, to)).toBe(false);
    }
  });

  it('self-transitions are invalid', () => {
    const states: ConnectionState[] = [
      'connected', 'unstable', 'disconnected', 'reconnecting',
      'suspended', 'reconnected', 'failed',
    ];
    for (const state of states) {
      expect(isValidTransition(state, state)).toBe(false);
    }
  });
});

// --- SessionStateMachine ---

describe('SessionStateMachine', () => {
  it('creates with default connected state', () => {
    const sm = new SessionStateMachine('sess-1');
    expect(sm.state).toBe('connected');
    expect(sm.sessionId).toBe('sess-1');
  });

  it('creates with custom initial state', () => {
    const sm = new SessionStateMachine('sess-1', 'disconnected');
    expect(sm.state).toBe('disconnected');
  });

  it('valid transition: connected -> unstable', () => {
    const sm = new SessionStateMachine('sess-1');
    sm.transition('unstable');
    expect(sm.state).toBe('unstable');
  });

  it('valid transition: connected -> disconnected', () => {
    const sm = new SessionStateMachine('sess-1');
    sm.transition('disconnected', 'abrupt loss');
    expect(sm.state).toBe('disconnected');
  });

  it('valid transition: unstable -> connected (recovered)', () => {
    const sm = new SessionStateMachine('sess-1', 'unstable');
    sm.transition('connected');
    expect(sm.state).toBe('connected');
  });

  it('invalid transition: connected -> failed', () => {
    const sm = new SessionStateMachine('sess-1');
    expect(() => sm.transition('failed')).toThrow('invalid session state transition');
  });

  it('invalid transition does not change state', () => {
    const sm = new SessionStateMachine('sess-1');
    try { sm.transition('failed'); } catch {}
    expect(sm.state).toBe('connected');
  });

  it('emits state_changed event', () => {
    const sm = new SessionStateMachine('sess-1');
    const events: StateChangedEvent[] = [];
    sm.onStateChanged((e) => events.push(e));

    sm.transition('unstable', 'high latency');

    expect(events.length).toBe(1);
    expect(events[0].sessionId).toBe('sess-1');
    expect(events[0].fromState).toBe('connected');
    expect(events[0].toState).toBe('unstable');
    expect(events[0].reason).toBe('high latency');
    expect(events[0].timestamp).toBeGreaterThan(0);
  });

  it('emits multiple events', () => {
    const sm = new SessionStateMachine('sess-1');
    const events: StateChangedEvent[] = [];
    sm.onStateChanged((e) => events.push(e));

    sm.transition('unstable');
    sm.transition('disconnected');
    sm.transition('reconnecting');

    expect(events.length).toBe(3);
    expect(events[0].fromState).toBe('connected');
    expect(events[1].fromState).toBe('unstable');
    expect(events[2].fromState).toBe('disconnected');
  });

  it('full reconnection cycle', () => {
    const sm = new SessionStateMachine('sess-1');
    sm.transition('unstable');
    sm.transition('disconnected');
    sm.transition('reconnecting');
    sm.transition('reconnected');
    sm.transition('connected');
    expect(sm.state).toBe('connected');
  });

  it('suspended retry then fail cycle', () => {
    const sm = new SessionStateMachine('sess-1');
    sm.transition('disconnected');
    sm.transition('reconnecting');
    sm.transition('suspended');
    sm.transition('reconnecting');
    sm.transition('suspended');
    sm.transition('failed', 'max retries');
    expect(sm.state).toBe('failed');
  });
});

// --- Channel name validation ---

describe('Channel name validation', () => {
  it('valid names', () => {
    expect(() => validateChannelName('my-channel')).not.toThrow();
    expect(() => validateChannelName('data')).not.toThrow();
    expect(() => validateChannelName('chat_room_1')).not.toThrow();
  });

  it('reserved prefix rejected', () => {
    expect(() => validateChannelName('__cairn_forward')).toThrow('reserved prefix');
    expect(() => validateChannelName('__cairn_custom')).toThrow('reserved prefix');
    expect(() => validateChannelName('__cairn_')).toThrow('reserved prefix');
  });

  it('empty name rejected', () => {
    expect(() => validateChannelName('')).toThrow('must not be empty');
  });

  it('reserved constants', () => {
    expect(RESERVED_CHANNEL_PREFIX).toBe('__cairn_');
    expect(CHANNEL_FORWARD).toBe('__cairn_forward');
    expect(CHANNEL_FORWARD.startsWith(RESERVED_CHANNEL_PREFIX)).toBe(true);
    expect(CHANNEL_INIT_TYPE).toBe(0x0303);
  });
});

// --- Channel state transitions ---

describe('Channel', () => {
  it('new channel is in opening state', () => {
    const ch = new Channel('test', 1);
    expect(ch.state).toBe('opening');
    expect(ch.name).toBe('test');
    expect(ch.streamId).toBe(1);
    expect(ch.isOpen()).toBe(false);
  });

  it('accept transitions to open', () => {
    const ch = new Channel('test', 1);
    ch.accept();
    expect(ch.state).toBe('open');
    expect(ch.isOpen()).toBe(true);
  });

  it('reject transitions to rejected', () => {
    const ch = new Channel('test', 1);
    ch.reject();
    expect(ch.state).toBe('rejected');
    expect(ch.isOpen()).toBe(false);
  });

  it('close from open', () => {
    const ch = new Channel('test', 1);
    ch.accept();
    ch.close();
    expect(ch.state).toBe('closed');
    expect(ch.isOpen()).toBe(false);
  });

  it('close from opening', () => {
    const ch = new Channel('test', 1);
    ch.close();
    expect(ch.state).toBe('closed');
  });

  it('double accept rejected', () => {
    const ch = new Channel('test', 1);
    ch.accept();
    expect(() => ch.accept()).toThrow();
  });

  it('accept after reject rejected', () => {
    const ch = new Channel('test', 1);
    ch.reject();
    expect(() => ch.accept()).toThrow();
  });

  it('double close rejected', () => {
    const ch = new Channel('test', 1);
    ch.close();
    expect(() => ch.close()).toThrow();
  });

  it('channel with metadata', () => {
    const meta = new Uint8Array([0xCA, 0xFE]);
    const ch = new Channel('test', 1, meta);
    expect(ch.metadata).toEqual(meta);
  });
});

// --- ChannelInit serialization ---

describe('ChannelInit serialization', () => {
  it('roundtrip without metadata', () => {
    const init = { channelName: 'my-channel' };
    const encoded = encodeChannelInit(init);
    const decoded = decodeChannelInit(encoded);
    expect(decoded.channelName).toBe('my-channel');
    expect(decoded.metadata).toBeUndefined();
  });

  it('roundtrip with metadata', () => {
    const init = { channelName: 'data-stream', metadata: new Uint8Array([0x01, 0x02, 0x03]) };
    const encoded = encodeChannelInit(init);
    const decoded = decodeChannelInit(encoded);
    expect(decoded.channelName).toBe('data-stream');
    expect(decoded.metadata).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });
});

// --- DataMessage ---

describe('DataMessage', () => {
  it('creates with UUID v7', () => {
    const msg = createDataMessage(new Uint8Array([0xDE, 0xAD]));
    expect(msg.msgId.length).toBe(16);
    expect(msg.payload).toEqual(new Uint8Array([0xDE, 0xAD]));
    // Version bits (byte 6): should be 0x7x
    expect((msg.msgId[6] & 0xf0)).toBe(0x70);
    // Variant bits (byte 8): should be 0b10xx_xxxx
    expect((msg.msgId[8] & 0xc0)).toBe(0x80);
  });

  it('unique msg_ids', () => {
    const msg1 = createDataMessage(new Uint8Array([]));
    const msg2 = createDataMessage(new Uint8Array([]));
    expect(msg1.msgId).not.toEqual(msg2.msgId);
  });
});

// --- ChannelManager ---

describe('ChannelManager', () => {
  it('open channel', () => {
    const mgr = new ChannelManager();
    const init = mgr.openChannel('chat', 1);
    expect(init.channelName).toBe('chat');
    expect(mgr.channelCount).toBe(1);
    expect(mgr.getChannel(1)!.state).toBe('opening');
  });

  it('open reserved channel rejected', () => {
    const mgr = new ChannelManager();
    expect(() => mgr.openChannel('__cairn_forward', 1)).toThrow('reserved prefix');
    expect(mgr.channelCount).toBe(0);
  });

  it('open duplicate stream rejected', () => {
    const mgr = new ChannelManager();
    mgr.openChannel('chat', 1);
    expect(() => mgr.openChannel('other', 1)).toThrow('already has a channel');
  });

  it('handle channel init emits opened event', () => {
    const mgr = new ChannelManager();
    const events: ChannelEvent[] = [];
    mgr.onEvent((e) => events.push(e));

    mgr.handleChannelInit(5, { channelName: 'remote-ch', metadata: new Uint8Array([0xAB]) });

    expect(mgr.channelCount).toBe(1);
    expect(mgr.getChannel(5)!.name).toBe('remote-ch');
    expect(events.length).toBe(1);
    expect(events[0].type).toBe('opened');
    if (events[0].type === 'opened') {
      expect(events[0].channelName).toBe('remote-ch');
      expect(events[0].streamId).toBe(5);
      expect(events[0].metadata).toEqual(new Uint8Array([0xAB]));
    }
  });

  it('accept channel', () => {
    const mgr = new ChannelManager();
    const events: ChannelEvent[] = [];
    mgr.onEvent((e) => events.push(e));

    mgr.handleChannelInit(1, { channelName: 'ch' });
    mgr.acceptChannel(1);

    expect(mgr.getChannel(1)!.state).toBe('open');
    expect(events.length).toBe(2); // opened + accepted
    expect(events[1].type).toBe('accepted');
  });

  it('reject channel', () => {
    const mgr = new ChannelManager();
    const events: ChannelEvent[] = [];
    mgr.onEvent((e) => events.push(e));

    mgr.handleChannelInit(1, { channelName: 'ch' });
    mgr.rejectChannel(1, 'not allowed');

    expect(mgr.getChannel(1)!.state).toBe('rejected');
    expect(events[1].type).toBe('rejected');
    if (events[1].type === 'rejected') {
      expect(events[1].reason).toBe('not allowed');
    }
  });

  it('data on open channel', () => {
    const mgr = new ChannelManager();
    const events: ChannelEvent[] = [];
    mgr.onEvent((e) => events.push(e));

    mgr.handleChannelInit(1, { channelName: 'data' });
    mgr.acceptChannel(1);

    const msg = createDataMessage(new Uint8Array([0x42]));
    mgr.handleData(1, msg);

    const dataEvent = events.find((e) => e.type === 'data');
    expect(dataEvent).toBeDefined();
    if (dataEvent?.type === 'data') {
      expect(dataEvent.message.payload).toEqual(new Uint8Array([0x42]));
    }
  });

  it('data on non-open channel rejected', () => {
    const mgr = new ChannelManager();
    mgr.handleChannelInit(1, { channelName: 'data' });
    // Channel still in opening state
    expect(() => mgr.handleData(1, createDataMessage(new Uint8Array([0x42])))).toThrow('not open');
  });

  it('data on unknown stream rejected', () => {
    const mgr = new ChannelManager();
    expect(() => mgr.handleData(99, createDataMessage(new Uint8Array([0x42])))).toThrow('no channel');
  });

  it('close channel', () => {
    const mgr = new ChannelManager();
    const events: ChannelEvent[] = [];
    mgr.onEvent((e) => events.push(e));

    mgr.handleChannelInit(1, { channelName: 'ch' });
    mgr.acceptChannel(1);
    mgr.closeChannel(1);

    expect(mgr.getChannel(1)!.state).toBe('closed');
    expect(events.find((e) => e.type === 'closed')).toBeDefined();
  });

  it('multiple channels', () => {
    const mgr = new ChannelManager();
    mgr.openChannel('ch1', 1);
    mgr.openChannel('ch2', 2);
    mgr.openChannel('ch3', 3);
    expect(mgr.channelCount).toBe(3);

    expect(mgr.getChannel(1)!.name).toBe('ch1');
    expect(mgr.getChannel(2)!.name).toBe('ch2');
    expect(mgr.getChannel(3)!.name).toBe('ch3');
    expect(mgr.getChannel(4)).toBeUndefined();
  });
});

// --- Session ---

describe('Session', () => {
  it('creates with connected state', () => {
    const session = new Session(new Uint8Array(32).fill(0x01));
    expect(session.connectionState).toBe('connected');
    expect(session.sequenceTx).toBe(0);
    expect(session.sequenceRx).toBe(0);
    expect(session.ratchetEpoch).toBe(0);
    expect(session.expiryMs).toBe(DEFAULT_SESSION_EXPIRY_MS);
    expect(session.id).toBeTruthy();
  });

  it('unique session IDs', () => {
    const s1 = new Session(new Uint8Array(32));
    const s2 = new Session(new Uint8Array(32));
    expect(s1.id).not.toBe(s2.id);
  });

  it('custom expiry', () => {
    const session = new Session(new Uint8Array(32), 3600_000);
    expect(session.expiryMs).toBe(3600_000);
  });

  it('not expired immediately', () => {
    const session = new Session(new Uint8Array(32));
    expect(session.isExpired).toBe(false);
  });

  it('state transition', () => {
    const session = new Session(new Uint8Array(32));
    session.transition('unstable');
    expect(session.connectionState).toBe('unstable');
  });

  it('invalid state transition throws', () => {
    const session = new Session(new Uint8Array(32));
    expect(() => session.transition('failed')).toThrow();
    expect(session.connectionState).toBe('connected');
  });

  it('state_changed listener', () => {
    const session = new Session(new Uint8Array(32));
    const events: StateChangedEvent[] = [];
    session.onStateChanged((e) => events.push(e));

    session.transition('unstable', 'latency spike');

    expect(events.length).toBe(1);
    expect(events[0].fromState).toBe('connected');
    expect(events[0].toState).toBe('unstable');
    expect(events[0].reason).toBe('latency spike');
  });

  it('sequence counters', () => {
    const session = new Session(new Uint8Array(32));
    expect(session.nextSequenceTx()).toBe(0);
    expect(session.nextSequenceTx()).toBe(1);
    expect(session.nextSequenceTx()).toBe(2);
    expect(session.sequenceTx).toBe(3);

    session.setSequenceRx(42);
    expect(session.sequenceRx).toBe(42);
  });

  it('ratchet epoch', () => {
    const session = new Session(new Uint8Array(32));
    expect(session.ratchetEpoch).toBe(0);
    session.advanceRatchetEpoch();
    expect(session.ratchetEpoch).toBe(1);
    session.advanceRatchetEpoch();
    expect(session.ratchetEpoch).toBe(2);
  });

  it('open channel', () => {
    const session = new Session(new Uint8Array(32));
    const ch = session.openChannel('chat');
    expect(ch.name).toBe('chat');
    expect(ch.state).toBe('opening');
    expect(session.channelCount).toBe(1);
  });

  it('open reserved channel rejected', () => {
    const session = new Session(new Uint8Array(32));
    expect(() => session.openChannel('__cairn_forward')).toThrow('reserved prefix');
  });

  it('handle incoming channel init', () => {
    const session = new Session(new Uint8Array(32));
    const events: Array<{ channelName: string; streamId: number }> = [];
    session.onChannelOpened((e) => events.push(e));

    session.handleChannelInit(10, 'remote-ch');

    expect(session.channelCount).toBe(1);
    expect(session.getChannel(10)!.name).toBe('remote-ch');
    expect(events.length).toBe(1);
    expect(events[0].channelName).toBe('remote-ch');
  });

  it('accept and send on channel', () => {
    const session = new Session(new Uint8Array(32));
    session.handleChannelInit(1, 'data');
    session.acceptChannel(1);

    const ch = session.getChannel(1)!;
    expect(ch.isOpen()).toBe(true);

    const msg = session.send(ch, new Uint8Array([0xDE, 0xAD]));
    expect(msg.msgId.length).toBe(16);
    expect(msg.payload).toEqual(new Uint8Array([0xDE, 0xAD]));
    expect(session.sequenceTx).toBe(1);
  });

  it('send on non-open channel throws', () => {
    const session = new Session(new Uint8Array(32));
    const ch = session.openChannel('chat');
    // Channel is in opening state
    expect(() => session.send(ch, new Uint8Array([1]))).toThrow('cannot send');
  });

  it('handle incoming data emits message', () => {
    const session = new Session(new Uint8Array(32));
    session.handleChannelInit(1, 'data');
    session.acceptChannel(1);

    const messages: Array<{ data: Uint8Array }> = [];
    session.onMessage((e) => messages.push({ data: e.data }));

    const msg = createDataMessage(new Uint8Array([0x42]));
    session.handleData(1, msg);

    expect(messages.length).toBe(1);
    expect(messages[0].data).toEqual(new Uint8Array([0x42]));
  });

  it('full reconnection cycle', () => {
    const session = new Session(new Uint8Array(32));
    const events: StateChangedEvent[] = [];
    session.onStateChanged((e) => events.push(e));

    session.transition('unstable');
    session.transition('disconnected');
    session.transition('reconnecting');
    session.advanceRatchetEpoch();
    session.transition('reconnected');
    session.transition('connected');

    expect(session.connectionState).toBe('connected');
    expect(session.ratchetEpoch).toBe(1);
    expect(events.length).toBe(5);
  });

  it('close channel', () => {
    const session = new Session(new Uint8Array(32));
    const ch = session.openChannel('chat');
    session.closeChannel(ch.streamId);
    expect(ch.state).toBe('closed');
  });

  it('reject channel', () => {
    const session = new Session(new Uint8Array(32));
    session.handleChannelInit(1, 'ch');
    session.rejectChannel(1, 'denied');
    expect(session.getChannel(1)!.state).toBe('rejected');
  });
});
