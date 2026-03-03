import { v7 as uuidv7 } from 'uuid';
import { CairnError } from './errors.js';
import { SessionStateMachine } from './session/state-machine.js';
import type { ConnectionState, StateChangedEvent } from './session/state-machine.js';
import {
  Channel,
  ChannelManager,
  validateChannelName,
  createDataMessage,
} from './channel.js';
import type { DataMessage } from './channel.js';

// ---------------------------------------------------------------------------
// Session constants
// ---------------------------------------------------------------------------

/** Default session expiry window (24 hours). */
export const DEFAULT_SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Session event listeners
// ---------------------------------------------------------------------------

export type SessionStateListener = (event: StateChangedEvent) => void;
export type ChannelOpenedListener = (event: { channelName: string; streamId: number; metadata?: Uint8Array }) => void;
export type MessageListener = (event: { channel: Channel; data: Uint8Array }) => void;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/**
 * A session that survives transport disruptions.
 *
 * Holds session identity, state, sequence counters, and expiry information.
 * The session layer is the primary abstraction the application interacts with;
 * transport churn is invisible above this layer.
 */
export class Session {
  /** Unique session identifier (UUID v7). */
  readonly id: string;
  /** The remote peer's identifier. */
  readonly peerId: Uint8Array;
  /** Session state machine. */
  private readonly _sm: SessionStateMachine;
  /** Channel manager. */
  private readonly _channels: ChannelManager;
  /** When this session was created (ms since epoch). */
  readonly createdAt: number;
  /** How long until this session expires (default: 24h). */
  readonly expiryMs: number;
  /** Outbound message sequence counter. */
  private _sequenceTx: number = 0;
  /** Inbound message sequence counter. */
  private _sequenceRx: number = 0;
  /** Ratchet epoch counter, incremented on each reconnection. */
  private _ratchetEpoch: number = 0;
  /** Next stream ID for new channels. */
  private _nextStreamId: number = 1;

  private readonly _stateListeners: SessionStateListener[] = [];
  private readonly _channelOpenedListeners: ChannelOpenedListener[] = [];
  private readonly _messageListeners: MessageListener[] = [];

  constructor(peerId: Uint8Array, expiryMs: number = DEFAULT_SESSION_EXPIRY_MS) {
    this.id = uuidv7();
    this.peerId = peerId;
    this.createdAt = Date.now();
    this.expiryMs = expiryMs;

    this._sm = new SessionStateMachine(this.id);
    this._sm.onStateChanged((event) => {
      for (const listener of this._stateListeners) {
        listener(event);
      }
    });

    this._channels = new ChannelManager();
    this._channels.onEvent((event) => {
      if (event.type === 'opened') {
        for (const listener of this._channelOpenedListeners) {
          listener({
            channelName: event.channelName,
            streamId: event.streamId,
            metadata: event.metadata,
          });
        }
      }
    });
  }

  /** Subscribe to state change events. */
  onStateChanged(listener: SessionStateListener): void {
    this._stateListeners.push(listener);
  }

  /** Subscribe to channel opened events. */
  onChannelOpened(listener: ChannelOpenedListener): void {
    this._channelOpenedListeners.push(listener);
  }

  /** Subscribe to message events. */
  onMessage(listener: MessageListener): void {
    this._messageListeners.push(listener);
  }

  /** Get the current connection state. */
  get connectionState(): ConnectionState {
    return this._sm.state;
  }

  /** Check if the session has expired. */
  get isExpired(): boolean {
    return Date.now() - this.createdAt > this.expiryMs;
  }

  /** Get the outbound sequence counter. */
  get sequenceTx(): number {
    return this._sequenceTx;
  }

  /** Get the inbound sequence counter. */
  get sequenceRx(): number {
    return this._sequenceRx;
  }

  /** Get the ratchet epoch. */
  get ratchetEpoch(): number {
    return this._ratchetEpoch;
  }

  /**
   * Attempt a state transition.
   * Throws CairnError if the transition is invalid.
   */
  transition(to: ConnectionState, reason?: string): void {
    this._sm.transition(to, reason);
  }

  /** Increment and return the next outbound sequence number. */
  nextSequenceTx(): number {
    const seq = this._sequenceTx;
    this._sequenceTx++;
    return seq;
  }

  /** Update the inbound sequence number. */
  setSequenceRx(seq: number): void {
    this._sequenceRx = seq;
  }

  /** Advance the ratchet epoch (called on reconnection). */
  advanceRatchetEpoch(): void {
    this._ratchetEpoch++;
  }

  /**
   * Open a new channel.
   *
   * Channel names starting with `__cairn_` are rejected.
   */
  openChannel(name: string, metadata?: Uint8Array): Channel {
    validateChannelName(name);
    const streamId = this._nextStreamId++;
    this._channels.openChannel(name, streamId, metadata);
    return this._channels.getChannel(streamId)!;
  }

  /** Handle an incoming channel init from a remote peer. */
  handleChannelInit(streamId: number, channelName: string, metadata?: Uint8Array): void {
    this._channels.handleChannelInit(streamId, { channelName, metadata });
  }

  /** Accept an incoming channel. */
  acceptChannel(streamId: number): void {
    this._channels.acceptChannel(streamId);
  }

  /** Reject an incoming channel. */
  rejectChannel(streamId: number, reason?: string): void {
    this._channels.rejectChannel(streamId, reason);
  }

  /** Get a channel by stream ID. */
  getChannel(streamId: number): Channel | undefined {
    return this._channels.getChannel(streamId);
  }

  /** Close a channel. */
  closeChannel(streamId: number): void {
    this._channels.closeChannel(streamId);
  }

  /** Get the number of tracked channels. */
  get channelCount(): number {
    return this._channels.channelCount;
  }

  /**
   * Send data on a channel.
   *
   * Creates a DataMessage with a fresh UUID v7 msg_id.
   * Increments the outbound sequence counter.
   */
  send(channel: Channel, data: Uint8Array): DataMessage {
    if (!channel.isOpen()) {
      throw new CairnError('PROTOCOL', `cannot send on channel '${channel.name}' in state ${channel.state}`);
    }
    this.nextSequenceTx();
    return createDataMessage(data);
  }

  /** Handle incoming data on a channel. */
  handleData(streamId: number, message: DataMessage): void {
    this._channels.handleData(streamId, message);
    const channel = this._channels.getChannel(streamId);
    if (channel) {
      for (const listener of this._messageListeners) {
        listener({ channel, data: message.payload });
      }
    }
  }
}
