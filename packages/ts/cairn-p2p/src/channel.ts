import { CairnError } from './errors.js';
import { encode, decode } from 'cborg';

// ---------------------------------------------------------------------------
// Channel constants
// ---------------------------------------------------------------------------

/** Prefix for reserved cairn-internal channel names. */
export const RESERVED_CHANNEL_PREFIX = '__cairn_';

/** Reserved channel name for store-and-forward operations. */
export const CHANNEL_FORWARD = '__cairn_forward';

/** Message type code for ChannelInit (first message on a new stream). */
export const CHANNEL_INIT_TYPE = 0x0303;

// ---------------------------------------------------------------------------
// Channel name validation
// ---------------------------------------------------------------------------

/** Validate that a channel name is not reserved and not empty. */
export function validateChannelName(name: string): void {
  if (!name) {
    throw new CairnError('PROTOCOL', 'channel name must not be empty');
  }
  if (name.startsWith(RESERVED_CHANNEL_PREFIX)) {
    throw new CairnError(
      'PROTOCOL',
      `channel name '${name}' uses reserved prefix '${RESERVED_CHANNEL_PREFIX}'`,
    );
  }
}

// ---------------------------------------------------------------------------
// Channel lifecycle states
// ---------------------------------------------------------------------------

/** Channel lifecycle states. */
export type ChannelState = 'opening' | 'open' | 'rejected' | 'closed';

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/** A named channel multiplexed over a yamux stream. */
export class Channel {
  readonly name: string;
  readonly streamId: number;
  private _state: ChannelState;
  readonly metadata?: Uint8Array;

  constructor(name: string, streamId: number, metadata?: Uint8Array) {
    this.name = name;
    this.streamId = streamId;
    this._state = 'opening';
    this.metadata = metadata;
  }

  /** Current channel state. */
  get state(): ChannelState {
    return this._state;
  }

  /** Check if the channel is open and ready for data flow. */
  isOpen(): boolean {
    return this._state === 'open';
  }

  /** Transition to the Open state (accepted by remote). */
  accept(): void {
    if (this._state !== 'opening') {
      throw new CairnError('PROTOCOL', `cannot accept channel '${this.name}' in state ${this._state}`);
    }
    this._state = 'open';
  }

  /** Transition to the Rejected state. */
  reject(): void {
    if (this._state !== 'opening') {
      throw new CairnError('PROTOCOL', `cannot reject channel '${this.name}' in state ${this._state}`);
    }
    this._state = 'rejected';
  }

  /** Transition to the Closed state. */
  close(): void {
    if (this._state === 'closed') {
      throw new CairnError('PROTOCOL', `channel '${this.name}' is already closed`);
    }
    this._state = 'closed';
  }
}

// ---------------------------------------------------------------------------
// ChannelInit payload
// ---------------------------------------------------------------------------

/** The first message sent on a newly opened yamux stream. */
export interface ChannelInit {
  channelName: string;
  metadata?: Uint8Array;
}

/** Encode a ChannelInit to CBOR bytes. */
export function encodeChannelInit(init: ChannelInit): Uint8Array {
  const obj: Record<string, unknown> = { channel_name: init.channelName };
  if (init.metadata) {
    obj.metadata = init.metadata;
  }
  return encode(obj);
}

/** Decode a ChannelInit from CBOR bytes. */
export function decodeChannelInit(data: Uint8Array): ChannelInit {
  const obj = decode(data) as Record<string, unknown>;
  const channelName = obj.channel_name as string;
  if (typeof channelName !== 'string') {
    throw new CairnError('PROTOCOL', 'ChannelInit missing channel_name');
  }
  return {
    channelName,
    metadata: obj.metadata instanceof Uint8Array ? obj.metadata : undefined,
  };
}

// ---------------------------------------------------------------------------
// DataMessage / DataAck / DataNack
// ---------------------------------------------------------------------------

/** Application data payload with reliable delivery semantics (0x0300). */
export interface DataMessage {
  msgId: Uint8Array;
  payload: Uint8Array;
}

/** Create a new DataMessage with a fresh UUID v7 identifier. */
export function createDataMessage(payload: Uint8Array): DataMessage {
  const msgId = new Uint8Array(16);
  crypto.getRandomValues(msgId);
  // Set version 7 (bits 48-51)
  msgId[6] = (msgId[6] & 0x0f) | 0x70;
  // Set variant (bits 64-65)
  msgId[8] = (msgId[8] & 0x3f) | 0x80;
  // Embed timestamp in first 48 bits for ordering
  const now = Date.now();
  msgId[0] = (now / 2 ** 40) & 0xff;
  msgId[1] = (now / 2 ** 32) & 0xff;
  msgId[2] = (now / 2 ** 24) & 0xff;
  msgId[3] = (now / 2 ** 16) & 0xff;
  msgId[4] = (now / 2 ** 8) & 0xff;
  msgId[5] = now & 0xff;
  return { msgId, payload };
}

/** Acknowledges successful receipt of a DataMessage (0x0301). */
export interface DataAck {
  ackedMsgId: Uint8Array;
}

/** Negative acknowledgment, requesting retransmission (0x0302). */
export interface DataNack {
  nackedMsgId: Uint8Array;
  reason?: string;
}

// ---------------------------------------------------------------------------
// ChannelManager
// ---------------------------------------------------------------------------

/** Events emitted by the channel manager. */
export type ChannelEvent =
  | { type: 'opened'; channelName: string; streamId: number; metadata?: Uint8Array }
  | { type: 'accepted'; streamId: number }
  | { type: 'rejected'; streamId: number; reason?: string }
  | { type: 'data'; streamId: number; message: DataMessage }
  | { type: 'closed'; streamId: number };

export type ChannelEventListener = (event: ChannelEvent) => void;

/** Manages channels within a session. */
export class ChannelManager {
  private readonly _channels = new Map<number, Channel>();
  private readonly _listeners: ChannelEventListener[] = [];

  onEvent(listener: ChannelEventListener): void {
    this._listeners.push(listener);
  }

  private emit(event: ChannelEvent): void {
    for (const listener of this._listeners) {
      listener(event);
    }
  }

  /** Open a new channel on a given stream. Returns the ChannelInit payload. */
  openChannel(name: string, streamId: number, metadata?: Uint8Array): ChannelInit {
    validateChannelName(name);

    if (this._channels.has(streamId)) {
      throw new CairnError('PROTOCOL', `stream ${streamId} already has a channel`);
    }

    const channel = new Channel(name, streamId, metadata);
    this._channels.set(streamId, channel);

    return { channelName: name, metadata };
  }

  /** Handle an incoming ChannelInit from a remote peer. */
  handleChannelInit(streamId: number, init: ChannelInit): void {
    if (this._channels.has(streamId)) {
      throw new CairnError('PROTOCOL', `stream ${streamId} already has a channel`);
    }

    const channel = new Channel(init.channelName, streamId, init.metadata);
    this._channels.set(streamId, channel);

    this.emit({
      type: 'opened',
      channelName: init.channelName,
      streamId,
      metadata: init.metadata,
    });
  }

  /** Accept an incoming channel. */
  acceptChannel(streamId: number): void {
    const channel = this._channels.get(streamId);
    if (!channel) {
      throw new CairnError('PROTOCOL', `no channel on stream ${streamId}`);
    }
    channel.accept();
    this.emit({ type: 'accepted', streamId });
  }

  /** Reject an incoming channel. */
  rejectChannel(streamId: number, reason?: string): void {
    const channel = this._channels.get(streamId);
    if (!channel) {
      throw new CairnError('PROTOCOL', `no channel on stream ${streamId}`);
    }
    channel.reject();
    this.emit({ type: 'rejected', streamId, reason });
  }

  /** Handle incoming data on a channel. */
  handleData(streamId: number, message: DataMessage): void {
    const channel = this._channels.get(streamId);
    if (!channel) {
      throw new CairnError('PROTOCOL', `no channel on stream ${streamId}`);
    }
    if (!channel.isOpen()) {
      throw new CairnError('PROTOCOL', `channel '${channel.name}' is not open (state: ${channel.state})`);
    }
    this.emit({ type: 'data', streamId, message });
  }

  /** Close a channel. */
  closeChannel(streamId: number): void {
    const channel = this._channels.get(streamId);
    if (!channel) {
      throw new CairnError('PROTOCOL', `no channel on stream ${streamId}`);
    }
    channel.close();
    this.emit({ type: 'closed', streamId });
  }

  /** Get a channel by stream ID. */
  getChannel(streamId: number): Channel | undefined {
    return this._channels.get(streamId);
  }

  /** Get the number of tracked channels. */
  get channelCount(): number {
    return this._channels.size;
  }
}
