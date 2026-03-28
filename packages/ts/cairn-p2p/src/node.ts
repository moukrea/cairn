// Node class — cairn peer node (spec section 3.1)

import type {
  CairnConfig,
  NatType,
  ConnectionState,
  ReconnectionPolicy,
  TransportType,
  TurnServerConfig,
  StorageBackend,
} from './config.js';
import {
  DEFAULT_RECONNECTION_POLICY,
  DEFAULT_MESH_SETTINGS,
  DEFAULT_STUN_SERVERS,
  DEFAULT_TRANSPORT_PREFERENCES,
} from './config.js';
import { CairnError } from './errors.js';
import { IdentityKeypair } from './crypto/identity.js';
import { NoiseXXHandshake } from './crypto/noise.js';
import type { HandshakeResult } from './crypto/noise.js';
import { DoubleRatchet } from './crypto/double-ratchet.js';
import type { RatchetHeader } from './crypto/double-ratchet.js';
import { X25519Keypair } from './crypto/exchange.js';
import { Spake2 } from './crypto/spake2.js';
import { generateQrPayload, consumeQrPayload } from './pairing/qr.js';
import { generatePin, formatPin, normalizePin, validatePin } from './pairing/pin.js';
import { generatePairingLink, parsePairingLink } from './pairing/link.js';
import type { PairingPayload } from './pairing/payload.js';
import { generateNonce } from './pairing/payload.js';
import { encodeEnvelope, decodeEnvelope, newMsgId } from './protocol/envelope.js';
import type { MessageEnvelope } from './protocol/envelope.js';
import {
  DATA_MESSAGE,
  HANDSHAKE_INIT,
  HANDSHAKE_RESPONSE,
  HANDSHAKE_FINISH,
  HANDSHAKE_ACK,
  SESSION_RESUME,
  SESSION_RESUME_ACK,
  SESSION_EXPIRED,
  isHandshakeType,
} from './protocol/message-types.js';
import { MessageQueue } from './session/message-queue.js';
import type { EnqueueResult } from './session/message-queue.js';
import { generateResumeProof, verifyResumeProof } from './session/reconnection.js';
import type { ConnectionHint } from './pairing/payload.js';
// Libp2p type used for _libp2pNode field — use 'any' to avoid static import
// createCairnNode is dynamically imported in startTransport() to avoid
// pulling Node.js-only libp2p deps into browser bundles.

/** Fully resolved configuration with no optional fields. */
export interface ResolvedConfig {
  stunServers: string[];
  turnServers: TurnServerConfig[];
  signalingServers: string[];
  trackerUrls: string[];
  bootstrapNodes: string[];
  transportPreferences: TransportType[];
  reconnectionPolicy: ReconnectionPolicy;
  meshSettings: Required<import('./config.js').MeshSettings>;
  storageBackend: StorageBackend;
}

// --- Event types ---

/** Events emitted by a Node. */
export interface NodeEvents {
  peer_paired: (peerId: string) => void;
  peer_unpaired: (peerId: string) => void;
  error: (error: CairnError) => void;
}

/** Events emitted by a NodeSession. */
export interface SessionEvents {
  state_changed: (prev: ConnectionState, current: ConnectionState) => void;
  channel_opened: (channel: NodeChannel) => void;
  error: (error: CairnError) => void;
}

// --- Pairing data types ---

export interface QrPairingData {
  payload: Uint8Array;
  expiresIn: number;
}

export interface PinPairingData {
  pin: string;
  expiresIn: number;
}

export interface LinkPairingData {
  uri: string;
  expiresIn: number;
}

// --- Saved session state for resume ---

/** State needed to resume a session without a full Noise XX handshake. */
export interface SavedSessionState {
  /** 16-byte session identifier. */
  sessionId: Uint8Array;
  /** Exported DoubleRatchet state (JSON-serializable object). */
  ratchetState: object;
  /** Next sequence number to send. */
  sequenceTx: number;
  /** Last sequence number received. */
  sequenceRx: number;
  /** Timestamp (ms) when the session was saved. */
  savedAt: number;
}

/** Maximum age of a saved session before it is considered expired (5 minutes). */
const SESSION_RESUME_MAX_AGE_MS = 5 * 60 * 1000;

/** Maximum allowed clock skew for resume timestamps (5 minutes). */
const SESSION_RESUME_TIMESTAMP_WINDOW_SEC = 5 * 60;

// --- Application message type range ---

const APP_MSG_TYPE_MIN = 0xf000;
const APP_MSG_TYPE_MAX = 0xffff;

// --- NodeChannel ---

/** A bidirectional data channel within a session. */
export class NodeChannel {
  private _open = true;

  constructor(readonly name: string) {}

  get isOpen(): boolean {
    return this._open;
  }

  close(): void {
    this._open = false;
  }
}

// --- NodeSession ---

/** A session with a paired peer (spec section 3.2). */
export class NodeSession {
  private _state: ConnectionState = 'connected';
  private readonly _channels = new Map<string, NodeChannel>();
  private readonly _stateListeners: Array<(prev: ConnectionState, current: ConnectionState) => void> = [];
  private readonly _channelListeners: Array<(channel: NodeChannel) => void> = [];
  private readonly _errorListeners: Array<(error: CairnError) => void> = [];
  private readonly _messageHandlers = new Map<string, Array<(data: Uint8Array) => void>>();
  private readonly _customHandlers = new Map<number, (data: Uint8Array) => void>();
  private _ratchet: DoubleRatchet | null = null;
  private readonly _messageQueue = new MessageQueue();
  private _sequenceCounter = 0;
  /** Outbox of encoded envelopes (transport would drain this). */
  readonly outbox: Uint8Array[] = [];
  /** Reference to the libp2p node for sending (null if no transport). */
  private _libp2pNode: any = null;
  /** The remote peer's libp2p PeerId (null if no transport). */
  private _remotePeerId: any = null;
  /** Guard to prevent concurrent outbox drains. */
  private _draining = false;
  /** 16-byte session identifier for resumption. */
  private _sessionId: Uint8Array | null = null;
  /** Last received sequence number (for resume sync). */
  private _sequenceRx = 0;

  constructor(readonly peerId: string) {}

  /** Get the session ID (16 bytes, or null if not set). */
  get sessionId(): Uint8Array | null {
    return this._sessionId;
  }

  /** Set the session ID (called during connect/resume). */
  _setSessionId(id: Uint8Array): void {
    this._sessionId = id;
  }

  /** Get the transmit sequence counter. */
  get sequenceTx(): number {
    return this._sequenceCounter;
  }

  /** Get the receive sequence counter. */
  get sequenceRx(): number {
    return this._sequenceRx;
  }

  /** Set the transmit sequence counter (for resume). */
  _setSequenceTx(n: number): void {
    this._sequenceCounter = n;
  }

  /** Set the receive sequence counter (for resume). */
  _setSequenceRx(n: number): void {
    this._sequenceRx = n;
  }

  /** Wire this session to a libp2p node and remote PeerId for transport. */
  _setTransport(libp2pNode: any, remotePeerId: any): void {
    this._libp2pNode = libp2pNode;
    this._remotePeerId = remotePeerId;
  }

  /** Whether this session has a live transport connection. */
  get hasTransport(): boolean {
    return this._libp2pNode !== null && this._remotePeerId !== null;
  }

  /** Get the current connection state. */
  get state(): ConnectionState {
    return this._state;
  }

  /** Get the Double Ratchet (for testing/inspection). */
  get ratchet(): DoubleRatchet | null {
    return this._ratchet;
  }

  /** Get the message queue. */
  get messageQueue(): MessageQueue {
    return this._messageQueue;
  }

  /** Set the ratchet for this session (called during connect). */
  _setRatchet(ratchet: DoubleRatchet): void {
    this._ratchet = ratchet;
  }

  /** Open a named channel. */
  openChannel(name: string): NodeChannel {
    if (!name) {
      throw new CairnError('PROTOCOL', 'channel name cannot be empty');
    }
    if (name.startsWith('__cairn_')) {
      throw new CairnError('PROTOCOL', 'reserved channel name prefix');
    }
    const channel = new NodeChannel(name);
    this._channels.set(name, channel);
    for (const listener of this._channelListeners) {
      listener(channel);
    }
    return channel;
  }

  /** Send data on a channel. Encrypts via Double Ratchet and wraps in CBOR envelope. */
  send(channel: NodeChannel, data: Uint8Array): void {
    if (!channel.isOpen) {
      throw new CairnError('PROTOCOL', 'channel is not open');
    }

    // If disconnected, queue for retransmission
    if (this._state === 'disconnected' || this._state === 'reconnecting' || this._state === 'suspended') {
      const seq = this._sequenceCounter++;
      const result: EnqueueResult = this._messageQueue.enqueue(seq, data);
      if (result === 'full') {
        throw new CairnError('PROTOCOL', 'message queue is full');
      }
      if (result === 'disabled') {
        throw new CairnError('PROTOCOL', 'message queuing is disabled');
      }
      return;
    }

    // Encrypt with Double Ratchet if available
    let payload: Uint8Array;
    if (this._ratchet) {
      const { header, ciphertext } = this._ratchet.encrypt(data);
      const headerJson = new TextEncoder().encode(JSON.stringify({
        dh_public: Array.from(header.dhPublic),
        prev_chain_len: header.prevChainLen,
        msg_num: header.msgNum,
      }));
      // Format: [4-byte header len][header json][ciphertext]
      const buf = new Uint8Array(4 + headerJson.length + ciphertext.length);
      const view = new DataView(buf.buffer);
      view.setUint32(0, headerJson.length);
      buf.set(headerJson, 4);
      buf.set(ciphertext, 4 + headerJson.length);
      payload = buf;
    } else {
      payload = data;
    }

    // Wrap in CBOR MessageEnvelope
    const envelope: MessageEnvelope = {
      version: 1,
      type: DATA_MESSAGE,
      msgId: newMsgId(),
      payload,
    };

    const encoded = encodeEnvelope(envelope);
    this.outbox.push(encoded);

    // If transport is wired, drain the outbox via libp2p
    if (this._libp2pNode && this._remotePeerId) {
      this._drainOutbox().catch((e) => {
        console.error('[cairn] _drainOutbox error:', e);
      });
    }
  }

  /**
   * Drain the outbox by sending each envelope as a length-prefixed frame
   * over a new libp2p stream using the cairn protocol.
   */
  private async _drainOutbox(): Promise<void> {
    if (this._draining) return;
    this._draining = true;
    try {
      const { CAIRN_PROTOCOL, encodeFrame } = await import('./transport/libp2p-node.js');
      while (this.outbox.length > 0) {
        const envelopeBytes = this.outbox.shift()!;
        try {
          const stream = await this._libp2pNode.dialProtocol(this._remotePeerId, CAIRN_PROTOCOL);
          const frame = encodeFrame(envelopeBytes);

          // Write the frame and close the write side.
          // Do NOT wait for a response -- the remote sends responses on
          // a separate stream (via its own dialProtocol), not as a reply
          // on this stream.  Waiting on readFrame() here would block the
          // drain loop forever.
          await stream.sink((async function* () {
            yield frame;
          })());
        } catch (e) {
          console.error('[cairn] drain send failed:', e);
          this.outbox.unshift(envelopeBytes);
          break;
        }
      }
    } finally {
      this._draining = false;
      // Re-check: messages may have been enqueued while we were draining.
      // Without this, a send() that arrived during drain would see _draining=true,
      // return early, and the message would sit in the outbox forever.
      if (this.outbox.length > 0 && this._libp2pNode && this._remotePeerId) {
        this._drainOutbox().catch((e) => {
          console.error('[cairn] _drainOutbox re-check error:', e);
        });
      }
    }
  }

  /** Register a callback for incoming messages on a channel. */
  onMessage(channel: NodeChannel, callback: (data: Uint8Array) => void): void {
    const handlers = this._messageHandlers.get(channel.name);
    if (handlers) {
      handlers.push(callback);
    } else {
      this._messageHandlers.set(channel.name, [callback]);
    }
  }

  /** Register a callback for connection state changes. */
  onStateChange(callback: (prev: ConnectionState, current: ConnectionState) => void): void {
    this._stateListeners.push(callback);
  }

  /** Register a callback for channel opened events. */
  onChannelOpened(callback: (channel: NodeChannel) => void): void {
    this._channelListeners.push(callback);
  }

  /** Register a callback for errors. */
  onError(callback: (error: CairnError) => void): void {
    this._errorListeners.push(callback);
  }

  /**
   * Register a handler for application-specific message types (0xF000-0xFFFF).
   */
  onCustomMessage(typeCode: number, callback: (data: Uint8Array) => void): void {
    if (typeCode < APP_MSG_TYPE_MIN || typeCode > APP_MSG_TYPE_MAX) {
      throw new CairnError(
        'PROTOCOL',
        `custom message type 0x${typeCode.toString(16).padStart(4, '0')} outside application range 0xF000-0xFFFF`,
      );
    }
    this._customHandlers.set(typeCode, callback);
  }

  /**
   * Dispatch an incoming CBOR envelope from the transport layer.
   * Decrypts if needed and routes to appropriate callbacks.
   */
  dispatchIncoming(envelopeBytes: Uint8Array): void {
    const envelope = decodeEnvelope(envelopeBytes);

    if (envelope.type === DATA_MESSAGE) {
      // Decrypt if we have a ratchet (otherwise treat payload as plaintext)
      let plaintext: Uint8Array;
      if (this._ratchet && envelope.payload.length >= 4) {
        const view = new DataView(envelope.payload.buffer, envelope.payload.byteOffset, envelope.payload.byteLength);
        const headerLen = view.getUint32(0);
        if (envelope.payload.length < 4 + headerLen) {
          throw new CairnError('PROTOCOL', 'payload too short for header');
        }
        const headerJson = new TextDecoder().decode(envelope.payload.slice(4, 4 + headerLen));
        const headerObj = JSON.parse(headerJson);
        const header: RatchetHeader = {
          dhPublic: new Uint8Array(headerObj.dh_public),
          prevChainLen: headerObj.prev_chain_len,
          msgNum: headerObj.msg_num,
        };
        const ciphertext = envelope.payload.slice(4 + headerLen);
        plaintext = this._ratchet.decrypt(header, ciphertext);
      } else {
        plaintext = envelope.payload;
      }

      // Dispatch to all channel message callbacks
      console.log('[cairn] dispatchIncoming: DATA_MESSAGE', plaintext.length, 'bytes plaintext, handlers:', this._messageHandlers.size);
      for (const [, cbs] of this._messageHandlers) {
        for (const cb of cbs) {
          cb(plaintext);
        }
      }
    } else if (envelope.type >= APP_MSG_TYPE_MIN && envelope.type <= APP_MSG_TYPE_MAX) {
      const handler = this._customHandlers.get(envelope.type);
      if (handler) {
        handler(envelope.payload);
      }
    }
    // HEARTBEAT, HEARTBEAT_ACK, etc. are no-ops at this layer
  }

  /** Drain queued messages after reconnection. Returns payloads. */
  drainMessageQueue(): Uint8Array[] {
    return this._messageQueue.drain().map(m => m.payload);
  }

  /** Close this session. */
  close(): void {
    const prev = this._state;
    this._state = 'disconnected';
    for (const listener of this._stateListeners) {
      listener(prev, 'disconnected');
    }
  }

  /** Transition state (for internal/test use). */
  _transitionState(to: ConnectionState): void {
    const prev = this._state;
    this._state = to;
    for (const listener of this._stateListeners) {
      listener(prev, to);
    }
  }
}

// --- Node ---

/**
 * A cairn node — the primary public API entry point.
 *
 * Wraps configuration, identity, and internal state. Provides methods for
 * pairing, connecting, and managing sessions with paired peers.
 */
export class Node {
  private readonly _config: ResolvedConfig;
  private readonly _sessions = new Map<string, NodeSession>();
  private readonly _peerPairedListeners: Array<(peerId: string) => void> = [];
  private readonly _peerUnpairedListeners: Array<(peerId: string) => void> = [];
  private readonly _errorListeners: Array<(error: CairnError) => void> = [];
  private readonly _customRegistry = new Map<number, (peerId: string, data: Uint8Array) => void>();
  private _natType: NatType = 'unknown';
  private _closed = false;
  private _identity: IdentityKeypair | null = null;
  private readonly _pairedPeers = new Set<string>();
  /** The libp2p node instance (null until startTransport is called). */
  private _libp2pNode: any = null;
  /** Listen addresses reported by the libp2p node. */
  private _listenAddresses: string[] = [];
  /** Connection hints from pairing, keyed by peer ID hex string. */
  private readonly _peerHints = new Map<string, ConnectionHint[]>();
  /**
   * In-progress inbound handshakes, keyed by remote libp2p PeerId string.
   * Stores the Noise responder and X25519 DH keypair from round 1.
   */
  private readonly _inboundHandshakes = new Map<string, { responder: NoiseXXHandshake; dhKeypair: X25519Keypair }>();
  /** Ed25519 private key seed (32 bytes) for the libp2p identity.
   *  When provided to startTransport(), produces a deterministic libp2p PeerId.
   *  null means a random identity will be generated. */
  private _libp2pPrivateKeySeed: Uint8Array | null = null;
  /**
   * Saved session states for resumption, keyed by remote libp2p PeerId string.
   * Populated after a successful handshake so that future connections can
   * skip the full Noise XX exchange.
   */
  private readonly _savedSessions = new Map<string, SavedSessionState>();
  /** Listeners called when a session state is saved (for external persistence). */
  private readonly _sessionSavedListeners: Array<(peerId: string, state: SavedSessionState) => void> = [];

  private constructor(config: ResolvedConfig) {
    this._config = config;
  }

  /** Create a new cairn peer node with zero-config defaults (Tier 0). */
  static async create(config?: Partial<CairnConfig>): Promise<Node> {
    const resolved = resolveConfig(config);
    const node = new Node(resolved);
    node._identity = await IdentityKeypair.generate();
    return node;
  }

  /**
   * Create a cairn node with a specific libp2p identity seed.
   *
   * This produces a deterministic libp2p PeerId, which is critical for
   * session persistence: the host identifies the browser by its PeerId,
   * so restoring the same seed after a page refresh allows the host
   * to recognize the reconnecting peer.
   *
   * @param config - Optional partial CairnConfig
   * @param libp2pSeed - 32-byte Ed25519 seed for the libp2p PeerId
   */
  static async createWithIdentity(
    config: Partial<CairnConfig> | undefined,
    libp2pSeed: Uint8Array,
  ): Promise<Node> {
    const resolved = resolveConfig(config);
    const node = new Node(resolved);
    node._identity = await IdentityKeypair.generate();
    node._libp2pPrivateKeySeed = new Uint8Array(libp2pSeed);
    return node;
  }

  /**
   * Create a server-mode cairn node.
   *
   * Server mode is NOT a separate class — it applies server-mode defaults:
   * meshEnabled: true, relayWilling: true, relayCapacity: 100, etc.
   */
  static async createServer(config?: Partial<CairnConfig>): Promise<Node> {
    const serverMeshDefaults = {
      meshEnabled: true,
      relayWilling: true,
      relayCapacity: 100,
      maxHops: 3,
    };
    const serverReconnectionDefaults: Partial<import('./config.js').ReconnectionPolicy> = {
      ...DEFAULT_RECONNECTION_POLICY,
      sessionExpiry: 7 * 24 * 60 * 60 * 1000,
      rendezvousPollInterval: 30_000,
      reconnectMaxDuration: Infinity,
    };

    const merged: Partial<CairnConfig> = {
      ...config,
      meshSettings: { ...serverMeshDefaults, ...config?.meshSettings },
      reconnectionPolicy: { ...serverReconnectionDefaults, ...config?.reconnectionPolicy },
    };
    const resolved = resolveConfig(merged);
    const node = new Node(resolved);
    node._identity = await IdentityKeypair.generate();
    return node;
  }

  /**
   * Create a node AND start the transport layer.
   * This is the recommended entry point for applications that need real
   * network connectivity.
   */
  static async createAndStart(config?: Partial<CairnConfig>): Promise<Node> {
    const node = await Node.create(config);
    await node.startTransport();
    return node;
  }

  /**
   * Start the libp2p transport layer.
   *
   * Creates a libp2p node with environment-appropriate transports
   * (WebRTC + WebSocket in browser, TCP + WebSocket in Node.js),
   * starts listening, registers the cairn protocol handler,
   * and populates listen addresses.
   *
   * Safe to skip in unit tests — the node works without transport.
   */
  async startTransport(): Promise<void> {
    const { createCairnNode, CAIRN_PROTOCOL, encodeFrame, readFrame } = await import("./transport/libp2p-node.js");
    const libp2pNode = await createCairnNode({
      ...(this._libp2pPrivateKeySeed ? { privateKeySeed: this._libp2pPrivateKeySeed } : {}),
    });
    await libp2pNode.start();
    this._libp2pNode = libp2pNode;

    // Register the cairn protocol handler for incoming streams
    libp2pNode.handle(CAIRN_PROTOCOL, async (data: { stream: any; connection: any }) => {
      const { stream, connection } = data;
      const remotePeerIdStr = connection.remotePeer.toString();

      try {
        // Read the incoming request frame
        const requestBytes = await readFrame(stream.source);
        const requestEnv = decodeEnvelope(requestBytes);

        if (requestEnv.type === HANDSHAKE_INIT) {
          // --- Inbound handshake round 1 ---
          await this._handleHandshakeInit(requestEnv, remotePeerIdStr, stream);
        } else if (requestEnv.type === HANDSHAKE_FINISH) {
          // --- Inbound handshake round 2 ---
          await this._handleHandshakeFinish(requestEnv, remotePeerIdStr, stream, connection.remotePeer);
        } else if (requestEnv.type === SESSION_RESUME) {
          // --- Session resume ---
          await this._handleSessionResume(requestEnv, remotePeerIdStr, stream, connection.remotePeer);
        } else if (requestEnv.type === DATA_MESSAGE || !isHandshakeType(requestEnv.type)) {
          // --- Regular data message ---
          const session = this._sessions.get(remotePeerIdStr);
          if (session) {
            session.dispatchIncoming(requestBytes);
          }
          // Send empty ACK response to complete the stream
          const ackFrame = encodeFrame(new Uint8Array(0));
          await stream.sink((async function* () {
            yield ackFrame;
          })());
        }
      } catch (err) {
        console.error('[cairn] Protocol handler error:', err);
        try { await stream.close(); } catch { /* ignore */ }
      }
    });

    // Collect listen addresses
    const addrs = libp2pNode.getMultiaddrs();
    this._listenAddresses = addrs.map((a: any) => a.toString());
  }

  /** Get the libp2p node (null if transport not started). */
  get libp2pNode(): unknown {
    return this._libp2pNode;
  }

  /** Get the node's listen addresses (available after startTransport). */
  get listenAddresses(): string[] {
    return [...this._listenAddresses];
  }

  /**
   * Look up a PeerId on the DHT using a PIN-derived key.
   * The host publishes HMAC("jaunt-pin-v1", PIN) → PeerId on the DHT.
   * Returns the PeerId string or null if not found.
   */
  async lookupPinOnDht(pin: string): Promise<string | null> {
    if (!this._libp2pNode) return null;
    try {
      // Compute the same HMAC key as the host
      const { hmac } = await import('@noble/hashes/hmac');
      const { sha256 } = await import('@noble/hashes/sha256');
      const key = hmac(sha256, new TextEncoder().encode('jaunt-pin-v1'), new TextEncoder().encode(pin));

      // Query the DHT for this key
      const dht = (this._libp2pNode as any).services?.dht;
      if (!dht) {
        console.warn('[cairn] No DHT service available for PIN lookup');
        return null;
      }

      // Use contentRouting to get the record
      const contentRouting = (this._libp2pNode as any).contentRouting;
      if (contentRouting?.get) {
        const result = await contentRouting.get(key);
        if (result) {
          return new TextDecoder().decode(result);
        }
      }
      return null;
    } catch (e) {
      console.warn('[cairn] DHT PIN lookup failed:', e);
      return null;
    }
  }

  /** Get the node configuration. */
  get config(): ResolvedConfig {
    return this._config;
  }

  /** Whether this node has been closed. */
  get isClosed(): boolean {
    return this._closed;
  }

  /** Get the node's identity keypair. */
  get identity(): IdentityKeypair | null {
    return this._identity;
  }

  /** Get the node's peer ID. */
  get peerId(): Uint8Array | null {
    return this._identity?.peerId() ?? null;
  }

  /**
   * Get the libp2p private key seed (32 bytes) for persisting the identity.
   *
   * After startTransport(), this returns the seed that was used to create
   * the libp2p node. If the node was created without a seed, this extracts
   * the seed from the running libp2p node so it can be saved and reused
   * on future createWithIdentity() calls.
   *
   * Returns null if transport has not been started.
   */
  get libp2pPrivateKeySeed(): Uint8Array | null {
    if (this._libp2pPrivateKeySeed) {
      return new Uint8Array(this._libp2pPrivateKeySeed);
    }
    // Extract from the running libp2p node if available
    if (this._libp2pNode) {
      try {
        const pk = (this._libp2pNode as any).privateKey;
        if (pk && pk.raw && pk.raw.length >= 32) {
          // libp2p Ed25519 raw key is 64 bytes: [32-byte seed][32-byte pubkey]
          const seed = pk.raw.slice(0, 32);
          this._libp2pPrivateKeySeed = new Uint8Array(seed);
          return new Uint8Array(seed);
        }
      } catch {
        // ignore
      }
    }
    return null;
  }

  /**
   * Get the libp2p PeerId string.
   * Returns the string representation of the libp2p peer ID (e.g. "12D3KooW...").
   * Returns null if transport has not been started.
   */
  get libp2pPeerId(): string | null {
    if (this._libp2pNode) {
      try {
        return (this._libp2pNode as any).peerId.toString();
      } catch {
        // ignore
      }
    }
    return null;
  }

  // --- Event listeners ---

  onPeerPaired(callback: (peerId: string) => void): void {
    this._peerPairedListeners.push(callback);
  }

  onPeerUnpaired(callback: (peerId: string) => void): void {
    this._peerUnpairedListeners.push(callback);
  }

  onError(callback: (error: CairnError) => void): void {
    this._errorListeners.push(callback);
  }

  /**
   * Register a callback invoked after a session's state is saved for resumption.
   *
   * This is called after every successful handshake (both initiator and responder).
   * Consumers can use this to persist the state to IndexedDB, disk, etc.
   */
  onSessionSaved(callback: (peerId: string, state: SavedSessionState) => void): void {
    this._sessionSavedListeners.push(callback);
  }

  /**
   * Register a node-wide handler for a custom message type (0xF000-0xFFFF).
   *
   * Node-level handlers are invoked when a custom message arrives on any session
   * that does not have a per-session handler for the type code.
   */
  registerCustomMessage(typeCode: number, handler: (peerId: string, data: Uint8Array) => void): void {
    if (typeCode < APP_MSG_TYPE_MIN || typeCode > APP_MSG_TYPE_MAX) {
      throw new CairnError(
        'PROTOCOL',
        `custom message type 0x${typeCode.toString(16).padStart(4, '0')} outside application range 0xF000-0xFFFF`,
      );
    }
    this._customRegistry.set(typeCode, handler);
  }

  // --- Internal helpers ---

  private _createPairingPayload(): PairingPayload {
    if (!this._identity) {
      throw new CairnError('PROTOCOL', 'node identity not initialized');
    }
    const nonce = generateNonce();
    const now = Math.floor(Date.now() / 1000);
    const ttlSec = Math.floor(this._config.reconnectionPolicy.pairingPayloadExpiry / 1000);

    // Include listen addresses as connection hints if transport is running
    const hints: ConnectionHint[] | undefined = this._listenAddresses.length > 0
      ? this._listenAddresses.map(addr => ({ hintType: 'multiaddr', value: addr }))
      : undefined;

    return {
      peerId: this._identity.peerId(),
      nonce,
      pakeCredential: nonce,
      hints,
      createdAt: now,
      expiresAt: now + ttlSec,
    };
  }

  private _runPairingExchange(password: Uint8Array): void {
    const alice = Spake2.startA(password);
    const bob = Spake2.startB(password);
    alice.finish(bob.outboundMsg);
    bob.finish(alice.outboundMsg);
  }

  private _completePairing(remotePeerId: string): void {
    this._pairedPeers.add(remotePeerId);
    for (const listener of this._peerPairedListeners) {
      listener(remotePeerId);
    }
  }

  private async _performNoiseHandshake(): Promise<HandshakeResult> {
    if (!this._identity) {
      throw new CairnError('PROTOCOL', 'node identity not initialized');
    }
    const remoteId = await IdentityKeypair.generate();
    const initiator = new NoiseXXHandshake('initiator', this._identity);
    const responder = new NoiseXXHandshake('responder', remoteId);

    const out1 = initiator.step();
    if (out1.type !== 'send_message') throw new CairnError('CRYPTO', 'unexpected at msg1');

    const out2 = responder.step(out1.data);
    if (out2.type !== 'send_message') throw new CairnError('CRYPTO', 'unexpected at msg2');

    const out3 = initiator.step(out2.data);
    if (out3.type !== 'send_message') throw new CairnError('CRYPTO', 'unexpected at msg3');

    responder.step(out3.data);
    return initiator.getResult();
  }

  // --- Pairing methods (spec section 3.3) ---

  async pairGenerateQr(): Promise<QrPairingData> {
    const payload = this._createPairingPayload();
    const cbor = generateQrPayload(payload);
    return {
      payload: cbor,
      expiresIn: this._config.reconnectionPolicy.pairingPayloadExpiry,
    };
  }

  async pairScanQr(data: Uint8Array): Promise<string> {
    const payload = consumeQrPayload(data);
    this._runPairingExchange(payload.pakeCredential);
    const remotePeerId = bytesToHex(payload.peerId);
    // Store connection hints from the remote peer for later dialing
    if (payload.hints && payload.hints.length > 0) {
      this._peerHints.set(remotePeerId, payload.hints);
    }
    this._completePairing(remotePeerId);
    return remotePeerId;
  }

  async pairGeneratePin(): Promise<PinPairingData> {
    const raw = generatePin();
    return {
      pin: formatPin(raw),
      expiresIn: this._config.reconnectionPolicy.pairingPayloadExpiry,
    };
  }

  async pairEnterPin(pin: string): Promise<string> {
    const normalized = normalizePin(pin);
    validatePin(normalized);
    const password = new TextEncoder().encode(normalized);
    this._runPairingExchange(password);
    // In a real implementation, the remote peer ID would come from the pairing exchange
    const remotePeerId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    this._completePairing(remotePeerId);
    return remotePeerId;
  }

  async pairGenerateLink(): Promise<LinkPairingData> {
    const payload = this._createPairingPayload();
    const uri = generatePairingLink(payload);
    return {
      uri,
      expiresIn: this._config.reconnectionPolicy.pairingPayloadExpiry,
    };
  }

  async pairFromLink(uri: string): Promise<string> {
    const payload = parsePairingLink(uri);
    this._runPairingExchange(payload.pakeCredential);
    const remotePeerId = bytesToHex(payload.peerId);
    this._completePairing(remotePeerId);
    return remotePeerId;
  }

  // --- Connection methods ---

  /** Connect to a paired peer. Dials via libp2p if transport is started, falls back to in-memory handshake. */
  async connect(peerId: string, _options?: { signal?: AbortSignal }): Promise<NodeSession> {
    // If transport is started AND we have connection hints, dial via libp2p
    if (this._libp2pNode && this._peerHints.has(peerId)) {
      const hints = this._peerHints.get(peerId)!;
      const { multiaddr } = await import('@multiformats/multiaddr');

      // Try each hint address until one works (prefer /ws for browser compat)
      const wsHints = hints.filter(h => h.hintType === 'multiaddr' && h.value.includes('/ws'));
      const tcpHints = hints.filter(h => h.hintType === 'multiaddr' && h.value.includes('/tcp/') && !h.value.includes('/ws'));
      const allHints = [...wsHints, ...tcpHints];

      let connected = false;
      for (const hint of allHints) {
        try {
          const ma = multiaddr(hint.value);
          await this._libp2pNode.dial(ma);
          connected = true;
          break;
        } catch {
          // Try next address
        }
      }

      if (!connected && allHints.length > 0) {
        throw new CairnError('TRANSPORT', `failed to connect to peer ${peerId} via any address`);
      }
    }

    // Perform crypto handshake (in-memory for now — will be over libp2p stream in future)
    const handshakeResult = await this._performNoiseHandshake();
    const bobDh = X25519Keypair.generate();
    const ratchet = DoubleRatchet.initSender(handshakeResult.sessionKey, bobDh.publicKeyBytes());
    const session = new NodeSession(peerId);
    session._setRatchet(ratchet);
    this._sessions.set(peerId, session);
    return session;
  }

  /** Unpair a peer, removing trust and closing sessions. */
  async unpair(peerId: string): Promise<void> {
    this._pairedPeers.delete(peerId);
    this._sessions.delete(peerId);
    for (const listener of this._peerUnpairedListeners) {
      listener(peerId);
    }
  }

  /** Get network diagnostic information. */
  async networkInfo(): Promise<{ natType: NatType }> {
    return { natType: this._natType };
  }

  /** Update the detected NAT type (called by transport layer). */
  setNatType(natType: NatType): void {
    this._natType = natType;
  }

  // --- Transport handshake methods ---

  /**
   * Connect to a remote peer over the transport layer (libp2p).
   *
   * Performs a 2-round Noise XX handshake over the cairn protocol,
   * creates a session with a matching Double Ratchet, and returns it.
   *
   * Requires `startTransport()` to have been called first.
   *
   * @param remotePeerId - The remote peer's libp2p PeerId string
   * @param addrs - Multiaddr strings for the remote peer
   */
  async connectTransport(remotePeerId: string, addrs: string[]): Promise<NodeSession> {
    if (!this._libp2pNode) {
      throw new CairnError('TRANSPORT', 'transport not started');
    }
    if (!this._identity) {
      throw new CairnError('PROTOCOL', 'node identity not initialized');
    }

    const { multiaddr } = await import('@multiformats/multiaddr');
    const { peerIdFromString } = await import('@libp2p/peer-id');
    const { CAIRN_PROTOCOL, encodeFrame, readFrame } = await import('./transport/libp2p-node.js');

    const remotePid = peerIdFromString(remotePeerId);

    // Dial the remote peer. Try explicit addresses first, then PeerId-only
    // (which triggers DHT discovery if Kademlia is configured).
    let connected = false;
    for (const addrStr of addrs) {
      try {
        const withPeerId = addrStr.includes('/p2p/')
          ? addrStr
          : `${addrStr}/p2p/${remotePeerId}`;
        const ma = multiaddr(withPeerId);
        await this._libp2pNode.dial(ma);
        connected = true;
        break;
      } catch (e) {
        console.warn(`[cairn] dial ${addrStr} failed:`, e);
      }
    }
    // If no explicit addresses worked (or none provided), try dialing by
    // PeerId alone — libp2p will query Kademlia DHT for the peer's addresses.
    if (!connected) {
      try {
        console.log(`[cairn] Trying DHT discovery for peer ${remotePeerId}...`);
        await this._libp2pNode.dial(remotePid);
        connected = true;
        console.log(`[cairn] Connected via DHT discovery`);
      } catch (e) {
        console.warn(`[cairn] DHT discovery failed:`, e);
      }
    }
    if (!connected) {
      throw new CairnError('TRANSPORT', `could not dial any address for peer ${remotePeerId}`);
    }

    // --- Handshake round 1: INIT -> RESPONSE ---
    const initiator = new NoiseXXHandshake('initiator', this._identity);
    const out1 = initiator.step();
    if (out1.type !== 'send_message') {
      throw new CairnError('CRYPTO', 'unexpected handshake state at msg1');
    }

    const initEnvelope: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_INIT,
      msgId: newMsgId(),
      payload: out1.data,
    };

    // Send INIT, read RESPONSE
    const stream1 = await this._libp2pNode.dialProtocol(remotePid, CAIRN_PROTOCOL);
    const initFrame = encodeFrame(encodeEnvelope(initEnvelope));
    await stream1.sink((async function* () {
      yield initFrame;
    })());

    const responseBytes = await readFrame(stream1.source);
    const responseEnv = decodeEnvelope(responseBytes);

    if (responseEnv.type !== HANDSHAKE_RESPONSE) {
      throw new CairnError('PROTOCOL', `expected HANDSHAKE_RESPONSE (0x01e1), got 0x${responseEnv.type.toString(16).padStart(4, '0')}`);
    }

    // Extract responder's DH public key from auth_tag
    if (!responseEnv.authTag) {
      throw new CairnError('PROTOCOL', 'HANDSHAKE_RESPONSE missing DH public key');
    }
    if (responseEnv.authTag.length !== 32) {
      throw new CairnError('PROTOCOL', 'DH public key must be 32 bytes');
    }
    const dhPublicBytes = responseEnv.authTag;

    // Process Noise msg2, produce msg3
    const out3 = initiator.step(responseEnv.payload);
    if (out3.type !== 'send_message') {
      throw new CairnError('CRYPTO', 'unexpected handshake state at msg3');
    }

    // --- Handshake round 2: FINISH -> ACK ---
    const finishEnvelope: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_FINISH,
      msgId: newMsgId(),
      payload: out3.data,
    };

    const stream2 = await this._libp2pNode.dialProtocol(remotePid, CAIRN_PROTOCOL);
    const finishFrame = encodeFrame(encodeEnvelope(finishEnvelope));
    await stream2.sink((async function* () {
      yield finishFrame;
    })());

    const ackBytes = await readFrame(stream2.source);
    const ackEnv = decodeEnvelope(ackBytes);

    if (ackEnv.type !== HANDSHAKE_ACK) {
      throw new CairnError('PROTOCOL', `expected HANDSHAKE_ACK (0x01e3), got 0x${ackEnv.type.toString(16).padStart(4, '0')}`);
    }

    // Handshake complete -- derive session key and create ratchet
    const hsResult = initiator.getResult();
    const ratchet = DoubleRatchet.initSender(hsResult.sessionKey, dhPublicBytes);

    const session = new NodeSession(remotePeerId);
    const sessionId = crypto.getRandomValues(new Uint8Array(16));
    session._setSessionId(sessionId);
    session._setRatchet(ratchet);
    session._setTransport(this._libp2pNode, remotePid);
    this._sessions.set(remotePeerId, session);

    // Save session state for future resumption
    this._saveSessionForResume(remotePeerId, session);

    return session;
  }

  /**
   * Resume a session with a remote peer without a full Noise XX handshake.
   *
   * Uses the saved DoubleRatchet state and a resumption proof to prove
   * prior session ownership in a single round-trip.
   *
   * @param remotePeerId - The remote peer's libp2p PeerId string
   * @param addrs - Multiaddr strings for the remote peer
   * @param savedState - Previously exported session state
   * @throws CairnError with code 'SESSION_EXPIRED' if the host rejects the resume
   */
  async tryResumeTransport(
    remotePeerId: string,
    addrs: string[],
    savedState: {
      sessionId: Uint8Array;
      ratchetState: object;
      sequenceTx: number;
      sequenceRx: number;
    },
  ): Promise<NodeSession> {
    if (!this._libp2pNode) {
      throw new CairnError('TRANSPORT', 'transport not started');
    }

    const { encode } = await import('cborg');
    const { multiaddr } = await import('@multiformats/multiaddr');
    const { peerIdFromString } = await import('@libp2p/peer-id');
    const { CAIRN_PROTOCOL, encodeFrame, readFrame } = await import('./transport/libp2p-node.js');

    const remotePid = peerIdFromString(remotePeerId);

    // Dial the remote peer (same as connectTransport)
    let connected = false;
    for (const addrStr of addrs) {
      try {
        const withPeerId = addrStr.includes('/p2p/')
          ? addrStr
          : `${addrStr}/p2p/${remotePeerId}`;
        const ma = multiaddr(withPeerId);
        await this._libp2pNode.dial(ma);
        connected = true;
        break;
      } catch (e) {
        console.warn(`[cairn] resume dial ${addrStr} failed:`, e);
      }
    }
    if (!connected) {
      throw new CairnError('TRANSPORT', `could not dial any address for peer ${remotePeerId}`);
    }

    // Restore ratchet and derive resumption key
    const ratchet = DoubleRatchet.fromExportedState(savedState.ratchetState);
    const resumptionKey = ratchet.deriveResumptionKey();

    // Generate proof
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const timestamp = Math.floor(Date.now() / 1000);
    const sessionId = savedState.sessionId instanceof Uint8Array
      ? savedState.sessionId
      : new Uint8Array(savedState.sessionId);
    const proof = generateResumeProof(resumptionKey, sessionId, nonce, timestamp);

    // Build SESSION_RESUME payload as CBOR map
    const resumePayload = encode(new Map<string, unknown>([
      ['session_id', sessionId],
      ['proof', proof],
      ['last_rx_sequence', savedState.sequenceRx],
      ['nonce', nonce],
      ['timestamp', timestamp],
    ]));

    const resumeEnvelope: MessageEnvelope = {
      version: 1,
      type: SESSION_RESUME,
      msgId: newMsgId(),
      payload: resumePayload,
    };

    // Send SESSION_RESUME, read response
    const stream = await this._libp2pNode.dialProtocol(remotePid, CAIRN_PROTOCOL);
    const resumeFrame = encodeFrame(encodeEnvelope(resumeEnvelope));
    await stream.sink((async function* () {
      yield resumeFrame;
    })());

    const responseBytes = await readFrame(stream.source);
    const responseEnv = decodeEnvelope(responseBytes);

    if (responseEnv.type === SESSION_EXPIRED) {
      throw new CairnError('SESSION_EXPIRED', 'remote peer rejected session resume');
    }

    if (responseEnv.type !== SESSION_RESUME_ACK) {
      throw new CairnError('PROTOCOL', `expected SESSION_RESUME_ACK, got 0x${responseEnv.type.toString(16).padStart(4, '0')}`);
    }

    // Parse ACK payload to get remote's last_rx_sequence
    const { decode: cborDecode } = await import('cborg');
    const ackPayload = cborDecode(responseEnv.payload, { useMaps: true }) as Map<string, unknown>;
    const remoteLastRx = (ackPayload.get('last_rx_sequence') ?? 0) as number;

    // Create session with restored ratchet
    const session = new NodeSession(remotePeerId);
    session._setSessionId(sessionId);
    session._setRatchet(ratchet);
    session._setTransport(this._libp2pNode, remotePid);
    session._setSequenceTx(savedState.sequenceTx);
    session._setSequenceRx(savedState.sequenceRx);
    this._sessions.set(remotePeerId, session);

    // Save updated session state
    this._saveSessionForResume(remotePeerId, session);

    console.log(`[cairn] Session resumed with ${remotePeerId} (remote lastRx=${remoteLastRx})`);
    return session;
  }

  /**
   * Handle an inbound HANDSHAKE_INIT message (round 1 of the handshake).
   * Creates a Noise responder, processes msg1, sends HANDSHAKE_RESPONSE with
   * the DH public key in the auth_tag field.
   */
  private async _handleHandshakeInit(
    requestEnv: MessageEnvelope,
    remotePeerIdStr: string,
    stream: any,
  ): Promise<void> {
    if (!this._identity) {
      throw new CairnError('PROTOCOL', 'node identity not initialized');
    }

    const { encodeFrame } = await import('./transport/libp2p-node.js');

    const responder = new NoiseXXHandshake('responder', this._identity);
    const out2 = responder.step(requestEnv.payload);
    if (out2.type !== 'send_message') {
      throw new CairnError('CRYPTO', 'unexpected handshake state at msg2');
    }

    // Generate DH keypair for Double Ratchet
    const dhKeypair = X25519Keypair.generate();

    const responseEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_RESPONSE,
      msgId: newMsgId(),
      payload: out2.data,
      authTag: dhKeypair.publicKeyBytes(),
    };

    const responseFrame = encodeFrame(encodeEnvelope(responseEnv));
    await stream.sink((async function* () {
      yield responseFrame;
    })());

    // Store handshake state for round 2
    this._inboundHandshakes.set(remotePeerIdStr, { responder, dhKeypair });
  }

  /**
   * Handle an inbound HANDSHAKE_FINISH message (round 2 of the handshake).
   * Completes the Noise handshake, creates a session with Double Ratchet,
   * and sends HANDSHAKE_ACK.
   */
  private async _handleHandshakeFinish(
    requestEnv: MessageEnvelope,
    remotePeerIdStr: string,
    stream: any,
    remotePeerId: any,
  ): Promise<void> {
    const { encodeFrame } = await import('./transport/libp2p-node.js');

    const hsEntry = this._inboundHandshakes.get(remotePeerIdStr);
    if (!hsEntry) {
      throw new CairnError('PROTOCOL', 'no pending handshake for this peer');
    }
    this._inboundHandshakes.delete(remotePeerIdStr);

    const { responder, dhKeypair } = hsEntry;
    const out = responder.step(requestEnv.payload);
    if (out.type !== 'complete') {
      throw new CairnError('CRYPTO', 'expected handshake completion at msg3');
    }

    // Create session with Double Ratchet (responder/receiver side)
    const ratchet = DoubleRatchet.initReceiver(out.result.sessionKey, dhKeypair);

    const session = new NodeSession(remotePeerIdStr);
    const sessionId = crypto.getRandomValues(new Uint8Array(16));
    session._setSessionId(sessionId);
    session._setRatchet(ratchet);
    session._setTransport(this._libp2pNode, remotePeerId);
    this._sessions.set(remotePeerIdStr, session);

    // Save session state for future resumption
    this._saveSessionForResume(remotePeerIdStr, session);

    // Send ACK
    const ackEnv: MessageEnvelope = {
      version: 1,
      type: HANDSHAKE_ACK,
      msgId: newMsgId(),
      payload: new Uint8Array(0),
    };

    const ackFrame = encodeFrame(encodeEnvelope(ackEnv));
    await stream.sink((async function* () {
      yield ackFrame;
    })());
  }

  /**
   * Handle an inbound SESSION_RESUME message.
   *
   * Validates the resume proof against saved session state, and if valid,
   * restores the session with the saved ratchet. Sends SESSION_RESUME_ACK
   * on success or SESSION_EXPIRED on failure.
   */
  private async _handleSessionResume(
    requestEnv: MessageEnvelope,
    remotePeerIdStr: string,
    stream: any,
    remotePeerId: any,
  ): Promise<void> {
    const { encode: cborEncode, decode: cborDecode } = await import('cborg');
    const { encodeFrame } = await import('./transport/libp2p-node.js');

    // Helper to send SESSION_EXPIRED and return
    const sendExpired = async () => {
      const expiredEnv: MessageEnvelope = {
        version: 1,
        type: SESSION_EXPIRED,
        msgId: newMsgId(),
        payload: new Uint8Array(0),
      };
      const expiredFrame = encodeFrame(encodeEnvelope(expiredEnv));
      await stream.sink((async function* () {
        yield expiredFrame;
      })());
    };

    try {
      // Decode the resume payload
      const payloadMap = cborDecode(requestEnv.payload, { useMaps: true }) as Map<string, unknown>;
      const sessionId = payloadMap.get('session_id') as Uint8Array;
      const proof = payloadMap.get('proof') as Uint8Array;
      const lastRxSequence = (payloadMap.get('last_rx_sequence') ?? 0) as number;
      const nonce = payloadMap.get('nonce') as Uint8Array;
      const timestamp = payloadMap.get('timestamp') as number;

      if (!sessionId || !proof || !nonce || timestamp === undefined) {
        console.warn('[cairn] SESSION_RESUME: missing fields');
        await sendExpired();
        return;
      }

      // Look up saved session by session ID
      const sessionIdHex = bytesToHex(sessionId);
      let savedState: SavedSessionState | undefined;
      for (const [, state] of this._savedSessions) {
        if (bytesToHex(state.sessionId) === sessionIdHex) {
          savedState = state;
          break;
        }
      }

      if (!savedState) {
        console.warn('[cairn] SESSION_RESUME: no saved session for ID', sessionIdHex);
        await sendExpired();
        return;
      }

      // Check timestamp freshness (within 5 minutes)
      const nowSec = Math.floor(Date.now() / 1000);
      if (Math.abs(nowSec - timestamp) > SESSION_RESUME_TIMESTAMP_WINDOW_SEC) {
        console.warn('[cairn] SESSION_RESUME: timestamp out of range');
        await sendExpired();
        return;
      }

      // Restore ratchet and verify proof
      const ratchet = DoubleRatchet.fromExportedState(savedState.ratchetState);
      const resumptionKey = ratchet.deriveResumptionKey();

      if (!verifyResumeProof(resumptionKey, sessionId, nonce, timestamp, proof)) {
        console.warn('[cairn] SESSION_RESUME: invalid proof');
        await sendExpired();
        return;
      }

      // Valid! Create restored session
      const session = new NodeSession(remotePeerIdStr);
      session._setSessionId(sessionId);
      session._setRatchet(ratchet);
      session._setTransport(this._libp2pNode, remotePeerId);
      session._setSequenceTx(savedState.sequenceTx);
      session._setSequenceRx(savedState.sequenceRx);
      this._sessions.set(remotePeerIdStr, session);

      // Save updated state
      this._saveSessionForResume(remotePeerIdStr, session);

      // Send ACK with our last_rx_sequence
      const ackPayload = cborEncode(new Map<string, unknown>([
        ['last_rx_sequence', savedState.sequenceRx],
      ]));

      const ackEnv: MessageEnvelope = {
        version: 1,
        type: SESSION_RESUME_ACK,
        msgId: newMsgId(),
        payload: ackPayload,
      };

      const ackFrame = encodeFrame(encodeEnvelope(ackEnv));
      await stream.sink((async function* () {
        yield ackFrame;
      })());

      console.log(`[cairn] Session resume accepted for ${remotePeerIdStr}`);
    } catch (err) {
      console.error('[cairn] SESSION_RESUME handler error:', err);
      await sendExpired();
    }
  }

  /**
   * Save session state internally and notify listeners.
   * Called after a successful handshake or resume.
   */
  private _saveSessionForResume(remotePeerIdStr: string, session: NodeSession): void {
    if (!session.ratchet || !session.sessionId) return;

    const state: SavedSessionState = {
      sessionId: new Uint8Array(session.sessionId),
      ratchetState: session.ratchet.exportStateObject(),
      sequenceTx: session.sequenceTx,
      sequenceRx: session.sequenceRx,
      savedAt: Date.now(),
    };

    this._savedSessions.set(remotePeerIdStr, state);

    // Notify listeners
    for (const listener of this._sessionSavedListeners) {
      try {
        listener(remotePeerIdStr, state);
      } catch (e) {
        console.error('[cairn] sessionSaved listener error:', e);
      }
    }
  }

  /** Get a saved session state by peer ID (for testing/external persistence). */
  getSavedSession(peerId: string): SavedSessionState | undefined {
    return this._savedSessions.get(peerId);
  }

  /** Restore a saved session state (for loading from external persistence). */
  restoreSavedSession(peerId: string, state: SavedSessionState): void {
    this._savedSessions.set(peerId, state);
  }

  /** Get a session by peer ID string (for testing). */
  getSession(peerId: string): NodeSession | undefined {
    return this._sessions.get(peerId);
  }

  /** Close the node and all sessions. */
  async close(): Promise<void> {
    this._closed = true;
    for (const session of this._sessions.values()) {
      session.close();
    }
    this._sessions.clear();
    if (this._libp2pNode) {
      try { await this._libp2pNode.stop(); } catch { /* ignore */ }
    }
  }
}

// --- Config resolution ---

function resolveConfig(partial?: Partial<CairnConfig>): ResolvedConfig {
  return {
    stunServers: partial?.stunServers ?? [...DEFAULT_STUN_SERVERS],
    turnServers: partial?.turnServers ?? [],
    signalingServers: partial?.signalingServers ?? [],
    trackerUrls: partial?.trackerUrls ?? [],
    bootstrapNodes: partial?.bootstrapNodes ?? [],
    transportPreferences: partial?.transportPreferences ?? [...DEFAULT_TRANSPORT_PREFERENCES],
    reconnectionPolicy: {
      connectTimeout: DEFAULT_RECONNECTION_POLICY.connectTimeout,
      transportTimeout: DEFAULT_RECONNECTION_POLICY.transportTimeout,
      reconnectMaxDuration: DEFAULT_RECONNECTION_POLICY.reconnectMaxDuration,
      reconnectBackoff: {
        ...DEFAULT_RECONNECTION_POLICY.reconnectBackoff,
        ...partial?.reconnectionPolicy?.reconnectBackoff,
      },
      rendezvousPollInterval: DEFAULT_RECONNECTION_POLICY.rendezvousPollInterval,
      sessionExpiry: DEFAULT_RECONNECTION_POLICY.sessionExpiry,
      pairingPayloadExpiry: DEFAULT_RECONNECTION_POLICY.pairingPayloadExpiry,
      ...partial?.reconnectionPolicy,
    },
    meshSettings: {
      meshEnabled: DEFAULT_MESH_SETTINGS.meshEnabled,
      maxHops: DEFAULT_MESH_SETTINGS.maxHops,
      relayWilling: DEFAULT_MESH_SETTINGS.relayWilling,
      relayCapacity: DEFAULT_MESH_SETTINGS.relayCapacity,
      ...partial?.meshSettings,
    },
    storageBackend: partial?.storageBackend ?? 'memory',
  };
}

/** Convert bytes to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
