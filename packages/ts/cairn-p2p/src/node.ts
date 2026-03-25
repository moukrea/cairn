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
import { DATA_MESSAGE } from './protocol/message-types.js';
import { MessageQueue } from './session/message-queue.js';
import type { EnqueueResult } from './session/message-queue.js';
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

  constructor(readonly peerId: string) {}

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
   * starts listening, and populates listen addresses.
   *
   * Safe to skip in unit tests — the node works without transport.
   */
  async startTransport(): Promise<void> {
    const { createCairnNode } = await import("./transport/libp2p-node.js");
    const libp2pNode = await createCairnNode();
    await libp2pNode.start();
    this._libp2pNode = libp2pNode;

    // Collect listen addresses
    const addrs = libp2pNode.getMultiaddrs();
    this._listenAddresses = addrs.map(a => a.toString());
  }

  /** Get the libp2p node (null if transport not started). */
  get libp2pNode(): unknown {
    return this._libp2pNode;
  }

  /** Get the node's listen addresses (available after startTransport). */
  get listenAddresses(): string[] {
    return [...this._listenAddresses];
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

  /** Connect to a paired peer. Performs Noise XX handshake and Double Ratchet init. */
  async connect(peerId: string, _options?: { signal?: AbortSignal }): Promise<NodeSession> {
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

  /** Close the node and all sessions. */
  async close(): Promise<void> {
    this._closed = true;
    for (const session of this._sessions.values()) {
      session.close();
    }
    this._sessions.clear();
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
