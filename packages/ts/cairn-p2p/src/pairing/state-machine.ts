import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { CairnError } from '../errors.js';
import { hkdfSha256 } from '../crypto/hkdf.js';
import { Spake2 } from '../crypto/spake2.js';
import { generateNonce } from './payload.js';

/** HKDF info string for pairing session key derivation. Must match Rust. */
const HKDF_INFO_PAIRING_SESSION = new TextEncoder().encode('cairn-pairing-session-key-v1');

/** HMAC key derivation info for key confirmation. Must match Rust. */
const HKDF_INFO_KEY_CONFIRM = new TextEncoder().encode('cairn-pairing-key-confirm-v1');

/** Default pairing timeout in milliseconds (5 minutes). */
export const DEFAULT_PAIRING_TIMEOUT_MS = 300_000;

/** Pairing flow type. */
export type PairingFlowType = 'initiation' | 'standard';

/** Pairing session state. */
export type PairingState =
  | 'idle'
  | 'awaiting_pake_exchange'
  | 'awaiting_verification'
  | 'awaiting_confirmation'
  | 'completed'
  | 'failed';

/** Whether this session is acting as initiator or responder. */
export type PairingRole = 'initiator' | 'responder';

/** Rejection reasons. */
export type PairRejectReason =
  | 'user_rejected'
  | 'authentication_failed'
  | 'timeout'
  | 'rate_limited';

/** Union of pairing messages exchanged during the handshake. */
export type PairingMessage =
  | { type: 'request'; peerId: Uint8Array; nonce: Uint8Array; pakeMsg?: Uint8Array; flowType: PairingFlowType }
  | { type: 'challenge'; peerId: Uint8Array; nonce: Uint8Array; pakeMsg: Uint8Array }
  | { type: 'response'; keyConfirmation: Uint8Array }
  | { type: 'confirm'; keyConfirmation: Uint8Array }
  | { type: 'reject'; reason: PairRejectReason };

/**
 * A pairing session driving the SPAKE2 exchange and state transitions.
 *
 * Follows the Rust PairingSession state machine:
 * - Initiation flow: PairRequest -> PairChallenge -> PairResponse -> PairConfirm
 * - Standard flow: PairRequest -> (SAS verification) -> PairResponse -> PairConfirm
 */
export class PairingSession {
  private _state: PairingState;
  private readonly _role: PairingRole;
  private readonly _flowType: PairingFlowType;
  private readonly _localNonce: Uint8Array;
  private _remoteNonce: Uint8Array | null = null;
  private _remotePeerId: Uint8Array | null = null;
  private _spake2: Spake2 | null;
  private _spake2Outbound: Uint8Array | null;
  private _sharedKey: Uint8Array | null = null;
  private readonly _createdAt: number;
  private readonly _timeoutMs: number;

  private constructor(
    role: PairingRole,
    flowType: PairingFlowType,
    spake2: Spake2 | null,
    spake2Outbound: Uint8Array | null,
    initialState: PairingState,
    timeoutMs: number,
  ) {
    this._role = role;
    this._flowType = flowType;
    this._spake2 = spake2;
    this._spake2Outbound = spake2Outbound;
    this._state = initialState;
    this._localNonce = generateNonce();
    this._createdAt = Date.now();
    this._timeoutMs = timeoutMs;
  }

  /**
   * Create a new initiator session for the initiation flow (SPAKE2).
   * Returns the session and the outbound PairRequest message.
   */
  static newInitiator(
    localPeerId: Uint8Array,
    password: Uint8Array,
    timeoutMs: number = DEFAULT_PAIRING_TIMEOUT_MS,
  ): { session: PairingSession; message: PairingMessage } {
    const spake2 = Spake2.startA(password);
    const session = new PairingSession(
      'initiator',
      'initiation',
      spake2,
      null,
      'awaiting_pake_exchange',
      timeoutMs,
    );

    const message: PairingMessage = {
      type: 'request',
      peerId: localPeerId,
      nonce: session._localNonce,
      pakeMsg: spake2.outboundMsg,
      flowType: 'initiation',
    };

    return { session, message };
  }

  /**
   * Create a new initiator session for the standard flow (no SPAKE2).
   * Returns the session and the outbound PairRequest message.
   */
  static newStandardInitiator(
    localPeerId: Uint8Array,
    timeoutMs: number = DEFAULT_PAIRING_TIMEOUT_MS,
  ): { session: PairingSession; message: PairingMessage } {
    const session = new PairingSession(
      'initiator',
      'standard',
      null,
      null,
      'awaiting_verification',
      timeoutMs,
    );

    const message: PairingMessage = {
      type: 'request',
      peerId: localPeerId,
      nonce: session._localNonce,
      flowType: 'standard',
    };

    return { session, message };
  }

  /**
   * Create a new responder session for the initiation flow (SPAKE2).
   */
  static newResponder(
    password: Uint8Array,
    timeoutMs: number = DEFAULT_PAIRING_TIMEOUT_MS,
  ): PairingSession {
    const spake2 = Spake2.startB(password);
    return new PairingSession(
      'responder',
      'initiation',
      spake2,
      spake2.outboundMsg,
      'idle',
      timeoutMs,
    );
  }

  /**
   * Create a new responder session for the standard flow (no SPAKE2).
   */
  static newStandardResponder(
    timeoutMs: number = DEFAULT_PAIRING_TIMEOUT_MS,
  ): PairingSession {
    return new PairingSession(
      'responder',
      'standard',
      null,
      null,
      'idle',
      timeoutMs,
    );
  }

  /** Get the current state. */
  get state(): PairingState { return this._state; }

  /** Get the role. */
  get role(): PairingRole { return this._role; }

  /** Get the flow type. */
  get flowType(): PairingFlowType { return this._flowType; }

  /** Get the remote peer ID (if known). */
  get remotePeerId(): Uint8Array | null { return this._remotePeerId; }

  /** Get the shared key (only available in completed state). */
  get sharedKey(): Uint8Array | null {
    if (this._state === 'completed') {
      return this._sharedKey;
    }
    return null;
  }

  /** Check if this session has expired. */
  get isExpired(): boolean {
    return this._timeoutMs === 0 || Date.now() - this._createdAt > this._timeoutMs;
  }

  /** Set a pre-established shared key (from Noise XX handshake, standard flow). */
  setSharedKey(key: Uint8Array): void {
    this._sharedKey = new Uint8Array(key);
  }

  /** Set remote nonce (for standard flow where nonces are exchanged separately). */
  setRemoteNonce(nonce: Uint8Array): void {
    this._remoteNonce = new Uint8Array(nonce);
  }

  /**
   * After SAS verification (standard flow), produce a key confirmation
   * message and advance to awaiting_confirmation.
   */
  sendKeyConfirmation(_localPeerId: Uint8Array): PairingMessage {
    if (this._state !== 'awaiting_verification') {
      throw new CairnError('PAIRING', `invalid state for key confirmation: expected awaiting_verification, got ${this._state}`);
    }

    const label = this._role === 'initiator' ? 'initiator' : 'responder';
    const confirmation = this.computeKeyConfirmation(label);
    this._state = 'awaiting_confirmation';

    if (this._role === 'initiator') {
      return { type: 'response', keyConfirmation: confirmation };
    }
    return { type: 'confirm', keyConfirmation: confirmation };
  }

  /**
   * Process an incoming pairing message. Returns an optional outbound response.
   */
  handleMessage(msg: PairingMessage, localPeerId?: Uint8Array): PairingMessage | null {
    if (this.isExpired) {
      this._state = 'failed';
      throw new CairnError('PAIRING', `pairing timed out after ${this._timeoutMs}ms`);
    }

    switch (msg.type) {
      case 'request': return this.handleRequest(msg, localPeerId);
      case 'challenge': return this.handleChallenge(msg);
      case 'response': return this.handleResponse(msg);
      case 'confirm': return this.handleConfirm(msg);
      case 'reject': return this.handleReject(msg);
    }
  }

  // --- Message handlers ---

  private handleRequest(
    req: Extract<PairingMessage, { type: 'request' }>,
    localPeerId?: Uint8Array,
  ): PairingMessage | null {
    if (this._role !== 'responder') {
      throw new CairnError('PAIRING', 'initiator cannot handle PairRequest');
    }
    if (this._state !== 'idle') {
      throw new CairnError('PAIRING', `invalid state for PairRequest: expected idle, got ${this._state}`);
    }

    this._remotePeerId = new Uint8Array(req.peerId);
    this._remoteNonce = new Uint8Array(req.nonce);

    if (req.flowType === 'initiation') {
      if (!req.pakeMsg) {
        throw new CairnError('PAIRING', 'initiation flow PairRequest must have pakeMsg');
      }

      const spake2 = this._spake2;
      if (!spake2) {
        throw new CairnError('PAIRING', 'SPAKE2 state not initialized');
      }

      // Finish SPAKE2 with the initiator's message
      const rawKey = spake2.finish(req.pakeMsg);
      this._spake2 = null;

      // Derive session key
      this._sharedKey = this.deriveSessionKey(rawKey);

      // Retrieve stored outbound SPAKE2 message
      const outbound = this._spake2Outbound;
      if (!outbound) {
        throw new CairnError('PAIRING', 'SPAKE2 outbound message not stored');
      }
      this._spake2Outbound = null;

      this._state = 'awaiting_verification';

      return {
        type: 'challenge',
        peerId: localPeerId ?? new Uint8Array(32),
        nonce: this._localNonce,
        pakeMsg: outbound,
      };
    }

    // Standard flow — no PAKE exchange needed.
    this._state = 'awaiting_verification';
    return null;
  }

  private handleChallenge(
    chal: Extract<PairingMessage, { type: 'challenge' }>,
  ): PairingMessage {
    if (this._role !== 'initiator') {
      throw new CairnError('PAIRING', 'responder cannot handle PairChallenge');
    }
    if (this._state !== 'awaiting_pake_exchange') {
      throw new CairnError('PAIRING', `invalid state for PairChallenge: expected awaiting_pake_exchange, got ${this._state}`);
    }

    this._remotePeerId = new Uint8Array(chal.peerId);
    this._remoteNonce = new Uint8Array(chal.nonce);

    // Finish SPAKE2 with responder's message
    const spake2 = this._spake2;
    if (!spake2) {
      throw new CairnError('PAIRING', 'SPAKE2 state already consumed');
    }

    const rawKey = spake2.finish(chal.pakeMsg);
    this._spake2 = null;

    // Derive session key
    this._sharedKey = this.deriveSessionKey(rawKey);

    // Compute key confirmation
    const confirmation = this.computeKeyConfirmation('initiator');

    this._state = 'awaiting_confirmation';
    return { type: 'response', keyConfirmation: confirmation };
  }

  private handleResponse(
    resp: Extract<PairingMessage, { type: 'response' }>,
  ): PairingMessage {
    if (this._role !== 'responder') {
      throw new CairnError('PAIRING', 'initiator cannot handle PairResponse');
    }
    if (this._state !== 'awaiting_verification') {
      throw new CairnError('PAIRING', `invalid state for PairResponse: expected awaiting_verification, got ${this._state}`);
    }

    // Verify initiator's key confirmation
    const expected = this.computeKeyConfirmation('initiator');
    if (!constantTimeEqual(resp.keyConfirmation, expected)) {
      this._state = 'failed';
      throw new CairnError('PAIRING', 'PAKE authentication failed: key confirmation mismatch');
    }

    // Send our own key confirmation
    const confirmation = this.computeKeyConfirmation('responder');

    this._state = 'awaiting_confirmation';
    return { type: 'confirm', keyConfirmation: confirmation };
  }

  private handleConfirm(
    confirm: Extract<PairingMessage, { type: 'confirm' }>,
  ): PairingMessage | null {
    if (this._state !== 'awaiting_confirmation') {
      throw new CairnError('PAIRING', `invalid state for PairConfirm: expected awaiting_confirmation, got ${this._state}`);
    }

    // Verify the peer's key confirmation
    const label = this._role === 'initiator' ? 'responder' : 'initiator';
    const expected = this.computeKeyConfirmation(label);
    if (!constantTimeEqual(confirm.keyConfirmation, expected)) {
      this._state = 'failed';
      throw new CairnError('PAIRING', 'PAKE authentication failed: key confirmation mismatch');
    }

    this._state = 'completed';

    // Initiator sends their own Confirm back
    if (this._role === 'initiator') {
      const ourConfirm = this.computeKeyConfirmation('initiator');
      return { type: 'confirm', keyConfirmation: ourConfirm };
    }

    return null;
  }

  private handleReject(
    reject: Extract<PairingMessage, { type: 'reject' }>,
  ): null {
    this._state = 'failed';
    throw new CairnError('PAIRING', `rejected by peer: ${reject.reason}`);
  }

  // --- Key derivation helpers ---

  private deriveSessionKey(rawKey: Uint8Array): Uint8Array {
    // salt = initiator_nonce || responder_nonce
    const parts: Uint8Array[] = [];
    if (this._role === 'initiator') {
      parts.push(this._localNonce);
      if (this._remoteNonce) parts.push(this._remoteNonce);
    } else {
      if (this._remoteNonce) parts.push(this._remoteNonce);
      parts.push(this._localNonce);
    }

    const saltLen = parts.reduce((sum, p) => sum + p.length, 0);
    const salt = new Uint8Array(saltLen);
    let offset = 0;
    for (const part of parts) {
      salt.set(part, offset);
      offset += part.length;
    }

    return hkdfSha256(rawKey, salt, HKDF_INFO_PAIRING_SESSION, 32);
  }

  private computeKeyConfirmation(label: string): Uint8Array {
    if (!this._sharedKey) {
      throw new CairnError('PAIRING', 'no shared key available for key confirmation');
    }

    // Derive a confirmation key via HKDF
    const confirmKey = hkdfSha256(this._sharedKey, undefined, HKDF_INFO_KEY_CONFIRM, 32);

    // HMAC-SHA256(confirm_key, label)
    const labelBytes = new TextEncoder().encode(label);
    return hmac(sha256, confirmKey, labelBytes);
  }
}

/** Constant-time byte comparison. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
