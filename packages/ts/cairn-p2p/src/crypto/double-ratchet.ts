import { CairnError } from '../errors.js';
import type { CipherSuite } from '../config.js';
import { X25519Keypair } from './exchange.js';
import { hkdfSha256 } from './hkdf.js';
import { aeadEncrypt, aeadDecrypt } from './aead.js';

// Domain separation constants — must match Rust exactly.
const ROOT_KDF_INFO = new TextEncoder().encode('cairn-root-chain-v1');
const CHAIN_KDF_INFO = new TextEncoder().encode('cairn-chain-advance-v1');
const MESSAGE_KEY_KDF_INFO = new TextEncoder().encode('cairn-msg-encrypt-v1');
const RESUMPTION_KEY_INFO = new TextEncoder().encode('cairn-session-resume-v1');

/** Header sent alongside each Double Ratchet encrypted message. */
export interface RatchetHeader {
  /** Sender's current DH ratchet public key (32 bytes). */
  dhPublic: Uint8Array;
  /** Number of messages in the previous sending chain. */
  prevChainLen: number;
  /** Message number in the current sending chain. */
  msgNum: number;
}

/** Configuration for the Double Ratchet. */
export interface RatchetConfig {
  /** Maximum number of skipped message keys to cache (default: 100). */
  maxSkip: number;
  /** AEAD cipher suite (default: 'aes-256-gcm'). */
  cipher: CipherSuite;
}

const DEFAULT_CONFIG: RatchetConfig = {
  maxSkip: 100,
  cipher: 'aes-256-gcm',
};

/** Internal serializable state. */
interface RatchetState {
  dhSelfSecret: Uint8Array;
  dhSelfPublic: Uint8Array;
  dhRemote: Uint8Array | null;
  rootKey: Uint8Array;
  chainKeySend: Uint8Array | null;
  chainKeyRecv: Uint8Array | null;
  msgNumSend: number;
  msgNumRecv: number;
  prevChainLen: number;
  skippedKeys: Map<string, Uint8Array>;
}

/**
 * Signal Double Ratchet session.
 *
 * Combines DH ratcheting (X25519), root chain KDF, and symmetric chain
 * KDF to provide forward secrecy and break-in recovery for each message.
 */
export class DoubleRatchet {
  private state: RatchetState;
  private config: RatchetConfig;

  private constructor(state: RatchetState, config: RatchetConfig) {
    this.state = state;
    this.config = config;
  }

  /**
   * Initialize as the sender (initiator/Alice) after a shared secret
   * has been established (e.g., from Noise XX handshake).
   */
  static initSender(
    sharedSecret: Uint8Array,
    remoteDh: Uint8Array,
    config?: Partial<RatchetConfig>,
  ): DoubleRatchet {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    const dhSelf = X25519Keypair.generate();

    // Perform initial DH ratchet step
    const dhOutput = dhSelf.diffieHellman(remoteDh);
    const [rootKey, chainKeySend] = kdfRk(sharedSecret, dhOutput);

    const state: RatchetState = {
      dhSelfSecret: dhSelf.secretBytes(),
      dhSelfPublic: dhSelf.publicKeyBytes(),
      dhRemote: new Uint8Array(remoteDh),
      rootKey,
      chainKeySend,
      chainKeyRecv: null,
      msgNumSend: 0,
      msgNumRecv: 0,
      prevChainLen: 0,
      skippedKeys: new Map(),
    };

    return new DoubleRatchet(state, cfg);
  }

  /**
   * Initialize as the receiver (responder/Bob) after a shared secret
   * has been established.
   */
  static initReceiver(
    sharedSecret: Uint8Array,
    ourKeypair: X25519Keypair,
    config?: Partial<RatchetConfig>,
  ): DoubleRatchet {
    const cfg = { ...DEFAULT_CONFIG, ...config };

    const state: RatchetState = {
      dhSelfSecret: ourKeypair.secretBytes(),
      dhSelfPublic: ourKeypair.publicKeyBytes(),
      dhRemote: null,
      rootKey: new Uint8Array(sharedSecret),
      chainKeySend: null,
      chainKeyRecv: null,
      msgNumSend: 0,
      msgNumRecv: 0,
      prevChainLen: 0,
      skippedKeys: new Map(),
    };

    return new DoubleRatchet(state, cfg);
  }

  /** Encrypt a message. Returns header and ciphertext. */
  encrypt(plaintext: Uint8Array): { header: RatchetHeader; ciphertext: Uint8Array } {
    if (!this.state.chainKeySend) {
      throw new CairnError('CRYPTO', 'no sending chain key established');
    }

    const [newChainKey, messageKey] = kdfCk(this.state.chainKeySend);
    this.state.chainKeySend = newChainKey;

    const header: RatchetHeader = {
      dhPublic: new Uint8Array(this.state.dhSelfPublic),
      prevChainLen: this.state.prevChainLen,
      msgNum: this.state.msgNumSend,
    };

    this.state.msgNumSend++;

    const nonce = deriveNonce(messageKey, header.msgNum);
    const aad = serializeHeader(header);

    const ciphertext = aeadEncrypt(this.config.cipher, messageKey, nonce, plaintext, aad);

    // Best-effort zero message key
    messageKey.fill(0);

    return { header, ciphertext };
  }

  /** Decrypt a message given the header and ciphertext. */
  decrypt(header: RatchetHeader, ciphertext: Uint8Array): Uint8Array {
    // Try skipped keys first
    const skippedId = skippedKeyId(header.dhPublic, header.msgNum);
    const skippedMk = this.state.skippedKeys.get(skippedId);
    if (skippedMk) {
      this.state.skippedKeys.delete(skippedId);
      return decryptWithKey(this.config.cipher, skippedMk, header, ciphertext);
    }

    // Check if peer's DH key changed (DH ratchet step needed)
    const needDhRatchet = this.state.dhRemote === null ||
      !bytesEqual(this.state.dhRemote, header.dhPublic);

    if (needDhRatchet) {
      this.skipMessageKeys(header.prevChainLen);
      this.dhRatchet(header.dhPublic);
    }

    // Skip ahead in the current receiving chain if needed
    this.skipMessageKeys(header.msgNum);

    // Derive the message key from the receiving chain
    if (!this.state.chainKeyRecv) {
      throw new CairnError('CRYPTO', 'no receiving chain key established');
    }
    const [newChainKey, messageKey] = kdfCk(this.state.chainKeyRecv);
    this.state.chainKeyRecv = newChainKey;
    this.state.msgNumRecv++;

    const result = decryptWithKey(this.config.cipher, messageKey, header, ciphertext);
    messageKey.fill(0);
    return result;
  }

  /** Export the ratchet state for persistence. */
  exportState(): Uint8Array {
    const skippedEntries: Array<[string, number[]]> = [];
    for (const [key, value] of this.state.skippedKeys) {
      skippedEntries.push([key, Array.from(value)]);
    }

    const obj = {
      dhSelfSecret: Array.from(this.state.dhSelfSecret),
      dhSelfPublic: Array.from(this.state.dhSelfPublic),
      dhRemote: this.state.dhRemote ? Array.from(this.state.dhRemote) : null,
      rootKey: Array.from(this.state.rootKey),
      chainKeySend: this.state.chainKeySend ? Array.from(this.state.chainKeySend) : null,
      chainKeyRecv: this.state.chainKeyRecv ? Array.from(this.state.chainKeyRecv) : null,
      msgNumSend: this.state.msgNumSend,
      msgNumRecv: this.state.msgNumRecv,
      prevChainLen: this.state.prevChainLen,
      skippedKeys: skippedEntries,
    };

    return new TextEncoder().encode(JSON.stringify(obj));
  }

  /** Import ratchet state from persisted bytes. */
  static importState(data: Uint8Array, config?: Partial<RatchetConfig>): DoubleRatchet {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    try {
      const json = new TextDecoder().decode(data);
      const obj = JSON.parse(json);

      const skippedKeys = new Map<string, Uint8Array>();
      if (obj.skippedKeys) {
        for (const [key, value] of obj.skippedKeys) {
          skippedKeys.set(key, new Uint8Array(value));
        }
      }

      const state: RatchetState = {
        dhSelfSecret: new Uint8Array(obj.dhSelfSecret),
        dhSelfPublic: new Uint8Array(obj.dhSelfPublic),
        dhRemote: obj.dhRemote ? new Uint8Array(obj.dhRemote) : null,
        rootKey: new Uint8Array(obj.rootKey),
        chainKeySend: obj.chainKeySend ? new Uint8Array(obj.chainKeySend) : null,
        chainKeyRecv: obj.chainKeyRecv ? new Uint8Array(obj.chainKeyRecv) : null,
        msgNumSend: obj.msgNumSend,
        msgNumRecv: obj.msgNumRecv,
        prevChainLen: obj.prevChainLen,
        skippedKeys,
      };

      return new DoubleRatchet(state, cfg);
    } catch (e) {
      if (e instanceof CairnError) throw e;
      throw new CairnError('CRYPTO', `ratchet state deserialization: ${e}`);
    }
  }

  /**
   * Export the ratchet state as a JSON-serializable object.
   *
   * Unlike `exportState()` which returns encoded bytes, this returns
   * a plain object suitable for storing in IndexedDB or embedding
   * in other JSON structures (e.g., SavedConnection).
   */
  exportStateObject(): object {
    const skippedEntries: Array<[string, number[]]> = [];
    for (const [key, value] of this.state.skippedKeys) {
      skippedEntries.push([key, Array.from(value)]);
    }

    return {
      dhSelfSecret: Array.from(this.state.dhSelfSecret),
      dhSelfPublic: Array.from(this.state.dhSelfPublic),
      dhRemote: this.state.dhRemote ? Array.from(this.state.dhRemote) : null,
      rootKey: Array.from(this.state.rootKey),
      chainKeySend: this.state.chainKeySend ? Array.from(this.state.chainKeySend) : null,
      chainKeyRecv: this.state.chainKeyRecv ? Array.from(this.state.chainKeyRecv) : null,
      msgNumSend: this.state.msgNumSend,
      msgNumRecv: this.state.msgNumRecv,
      prevChainLen: this.state.prevChainLen,
      skippedKeys: skippedEntries,
      cipher: this.config.cipher,
      maxSkip: this.config.maxSkip,
    };
  }

  /**
   * Restore a DoubleRatchet from an exported state object.
   *
   * This is the inverse of `exportStateObject()`. Accepts a plain
   * object (as returned from IndexedDB or JSON.parse).
   */
  static fromExportedState(stateObj: object): DoubleRatchet {
    const obj = stateObj as any;
    try {
      if (!Array.isArray(obj.dhSelfSecret) || !Array.isArray(obj.dhSelfPublic) || !Array.isArray(obj.rootKey)) {
        throw new Error('missing required array fields');
      }
      if (typeof obj.msgNumSend !== 'number' || typeof obj.msgNumRecv !== 'number') {
        throw new Error('missing required numeric fields');
      }

      const skippedKeys = new Map<string, Uint8Array>();
      if (obj.skippedKeys) {
        for (const [key, value] of obj.skippedKeys) {
          skippedKeys.set(key, new Uint8Array(value));
        }
      }

      const state: RatchetState = {
        dhSelfSecret: new Uint8Array(obj.dhSelfSecret),
        dhSelfPublic: new Uint8Array(obj.dhSelfPublic),
        dhRemote: obj.dhRemote ? new Uint8Array(obj.dhRemote) : null,
        rootKey: new Uint8Array(obj.rootKey),
        chainKeySend: obj.chainKeySend ? new Uint8Array(obj.chainKeySend) : null,
        chainKeyRecv: obj.chainKeyRecv ? new Uint8Array(obj.chainKeyRecv) : null,
        msgNumSend: obj.msgNumSend,
        msgNumRecv: obj.msgNumRecv,
        prevChainLen: obj.prevChainLen,
        skippedKeys,
      };

      const config: RatchetConfig = {
        cipher: obj.cipher ?? 'aes-256-gcm',
        maxSkip: obj.maxSkip ?? 100,
      };

      return new DoubleRatchet(state, config);
    } catch (e) {
      if (e instanceof CairnError) throw e;
      throw new CairnError('CRYPTO', `ratchet state object deserialization: ${e}`);
    }
  }

  /**
   * Derive a 32-byte resumption key from the current root key.
   *
   * Used by the SESSION_RESUME protocol to prove that both sides
   * share the same session state without revealing the root key.
   *
   * HKDF-SHA256(root_key, info="cairn-session-resume-v1") -> 32 bytes
   */
  deriveResumptionKey(): Uint8Array {
    return hkdfSha256(this.state.rootKey, undefined, RESUMPTION_KEY_INFO, 32);
  }

  /** Skip message keys up to (but not including) the given message number. */
  private skipMessageKeys(until: number): void {
    if (!this.state.chainKeyRecv) return;

    const toSkip = until - this.state.msgNumRecv;
    if (toSkip <= 0) return;
    if (toSkip > this.config.maxSkip) {
      throw new CairnError('CRYPTO', 'max skip threshold exceeded');
    }

    let ck = this.state.chainKeyRecv;
    for (let i = this.state.msgNumRecv; i < until; i++) {
      const [newCk, mk] = kdfCk(ck);
      if (!this.state.dhRemote) {
        throw new CairnError('CRYPTO', 'no remote DH key for skipping');
      }
      const id = skippedKeyId(this.state.dhRemote, i);
      this.state.skippedKeys.set(id, mk);
      ck = newCk;
      this.state.msgNumRecv++;
    }
    this.state.chainKeyRecv = ck;
  }

  /** Perform a DH ratchet step when the peer's public key changes. */
  private dhRatchet(newRemotePublic: Uint8Array): void {
    this.state.prevChainLen = this.state.msgNumSend;
    this.state.msgNumSend = 0;
    this.state.msgNumRecv = 0;
    this.state.dhRemote = new Uint8Array(newRemotePublic);

    // Derive receiving chain key from current DH keypair + new remote key
    const dhSelf = X25519Keypair.fromBytes(this.state.dhSelfSecret);
    const dhOutput = dhSelf.diffieHellman(newRemotePublic);
    const [rootKey1, chainKeyRecv] = kdfRk(this.state.rootKey, dhOutput);
    this.state.rootKey = rootKey1;
    this.state.chainKeyRecv = chainKeyRecv;

    // Generate new DH keypair and derive sending chain key
    const newDhSelf = X25519Keypair.generate();
    this.state.dhSelfSecret = newDhSelf.secretBytes();
    this.state.dhSelfPublic = newDhSelf.publicKeyBytes();

    const dhOutput2 = newDhSelf.diffieHellman(newRemotePublic);
    const [rootKey2, chainKeySend] = kdfRk(this.state.rootKey, dhOutput2);
    this.state.rootKey = rootKey2;
    this.state.chainKeySend = chainKeySend;
  }
}

/** Derive new root key and chain key from DH output. */
function kdfRk(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const output = hkdfSha256(dhOutput, rootKey, ROOT_KDF_INFO, 64);
  return [output.slice(0, 32), output.slice(32, 64)];
}

/** Derive message key from chain key and advance the chain. */
function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newCk = hkdfSha256(chainKey, undefined, CHAIN_KDF_INFO, 32);
  const mk = hkdfSha256(chainKey, undefined, MESSAGE_KEY_KDF_INFO, 32);
  return [newCk, mk];
}

/** Derive a 12-byte nonce from a message key and message number. */
function deriveNonce(messageKey: Uint8Array, msgNum: number): Uint8Array {
  const nonce = new Uint8Array(12);
  // First 8 bytes from message key, last 4 from message number (big-endian)
  nonce.set(messageKey.slice(0, 8), 0);
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  view.setUint32(8, msgNum);
  return nonce;
}

/** Serialize a RatchetHeader as JSON for AEAD AAD. */
function serializeHeader(header: RatchetHeader): Uint8Array {
  const obj = {
    dh_public: Array.from(header.dhPublic),
    prev_chain_len: header.prevChainLen,
    msg_num: header.msgNum,
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}

/** Decrypt ciphertext with a specific message key. */
function decryptWithKey(
  cipher: CipherSuite,
  messageKey: Uint8Array,
  header: RatchetHeader,
  ciphertext: Uint8Array,
): Uint8Array {
  const nonce = deriveNonce(messageKey, header.msgNum);
  const aad = serializeHeader(header);
  return aeadDecrypt(cipher, messageKey, nonce, ciphertext, aad);
}

/** Create a skipped key ID string from DH public key and message number. */
function skippedKeyId(dhPublic: Uint8Array, msgNum: number): string {
  return bytesToHex(dhPublic) + ':' + msgNum;
}

/** Convert bytes to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Compare two Uint8Arrays for equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
