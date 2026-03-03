import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { CairnError } from '../errors.js';
import { hkdfSha256, HKDF_INFO_SESSION_KEY } from './hkdf.js';
import { aeadEncrypt, aeadDecrypt } from './aead.js';
import type { IdentityKeypair } from './identity.js';

/** Protocol name used to initialize the handshake hash (Noise spec section 5.2). */
const PROTOCOL_NAME = new TextEncoder().encode('Noise_XX_25519_ChaChaPoly_SHA256');

/** AEAD tag size (16 bytes for ChaCha20-Poly1305). */
const TAG_SIZE = 16;
/** Size of an X25519 public key. */
const DH_KEY_SIZE = 32;
/** Size of an Ed25519 public key. */
const ED25519_PUB_SIZE = 32;
/** Zero nonce used for handshake AEAD operations. */
const ZERO_NONCE = new Uint8Array(12);

/** Noise XX handshake role. */
export type Role = 'initiator' | 'responder';

/** Result of a completed Noise XX handshake. */
export interface HandshakeResult {
  /** Shared symmetric key for session encryption (32 bytes). */
  sessionKey: Uint8Array;
  /** Remote peer's static public key (Ed25519, 32 bytes). */
  remoteStatic: Uint8Array;
  /** Handshake transcript hash for SAS derivation (32 bytes). */
  transcriptHash: Uint8Array;
}

/** Output of a single handshake step. */
export type StepOutput =
  | { type: 'send_message'; data: Uint8Array }
  | { type: 'complete'; result: HandshakeResult };

/** Internal handshake state. */
type HandshakeState =
  | 'initiator_start'
  | 'responder_wait_msg1'
  | 'initiator_wait_msg2'
  | 'responder_wait_msg3'
  | 'complete';

/**
 * Noise XX handshake state machine.
 *
 * Implements the three-message Noise XX pattern:
 * ```
 * -> e                 (message 1)
 * <- e, ee, s, es      (message 2)
 * -> s, se             (message 3)
 * ```
 *
 * Initiator flow:
 *   1. step()        -> SendMessage(msg1)
 *   2. step(msg2)    -> SendMessage(msg3) — call result() to get HandshakeResult
 *   3. (done — call result() after step 2)
 *
 * Responder flow:
 *   1. step(msg1)    -> SendMessage(msg2)
 *   2. step(msg3)    -> Complete(result)
 */
export class NoiseXXHandshake {
  private state: HandshakeState;
  private readonly localIdentity: IdentityKeypair;
  private readonly localStaticX25519Secret: Uint8Array;

  private localEphemeralSecret?: Uint8Array;
  private localEphemeralPub?: Uint8Array;
  private remoteEphemeralPub?: Uint8Array;
  private remoteStaticEd25519?: Uint8Array;

  private chainingKey: Uint8Array;
  private handshakeHash: Uint8Array;
  private currentKey?: Uint8Array;
  private pakeSecret?: Uint8Array;
  private cachedResult?: HandshakeResult;

  constructor(role: Role, identity: IdentityKeypair, pakeSecret?: Uint8Array) {
    // Convert Ed25519 identity to X25519 for DH operations.
    this.localStaticX25519Secret = ed25519.utils.toMontgomerySecret(identity.secretBytes());

    // Initialize handshake hash from protocol name (Noise spec section 5.2).
    // If protocol name <= 32 bytes, pad with zeros.
    if (PROTOCOL_NAME.length <= 32) {
      this.handshakeHash = new Uint8Array(32);
      this.handshakeHash.set(PROTOCOL_NAME);
    } else {
      this.handshakeHash = sha256(PROTOCOL_NAME);
    }

    // Chaining key starts as the handshake hash (Noise spec).
    this.chainingKey = new Uint8Array(this.handshakeHash);

    this.localIdentity = identity;
    this.state = role === 'initiator' ? 'initiator_start' : 'responder_wait_msg1';

    if (pakeSecret) {
      if (pakeSecret.length !== 32) {
        throw new CairnError('CRYPTO', 'PAKE secret must be 32 bytes');
      }
      this.pakeSecret = new Uint8Array(pakeSecret);
    }
  }

  /**
   * Process the next handshake step.
   *
   * Initiator: step() -> step(msg2)
   * Responder: step(msg1) -> step(msg3)
   */
  step(input?: Uint8Array): StepOutput {
    switch (this.state) {
      case 'initiator_start':
        if (input !== undefined) {
          throw new CairnError('CRYPTO', 'initiator start expects no input');
        }
        return this.initiatorSendMsg1();

      case 'responder_wait_msg1':
        if (input === undefined) {
          throw new CairnError('CRYPTO', 'responder expects message 1 input');
        }
        return this.responderRecvMsg1SendMsg2(input);

      case 'initiator_wait_msg2':
        if (input === undefined) {
          throw new CairnError('CRYPTO', 'initiator expects message 2 input');
        }
        return this.initiatorRecvMsg2SendMsg3(input);

      case 'responder_wait_msg3':
        if (input === undefined) {
          throw new CairnError('CRYPTO', 'responder expects message 3 input');
        }
        return this.responderRecvMsg3(input);

      case 'complete':
        throw new CairnError('CRYPTO', 'handshake already complete');
    }
  }

  /** Get the handshake result after the initiator has sent message 3. */
  getResult(): HandshakeResult {
    if (!this.cachedResult) {
      throw new CairnError('CRYPTO', 'handshake not yet complete');
    }
    return this.cachedResult;
  }

  // --- Message 1: -> e ---

  private initiatorSendMsg1(): StepOutput {
    // Generate ephemeral keypair
    const ephemeralSecret = x25519.utils.randomSecretKey();
    const ephemeralPub = x25519.getPublicKey(ephemeralSecret);

    // Mix ephemeral public key into handshake hash
    this.mixHash(ephemeralPub);

    this.localEphemeralSecret = ephemeralSecret;
    this.localEphemeralPub = ephemeralPub;

    // Message 1 is just the ephemeral public key (32 bytes)
    this.state = 'initiator_wait_msg2';
    return { type: 'send_message', data: new Uint8Array(ephemeralPub) };
  }

  // --- Message 2: <- e, ee, s, es ---

  private responderRecvMsg1SendMsg2(msg1: Uint8Array): StepOutput {
    if (msg1.length !== DH_KEY_SIZE) {
      throw new CairnError('CRYPTO', `message 1 invalid length: expected ${DH_KEY_SIZE}, got ${msg1.length}`);
    }

    // Store remote ephemeral and mix into hash
    this.remoteEphemeralPub = new Uint8Array(msg1);
    this.mixHash(this.remoteEphemeralPub);

    // Build message 2
    const parts: Uint8Array[] = [];

    // e: generate responder ephemeral
    const ephemeralSecret = x25519.utils.randomSecretKey();
    const ephemeralPub = x25519.getPublicKey(ephemeralSecret);

    this.mixHash(ephemeralPub);
    parts.push(ephemeralPub);

    this.localEphemeralSecret = ephemeralSecret;
    this.localEphemeralPub = ephemeralPub;

    // ee: DH(responder_ephemeral, initiator_ephemeral)
    const eeShared = x25519.getSharedSecret(ephemeralSecret, this.remoteEphemeralPub);
    this.mixKey(eeShared);

    // s: encrypt and send our static Ed25519 public key
    const staticPubBytes = this.localIdentity.publicKey();
    const encryptedStatic = this.encryptAndHash(staticPubBytes);
    parts.push(encryptedStatic);

    // es: DH(responder_static_x25519, initiator_ephemeral)
    const esShared = x25519.getSharedSecret(this.localStaticX25519Secret, this.remoteEphemeralPub);
    this.mixKey(esShared);

    // Encrypt empty payload
    const encryptedPayload = this.encryptAndHash(new Uint8Array(0));
    parts.push(encryptedPayload);

    this.state = 'responder_wait_msg3';
    return { type: 'send_message', data: concatBytes(...parts) };
  }

  // --- Initiator: recv message 2, send message 3 ---

  private initiatorRecvMsg2SendMsg3(msg2: Uint8Array): StepOutput {
    const minLen = DH_KEY_SIZE + (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE;
    if (msg2.length < minLen) {
      throw new CairnError('CRYPTO', `message 2 too short: expected at least ${minLen}, got ${msg2.length}`);
    }

    let offset = 0;

    // e: responder ephemeral
    const remoteEBytes = msg2.slice(offset, offset + DH_KEY_SIZE);
    this.mixHash(remoteEBytes);
    offset += DH_KEY_SIZE;
    this.remoteEphemeralPub = remoteEBytes;

    // ee: DH(initiator_ephemeral, responder_ephemeral)
    if (!this.localEphemeralSecret) {
      throw new CairnError('CRYPTO', 'missing local ephemeral for ee DH');
    }
    const eeShared = x25519.getSharedSecret(this.localEphemeralSecret, remoteEBytes);
    this.mixKey(eeShared);

    // s: decrypt responder's static public key
    const encryptedStatic = msg2.slice(offset, offset + ED25519_PUB_SIZE + TAG_SIZE);
    const staticPubBytes = this.decryptAndHash(encryptedStatic);
    offset += ED25519_PUB_SIZE + TAG_SIZE;

    if (staticPubBytes.length !== ED25519_PUB_SIZE) {
      throw new CairnError('CRYPTO', 'decrypted static key wrong size');
    }

    // Convert remote Ed25519 public key to X25519 for DH
    const remoteStaticX25519 = ed25519.utils.toMontgomery(staticPubBytes);
    this.remoteStaticEd25519 = new Uint8Array(staticPubBytes);

    // es: DH(initiator_ephemeral, responder_static_x25519)
    const esShared = x25519.getSharedSecret(this.localEphemeralSecret, remoteStaticX25519);
    this.mixKey(esShared);

    // Decrypt payload from message 2
    const encryptedPayload = msg2.slice(offset);
    this.decryptAndHash(encryptedPayload);

    // Build message 3: -> s, se
    const parts: Uint8Array[] = [];

    // s: encrypt initiator's static Ed25519 public key
    const ourStaticPubBytes = this.localIdentity.publicKey();
    const encryptedOurStatic = this.encryptAndHash(ourStaticPubBytes);
    parts.push(encryptedOurStatic);

    // se: DH(initiator_static_x25519, responder_ephemeral)
    const seShared = x25519.getSharedSecret(this.localStaticX25519Secret, remoteEBytes);
    this.mixKey(seShared);

    // Mix in PAKE secret if present
    if (this.pakeSecret) {
      this.mixKey(this.pakeSecret);
    }

    // Encrypt empty payload for message 3
    const encryptedMsg3Payload = this.encryptAndHash(new Uint8Array(0));
    parts.push(encryptedMsg3Payload);

    // Derive session key
    const sessionKey = this.deriveSessionKey();
    const result: HandshakeResult = {
      sessionKey,
      remoteStatic: new Uint8Array(staticPubBytes),
      transcriptHash: new Uint8Array(this.handshakeHash),
    };

    this.state = 'complete';
    this.cachedResult = result;

    return { type: 'send_message', data: concatBytes(...parts) };
  }

  // --- Message 3: responder receives -> s, se ---

  private responderRecvMsg3(msg3: Uint8Array): StepOutput {
    const minLen = (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE;
    if (msg3.length < minLen) {
      throw new CairnError('CRYPTO', `message 3 too short: expected at least ${minLen}, got ${msg3.length}`);
    }

    let offset = 0;

    // s: decrypt initiator's static public key
    const encryptedStatic = msg3.slice(offset, offset + ED25519_PUB_SIZE + TAG_SIZE);
    const staticPubBytes = this.decryptAndHash(encryptedStatic);
    offset += ED25519_PUB_SIZE + TAG_SIZE;

    if (staticPubBytes.length !== ED25519_PUB_SIZE) {
      throw new CairnError('CRYPTO', 'decrypted static key wrong size');
    }

    // Convert remote Ed25519 to X25519
    const remoteStaticX25519 = ed25519.utils.toMontgomery(staticPubBytes);
    this.remoteStaticEd25519 = new Uint8Array(staticPubBytes);

    // se: DH(responder_ephemeral, initiator_static_x25519)
    if (!this.localEphemeralSecret) {
      throw new CairnError('CRYPTO', 'missing local ephemeral for se DH');
    }
    const seShared = x25519.getSharedSecret(this.localEphemeralSecret, remoteStaticX25519);
    this.mixKey(seShared);

    // Mix in PAKE secret if present
    if (this.pakeSecret) {
      this.mixKey(this.pakeSecret);
    }

    // Decrypt payload
    const encryptedPayload = msg3.slice(offset);
    this.decryptAndHash(encryptedPayload);

    // Derive session key
    const sessionKey = this.deriveSessionKey();

    this.state = 'complete';
    const result: HandshakeResult = {
      sessionKey,
      remoteStatic: new Uint8Array(staticPubBytes),
      transcriptHash: new Uint8Array(this.handshakeHash),
    };
    this.cachedResult = result;
    return { type: 'complete', result };
  }

  // --- Noise symmetric state operations ---

  /**
   * Mix a DH result into the chaining key via HKDF.
   * Updates the chaining key and stores the derived encryption key.
   */
  private mixKey(inputKeyMaterial: Uint8Array): void {
    const output = hkdfSha256(inputKeyMaterial, this.chainingKey, new Uint8Array(0), 64);
    this.chainingKey = output.slice(0, 32);
    this.currentKey = output.slice(32, 64);
  }

  /** Mix data into the handshake hash: h = SHA-256(h || data). */
  private mixHash(data: Uint8Array): void {
    const combined = concatBytes(this.handshakeHash, data);
    this.handshakeHash = sha256(combined);
  }

  /** Encrypt plaintext and mix the ciphertext into the handshake hash. */
  private encryptAndHash(plaintext: Uint8Array): Uint8Array {
    if (!this.currentKey) {
      throw new CairnError('CRYPTO', 'no encryption key available (mixKey not called)');
    }
    const ciphertext = aeadEncrypt(
      'chacha20-poly1305',
      this.currentKey,
      ZERO_NONCE,
      plaintext,
      this.handshakeHash,
    );
    this.mixHash(ciphertext);
    return ciphertext;
  }

  /** Decrypt ciphertext and mix it into the handshake hash. */
  private decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    if (!this.currentKey) {
      throw new CairnError('CRYPTO', 'no decryption key available (mixKey not called)');
    }
    const hBefore = new Uint8Array(this.handshakeHash);
    this.mixHash(ciphertext);
    return aeadDecrypt(
      'chacha20-poly1305',
      this.currentKey,
      ZERO_NONCE,
      ciphertext,
      hBefore,
    );
  }

  /** Derive the final session key from the chaining key. */
  private deriveSessionKey(): Uint8Array {
    return hkdfSha256(this.chainingKey, undefined, HKDF_INFO_SESSION_KEY, 32);
  }
}

/** Concatenate multiple Uint8Arrays. */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) totalLen += arr.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
