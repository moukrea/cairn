import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { CairnError } from '../errors.js';

/**
 * An Ed25519 identity keypair used for signing and peer identification.
 */
export class IdentityKeypair {
  private readonly secret: Uint8Array;
  private readonly pubKey: Uint8Array;

  private constructor(secret: Uint8Array, pubKey: Uint8Array) {
    this.secret = secret;
    this.pubKey = pubKey;
  }

  /** Generate a new random Ed25519 identity keypair. */
  static async generate(): Promise<IdentityKeypair> {
    const secret = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(secret);
    return new IdentityKeypair(secret, pubKey);
  }

  /** Restore from a 32-byte secret key seed. */
  static async fromBytes(secret: Uint8Array): Promise<IdentityKeypair> {
    if (secret.length !== 32) {
      throw new CairnError('CRYPTO', 'Ed25519 secret key must be 32 bytes');
    }
    const copy = new Uint8Array(secret);
    const pubKey = await ed.getPublicKeyAsync(copy);
    return new IdentityKeypair(copy, pubKey);
  }

  /** Export the 32-byte secret key seed. */
  secretBytes(): Uint8Array {
    return new Uint8Array(this.secret);
  }

  /** Get the 32-byte public key. */
  publicKey(): Uint8Array {
    return new Uint8Array(this.pubKey);
  }

  /** Derive the Peer ID: SHA-256 hash of the Ed25519 public key bytes (32 bytes). */
  peerId(): Uint8Array {
    return peerIdFromPublicKey(this.pubKey);
  }

  /** Sign a message. Returns 64-byte signature. */
  async sign(message: Uint8Array): Promise<Uint8Array> {
    try {
      return await ed.signAsync(message, this.secret);
    } catch (e) {
      throw new CairnError('CRYPTO', `Ed25519 sign error: ${e}`);
    }
  }

  /** Verify a signature against this keypair's public key. Throws on failure. */
  async verify(message: Uint8Array, signature: Uint8Array): Promise<void> {
    return verifySignature(this.pubKey, message, signature);
  }
}

/** Derive Peer ID from a public key (without needing the private key). */
export function peerIdFromPublicKey(publicKey: Uint8Array): Uint8Array {
  return sha256(publicKey);
}

/** Verify a signature against an arbitrary public key. Throws on failure. */
export async function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  try {
    const valid = await ed.verifyAsync(signature, message, publicKey);
    if (!valid) {
      throw new CairnError('CRYPTO', 'Ed25519 signature verification failed');
    }
  } catch (e) {
    if (e instanceof CairnError) throw e;
    throw new CairnError('CRYPTO', `Ed25519 verify error: ${e}`);
  }
}
