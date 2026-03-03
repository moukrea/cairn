import { x25519 } from '@noble/curves/ed25519';
import { CairnError } from '../errors.js';

/**
 * An X25519 keypair for Diffie-Hellman key exchange.
 */
export class X25519Keypair {
  private readonly secret: Uint8Array;
  private readonly pubKey: Uint8Array;

  private constructor(secret: Uint8Array, pubKey: Uint8Array) {
    this.secret = secret;
    this.pubKey = pubKey;
  }

  /** Generate a new random X25519 keypair. */
  static generate(): X25519Keypair {
    const secret = x25519.utils.randomSecretKey();
    const pubKey = x25519.getPublicKey(secret);
    return new X25519Keypair(secret, pubKey);
  }

  /** Restore from a 32-byte secret key. */
  static fromBytes(secret: Uint8Array): X25519Keypair {
    if (secret.length !== 32) {
      throw new CairnError('CRYPTO', 'X25519 secret key must be 32 bytes');
    }
    const copy = new Uint8Array(secret);
    const pubKey = x25519.getPublicKey(copy);
    return new X25519Keypair(copy, pubKey);
  }

  /** Get the 32-byte public key. */
  publicKeyBytes(): Uint8Array {
    return new Uint8Array(this.pubKey);
  }

  /** Export the 32-byte secret key. */
  secretBytes(): Uint8Array {
    return new Uint8Array(this.secret);
  }

  /** Perform Diffie-Hellman key exchange with a peer's public key. Returns 32-byte shared secret. */
  diffieHellman(peerPublic: Uint8Array): Uint8Array {
    try {
      return x25519.getSharedSecret(this.secret, peerPublic);
    } catch (e) {
      throw new CairnError('CRYPTO', `X25519 DH error: ${e}`);
    }
  }
}
