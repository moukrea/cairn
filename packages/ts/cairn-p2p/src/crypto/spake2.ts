import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { CairnError } from '../errors.js';

/**
 * SPAKE2 balanced PAKE (Password-Authenticated Key Exchange) using the Ed25519 group.
 *
 * Wire-compatible with the RustCrypto `spake2` crate (v0.4) using `Ed25519Group`.
 *
 * Protocol:
 *   - Side A computes: T_A = pw * M + x * G, sends 0x41 || T_A (33 bytes)
 *   - Side B computes: T_B = pw * N + y * G, sends 0x42 || T_B (33 bytes)
 *   - Both derive: shared = SHA256(SHA256(pw) || SHA256(idA) || SHA256(idB) || X || Y || K)
 *
 * M and N are the standard Ed25519 SPAKE2 constants from RustCrypto / python-spake2.
 */

const ExtendedPoint = ed25519.ExtendedPoint;
type ExtendedPoint = InstanceType<typeof ExtendedPoint>;

/** Fixed SPAKE2 identity labels (must match Rust). */
const SPAKE2_ID_A = new TextEncoder().encode('cairn-initiator');
const SPAKE2_ID_B = new TextEncoder().encode('cairn-responder');

/** Ed25519 group order L. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * M point for side A (initiator).
 * Hex: 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
 */
const M_POINT = ExtendedPoint.fromHex(
  '15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312',
);

/**
 * N point for side B (responder).
 * Hex: f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
 */
const N_POINT = ExtendedPoint.fromHex(
  'f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3',
);

/**
 * Derive a password scalar using HKDF-SHA256, matching the RustCrypto spake2 crate.
 *
 * HKDF(salt=empty, ikm=password, info="SPAKE2 pw", len=48)
 * Then reverse into 64-byte LE buffer and reduce mod L.
 */
function passwordToScalar(password: Uint8Array): bigint {
  const okm = hkdf(sha256, password, new Uint8Array(0), 'SPAKE2 pw', 48);

  // Reverse 48-byte big-endian HKDF output into 64-byte LE buffer
  const reducible = new Uint8Array(64);
  for (let i = 0; i < 48; i++) {
    reducible[47 - i] = okm[i];
  }
  // bytes 48-63 remain zero

  // Interpret as little-endian 512-bit integer and reduce mod L
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(reducible[i]);
  }
  n = n % L;
  if (n === 0n) n = 1n;
  return n;
}

/** Generate a random scalar in [1, L). */
function randomScalar(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  n = n % L;
  if (n === 0n) n = 1n;
  return n;
}

export type Spake2Role = 'A' | 'B';

/**
 * A SPAKE2 session. Create with `Spake2.startA()` (initiator) or `Spake2.startB()` (responder).
 *
 * Wire-compatible with the RustCrypto spake2 crate v0.4 Ed25519Group.
 */
export class Spake2 {
  private readonly role: Spake2Role;
  private readonly password: Uint8Array;
  private readonly scalar: bigint;
  private readonly pwScalar: bigint;
  private readonly myMsg: Uint8Array; // 32-byte point (no prefix)
  /** Our outbound message: 33 bytes (1-byte side prefix + 32-byte point). */
  readonly outboundMsg: Uint8Array;

  private constructor(role: Spake2Role, password: Uint8Array) {
    this.role = role;
    this.password = new Uint8Array(password);
    this.scalar = randomScalar();
    this.pwScalar = passwordToScalar(password);

    // T = pwScalar * (M or N) + scalar * G
    const blindingPoint = role === 'A' ? M_POINT : N_POINT;
    const blinded = blindingPoint.multiply(this.pwScalar);
    const ephemeral = ExtendedPoint.BASE.multiply(this.scalar);
    const T = blinded.add(ephemeral);
    this.myMsg = T.toRawBytes(); // 32 bytes

    // Prepend side byte: 0x41 for A, 0x42 for B
    const sideByte = role === 'A' ? 0x41 : 0x42;
    this.outboundMsg = new Uint8Array(33);
    this.outboundMsg[0] = sideByte;
    this.outboundMsg.set(this.myMsg, 1);
  }

  /** Start SPAKE2 as side A (initiator). */
  static startA(password: Uint8Array): Spake2 {
    return new Spake2('A', password);
  }

  /** Start SPAKE2 as side B (responder). */
  static startB(password: Uint8Array): Spake2 {
    return new Spake2('B', password);
  }

  /**
   * Finish the SPAKE2 exchange with the peer's 33-byte message.
   * Returns the 32-byte shared key.
   */
  finish(peerMsg: Uint8Array): Uint8Array {
    try {
      if (peerMsg.length !== 33) {
        throw new CairnError(
          'CRYPTO',
          `SPAKE2 peer message must be 33 bytes, got ${peerMsg.length}`,
        );
      }

      // Validate side byte
      const peerSide = peerMsg[0];
      if (this.role === 'A' && peerSide !== 0x42) {
        throw new CairnError('CRYPTO', `SPAKE2 bad side byte: expected 0x42, got 0x${peerSide.toString(16)}`);
      }
      if (this.role === 'B' && peerSide !== 0x41) {
        throw new CairnError('CRYPTO', `SPAKE2 bad side byte: expected 0x41, got 0x${peerSide.toString(16)}`);
      }

      const peerPointBytes = peerMsg.slice(1); // 32 bytes
      const peerPoint = ExtendedPoint.fromHex(peerPointBytes);

      // Z = scalar * (peerPoint - pwScalar * (N or M))
      const peerBlindingPoint = this.role === 'A' ? N_POINT : M_POINT;
      const unblinded = peerPoint.add(peerBlindingPoint.multiply(this.pwScalar).negate());
      const Z = unblinded.multiply(this.scalar);

      // Transcript hash matching RustCrypto spake2:
      // SHA256(SHA256(pw) || SHA256(idA) || SHA256(idB) || X_msg || Y_msg || K_bytes)
      const pwHash = sha256(this.password);
      const idAHash = sha256(SPAKE2_ID_A);
      const idBHash = sha256(SPAKE2_ID_B);

      const xMsg = this.role === 'A' ? this.myMsg : peerPointBytes;
      const yMsg = this.role === 'A' ? peerPointBytes : this.myMsg;
      const kBytes = Z.toRawBytes();

      // Fixed-length 192-byte transcript
      const transcript = new Uint8Array(192);
      transcript.set(pwHash, 0);
      transcript.set(idAHash, 32);
      transcript.set(idBHash, 64);
      transcript.set(xMsg, 96);
      transcript.set(yMsg, 128);
      transcript.set(kBytes, 160);

      return sha256(transcript);
    } catch (e) {
      if (e instanceof CairnError) throw e;
      throw new CairnError('CRYPTO', `SPAKE2 finish error: ${e}`);
    }
  }
}
