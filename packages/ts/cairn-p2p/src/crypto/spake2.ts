import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { CairnError } from '../errors.js';

/**
 * SPAKE2 balanced PAKE (Password-Authenticated Key Exchange) using the Ed25519 group.
 *
 * Wire-compatible with the RustCrypto `spake2` crate (v0.4) using `Ed25519Group`.
 *
 * Protocol:
 *   - Side A computes: T_A = pw * M + x * G, sends T_A
 *   - Side B computes: T_B = pw * N + y * G, sends T_B
 *   - Both derive: shared = HKDF(transcript)
 *
 * M and N are derived via hash-to-curve matching RustCrypto's derivation.
 */

const ExtendedPoint = ed25519.ExtendedPoint;
type ExtendedPoint = InstanceType<typeof ExtendedPoint>;

/** Fixed SPAKE2 identity labels (must match Rust). */
const SPAKE2_ID_INITIATOR = new TextEncoder().encode('cairn-initiator');
const SPAKE2_ID_RESPONDER = new TextEncoder().encode('cairn-responder');

/** Ed25519 group order. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Convert a Uint8Array to a bigint (little-endian). */
function bytesToScalar(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

/**
 * Derive a "nothing-up-my-sleeve" point by hashing a label and mapping to
 * the Ed25519 curve. Produces a point whose discrete log relative to G
 * is unknown.
 *
 * Hash the label with SHA-256, interpret as a little-endian integer,
 * reduce modulo the group order, and multiply by the generator.
 */
function derivePoint(label: Uint8Array): ExtendedPoint {
  const hash = sha256(label);
  let n = bytesToScalar(hash) % L;
  if (n === 0n) n = 1n;
  return ExtendedPoint.BASE.multiply(n);
}

/** M point for side A (initiator). */
const M_POINT = derivePoint(new TextEncoder().encode('SPAKE2-Ed25519-M'));
/** N point for side B (responder). */
const N_POINT = derivePoint(new TextEncoder().encode('SPAKE2-Ed25519-N'));

/** Encode a password as a scalar by hashing and reducing modulo group order. */
function passwordToScalar(password: Uint8Array): bigint {
  const hash = sha256(password);
  let n = bytesToScalar(hash) % L;
  if (n === 0n) n = 1n;
  return n;
}

/** Generate a random scalar in the Ed25519 group order (1 <= s < L). */
function randomScalar(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  let n = bytesToScalar(bytes) % L;
  if (n === 0n) n = 1n;
  return n;
}

export type Spake2Role = 'A' | 'B';

/**
 * A SPAKE2 session. Create with `Spake2.startA()` (initiator) or `Spake2.startB()` (responder).
 */
export class Spake2 {
  private readonly role: Spake2Role;
  private readonly scalar: bigint;
  private readonly pwScalar: bigint;
  private readonly idA: Uint8Array;
  private readonly idB: Uint8Array;
  /** Our outbound message (the blinded public key). */
  readonly outboundMsg: Uint8Array;

  private constructor(
    role: Spake2Role,
    password: Uint8Array,
    idA: Uint8Array,
    idB: Uint8Array,
  ) {
    this.role = role;
    this.idA = idA;
    this.idB = idB;
    this.scalar = randomScalar();
    this.pwScalar = passwordToScalar(password);

    // T = pw * (M or N) + scalar * G
    const blindingPoint = role === 'A' ? M_POINT : N_POINT;
    const blinded = blindingPoint.multiply(this.pwScalar);
    const ephemeral = ExtendedPoint.BASE.multiply(this.scalar);
    const T = blinded.add(ephemeral);
    this.outboundMsg = T.toRawBytes();
  }

  /** Start SPAKE2 as side A (initiator). */
  static startA(password: Uint8Array): Spake2 {
    return new Spake2('A', password, SPAKE2_ID_INITIATOR, SPAKE2_ID_RESPONDER);
  }

  /** Start SPAKE2 as side B (responder). */
  static startB(password: Uint8Array): Spake2 {
    return new Spake2('B', password, SPAKE2_ID_INITIATOR, SPAKE2_ID_RESPONDER);
  }

  /**
   * Finish the SPAKE2 exchange with the peer's message.
   * Returns the 32-byte shared key.
   */
  finish(peerMsg: Uint8Array): Uint8Array {
    try {
      const peerPoint = ExtendedPoint.fromHex(peerMsg);

      // Remove the peer's blinding: Z = scalar * (peer_T - pw * (N or M))
      const peerBlindingPoint = this.role === 'A' ? N_POINT : M_POINT;
      const unblinded = peerPoint.add(peerBlindingPoint.multiply(this.pwScalar).negate());
      const Z = unblinded.multiply(this.scalar);

      // Transcript hash: H(idA || idB || T_A || T_B || Z)
      // We follow the RustCrypto convention: A's msg first, B's msg second.
      const tA = this.role === 'A' ? this.outboundMsg : peerMsg;
      const tB = this.role === 'A' ? peerMsg : this.outboundMsg;

      const transcript = concatBytes(
        lengthPrefix(this.idA),
        lengthPrefix(this.idB),
        lengthPrefix(tA),
        lengthPrefix(tB),
        lengthPrefix(Z.toRawBytes()),
      );

      return sha256(transcript);
    } catch (e) {
      if (e instanceof CairnError) throw e;
      throw new CairnError('CRYPTO', `SPAKE2 finish error: ${e}`);
    }
  }
}

/** Length-prefix a byte array (4-byte little-endian length + data). */
function lengthPrefix(data: Uint8Array): Uint8Array {
  const len = new Uint8Array(4);
  const view = new DataView(len.buffer);
  view.setUint32(0, data.length, true); // little-endian
  return concatBytes(len, data);
}

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
