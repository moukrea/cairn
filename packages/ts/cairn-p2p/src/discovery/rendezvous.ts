// Rendezvous ID derivation and rotation (spec/08 section 4)

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { CairnError } from '../errors.js';

// HKDF info strings — must match Rust constants exactly.
const encoder = new TextEncoder();
const HKDF_INFO_RENDEZVOUS = encoder.encode('cairn-rendezvous-v1');
const HKDF_INFO_PAIRING_RENDEZVOUS = encoder.encode('cairn-pairing-rendezvous-v1');
const HKDF_INFO_EPOCH_OFFSET = encoder.encode('cairn-epoch-offset-v1');

/** A 32-byte opaque rendezvous identifier. */
export class RendezvousId {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (bytes.length !== 32) {
      throw new CairnError('DISCOVERY', `RendezvousId must be 32 bytes, got ${bytes.length}`);
    }
    this.bytes = new Uint8Array(bytes);
  }

  /** Encode as hex string for display and use as topic/key names. */
  toHex(): string {
    return Array.from(this.bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /** Truncate to 20-byte info_hash for BitTorrent tracker use. */
  toInfoHash(): Uint8Array {
    return this.bytes.slice(0, 20);
  }

  /** Compare equality with another RendezvousId. */
  equals(other: RendezvousId): boolean {
    if (this.bytes.length !== other.bytes.length) return false;
    for (let i = 0; i < this.bytes.length; i++) {
      if (this.bytes[i] !== other.bytes[i]) return false;
    }
    return true;
  }
}

/** Configuration for rendezvous ID rotation. */
export interface RotationConfig {
  /** Rotation interval in seconds. Default: 86400 (24 hours). */
  rotationIntervalSecs: number;
  /** Overlap window in seconds centered on epoch boundary. Default: 3600 (1 hour). */
  overlapWindowSecs: number;
  /** Clock tolerance in seconds. Default: 300 (5 minutes). */
  clockToleranceSecs: number;
}

/** Default rotation config: 24h interval, 1h overlap, 5min tolerance. */
export function defaultRotationConfig(): RotationConfig {
  return {
    rotationIntervalSecs: 86400,
    overlapWindowSecs: 3600,
    clockToleranceSecs: 300,
  };
}

/**
 * Derive a rendezvous ID from a pairing secret and epoch number.
 *
 * Uses HKDF-SHA256 with info string "cairn-rendezvous-v1". The epoch
 * number is encoded as big-endian u64 and used as the HKDF salt.
 */
export function deriveRendezvousId(pairingSecret: Uint8Array, epoch: number): RendezvousId {
  const salt = epochToBytes(epoch);
  const bytes = hkdf(sha256, pairingSecret, salt, HKDF_INFO_RENDEZVOUS, 32);
  return new RendezvousId(bytes);
}

/**
 * Derive a pairing-bootstrapped rendezvous ID from PAKE credentials and a nonce.
 *
 * Used for initial discovery before a pairing secret exists.
 */
export function derivePairingRendezvousId(
  pakeCredential: Uint8Array,
  nonce: Uint8Array,
): RendezvousId {
  const bytes = hkdf(sha256, pakeCredential, nonce, HKDF_INFO_PAIRING_RENDEZVOUS, 32);
  return new RendezvousId(bytes);
}

/**
 * Derive the epoch offset from a pairing secret.
 *
 * Makes epoch boundaries unpredictable to observers since they
 * differ per pairing relationship.
 */
function deriveEpochOffset(pairingSecret: Uint8Array): bigint {
  const bytes = hkdf(sha256, pairingSecret, undefined, HKDF_INFO_EPOCH_OFFSET, 8);
  return bytesToBigUint64BE(bytes);
}

/**
 * Compute the epoch number for a given pairing secret and timestamp.
 *
 * The epoch boundary is offset by a value derived from the pairing secret.
 */
export function computeEpoch(
  pairingSecret: Uint8Array,
  rotationIntervalSecs: number,
  timestampSecs: number,
): number {
  if (rotationIntervalSecs <= 0) {
    throw new CairnError('DISCOVERY', 'rotation interval must be > 0');
  }
  const offset = deriveEpochOffset(pairingSecret);
  const interval = BigInt(rotationIntervalSecs);
  // Wrapping add: use BigInt modular arithmetic with 2^64
  const mask = (1n << 64n) - 1n;
  const adjusted = (BigInt(timestampSecs) + offset) & mask;
  return Number(adjusted / interval);
}

/** Compute the current epoch using the system clock. */
export function currentEpoch(pairingSecret: Uint8Array, rotationIntervalSecs: number): number {
  return computeEpoch(pairingSecret, rotationIntervalSecs, Math.floor(Date.now() / 1000));
}

/**
 * Determine which rendezvous IDs are active at a given timestamp.
 *
 * Outside the overlap window: returns only the current epoch's ID.
 * Inside the overlap window: returns both current and adjacent epoch's ID.
 */
export function activeRendezvousIdsAt(
  pairingSecret: Uint8Array,
  config: RotationConfig,
  timestampSecs: number,
): RendezvousId[] {
  const interval = config.rotationIntervalSecs;
  if (interval <= 0) {
    throw new CairnError('DISCOVERY', 'rotation interval must be > 0');
  }

  const offset = deriveEpochOffset(pairingSecret);
  const mask = (1n << 64n) - 1n;
  const adjusted = (BigInt(timestampSecs) + offset) & mask;
  const intervalBig = BigInt(interval);
  const currentEpochNum = Number(adjusted / intervalBig);
  const positionInEpoch = Number(adjusted % intervalBig);

  const halfOverlap = Math.floor(config.overlapWindowSecs / 2) + config.clockToleranceSecs;

  const currentId = deriveRendezvousId(pairingSecret, currentEpochNum);

  // Check if we're in the overlap window near epoch boundary
  const inOverlap = positionInEpoch < halfOverlap || positionInEpoch > interval - halfOverlap;

  if (inOverlap && currentEpochNum > 0) {
    const otherEpoch =
      positionInEpoch < halfOverlap ? currentEpochNum - 1 : currentEpochNum + 1;
    const otherId = deriveRendezvousId(pairingSecret, otherEpoch);
    return [currentId, otherId];
  }

  return [currentId];
}

/** Determine which rendezvous IDs are active right now. */
export function activeRendezvousIds(
  pairingSecret: Uint8Array,
  config: RotationConfig,
): RendezvousId[] {
  return activeRendezvousIdsAt(pairingSecret, config, Math.floor(Date.now() / 1000));
}

// --- Helpers ---

/** Encode an epoch number as 8-byte big-endian (u64). */
function epochToBytes(epoch: number): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(epoch), false); // big-endian
  return buf;
}

/** Read 8 bytes as big-endian u64 BigInt. */
function bytesToBigUint64BE(bytes: Uint8Array): bigint {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getBigUint64(0, false);
}
