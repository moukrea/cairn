import { encode, decode } from 'cborg';
import { CairnError } from '../errors.js';

/** A hint for how to reach a peer. */
export interface ConnectionHint {
  hintType: string;
  value: string;
}

/**
 * The data exchanged during pairing initiation.
 * Contains everything a peer needs to bootstrap a connection and PAKE handshake.
 */
export interface PairingPayload {
  /** 32-byte Peer ID (SHA-256 hash of Ed25519 public key). */
  peerId: Uint8Array;
  /** 16-byte one-time nonce for this pairing attempt. */
  nonce: Uint8Array;
  /** PAKE credential (derived from mechanism-specific secret). */
  pakeCredential: Uint8Array;
  /** Optional connection hints (rendezvous addresses, etc.). */
  hints?: ConnectionHint[];
  /** Unix timestamp (seconds) when payload was created. */
  createdAt: number;
  /** Unix timestamp (seconds) when payload expires. */
  expiresAt: number;
}

/**
 * Serialize a PairingPayload to CBOR using compact integer keys.
 *
 * Key mapping (matches Rust): 0=peer_id, 1=nonce, 2=pake_credential, 3=hints, 4=created_at, 5=expires_at
 */
export function encodePairingPayload(payload: PairingPayload): Uint8Array {
  const map = new Map<number, unknown>();
  map.set(0, payload.peerId);
  map.set(1, payload.nonce);
  map.set(2, payload.pakeCredential);

  if (payload.hints && payload.hints.length > 0) {
    const hintArrays = payload.hints.map(h => [h.hintType, h.value]);
    map.set(3, hintArrays);
  }

  map.set(4, payload.createdAt);
  map.set(5, payload.expiresAt);

  return encode(map);
}

/**
 * Deserialize a PairingPayload from CBOR with compact integer keys.
 */
export function decodePairingPayload(data: Uint8Array): PairingPayload {
  try {
    const map = decode(data, { useMaps: true }) as Map<number, unknown>;

    const peerId = map.get(0) as Uint8Array;
    const nonce = map.get(1) as Uint8Array;
    const pakeCredential = map.get(2) as Uint8Array;

    if (!peerId || !nonce || !pakeCredential) {
      throw new CairnError('PAIRING', 'missing required fields in pairing payload');
    }

    let hints: ConnectionHint[] | undefined;
    const rawHints = map.get(3);
    if (rawHints && Array.isArray(rawHints)) {
      hints = rawHints.map((h: unknown) => {
        const arr = h as string[];
        return { hintType: arr[0], value: arr[1] };
      });
    }

    const createdAt = (map.get(4) as number) ?? 0;
    const expiresAt = (map.get(5) as number) ?? 0;

    return { peerId, nonce, pakeCredential, hints, createdAt, expiresAt };
  } catch (e) {
    if (e instanceof CairnError) throw e;
    throw new CairnError('PAIRING', `failed to decode pairing payload: ${e}`);
  }
}

/**
 * Check whether a payload has expired relative to the given unix timestamp (seconds).
 */
export function isPayloadExpired(payload: PairingPayload, nowUnix?: number): boolean {
  const now = nowUnix ?? Math.floor(Date.now() / 1000);
  return now > payload.expiresAt;
}

/**
 * Generate a 16-byte random nonce.
 */
export function generateNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}
