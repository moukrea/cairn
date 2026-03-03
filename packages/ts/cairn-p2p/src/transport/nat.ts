import { CairnError } from '../errors.js';

// ---------------------------------------------------------------------------
// NAT Type (spec section 7)
// ---------------------------------------------------------------------------

/**
 * Detected NAT type, exposed as a read-only diagnostic.
 *
 * "Application behavior should never depend on NAT type -- the transport
 * chain handles it transparently. This diagnostic is provided for
 * debugging connectivity issues only." (spec section 7)
 */
export type NatType =
  | 'open'
  | 'full_cone'
  | 'restricted_cone'
  | 'port_restricted_cone'
  | 'symmetric'
  | 'unknown';

// ---------------------------------------------------------------------------
// Network info (public API surface)
// ---------------------------------------------------------------------------

/** Read-only network diagnostic info. */
export interface NetworkInfo {
  natType: NatType;
  externalAddr?: string;
}

/** Default network info (detection not yet attempted). */
export function defaultNetworkInfo(): NetworkInfo {
  return { natType: 'unknown' };
}

// ---------------------------------------------------------------------------
// STUN protocol constants (minimal RFC 5389)
// ---------------------------------------------------------------------------

const STUN_MAGIC_COOKIE = 0x2112_A442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;

/** Build a minimal STUN Binding Request (20 bytes header, no attributes). */
export function buildBindingRequest(transactionId: Uint8Array): Uint8Array {
  if (transactionId.length !== 12) {
    throw new CairnError('TRANSPORT', 'transaction ID must be 12 bytes');
  }
  const buf = new Uint8Array(20);
  const view = new DataView(buf.buffer);
  view.setUint16(0, STUN_BINDING_REQUEST);
  view.setUint16(2, 0); // message length = 0
  view.setUint32(4, STUN_MAGIC_COOKIE);
  buf.set(transactionId, 8);
  return buf;
}

/** Parsed STUN mapped address. */
export interface StunMappedAddress {
  ip: string;
  port: number;
  family: 'IPv4' | 'IPv6';
}

/** Parse a STUN Binding Response, returning the mapped address. */
export function parseBindingResponse(
  data: Uint8Array,
  expectedTxnId: Uint8Array,
): StunMappedAddress {
  if (data.length < 20) {
    throw new CairnError('TRANSPORT', 'STUN response too short');
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const msgType = view.getUint16(0);
  if (msgType !== STUN_BINDING_RESPONSE) {
    throw new CairnError('TRANSPORT', `unexpected STUN message type: 0x${msgType.toString(16).padStart(4, '0')}`);
  }

  const msgLen = view.getUint16(2);
  const magic = view.getUint32(4);
  if (magic !== STUN_MAGIC_COOKIE) {
    throw new CairnError('TRANSPORT', 'invalid STUN magic cookie');
  }

  // Verify transaction ID
  for (let i = 0; i < 12; i++) {
    if (data[8 + i] !== expectedTxnId[i]) {
      throw new CairnError('TRANSPORT', 'STUN transaction ID mismatch');
    }
  }

  // Parse attributes
  const attrsEnd = Math.min(20 + msgLen, data.length);
  let offset = 20;
  let xorMapped: StunMappedAddress | undefined;
  let mapped: StunMappedAddress | undefined;

  while (offset + 4 <= attrsEnd) {
    const attrType = view.getUint16(offset);
    const attrLen = view.getUint16(offset + 2);
    const attrStart = offset + 4;

    if (attrStart + attrLen > attrsEnd) break;

    const attrData = data.subarray(attrStart, attrStart + attrLen);

    if (attrType === ATTR_XOR_MAPPED_ADDRESS) {
      xorMapped = parseXorMappedAddress(attrData, expectedTxnId);
    } else if (attrType === ATTR_MAPPED_ADDRESS) {
      mapped = parseMappedAddress(attrData);
    }

    // Attributes padded to 4-byte boundaries
    const paddedLen = (attrLen + 3) & ~3;
    offset = attrStart + paddedLen;
  }

  const result = xorMapped ?? mapped;
  if (!result) {
    throw new CairnError('TRANSPORT', 'no mapped address in STUN response');
  }
  return result;
}

/** Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2). */
function parseXorMappedAddress(data: Uint8Array, txnId: Uint8Array): StunMappedAddress | undefined {
  if (data.length < 8) return undefined;

  const family = data[1];
  const xorPort = ((data[2] << 8) | data[3]) ^ (STUN_MAGIC_COOKIE >>> 16);

  if (family === 0x01) {
    // IPv4
    const xorIp =
      ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]) ^
      STUN_MAGIC_COOKIE;
    const ip = `${(xorIp >>> 24) & 0xff}.${(xorIp >>> 16) & 0xff}.${(xorIp >>> 8) & 0xff}.${xorIp & 0xff}`;
    return { ip, port: xorPort, family: 'IPv4' };
  }

  if (family === 0x02) {
    // IPv6
    if (data.length < 20) return undefined;
    const ipBytes = new Uint8Array(16);
    ipBytes.set(data.subarray(4, 20));
    // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
    const cookieBytes = new Uint8Array(4);
    new DataView(cookieBytes.buffer).setUint32(0, STUN_MAGIC_COOKIE);
    for (let i = 0; i < 4; i++) ipBytes[i] ^= cookieBytes[i];
    for (let i = 0; i < 12; i++) ipBytes[4 + i] ^= txnId[i];

    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((ipBytes[i] << 8) | ipBytes[i + 1]).toString(16));
    }
    return { ip: parts.join(':'), port: xorPort, family: 'IPv6' };
  }

  return undefined;
}

/** Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1). */
function parseMappedAddress(data: Uint8Array): StunMappedAddress | undefined {
  if (data.length < 8) return undefined;

  const family = data[1];
  const port = (data[2] << 8) | data[3];

  if (family === 0x01) {
    const ip = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
    return { ip, port, family: 'IPv4' };
  }

  if (family === 0x02) {
    if (data.length < 20) return undefined;
    const parts: string[] = [];
    for (let i = 4; i < 20; i += 2) {
      parts.push(((data[i] << 8) | data[i + 1]).toString(16));
    }
    return { ip: parts.join(':'), port, family: 'IPv6' };
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// NAT classification
// ---------------------------------------------------------------------------

/**
 * Classify NAT type by comparing mapped addresses from multiple servers.
 *
 * Simplified RFC 5780 logic:
 * - Same mapped address from all servers: cone NAT (default PortRestrictedCone)
 * - Different mapped addresses: Symmetric
 * - Single server: Unknown (can't differentiate)
 */
export function classifyNat(
  mappedAddrs: Array<{ server: string; mapped: StunMappedAddress }>,
): NatType {
  if (mappedAddrs.length === 0) return 'unknown';
  if (mappedAddrs.length < 2) return 'unknown';

  const firstIp = mappedAddrs[0].mapped.ip;
  const firstPort = mappedAddrs[0].mapped.port;

  const allSameIp = mappedAddrs.every((m) => m.mapped.ip === firstIp);
  const allSamePort = mappedAddrs.every((m) => m.mapped.port === firstPort);

  if (!allSameIp || !allSamePort) {
    return 'symmetric';
  }

  // Same IP and port from all servers -- some form of cone NAT.
  // Without CHANGE-REQUEST support, default to port_restricted_cone
  // (conservative classification).
  return 'port_restricted_cone';
}

// ---------------------------------------------------------------------------
// NatDetector
// ---------------------------------------------------------------------------

export interface StunServerConfig {
  host: string;
  port: number;
}

/** Default public STUN servers. */
export const DEFAULT_STUN_SERVERS: StunServerConfig[] = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun1.l.google.com', port: 19302 },
];

/**
 * STUN-based NAT type detector.
 *
 * Queries configured STUN servers and classifies the NAT type by
 * comparing mapped addresses across servers (simplified RFC 5780 logic).
 *
 * This is diagnostic-only — application behavior should never depend on it.
 */
export class NatDetector {
  private readonly _stunServers: StunServerConfig[];
  private readonly _timeoutMs: number;

  constructor(stunServers?: StunServerConfig[], timeoutMs: number = 3000) {
    this._stunServers = stunServers ?? DEFAULT_STUN_SERVERS;
    this._timeoutMs = timeoutMs;
  }

  get stunServers(): readonly StunServerConfig[] {
    return this._stunServers;
  }

  get timeoutMs(): number {
    return this._timeoutMs;
  }

  /**
   * Detect the NAT type by querying STUN servers.
   *
   * Returns NetworkInfo with `natType: 'unknown'` if detection fails.
   * Never throws — failures result in Unknown status.
   *
   * Note: Requires a UDP socket implementation. In Node.js this uses
   * `dgram`. In browsers, STUN detection is not directly available
   * (use WebRTC ICE candidates instead).
   */
  async detect(): Promise<NetworkInfo> {
    if (this._stunServers.length === 0) {
      return defaultNetworkInfo();
    }

    const mappedAddrs: Array<{ server: string; mapped: StunMappedAddress }> = [];

    for (const server of this._stunServers) {
      try {
        const mapped = await this.stunBindingRequest(server);
        mappedAddrs.push({ server: `${server.host}:${server.port}`, mapped });
      } catch {
        // Failures are expected (firewall, unreachable server)
      }
    }

    if (mappedAddrs.length === 0) {
      return defaultNetworkInfo();
    }

    const natType = classifyNat(mappedAddrs);
    const firstMapped = mappedAddrs[0].mapped;

    return {
      natType,
      externalAddr: `${firstMapped.ip}:${firstMapped.port}`,
    };
  }

  /** Send a STUN Binding Request via UDP and return our mapped address. */
  private async stunBindingRequest(server: StunServerConfig): Promise<StunMappedAddress> {
    // Dynamic import of dgram for Node.js only
    const dgram = await import('dgram').catch(() => {
      throw new CairnError('TRANSPORT', 'dgram module not available (browser environment)');
    });

    return new Promise<StunMappedAddress>((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      const txnId = new Uint8Array(12);
      crypto.getRandomValues(txnId);

      const request = buildBindingRequest(txnId);

      const timeout = setTimeout(() => {
        socket.close();
        reject(new CairnError('TRANSPORT', 'STUN request timed out'));
      }, this._timeoutMs);

      socket.on('message', (msg: Buffer) => {
        clearTimeout(timeout);
        socket.close();
        try {
          const addr = parseBindingResponse(new Uint8Array(msg), txnId);
          resolve(addr);
        } catch (e) {
          reject(e);
        }
      });

      socket.on('error', (err: Error) => {
        clearTimeout(timeout);
        socket.close();
        reject(new CairnError('TRANSPORT', `STUN socket error: ${err.message}`));
      });

      socket.send(Buffer.from(request), server.port, server.host, (err) => {
        if (err) {
          clearTimeout(timeout);
          socket.close();
          reject(new CairnError('TRANSPORT', `failed to send STUN request: ${err.message}`));
        }
      });
    });
  }
}
