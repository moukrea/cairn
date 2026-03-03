/**
 * Storage adapter interface for persisting identity, per-peer state, and
 * per-session state. All values are opaque Uint8Array blobs.
 */
export interface StorageAdapter {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * Transport protocol in the fallback chain.
 */
export type TransportType = 'quic' | 'tcp' | 'websocket' | 'webtransport' | 'circuit-relay-v2';

/**
 * Storage backend selection.
 *
 * - `'filesystem'` — encrypted at rest with passphrase (Node.js)
 * - `'memory'` — ephemeral, for testing
 * - A `StorageAdapter` instance for custom backends (keychains, HSMs, IndexedDB)
 */
export type StorageBackend = 'filesystem' | 'memory' | StorageAdapter;

/**
 * NAT type as detected by STUN probing.
 */
export type NatType =
  | 'open'
  | 'full_cone'
  | 'restricted_cone'
  | 'port_restricted_cone'
  | 'symmetric'
  | 'unknown';

/**
 * Connection state machine states (spec/07 section 2).
 */
export type ConnectionState =
  | 'connected'
  | 'unstable'
  | 'disconnected'
  | 'reconnecting'
  | 'suspended'
  | 'reconnected'
  | 'failed';

/**
 * Cipher suite for AEAD encryption.
 */
export type CipherSuite = 'aes-256-gcm' | 'chacha20-poly1305';

/**
 * Peer identity — 34-byte multihash (0x12, 0x20, <32-byte SHA-256>).
 */
export type PeerId = Uint8Array;

/**
 * TURN relay server credentials.
 */
export interface TurnServerConfig {
  url: string;
  username: string;
  credential: string;
}

/**
 * Exponential backoff parameters.
 */
export interface BackoffConfig {
  initialDelay: number;
  maxDelay: number;
  factor: number;
}

/**
 * Reconnection and timeout policy (spec/11 section 2.2).
 */
export interface ReconnectionPolicy {
  connectTimeout: number;
  transportTimeout: number;
  reconnectMaxDuration: number;
  reconnectBackoff: BackoffConfig;
  rendezvousPollInterval: number;
  sessionExpiry: number;
  pairingPayloadExpiry: number;
}

/**
 * Mesh routing settings.
 */
export interface MeshSettings {
  meshEnabled?: boolean;
  maxHops?: number;
  relayWilling?: boolean;
  relayCapacity?: number;
}

/**
 * Top-level configuration object.
 *
 * Every field is optional — sensible defaults enable zero-config usage (Tier 0).
 */
export interface CairnConfig {
  stunServers?: string[];
  turnServers?: TurnServerConfig[];
  signalingServers?: string[];
  trackerUrls?: string[];
  bootstrapNodes?: string[];
  transportPreferences?: TransportType[];
  reconnectionPolicy?: Partial<ReconnectionPolicy>;
  meshSettings?: MeshSettings;
  storageBackend?: StorageBackend;
}

/**
 * Default STUN servers (Google, Cloudflare).
 */
export const DEFAULT_STUN_SERVERS: readonly string[] = [
  'stun:stun.l.google.com:19302',
  'stun:stun1.l.google.com:19302',
  'stun:stun.cloudflare.com:3478',
];

/**
 * Default transport fallback order.
 */
export const DEFAULT_TRANSPORT_PREFERENCES: readonly TransportType[] = [
  'quic',
  'tcp',
  'websocket',
  'webtransport',
  'circuit-relay-v2',
];

/**
 * Default reconnection policy values.
 */
export const DEFAULT_RECONNECTION_POLICY: Readonly<ReconnectionPolicy> = {
  connectTimeout: 30_000,
  transportTimeout: 10_000,
  reconnectMaxDuration: 3_600_000,
  reconnectBackoff: {
    initialDelay: 1_000,
    maxDelay: 60_000,
    factor: 2.0,
  },
  rendezvousPollInterval: 30_000,
  sessionExpiry: 86_400_000,
  pairingPayloadExpiry: 300_000,
};

/**
 * Default mesh settings.
 */
export const DEFAULT_MESH_SETTINGS: Readonly<Required<MeshSettings>> = {
  meshEnabled: false,
  maxHops: 3,
  relayWilling: false,
  relayCapacity: 10,
};
