// Server module — store-and-forward, management

export type {
  ForwardRequest,
  ForwardAck,
  ForwardDeliver,
  ForwardPurge,
  StoredMessage,
  RetentionPolicy,
} from './store-forward.js';
export {
  FORWARD_CHANNEL,
  MAX_SKIP_THRESHOLD,
  defaultRetentionPolicy,
  MessageStore,
  DeduplicationTracker,
} from './store-forward.js';

export type {
  ManagementConfig,
  PeerInfo,
  QueueInfo,
  PeerRelayStats,
  RelayStats,
  PeersResponse,
  QueuesResponse,
  RelayStatsResponse,
  HealthResponse,
} from './management.js';
export {
  defaultManagementConfig,
  ManagementState,
  ManagementServer,
  createManagementServer,
} from './management.js';

/** Server mode configuration posture (spec 10.2). */
export interface ServerConfig {
  meshEnabled: boolean;
  relayWilling: boolean;
  relayCapacity: number;
  storeForwardEnabled: boolean;
  storeForwardMaxPerPeer: number;
  storeForwardMaxAgeMs: number;
  storeForwardMaxTotalSize: number;
  sessionExpiryMs: number;
  heartbeatIntervalMs: number;
  reconnectMaxDurationMs: number | null;
  headless: boolean;
}

/** Default server configuration. */
export function defaultServerConfig(): ServerConfig {
  return {
    meshEnabled: true,
    relayWilling: true,
    relayCapacity: 100,
    storeForwardEnabled: true,
    storeForwardMaxPerPeer: 1000,
    storeForwardMaxAgeMs: 7 * 24 * 60 * 60 * 1000,        // 7 days
    storeForwardMaxTotalSize: 1_073_741_824,                // 1 GB
    sessionExpiryMs: 7 * 24 * 60 * 60 * 1000,              // 7 days
    heartbeatIntervalMs: 60_000,                            // 60s
    reconnectMaxDurationMs: null,                           // indefinite
    headless: true,
  };
}
