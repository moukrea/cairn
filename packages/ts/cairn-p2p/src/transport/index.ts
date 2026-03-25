// Transport module — libp2p integration, fallback chain, NAT (task 035)

export type { FallbackTransportType } from './fallback.js';
export {
  transportPriority,
  transportDisplayName,
  isTier0Available,
  allTransportsInOrder,
  DEFAULT_TRANSPORT_TIMEOUT_MS,
  FallbackChain,
  defaultConnectionQuality,
  defaultQualityThresholds,
  ConnectionQualityMonitor,
  TransportMigrator,
} from './fallback.js';
export type {
  TransportAttempt,
  TransportAttemptResult,
  ConnectionQuality,
  QualityThresholds,
  DegradationReason,
  DegradationEvent,
  DegradationListener,
  MigrationEvent,
  MigrationListener,
} from './fallback.js';

export type { NatType, NetworkInfo, StunMappedAddress, StunServerConfig } from './nat.js';
export {
  defaultNetworkInfo,
  buildBindingRequest,
  parseBindingResponse,
  classifyNat,
  DEFAULT_STUN_SERVERS,
  NatDetector,
} from './nat.js';

export type { TransportConfig, CreateNodeOptions } from './libp2p-node.js';
export {
  defaultTransportConfig,
  isNodeEnvironment,
  isBrowserEnvironment,
  createCairnNode,
  BROWSER_TRANSPORT_CHAIN,
  NODEJS_TRANSPORT_CHAIN,
  CAIRN_PROTOCOL,
  encodeFrame,
  decodeFrame,
  readFrame,
  writeFrame,
} from './libp2p-node.js';
