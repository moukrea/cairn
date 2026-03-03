// Public API exports

// Node
export { Node, NodeSession, NodeChannel } from './node.js';
export type {
  NodeEvents,
  SessionEvents,
  QrPairingData,
  PinPairingData,
  LinkPairingData,
  ResolvedConfig,
} from './node.js';

// Configuration types
export type {
  CairnConfig,
  TurnServerConfig,
  BackoffConfig,
  ReconnectionPolicy,
  MeshSettings,
  StorageAdapter,
  StorageBackend,
  TransportType,
  NatType,
  ConnectionState,
  CipherSuite,
  PeerId,
} from './config.js';

export {
  DEFAULT_STUN_SERVERS,
  DEFAULT_TRANSPORT_PREFERENCES,
  DEFAULT_RECONNECTION_POLICY,
  DEFAULT_MESH_SETTINGS,
} from './config.js';

// Error types
export {
  ErrorBehavior,
  CairnError,
  TransportExhaustedError,
  SessionExpiredError,
  PeerUnreachableError,
  AuthenticationFailedError,
  PairingRejectedError,
  PairingExpiredError,
  MeshRouteNotFoundError,
  VersionMismatchError,
} from './errors.js';

// Session state machine
export { SessionStateMachine, isValidTransition } from './session/index.js';
export type { StateChangedEvent, StateChangedListener } from './session/index.js';

// Server
export type { ServerConfig } from './server/index.js';
export { defaultServerConfig } from './server/index.js';
