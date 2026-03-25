// Browser-safe entry point for cairn-p2p.
//
// Re-exports everything from the main index EXCEPT the transport/libp2p-node
// module which pulls in Node.js-only dependencies (@libp2p/tcp, @libp2p/yamux
// native builds, etc.) that fail to bundle with Vite/Rollup for browsers.
//
// Browser applications should import from 'cairn-p2p/browser' or use the
// package.json "browser" export condition (automatic in Vite/webpack).

// Re-export everything from the main module
export {
  Node,
  NodeSession,
  NodeChannel,
} from './node.js';

export type {
  NodeEvents,
  SessionEvents,
  QrPairingData,
  PinPairingData,
  LinkPairingData,
  ResolvedConfig,
} from './node.js';

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

export { SessionStateMachine, isValidTransition } from './session/index.js';
export type { StateChangedEvent, StateChangedListener } from './session/index.js';

export type { ServerConfig } from './server/index.js';
export { defaultServerConfig } from './server/index.js';
