// Browser-safe entry point for cairn-p2p.
//
// Exports the Node class but WITHOUT startTransport/createAndStart which
// pull in @libp2p/* Node.js dependencies that don't bundle for browsers.
//
// Bundlers (Vite, webpack, etc.) auto-resolve this via the "browser"
// condition in package.json exports. Can also be imported explicitly
// as 'cairn-p2p/browser'.

// Re-export the core Node class. The startTransport() method exists on
// the class but will fail at runtime in browsers (dynamic imports to
// @libp2p/* won't resolve). This is expected — browser transport requires
// a different approach (e.g., WebSocket to a signaling server).
//
// IMPORTANT: This file must NOT statically import anything from
// transport/libp2p-node.ts to avoid bundler errors.

export { Node, NodeSession, NodeChannel } from './node.js';
export type {
  NodeEvents, SessionEvents, QrPairingData, PinPairingData,
  LinkPairingData, ResolvedConfig,
} from './node.js';

export type {
  CairnConfig, TurnServerConfig, BackoffConfig, ReconnectionPolicy,
  MeshSettings, StorageAdapter, StorageBackend, TransportType,
  NatType, ConnectionState, CipherSuite, PeerId,
} from './config.js';

export {
  DEFAULT_STUN_SERVERS, DEFAULT_TRANSPORT_PREFERENCES,
  DEFAULT_RECONNECTION_POLICY, DEFAULT_MESH_SETTINGS,
} from './config.js';

export {
  ErrorBehavior, CairnError, TransportExhaustedError, SessionExpiredError,
  PeerUnreachableError, AuthenticationFailedError, PairingRejectedError,
  PairingExpiredError, MeshRouteNotFoundError, VersionMismatchError,
} from './errors.js';

export { SessionStateMachine, isValidTransition } from './session/index.js';
export type { StateChangedEvent, StateChangedListener } from './session/index.js';

export type { ServerConfig } from './server/index.js';
export { defaultServerConfig } from './server/index.js';
