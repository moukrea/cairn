// Browser entry point for cairn-p2p.
//
// Exports the Node class with full transport support for browsers.
// The browser build bundles libp2p core, WebSocket transport, yamux muxer,
// and noise encryption so that Node.startTransport() works in browsers.
// Node.js-only transports (TCP) and optional transports (WebRTC,
// WebTransport, Circuit Relay) are externalized and loaded on demand.
//
// Bundlers (Vite, webpack, etc.) auto-resolve this via the "browser"
// condition in package.json exports. Can also be imported explicitly
// as 'cairn-p2p/browser'.
//
// IMPORTANT: This file must NOT statically import anything from
// transport/libp2p-node.ts — the dynamic imports in Node.startTransport()
// will resolve at runtime from the bundled dependencies.

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

// Server exports omitted from browser build — they require Node.js
// builtins (http.createServer, crypto.timingSafeEqual) that aren't
// available in browsers. Use the main entry point for server mode.
