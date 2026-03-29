// Discovery module — mDNS, DHT, trackers, signaling, rendezvous

export type { RotationConfig } from './rendezvous.js';
export {
  RendezvousId,
  defaultRotationConfig,
  deriveRendezvousId,
  derivePairingRendezvousId,
  computeEpoch,
  currentEpoch,
  activeRendezvousIdsAt,
  activeRendezvousIds,
} from './rendezvous.js';

export type {
  DiscoveryBackend,
  DiscoveryResult,
  PublishResult,
} from './manager.js';
export { DiscoveryManager, InMemoryBackend } from './manager.js';

export { MdnsBackend } from './mdns-backend.js';
export { DhtBackend } from './dht-backend.js';
export type { SignalingConfig } from './signaling-backend.js';
export { SignalingBackend } from './signaling-backend.js';

export type {
  TrackerProtocol,
  TrackerConfig,
  TrackerPeer,
} from './tracker.js';
export {
  TrackerBackend,
  MIN_REANNOUNCE_INTERVAL_MS,
  parseTrackerProtocol,
  urlEncodeBytes,
  buildHttpAnnounceUrl,
  buildUdpConnectRequest,
  parseUdpConnectResponse,
  buildUdpAnnounceRequest,
  parseUdpAnnounceResponse,
  generatePeerId,
} from './tracker.js';
