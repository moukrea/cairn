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
