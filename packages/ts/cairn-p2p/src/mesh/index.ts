// Mesh module — routing, relay, multi-hop networking

/** Mesh networking configuration (spec 9.4). */
export interface MeshConfig {
  /** Enable/disable mesh routing. Default: false. */
  meshEnabled: boolean;
  /** Maximum relay hops allowed for any route. Default: 3. */
  maxHops: number;
  /** Whether this peer is willing to relay traffic for others. Default: false. */
  relayWilling: boolean;
  /** Maximum simultaneous relay connections this peer will serve. Default: 10. */
  relayCapacity: number;
}

/** Default mesh config: disabled, 3 max hops, not willing, capacity 10. */
export function defaultMeshConfig(): MeshConfig {
  return {
    meshEnabled: false,
    maxHops: 3,
    relayWilling: false,
    relayCapacity: 10,
  };
}

/** Server-mode mesh config: enabled, willing, capacity 100. */
export function serverMeshConfig(): MeshConfig {
  return {
    meshEnabled: true,
    maxHops: 3,
    relayWilling: true,
    relayCapacity: 100,
  };
}

export type {
  Route,
  ReachabilityEntry,
  MeshTopologyUpdate,
} from './routing-table.js';
export {
  RoutingTable,
  directRoute,
  relayedRoute,
  hopCount,
} from './routing-table.js';

export type { RelaySessionId, RelaySession } from './relay.js';
export { RelayManager } from './relay.js';
