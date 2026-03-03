// Mesh routing table and route selection (spec/09 section 9.2)

import { CairnError, MeshRouteNotFoundError } from '../errors.js';

/** A route to a destination peer, potentially through intermediate relay hops. */
export interface Route {
  /** Ordered list of intermediate relay peer IDs (hex). Empty means direct. */
  hops: string[];
  /** Measured or estimated latency in milliseconds. */
  latencyMs: number;
  /** Estimated available bandwidth in bytes/sec. */
  bandwidthBps: number;
  /** When this route was last confirmed reachable (unix ms). */
  lastSeen: number;
}

/** Create a direct route (zero hops). */
export function directRoute(latencyMs: number, bandwidthBps: number): Route {
  return { hops: [], latencyMs, bandwidthBps, lastSeen: Date.now() };
}

/** Create a relayed route through intermediate hops. */
export function relayedRoute(hops: string[], latencyMs: number, bandwidthBps: number): Route {
  return { hops: [...hops], latencyMs, bandwidthBps, lastSeen: Date.now() };
}

/** Get the hop count for a route. */
export function hopCount(route: Route): number {
  return route.hops.length;
}

/** A single reachability entry in a topology update. */
export interface ReachabilityEntry {
  /** The reachable peer (hex peer ID). */
  peerId: string;
  /** Intermediate hops to reach this peer from the sender (empty = direct). */
  viaHops: string[];
  /** Estimated latency in milliseconds. */
  latencyMs: number;
  /** Estimated bandwidth in bytes/sec. */
  bandwidthBps: number;
}

/** A topology update message exchanged between mesh peers (distance-vector). */
export interface MeshTopologyUpdate {
  /** Peers reachable from the sender. */
  reachablePeers: ReachabilityEntry[];
}

/**
 * Route selection comparison.
 *
 * Priority: shortest hops -> lowest latency -> highest bandwidth.
 * Returns negative if a is better, positive if b is better, 0 if equal.
 */
function compareRoutes(a: Route, b: Route): number {
  const hopDiff = hopCount(a) - hopCount(b);
  if (hopDiff !== 0) return hopDiff;

  const latDiff = a.latencyMs - b.latencyMs;
  if (latDiff !== 0) return latDiff;

  // Higher bandwidth is better, so reverse comparison
  return b.bandwidthBps - a.bandwidthBps;
}

/**
 * Routing table maintaining known peers and their reachability.
 */
export class RoutingTable {
  private readonly _routes = new Map<string, Route[]>();
  private readonly _maxHops: number;

  constructor(maxHops: number) {
    this._maxHops = maxHops;
  }

  /** Get the max hops limit. */
  get maxHops(): number {
    return this._maxHops;
  }

  /**
   * Add or update a route to a destination peer.
   * Routes exceeding maxHops are rejected.
   */
  addRoute(destination: string, route: Route): void {
    const hops = hopCount(route);
    if (hops > this._maxHops) {
      throw new CairnError(
        'MESH_MAX_HOPS_EXCEEDED',
        `max hops exceeded: ${hops} > ${this._maxHops}`,
      );
    }

    const existing = this._routes.get(destination);
    if (existing) {
      existing.push(route);
    } else {
      this._routes.set(destination, [route]);
    }
  }

  /**
   * Select the best route to a destination peer.
   *
   * Priority order per spec 9.2:
   * 1. Shortest hop count
   * 2. Lowest latency
   * 3. Highest bandwidth
   */
  selectBestRoute(destination: string): Route {
    const routes = this._routes.get(destination);
    if (!routes || routes.length === 0) {
      throw new MeshRouteNotFoundError(`no route to peer ${destination}`);
    }

    let best = routes[0];
    for (let i = 1; i < routes.length; i++) {
      if (compareRoutes(routes[i], best) < 0) {
        best = routes[i];
      }
    }
    return best;
  }

  /** Get all known routes to a destination peer. */
  getRoutes(destination: string): Route[] | undefined {
    return this._routes.get(destination);
  }

  /** Remove all routes to a destination peer. */
  removeRoutes(destination: string): void {
    this._routes.delete(destination);
  }

  /** Remove stale routes older than the given age (ms). */
  expireRoutes(maxAgeMs: number): void {
    const cutoff = Date.now() - maxAgeMs;
    for (const [dest, routes] of this._routes) {
      const fresh = routes.filter((r) => r.lastSeen >= cutoff);
      if (fresh.length === 0) {
        this._routes.delete(dest);
      } else {
        this._routes.set(dest, fresh);
      }
    }
  }

  /** Get the number of known destination peers. */
  get peerCount(): number {
    return this._routes.size;
  }

  /** Get the total number of routes across all destinations. */
  get routeCount(): number {
    let count = 0;
    for (const routes of this._routes.values()) {
      count += routes.length;
    }
    return count;
  }

  /** Get all known destination peer IDs. */
  get destinations(): string[] {
    return [...this._routes.keys()];
  }

  /**
   * Apply a topology update from a neighboring peer.
   *
   * Merges the neighbor's reachability information, adding the neighbor
   * as an additional hop to each advertised destination.
   * Returns the number of routes successfully added.
   */
  applyTopologyUpdate(neighbor: string, update: MeshTopologyUpdate): number {
    let added = 0;
    for (const entry of update.reachablePeers) {
      const hops = [neighbor, ...entry.viaHops];
      const route: Route = {
        hops,
        latencyMs: entry.latencyMs,
        bandwidthBps: entry.bandwidthBps,
        lastSeen: Date.now(),
      };

      try {
        this.addRoute(entry.peerId, route);
        added++;
      } catch {
        // Skip routes exceeding max hops
      }
    }
    return added;
  }
}
