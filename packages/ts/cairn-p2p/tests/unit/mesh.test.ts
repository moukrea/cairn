import { describe, it, expect } from 'vitest';
import {
  defaultMeshConfig,
  serverMeshConfig,
} from '../../src/mesh/index.js';
import type { MeshConfig } from '../../src/mesh/index.js';
import {
  RoutingTable,
  directRoute,
  relayedRoute,
  hopCount,
} from '../../src/mesh/routing-table.js';
import type { MeshTopologyUpdate } from '../../src/mesh/routing-table.js';
import { RelayManager } from '../../src/mesh/relay.js';

// --- MeshConfig ---

describe('MeshConfig', () => {
  it('default config', () => {
    const config = defaultMeshConfig();
    expect(config.meshEnabled).toBe(false);
    expect(config.maxHops).toBe(3);
    expect(config.relayWilling).toBe(false);
    expect(config.relayCapacity).toBe(10);
  });

  it('server mode config', () => {
    const config = serverMeshConfig();
    expect(config.meshEnabled).toBe(true);
    expect(config.relayWilling).toBe(true);
    expect(config.relayCapacity).toBe(100);
    expect(config.maxHops).toBe(3);
  });
});

// --- Route helpers ---

describe('Route helpers', () => {
  it('directRoute has 0 hops', () => {
    const r = directRoute(10, 1_000_000);
    expect(hopCount(r)).toBe(0);
    expect(r.latencyMs).toBe(10);
    expect(r.bandwidthBps).toBe(1_000_000);
    expect(r.lastSeen).toBeGreaterThan(0);
  });

  it('relayedRoute has correct hops', () => {
    const r = relayedRoute(['relay-peer-1'], 50, 500_000);
    expect(hopCount(r)).toBe(1);
    expect(r.hops).toEqual(['relay-peer-1']);
  });

  it('relayedRoute copies hops array', () => {
    const hops = ['a', 'b'];
    const r = relayedRoute(hops, 10, 100);
    hops.push('c');
    expect(r.hops.length).toBe(2);
  });
});

// --- RoutingTable ---

describe('RoutingTable', () => {
  it('starts empty', () => {
    const rt = new RoutingTable(3);
    expect(rt.peerCount).toBe(0);
    expect(rt.routeCount).toBe(0);
    expect(rt.maxHops).toBe(3);
    expect(rt.destinations).toEqual([]);
  });

  it('add and select route', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest-1', directRoute(20, 1_000_000));
    const best = rt.selectBestRoute('dest-1');
    expect(hopCount(best)).toBe(0);
    expect(best.latencyMs).toBe(20);
  });

  it('max hops enforced', () => {
    const rt = new RoutingTable(2);
    expect(() =>
      rt.addRoute('dest', relayedRoute(['a', 'b', 'c'], 100, 100_000)),
    ).toThrow('max hops exceeded: 3 > 2');
  });

  it('selects fewer hops over better latency', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest', relayedRoute(['relay'], 5, 10_000_000));
    rt.addRoute('dest', directRoute(100, 100_000));

    const best = rt.selectBestRoute('dest');
    expect(hopCount(best)).toBe(0); // direct wins
  });

  it('selects lower latency at same hops', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest', directRoute(100, 1_000_000));
    rt.addRoute('dest', directRoute(10, 1_000_000));

    const best = rt.selectBestRoute('dest');
    expect(best.latencyMs).toBe(10);
  });

  it('selects higher bandwidth at same hops and latency', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest', directRoute(10, 100_000));
    rt.addRoute('dest', directRoute(10, 10_000_000));

    const best = rt.selectBestRoute('dest');
    expect(best.bandwidthBps).toBe(10_000_000);
  });

  it('no route throws MeshRouteNotFoundError', () => {
    const rt = new RoutingTable(3);
    expect(() => rt.selectBestRoute('unknown')).toThrow('no route to peer');
  });

  it('remove routes', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest', directRoute(10, 1_000_000));
    expect(rt.peerCount).toBe(1);

    rt.removeRoutes('dest');
    expect(rt.peerCount).toBe(0);
  });

  it('peer and route counts', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest1', directRoute(10, 1_000_000));
    rt.addRoute('dest1', directRoute(20, 500_000));
    rt.addRoute('dest2', directRoute(15, 800_000));

    expect(rt.peerCount).toBe(2);
    expect(rt.routeCount).toBe(3);
  });

  it('destinations', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest1', directRoute(10, 1_000_000));
    rt.addRoute('dest2', directRoute(20, 500_000));

    const dests = rt.destinations;
    expect(dests.length).toBe(2);
    expect(dests).toContain('dest1');
    expect(dests).toContain('dest2');
  });

  it('get routes', () => {
    const rt = new RoutingTable(3);
    rt.addRoute('dest', directRoute(10, 1_000_000));
    rt.addRoute('dest', directRoute(20, 500_000));

    const routes = rt.getRoutes('dest');
    expect(routes).toBeDefined();
    expect(routes!.length).toBe(2);
    expect(rt.getRoutes('unknown')).toBeUndefined();
  });

  it('expire routes', () => {
    const rt = new RoutingTable(3);
    const old: import('../../src/mesh/routing-table.js').Route = {
      hops: [],
      latencyMs: 10,
      bandwidthBps: 1_000_000,
      lastSeen: Date.now() - 120_000, // 2 minutes ago
    };
    const fresh = directRoute(20, 500_000);

    rt.addRoute('dest', old);
    rt.addRoute('dest', fresh);
    expect(rt.routeCount).toBe(2);

    rt.expireRoutes(60_000); // 1 minute max age
    expect(rt.routeCount).toBe(1);
    const best = rt.selectBestRoute('dest');
    expect(best.latencyMs).toBe(20);
  });

  it('expire removes peer with no remaining routes', () => {
    const rt = new RoutingTable(3);
    const old: import('../../src/mesh/routing-table.js').Route = {
      hops: [],
      latencyMs: 10,
      bandwidthBps: 1_000_000,
      lastSeen: Date.now() - 120_000,
    };
    rt.addRoute('dest', old);
    rt.expireRoutes(60_000);
    expect(rt.peerCount).toBe(0);
  });
});

// --- Topology update ---

describe('RoutingTable topology update', () => {
  it('apply topology update', () => {
    const rt = new RoutingTable(3);
    const update: MeshTopologyUpdate = {
      reachablePeers: [
        {
          peerId: 'remote-peer',
          viaHops: [],
          latencyMs: 30,
          bandwidthBps: 500_000,
        },
      ],
    };

    const added = rt.applyTopologyUpdate('neighbor', update);
    expect(added).toBe(1);

    const best = rt.selectBestRoute('remote-peer');
    expect(hopCount(best)).toBe(1); // through neighbor
    expect(best.hops[0]).toBe('neighbor');
    expect(best.latencyMs).toBe(30);
  });

  it('topology update exceeding max hops is skipped', () => {
    const rt = new RoutingTable(1);
    const update: MeshTopologyUpdate = {
      reachablePeers: [
        {
          peerId: 'remote-peer',
          viaHops: ['relay'], // neighbor + relay = 2 hops, exceeds max 1
          latencyMs: 30,
          bandwidthBps: 500_000,
        },
      ],
    };

    const added = rt.applyTopologyUpdate('neighbor', update);
    expect(added).toBe(0);
    expect(() => rt.selectBestRoute('remote-peer')).toThrow();
  });

  it('topology update with multiple entries', () => {
    const rt = new RoutingTable(3);
    const update: MeshTopologyUpdate = {
      reachablePeers: [
        { peerId: 'peer-a', viaHops: [], latencyMs: 10, bandwidthBps: 1_000_000 },
        { peerId: 'peer-b', viaHops: [], latencyMs: 20, bandwidthBps: 500_000 },
        { peerId: 'peer-c', viaHops: ['relay'], latencyMs: 50, bandwidthBps: 200_000 },
      ],
    };

    const added = rt.applyTopologyUpdate('neighbor', update);
    expect(added).toBe(3);
    expect(rt.peerCount).toBe(3);
  });
});

// --- RelayManager ---

describe('RelayManager', () => {
  const willingConfig = (): MeshConfig => ({
    meshEnabled: true,
    maxHops: 3,
    relayWilling: true,
    relayCapacity: 10,
  });

  it('request relay success', () => {
    const mgr = new RelayManager(willingConfig());
    const id = mgr.requestRelay('src', 'dst');
    expect(mgr.activeSessionCount).toBe(1);
    expect(mgr.getSession(id)).toBeDefined();
    expect(mgr.getSession(id)!.source).toBe('src');
    expect(mgr.getSession(id)!.destination).toBe('dst');
  });

  it('mesh disabled rejects relay', () => {
    const mgr = new RelayManager({ ...willingConfig(), meshEnabled: false });
    expect(() => mgr.requestRelay('src', 'dst')).toThrow('mesh routing disabled');
  });

  it('not willing rejects relay', () => {
    const mgr = new RelayManager({ ...willingConfig(), relayWilling: false });
    expect(() => mgr.requestRelay('src', 'dst')).toThrow('relay not willing');
  });

  it('capacity enforced', () => {
    const mgr = new RelayManager({ ...willingConfig(), relayCapacity: 2 });
    mgr.requestRelay('a', 'b');
    mgr.requestRelay('c', 'd');
    expect(() => mgr.requestRelay('e', 'f')).toThrow('relay capacity full');
  });

  it('same source and dest rejected', () => {
    const mgr = new RelayManager(willingConfig());
    expect(() => mgr.requestRelay('same', 'same')).toThrow('source and destination are the same');
  });

  it('close session', () => {
    const mgr = new RelayManager(willingConfig());
    const id = mgr.requestRelay('src', 'dst');
    expect(mgr.activeSessionCount).toBe(1);
    expect(mgr.closeSession(id)).toBe(true);
    expect(mgr.activeSessionCount).toBe(0);
  });

  it('close nonexistent session', () => {
    const mgr = new RelayManager(willingConfig());
    expect(mgr.closeSession(999)).toBe(false);
  });

  it('remaining capacity', () => {
    const mgr = new RelayManager({ ...willingConfig(), relayCapacity: 5 });
    expect(mgr.remainingCapacity).toBe(5);
    mgr.requestRelay('a', 'b');
    expect(mgr.remainingCapacity).toBe(4);
  });

  it('capacity restored after close', () => {
    const mgr = new RelayManager({ ...willingConfig(), relayCapacity: 2 });
    const id1 = mgr.requestRelay('a', 'b');
    mgr.requestRelay('c', 'd');
    expect(() => mgr.requestRelay('e', 'f')).toThrow();
    mgr.closeSession(id1);
    expect(() => mgr.requestRelay('g', 'h')).not.toThrow();
  });

  it('unique session IDs', () => {
    const mgr = new RelayManager(willingConfig());
    const id1 = mgr.requestRelay('a', 'b');
    const id2 = mgr.requestRelay('c', 'd');
    expect(id1).not.toBe(id2);
  });

  it('isWilling', () => {
    const willing = new RelayManager(willingConfig());
    expect(willing.isWilling).toBe(true);

    const notWilling = new RelayManager({ ...willingConfig(), relayWilling: false });
    expect(notWilling.isWilling).toBe(false);
  });

  it('update config', () => {
    const mgr = new RelayManager(willingConfig());
    expect(mgr.isWilling).toBe(true);
    mgr.updateConfig({ ...willingConfig(), relayWilling: false });
    expect(mgr.isWilling).toBe(false);
  });

  it('get nonexistent session returns undefined', () => {
    const mgr = new RelayManager(willingConfig());
    expect(mgr.getSession(42)).toBeUndefined();
  });
});
