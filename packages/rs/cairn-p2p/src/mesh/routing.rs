//! Mesh routing table and route selection (spec/09-mesh-networking.md section 9.2).
//!
//! Maintains known peers and their reachability, selects optimal routes based on
//! hop count, latency, and bandwidth.

use crate::identity::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::Instant;
use tracing::debug;

use super::MeshError;

/// A route to a destination peer, potentially through intermediate relay hops.
#[derive(Debug, Clone)]
pub struct Route {
    /// Ordered list of intermediate relay peer IDs. Empty means direct connection.
    pub hops: Vec<PeerId>,
    /// Measured or estimated latency in milliseconds.
    pub latency_ms: u32,
    /// Estimated available bandwidth in bytes/sec.
    pub bandwidth_bps: u64,
    /// When this route was last confirmed reachable.
    pub last_seen: Instant,
}

impl Route {
    /// Create a direct route (zero hops).
    pub fn direct(latency_ms: u32, bandwidth_bps: u64) -> Self {
        Self {
            hops: Vec::new(),
            latency_ms,
            bandwidth_bps,
            last_seen: Instant::now(),
        }
    }

    /// Create a relayed route through intermediate hops.
    pub fn relayed(hops: Vec<PeerId>, latency_ms: u32, bandwidth_bps: u64) -> Self {
        Self {
            hops,
            latency_ms,
            bandwidth_bps,
            last_seen: Instant::now(),
        }
    }

    /// Number of hops (0 = direct).
    pub fn hop_count(&self) -> u8 {
        self.hops.len() as u8
    }

    /// Route selection key: (hop_count ASC, latency_ms ASC, bandwidth_bps DESC).
    ///
    /// Lower is better for hops and latency; higher is better for bandwidth.
    /// We negate bandwidth so sorting ascending gives us highest bandwidth first.
    fn selection_key(&self) -> (u8, u32, std::cmp::Reverse<u64>) {
        (
            self.hop_count(),
            self.latency_ms,
            std::cmp::Reverse(self.bandwidth_bps),
        )
    }
}

/// Routing table maintaining known peers and their reachability.
pub struct RoutingTable {
    /// Map from destination peer ID to known routes.
    routes: HashMap<PeerId, Vec<Route>>,
    /// Maximum allowed hops for any route.
    max_hops: u8,
}

impl RoutingTable {
    /// Create a new routing table with the given max hop limit.
    pub fn new(max_hops: u8) -> Self {
        Self {
            routes: HashMap::new(),
            max_hops,
        }
    }

    /// Add or update a route to a destination peer.
    ///
    /// Routes exceeding `max_hops` are rejected.
    pub fn add_route(&mut self, destination: PeerId, route: Route) -> Result<(), MeshError> {
        let hop_count = route.hop_count();
        if hop_count > self.max_hops {
            return Err(MeshError::MaxHopsExceeded(hop_count, self.max_hops));
        }

        debug!(
            destination = %destination,
            hops = hop_count,
            latency_ms = route.latency_ms,
            bandwidth_bps = route.bandwidth_bps,
            "adding route"
        );

        self.routes.entry(destination).or_default().push(route);

        Ok(())
    }

    /// Select the best route to a destination peer.
    ///
    /// Priority order per spec 9.2:
    /// 1. Shortest hop count
    /// 2. Lowest latency
    /// 3. Highest bandwidth
    pub fn select_best_route(&self, destination: &PeerId) -> Result<&Route, MeshError> {
        let routes = self
            .routes
            .get(destination)
            .ok_or_else(|| MeshError::NoRoute(destination.to_string()))?;

        routes
            .iter()
            .min_by_key(|r| r.selection_key())
            .ok_or_else(|| MeshError::NoRoute(destination.to_string()))
    }

    /// Get all known routes to a destination peer.
    pub fn get_routes(&self, destination: &PeerId) -> Option<&[Route]> {
        self.routes.get(destination).map(|v| v.as_slice())
    }

    /// Remove all routes to a destination peer.
    pub fn remove_routes(&mut self, destination: &PeerId) {
        self.routes.remove(destination);
    }

    /// Remove stale routes older than the given age.
    pub fn expire_routes(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        for routes in self.routes.values_mut() {
            routes.retain(|r| now.duration_since(r.last_seen) < max_age);
        }
        // Remove peers with no remaining routes
        self.routes.retain(|_, routes| !routes.is_empty());
    }

    /// Get the number of known destination peers.
    pub fn peer_count(&self) -> usize {
        self.routes.len()
    }

    /// Get the total number of routes across all destinations.
    pub fn route_count(&self) -> usize {
        self.routes.values().map(|v| v.len()).sum()
    }

    /// Get the max hops limit.
    pub fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Get all known destination peer IDs.
    pub fn destinations(&self) -> Vec<&PeerId> {
        self.routes.keys().collect()
    }

    /// Apply a topology update from a neighboring peer.
    ///
    /// Merges the neighbor's reachability information into the local routing table,
    /// adding the neighbor as an additional hop to each advertised destination.
    pub fn apply_topology_update(
        &mut self,
        neighbor: &PeerId,
        update: &MeshTopologyUpdate,
    ) -> usize {
        let mut added = 0;
        for entry in &update.reachable_peers {
            // Build a route through the neighbor
            let mut hops = vec![neighbor.clone()];
            hops.extend(entry.via_hops.iter().cloned());

            let route = Route {
                hops,
                latency_ms: entry.latency_ms,
                bandwidth_bps: entry.bandwidth_bps,
                last_seen: Instant::now(),
            };

            if self.add_route(entry.peer_id.clone(), route).is_ok() {
                added += 1;
            }
        }
        added
    }
}

/// A topology update message exchanged between mesh peers (distance-vector).
///
/// Contains the sender's known reachability: which peers it can reach and via which paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshTopologyUpdate {
    /// Peers reachable from the sender.
    pub reachable_peers: Vec<ReachabilityEntry>,
}

/// A single reachability entry in a topology update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityEntry {
    /// The reachable peer.
    pub peer_id: PeerId,
    /// Intermediate hops to reach this peer from the sender (empty = direct).
    pub via_hops: Vec<PeerId>,
    /// Estimated latency in milliseconds.
    pub latency_ms: u32,
    /// Estimated bandwidth in bytes/sec.
    pub bandwidth_bps: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn make_peer() -> PeerId {
        LocalIdentity::generate().peer_id().clone()
    }

    #[test]
    fn test_route_direct() {
        let r = Route::direct(10, 1_000_000);
        assert_eq!(r.hop_count(), 0);
        assert_eq!(r.latency_ms, 10);
        assert_eq!(r.bandwidth_bps, 1_000_000);
    }

    #[test]
    fn test_route_relayed() {
        let relay = make_peer();
        let r = Route::relayed(vec![relay], 50, 500_000);
        assert_eq!(r.hop_count(), 1);
    }

    #[test]
    fn test_routing_table_add_and_select() {
        let mut rt = RoutingTable::new(3);
        let dest = make_peer();

        rt.add_route(dest.clone(), Route::direct(20, 1_000_000))
            .unwrap();

        let best = rt.select_best_route(&dest).unwrap();
        assert_eq!(best.hop_count(), 0);
        assert_eq!(best.latency_ms, 20);
    }

    #[test]
    fn test_routing_table_max_hops_enforced() {
        let mut rt = RoutingTable::new(2);
        let dest = make_peer();
        let hops: Vec<PeerId> = (0..3).map(|_| make_peer()).collect();

        let result = rt.add_route(dest, Route::relayed(hops, 100, 100_000));
        assert!(result.is_err());
        match result.unwrap_err() {
            MeshError::MaxHopsExceeded(got, max) => {
                assert_eq!(got, 3);
                assert_eq!(max, 2);
            }
            _ => panic!("expected MaxHopsExceeded"),
        }
    }

    #[test]
    fn test_route_selection_prefers_fewer_hops() {
        let mut rt = RoutingTable::new(3);
        let dest = make_peer();
        let relay = make_peer();

        // 1-hop route with better latency
        rt.add_route(dest.clone(), Route::relayed(vec![relay], 5, 10_000_000))
            .unwrap();
        // Direct route with worse latency
        rt.add_route(dest.clone(), Route::direct(100, 100_000))
            .unwrap();

        let best = rt.select_best_route(&dest).unwrap();
        assert_eq!(best.hop_count(), 0); // Direct wins despite higher latency
    }

    #[test]
    fn test_route_selection_prefers_lower_latency_at_same_hops() {
        let mut rt = RoutingTable::new(3);
        let dest = make_peer();

        rt.add_route(dest.clone(), Route::direct(100, 1_000_000))
            .unwrap();
        rt.add_route(dest.clone(), Route::direct(10, 1_000_000))
            .unwrap();

        let best = rt.select_best_route(&dest).unwrap();
        assert_eq!(best.latency_ms, 10);
    }

    #[test]
    fn test_route_selection_prefers_higher_bandwidth_at_same_hops_and_latency() {
        let mut rt = RoutingTable::new(3);
        let dest = make_peer();

        rt.add_route(dest.clone(), Route::direct(10, 100_000))
            .unwrap();
        rt.add_route(dest.clone(), Route::direct(10, 10_000_000))
            .unwrap();

        let best = rt.select_best_route(&dest).unwrap();
        assert_eq!(best.bandwidth_bps, 10_000_000);
    }

    #[test]
    fn test_no_route_error() {
        let rt = RoutingTable::new(3);
        let dest = make_peer();
        let result = rt.select_best_route(&dest);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_routes() {
        let mut rt = RoutingTable::new(3);
        let dest = make_peer();
        rt.add_route(dest.clone(), Route::direct(10, 1_000_000))
            .unwrap();
        assert_eq!(rt.peer_count(), 1);

        rt.remove_routes(&dest);
        assert_eq!(rt.peer_count(), 0);
    }

    #[test]
    fn test_peer_and_route_counts() {
        let mut rt = RoutingTable::new(3);
        let dest1 = make_peer();
        let dest2 = make_peer();

        rt.add_route(dest1.clone(), Route::direct(10, 1_000_000))
            .unwrap();
        rt.add_route(dest1.clone(), Route::direct(20, 500_000))
            .unwrap();
        rt.add_route(dest2, Route::direct(15, 800_000)).unwrap();

        assert_eq!(rt.peer_count(), 2);
        assert_eq!(rt.route_count(), 3);
    }

    #[test]
    fn test_apply_topology_update() {
        let mut rt = RoutingTable::new(3);
        let neighbor = make_peer();
        let remote_peer = make_peer();

        let update = MeshTopologyUpdate {
            reachable_peers: vec![ReachabilityEntry {
                peer_id: remote_peer.clone(),
                via_hops: vec![],
                latency_ms: 30,
                bandwidth_bps: 500_000,
            }],
        };

        let added = rt.apply_topology_update(&neighbor, &update);
        assert_eq!(added, 1);

        let best = rt.select_best_route(&remote_peer).unwrap();
        assert_eq!(best.hop_count(), 1); // through neighbor
        assert_eq!(best.latency_ms, 30);
    }

    #[test]
    fn test_apply_topology_update_exceeding_max_hops_skipped() {
        let mut rt = RoutingTable::new(1); // max 1 hop
        let neighbor = make_peer();
        let relay = make_peer();
        let remote_peer = make_peer();

        let update = MeshTopologyUpdate {
            reachable_peers: vec![ReachabilityEntry {
                peer_id: remote_peer.clone(),
                via_hops: vec![relay], // neighbor + relay = 2 hops, exceeds max
                latency_ms: 30,
                bandwidth_bps: 500_000,
            }],
        };

        let added = rt.apply_topology_update(&neighbor, &update);
        assert_eq!(added, 0);
        assert!(rt.select_best_route(&remote_peer).is_err());
    }

    #[test]
    fn test_destinations() {
        let mut rt = RoutingTable::new(3);
        let dest1 = make_peer();
        let dest2 = make_peer();
        rt.add_route(dest1.clone(), Route::direct(10, 1_000_000))
            .unwrap();
        rt.add_route(dest2.clone(), Route::direct(20, 500_000))
            .unwrap();

        let dests = rt.destinations();
        assert_eq!(dests.len(), 2);
        assert!(dests.contains(&&dest1));
        assert!(dests.contains(&&dest2));
    }
}
