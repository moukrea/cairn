package mesh

import (
	"fmt"
	"sort"
	"sync"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

const (
	// DefaultMaxHops is the default maximum number of relay hops.
	DefaultMaxHops = 3

	// DefaultRelayCapacity is the default maximum number of concurrent relay connections.
	DefaultRelayCapacity = 10
)

// MeshSettings configures mesh networking behavior.
type MeshSettings struct {
	Enabled       bool   // Mesh routing enabled (default: false)
	MaxHops       uint8  // Maximum relay hops (default: 3)
	RelayWilling  bool   // Willing to relay for other peers (default: false)
	RelayCapacity uint32 // Maximum concurrent relay connections (default: 10)
}

// DefaultMeshSettings returns mesh settings with defaults (disabled).
func DefaultMeshSettings() MeshSettings {
	return MeshSettings{
		Enabled:       false,
		MaxHops:       DefaultMaxHops,
		RelayWilling:  false,
		RelayCapacity: DefaultRelayCapacity,
	}
}

// RouteEntry represents a route to a destination peer through the mesh.
type RouteEntry struct {
	Destination cairn.PeerID
	NextHop     cairn.PeerID
	HopCount    int
	Latency     time.Duration
	Bandwidth   int64 // bytes/sec estimate
	LastUpdated time.Time
}

// Router manages the mesh routing table and route selection.
type Router struct {
	mu       sync.RWMutex
	settings MeshSettings
	routes   map[cairn.PeerID][]RouteEntry
}

// NewRouter creates a mesh router with the given settings.
func NewRouter(settings MeshSettings) *Router {
	return &Router{
		settings: settings,
		routes:   make(map[cairn.PeerID][]RouteEntry),
	}
}

// IsEnabled reports whether mesh routing is enabled.
func (r *Router) IsEnabled() bool {
	return r.settings.Enabled
}

// Settings returns the current mesh settings.
func (r *Router) Settings() MeshSettings {
	return r.settings
}

// FindRoute finds the best route to the given destination peer.
// Route selection priority: shortest hops -> lowest latency -> highest bandwidth.
// Returns MeshRouteNotFound if no route exists or mesh is disabled.
func (r *Router) FindRoute(dest cairn.PeerID) (*RouteEntry, error) {
	if !r.settings.Enabled {
		return nil, cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			"mesh routing is disabled",
			"Enable mesh networking via MeshSettings{Enabled: true}.",
		)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	entries, ok := r.routes[dest]
	if !ok || len(entries) == 0 {
		return nil, cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			fmt.Sprintf("no mesh route found to peer %s", dest),
			"Ensure the destination peer is connected to the mesh network.",
		)
	}

	// Filter routes exceeding max hops
	var valid []RouteEntry
	for _, e := range entries {
		if e.HopCount <= int(r.settings.MaxHops) {
			valid = append(valid, e)
		}
	}

	if len(valid) == 0 {
		return nil, cairn.NewCairnError(
			cairn.ErrKindMeshRouteNotFound,
			fmt.Sprintf("all routes to %s exceed max hops (%d)", dest, r.settings.MaxHops),
			"Increase MaxHops or ensure a shorter path exists.",
		)
	}

	// Sort: shortest hops -> lowest latency -> highest bandwidth
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].HopCount != valid[j].HopCount {
			return valid[i].HopCount < valid[j].HopCount
		}
		if valid[i].Latency != valid[j].Latency {
			return valid[i].Latency < valid[j].Latency
		}
		return valid[i].Bandwidth > valid[j].Bandwidth
	})

	best := valid[0]
	return &best, nil
}

// UpdateReachability updates the routing table with reachability information from a peer.
func (r *Router) UpdateReachability(peer cairn.PeerID, entries []RouteEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for i := range entries {
		entries[i].LastUpdated = now
	}

	// Merge new entries with existing routes
	for _, entry := range entries {
		dest := entry.Destination
		existing := r.routes[dest]

		// Replace routes from same next hop, add new routes
		updated := false
		for i, e := range existing {
			if e.NextHop == entry.NextHop {
				existing[i] = entry
				updated = true
				break
			}
		}
		if !updated {
			existing = append(existing, entry)
		}
		r.routes[dest] = existing
	}
}

// RemovePeer removes all routes associated with a peer (both as destination and next hop).
func (r *Router) RemovePeer(peer cairn.PeerID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove peer as destination
	delete(r.routes, peer)

	// Remove routes using peer as next hop
	for dest, entries := range r.routes {
		filtered := entries[:0]
		for _, e := range entries {
			if e.NextHop != peer {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(r.routes, dest)
		} else {
			r.routes[dest] = filtered
		}
	}
}

// RouteCount returns the number of destination peers with known routes.
func (r *Router) RouteCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes)
}

// AllRoutes returns all known routes (snapshot).
func (r *Router) AllRoutes() map[cairn.PeerID][]RouteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[cairn.PeerID][]RouteEntry, len(r.routes))
	for k, v := range r.routes {
		entries := make([]RouteEntry, len(v))
		copy(entries, v)
		result[k] = entries
	}
	return result
}
