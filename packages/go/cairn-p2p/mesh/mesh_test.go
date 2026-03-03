package mesh

import (
	"errors"
	"testing"
	"time"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create PeerIDs for testing
func testPeerID(b byte) cairn.PeerID {
	pid := cairn.PeerID{}
	pid[0] = 0x12
	pid[1] = 0x20
	pid[2] = b
	return pid
}

// --- MeshSettings tests ---

func TestDefaultMeshSettings(t *testing.T) {
	s := DefaultMeshSettings()
	assert.False(t, s.Enabled)
	assert.Equal(t, uint8(3), s.MaxHops)
	assert.False(t, s.RelayWilling)
	assert.Equal(t, uint32(10), s.RelayCapacity)
}

// --- Router tests ---

func TestNewRouterDisabledByDefault(t *testing.T) {
	r := NewRouter(DefaultMeshSettings())
	assert.False(t, r.IsEnabled())
}

func TestFindRouteWhenDisabledReturnsMeshError(t *testing.T) {
	r := NewRouter(DefaultMeshSettings())
	_, err := r.FindRoute(testPeerID(1))
	require.Error(t, err)

	var cairnErr *cairn.CairnError
	require.True(t, errors.As(err, &cairnErr))
	assert.Equal(t, cairn.ErrKindMeshRouteNotFound, cairnErr.Kind)
}

func TestFindRouteNoRoutesReturnsError(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)
	_, err := r.FindRoute(testPeerID(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no mesh route found")
}

func TestUpdateAndFindRoute(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)

	dest := testPeerID(1)
	nextHop := testPeerID(2)
	r.UpdateReachability(nextHop, []RouteEntry{
		{Destination: dest, NextHop: nextHop, HopCount: 1, Latency: 10 * time.Millisecond, Bandwidth: 1000000},
	})

	route, err := r.FindRoute(dest)
	require.NoError(t, err)
	assert.Equal(t, dest, route.Destination)
	assert.Equal(t, nextHop, route.NextHop)
	assert.Equal(t, 1, route.HopCount)
}

func TestRouteSelectionShortestHops(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 5}
	r := NewRouter(settings)

	dest := testPeerID(1)
	r.UpdateReachability(testPeerID(2), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(2), HopCount: 3, Latency: 5 * time.Millisecond},
	})
	r.UpdateReachability(testPeerID(3), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(3), HopCount: 1, Latency: 100 * time.Millisecond},
	})

	route, err := r.FindRoute(dest)
	require.NoError(t, err)
	assert.Equal(t, 1, route.HopCount) // shortest hops wins
}

func TestRouteSelectionLowestLatencyForSameHops(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 5}
	r := NewRouter(settings)

	dest := testPeerID(1)
	r.UpdateReachability(testPeerID(2), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(2), HopCount: 2, Latency: 100 * time.Millisecond},
	})
	r.UpdateReachability(testPeerID(3), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(3), HopCount: 2, Latency: 10 * time.Millisecond},
	})

	route, err := r.FindRoute(dest)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Millisecond, route.Latency) // lower latency wins
}

func TestRouteSelectionHighestBandwidthForSameHopsAndLatency(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 5}
	r := NewRouter(settings)

	dest := testPeerID(1)
	r.UpdateReachability(testPeerID(2), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(2), HopCount: 2, Latency: 10 * time.Millisecond, Bandwidth: 500000},
	})
	r.UpdateReachability(testPeerID(3), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(3), HopCount: 2, Latency: 10 * time.Millisecond, Bandwidth: 5000000},
	})

	route, err := r.FindRoute(dest)
	require.NoError(t, err)
	assert.Equal(t, int64(5000000), route.Bandwidth) // higher bandwidth wins
}

func TestMaxHopsEnforced(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 2}
	r := NewRouter(settings)

	dest := testPeerID(1)
	r.UpdateReachability(testPeerID(2), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(2), HopCount: 3}, // exceeds max
	})

	_, err := r.FindRoute(dest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceed max hops")
}

func TestRemovePeerAsDestination(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)

	dest := testPeerID(1)
	r.UpdateReachability(testPeerID(2), []RouteEntry{
		{Destination: dest, NextHop: testPeerID(2), HopCount: 1},
	})
	assert.Equal(t, 1, r.RouteCount())

	r.RemovePeer(dest)
	assert.Equal(t, 0, r.RouteCount())
}

func TestRemovePeerAsNextHop(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)

	dest := testPeerID(1)
	hop := testPeerID(2)
	r.UpdateReachability(hop, []RouteEntry{
		{Destination: dest, NextHop: hop, HopCount: 1},
	})

	r.RemovePeer(hop)
	_, err := r.FindRoute(dest)
	assert.Error(t, err) // route via hop should be gone
}

func TestRouteCountMultipleDestinations(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)

	hop := testPeerID(10)
	r.UpdateReachability(hop, []RouteEntry{
		{Destination: testPeerID(1), NextHop: hop, HopCount: 1},
		{Destination: testPeerID(2), NextHop: hop, HopCount: 2},
		{Destination: testPeerID(3), NextHop: hop, HopCount: 1},
	})
	assert.Equal(t, 3, r.RouteCount())
}

func TestAllRoutesReturnsSnapshot(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 3}
	r := NewRouter(settings)

	hop := testPeerID(10)
	r.UpdateReachability(hop, []RouteEntry{
		{Destination: testPeerID(1), NextHop: hop, HopCount: 1},
	})

	routes := r.AllRoutes()
	assert.Len(t, routes, 1)
}

func TestUpdateReachabilityReplacesSameNextHop(t *testing.T) {
	settings := MeshSettings{Enabled: true, MaxHops: 5}
	r := NewRouter(settings)

	dest := testPeerID(1)
	hop := testPeerID(2)

	r.UpdateReachability(hop, []RouteEntry{
		{Destination: dest, NextHop: hop, HopCount: 2, Latency: 100 * time.Millisecond},
	})
	r.UpdateReachability(hop, []RouteEntry{
		{Destination: dest, NextHop: hop, HopCount: 1, Latency: 10 * time.Millisecond},
	})

	route, err := r.FindRoute(dest)
	require.NoError(t, err)
	assert.Equal(t, 1, route.HopCount) // updated value
}

// --- RelayManager tests ---

func TestNewRelayManagerZeroActiveRelays(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 10, MaxHops: 3})
	assert.Equal(t, 0, rm.ActiveRelays())
}

func TestRelayRequestSuccess(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 10, MaxHops: 3})
	err := rm.HandleRelayRequest(testPeerID(1), testPeerID(2), 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, rm.ActiveRelays())
}

func TestRelayRequestNotWilling(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: false, RelayCapacity: 10, MaxHops: 3})
	err := rm.HandleRelayRequest(testPeerID(1), testPeerID(2), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not willing")
}

func TestRelayRequestExceedsMaxHops(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 10, MaxHops: 3})
	err := rm.HandleRelayRequest(testPeerID(1), testPeerID(2), 4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds max hops")
}

func TestRelayRequestExceedsCapacity(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 2, MaxHops: 3})
	require.NoError(t, rm.HandleRelayRequest(testPeerID(1), testPeerID(2), 1))
	require.NoError(t, rm.HandleRelayRequest(testPeerID(3), testPeerID(4), 1))

	err := rm.HandleRelayRequest(testPeerID(5), testPeerID(6), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "capacity exceeded")
}

func TestRemoveRelay(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 10, MaxHops: 3})
	rm.HandleRelayRequest(testPeerID(1), testPeerID(2), 1)
	assert.Equal(t, 1, rm.ActiveRelays())

	rm.RemoveRelay(testPeerID(1), testPeerID(2))
	assert.Equal(t, 0, rm.ActiveRelays())
}

func TestRemoveRelayNonexistent(t *testing.T) {
	rm := NewRelayManager(MeshSettings{RelayWilling: true, RelayCapacity: 10, MaxHops: 3})
	rm.RemoveRelay(testPeerID(1), testPeerID(2)) // no-op, no panic
	assert.Equal(t, 0, rm.ActiveRelays())
}

func TestIsWilling(t *testing.T) {
	rm1 := NewRelayManager(MeshSettings{RelayWilling: true})
	assert.True(t, rm1.IsWilling())

	rm2 := NewRelayManager(MeshSettings{RelayWilling: false})
	assert.False(t, rm2.IsWilling())
}
