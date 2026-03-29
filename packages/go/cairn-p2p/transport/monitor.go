package transport

// NetworkEvent represents a network interface change event.
type NetworkEvent struct {
	Type    NetworkEventType
	Details string
}

// NetworkEventType identifies the type of network change.
type NetworkEventType int

const (
	// NetworkEventInterfaceChanged indicates a WiFi/cellular transition or new IP assignment.
	NetworkEventInterfaceChanged NetworkEventType = iota
	// NetworkEventVPNChanged indicates VPN connect/disconnect.
	NetworkEventVPNChanged
	// NetworkEventConnectivityLost indicates complete network loss.
	NetworkEventConnectivityLost
	// NetworkEventConnectivityRestored indicates network restoration.
	NetworkEventConnectivityRestored
)

// NetworkMonitor observes OS-level network interface changes and triggers
// proactive reconnection. Platform-specific implementations subscribe to
// OS notifications (e.g., netlink on Linux, SCNetworkReachability on macOS).
type NetworkMonitor interface {
	// Start begins monitoring network changes. Events are delivered to the callback.
	Start(callback func(NetworkEvent)) error

	// Stop halts monitoring and releases resources.
	Stop() error
}

// NoopNetworkMonitor is a no-op implementation of NetworkMonitor.
// Used as the default when no platform-specific monitor is available.
type NoopNetworkMonitor struct{}

// Start is a no-op.
func (n *NoopNetworkMonitor) Start(callback func(NetworkEvent)) error {
	return nil
}

// Stop is a no-op.
func (n *NoopNetworkMonitor) Stop() error {
	return nil
}
