//go:build !linux

package transport

// NewNetworkMonitor returns a no-op NetworkMonitor on non-Linux platforms.
// Platform-specific implementations (e.g., SCNetworkReachability on macOS/iOS)
// may be added in the future.
func NewNetworkMonitor() NetworkMonitor {
	return &NoopNetworkMonitor{}
}
