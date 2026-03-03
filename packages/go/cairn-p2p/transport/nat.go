package transport

import (
	"context"
)

// NatType represents the detected NAT type for diagnostic purposes.
// Application behavior should never depend on NAT type — the transport chain
// handles it transparently. This is for debugging connectivity issues only.
type NatType string

const (
	NatOpen           NatType = "open"
	NatFullCone       NatType = "full_cone"
	NatRestrictedCone NatType = "restricted_cone"
	NatPortRestricted NatType = "port_restricted_cone"
	NatSymmetric      NatType = "symmetric"
	NatUnknown        NatType = "unknown"
)

// NatDetector detects the NAT type using STUN servers.
type NatDetector struct {
	stunServers []string
}

// NewNatDetector creates a NatDetector with the given STUN servers.
func NewNatDetector(stunServers []string) *NatDetector {
	if len(stunServers) == 0 {
		stunServers = DefaultStunServers
	}
	return &NatDetector{stunServers: stunServers}
}

// DetectNATType probes STUN servers to determine the NAT type.
// This is a diagnostic API — the transport chain does not depend on the result.
//
// Full STUN-based NAT classification requires multi-server probing per RFC 5780.
// The current implementation returns NatUnknown as a safe default;
// integration with go-libp2p AutoNAT will provide real detection.
func DetectNATType(ctx context.Context, stunServers []string) NatType {
	if len(stunServers) == 0 {
		return NatUnknown
	}

	// NAT type detection requires actual STUN binding requests and multi-server
	// comparison (RFC 5780). This will be implemented via go-libp2p's AutoNAT
	// service which provides NAT reachability information.
	// For now, return Unknown as a safe default that doesn't mislead callers.
	return NatUnknown
}

// Detect runs NAT type detection using the configured STUN servers.
func (d *NatDetector) Detect(ctx context.Context) NatType {
	return DetectNATType(ctx, d.stunServers)
}

// StunServers returns the configured STUN servers.
func (d *NatDetector) StunServers() []string {
	return d.stunServers
}

// AllNatTypes returns all defined NAT type values.
func AllNatTypes() []NatType {
	return []NatType{
		NatOpen,
		NatFullCone,
		NatRestrictedCone,
		NatPortRestricted,
		NatSymmetric,
		NatUnknown,
	}
}
