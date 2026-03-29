package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
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

const (
	stunBindingRequestType  = 0x0001
	stunBindingResponse = 0x0101
	stunMagicCookie     = 0x2112A442

	stunAttrXorMappedAddress = 0x0020
	stunAttrMappedAddress    = 0x0001

	stunTimeout = 3 * time.Second
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

// StunResult holds the result of a single STUN binding request.
type StunResult struct {
	ExternalIP   string
	ExternalPort int
	ServerAddr   string
}

// DetectNATType probes STUN servers to determine the NAT type.
// Uses a basic heuristic: if external IP:port is the same from two servers,
// it's likely full cone or open. If different ports, it's symmetric.
func DetectNATType(ctx context.Context, stunServers []string) NatType {
	if len(stunServers) == 0 {
		return NatUnknown
	}

	// Try to get external address from at least two STUN servers
	var results []StunResult
	for _, server := range stunServers {
		if len(results) >= 2 {
			break
		}
		result, err := stunBindingReq(ctx, server)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return NatUnknown
	}

	if len(results) == 1 {
		// Can't determine NAT type with only one result
		// but we know we're not completely blocked
		return NatUnknown
	}

	// Compare external addresses from two different servers
	if results[0].ExternalIP == results[1].ExternalIP &&
		results[0].ExternalPort == results[1].ExternalPort {
		// Same external IP:port from different servers → likely open or full cone
		return NatFullCone
	}

	if results[0].ExternalIP == results[1].ExternalIP {
		// Same IP but different ports → port-dependent mapping (symmetric-ish)
		return NatSymmetric
	}

	// Different IPs — unusual, might be multi-homed or VPN
	return NatUnknown
}

// Detect runs NAT type detection using the configured STUN servers.
func (d *NatDetector) Detect(ctx context.Context) NatType {
	return DetectNATType(ctx, d.stunServers)
}

// GetExternalAddress returns the external IP:port as seen by a STUN server.
func (d *NatDetector) GetExternalAddress(ctx context.Context) (*StunResult, error) {
	for _, server := range d.stunServers {
		result, err := stunBindingReq(ctx, server)
		if err != nil {
			continue
		}
		return &result, nil
	}
	return nil, fmt.Errorf("all STUN servers unreachable")
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

// stunBindingReq sends a STUN Binding Request (RFC 5389) and parses the response.
func stunBindingReq(ctx context.Context, serverAddr string) (StunResult, error) {
	// Resolve server address
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "3478")
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(stunTimeout)
	}

	conn, err := net.DialTimeout("udp", serverAddr, stunTimeout)
	if err != nil {
		return StunResult{}, fmt.Errorf("stun dial %s: %w", serverAddr, err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	// Build STUN Binding Request (RFC 5389 Section 6)
	// Header: Type(2) + Length(2) + Magic Cookie(4) + Transaction ID(12) = 20 bytes
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequestType)
	binary.BigEndian.PutUint16(req[2:4], 0) // length (no attributes)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	// Random transaction ID (12 bytes)
	for i := 8; i < 20; i++ {
		req[i] = byte(rand.Intn(256))
	}

	if _, err := conn.Write(req[:]); err != nil {
		return StunResult{}, fmt.Errorf("stun write: %w", err)
	}

	// Read response
	var resp [1024]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return StunResult{}, fmt.Errorf("stun read: %w", err)
	}
	if n < 20 {
		return StunResult{}, fmt.Errorf("stun response too short: %d bytes", n)
	}

	// Verify response type
	respType := binary.BigEndian.Uint16(resp[0:2])
	if respType != stunBindingResponse {
		return StunResult{}, fmt.Errorf("unexpected STUN response type: 0x%04x", respType)
	}

	// Verify transaction ID matches
	for i := 8; i < 20; i++ {
		if resp[i] != req[i] {
			return StunResult{}, fmt.Errorf("STUN transaction ID mismatch")
		}
	}

	// Parse attributes to find XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
	msgLen := binary.BigEndian.Uint16(resp[2:4])
	attrs := resp[20 : 20+int(msgLen)]
	if 20+int(msgLen) > n {
		attrs = resp[20:n]
	}

	result := StunResult{ServerAddr: serverAddr}
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attrs[offset+2 : offset+4])
		attrData := attrs[offset+4:]
		if int(attrLen) > len(attrData) {
			break
		}
		attrData = attrData[:attrLen]

		switch attrType {
		case stunAttrXorMappedAddress:
			ip, port := parseXorMappedAddress(attrData, req[4:8])
			if ip != "" {
				result.ExternalIP = ip
				result.ExternalPort = port
				return result, nil
			}
		case stunAttrMappedAddress:
			ip, port := parseMappedAddress(attrData)
			if ip != "" {
				result.ExternalIP = ip
				result.ExternalPort = port
			}
		}

		// Advance to next attribute (4-byte aligned)
		offset += 4 + int(attrLen)
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	if result.ExternalIP != "" {
		return result, nil
	}
	return StunResult{}, fmt.Errorf("no mapped address in STUN response")
}

// parseXorMappedAddress parses a STUN XOR-MAPPED-ADDRESS attribute (RFC 5389 Section 15.2).
func parseXorMappedAddress(data []byte, magicCookie []byte) (string, int) {
	if len(data) < 8 {
		return "", 0
	}
	family := data[1]
	xPort := binary.BigEndian.Uint16(data[2:4])
	port := xPort ^ binary.BigEndian.Uint16(magicCookie[0:2])

	if family == 0x01 { // IPv4
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ magicCookie[i]
		}
		return ip.String(), int(port)
	}
	return "", 0
}

// parseMappedAddress parses a STUN MAPPED-ADDRESS attribute (RFC 5389 Section 15.1).
func parseMappedAddress(data []byte) (string, int) {
	if len(data) < 8 {
		return "", 0
	}
	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	if family == 0x01 { // IPv4
		ip := net.IPv4(data[4], data[5], data[6], data[7])
		return ip.String(), int(port)
	}
	return "", 0
}
