package protocol

import (
	"fmt"
)

// CurrentProtocolVersion is the protocol version used by this implementation.
const CurrentProtocolVersion uint8 = 1

// SupportedVersions lists all protocol versions this implementation supports,
// ordered highest first.
var SupportedVersions = []uint8{1}

// ProtocolVersion represents a protocol version with major and minor components.
type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

// CurrentVersion is the current protocol version.
var CurrentVersion = ProtocolVersion{Major: 1, Minor: 0}

// SelectVersion finds the highest mutually supported version.
// Both slices should be ordered highest first.
func SelectVersion(ours, theirs []uint8) (uint8, error) {
	for _, v := range ours {
		for _, tv := range theirs {
			if v == tv {
				return v, nil
			}
		}
	}
	return 0, fmt.Errorf("version mismatch: local supports %v, remote supports %v", ours, theirs)
}
