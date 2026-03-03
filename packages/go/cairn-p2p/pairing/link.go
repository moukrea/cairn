package pairing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/mr-tron/base58"
)

// LinkPairingData holds the data encoded in a pairing link URI.
type LinkPairingData struct {
	PeerID    [34]byte
	Nonce     [16]byte
	PakeCred  [32]byte
	Hints     []string
	CreatedAt uint64
	ExpiresAt uint64
}

// GeneratePairingLink creates a pairing link URI.
// Returns the pairing data and the URI string.
func GeneratePairingLink(identity *crypto.IdentityKeypair, ttl time.Duration, hints []string) (*LinkPairingData, string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, "", fmt.Errorf("nonce generation failed: %w", err)
	}

	var pakeCred [32]byte
	if _, err := io.ReadFull(rand.Reader, pakeCred[:]); err != nil {
		return nil, "", fmt.Errorf("PAKE credential generation failed: %w", err)
	}

	now := uint64(time.Now().Unix())
	data := &LinkPairingData{
		PeerID:    identity.PeerID(),
		Nonce:     nonce,
		PakeCred:  pakeCred,
		Hints:     hints,
		CreatedAt: now,
		ExpiresAt: now + uint64(ttl.Seconds()),
	}

	uri := fmt.Sprintf("cairn://pair?pid=%s&nonce=%s&pake=%s",
		base58.Encode(data.PeerID[:]),
		hex.EncodeToString(nonce[:]),
		hex.EncodeToString(pakeCred[:]),
	)

	if len(hints) > 0 {
		uri += "&hints=" + url.QueryEscape(strings.Join(hints, ","))
	}

	uri += fmt.Sprintf("&t=%d&x=%d", data.CreatedAt, data.ExpiresAt)

	return data, uri, nil
}

// ParsePairingLink parses a cairn:// pairing link URI.
func ParsePairingLink(uri string) (*LinkPairingData, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}
	if u.Scheme != "cairn" {
		return nil, fmt.Errorf("expected scheme 'cairn', got '%s'", u.Scheme)
	}
	if u.Host != "pair" {
		return nil, fmt.Errorf("expected host 'pair', got '%s'", u.Host)
	}

	params := u.Query()

	// pid (base58)
	pidStr := params.Get("pid")
	if pidStr == "" {
		return nil, fmt.Errorf("missing 'pid' parameter")
	}
	pidBytes, err := base58.Decode(pidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid pid base58: %w", err)
	}
	if len(pidBytes) != 34 {
		return nil, fmt.Errorf("invalid pid length: got %d, want 34", len(pidBytes))
	}
	var peerID [34]byte
	copy(peerID[:], pidBytes)

	// nonce (hex)
	nonceStr := params.Get("nonce")
	if nonceStr == "" {
		return nil, fmt.Errorf("missing 'nonce' parameter")
	}
	nonceBytes, err := hex.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex nonce: %w", err)
	}
	if len(nonceBytes) != 16 {
		return nil, fmt.Errorf("nonce must be 16 bytes, got %d", len(nonceBytes))
	}
	var nonce [16]byte
	copy(nonce[:], nonceBytes)

	// pake (hex)
	pakeStr := params.Get("pake")
	if pakeStr == "" {
		return nil, fmt.Errorf("missing 'pake' parameter")
	}
	pakeBytes, err := hex.DecodeString(pakeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex pake: %w", err)
	}
	if len(pakeBytes) != 32 {
		return nil, fmt.Errorf("pake credential must be 32 bytes, got %d", len(pakeBytes))
	}
	var pakeCred [32]byte
	copy(pakeCred[:], pakeBytes)

	// hints (optional, comma-separated)
	var hints []string
	if hintsStr := params.Get("hints"); hintsStr != "" {
		hints = strings.Split(hintsStr, ",")
	}

	// timestamps
	var createdAt, expiresAt uint64
	if tStr := params.Get("t"); tStr != "" {
		fmt.Sscanf(tStr, "%d", &createdAt)
	}
	if xStr := params.Get("x"); xStr != "" {
		fmt.Sscanf(xStr, "%d", &expiresAt)
	}

	return &LinkPairingData{
		PeerID:    peerID,
		Nonce:     nonce,
		PakeCred:  pakeCred,
		Hints:     hints,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}, nil
}

// IsExpired reports whether the link data has expired.
func (l *LinkPairingData) IsExpired() bool {
	return uint64(time.Now().Unix()) > l.ExpiresAt
}
