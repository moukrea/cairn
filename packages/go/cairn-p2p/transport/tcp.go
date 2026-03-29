package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

// TCPTransport provides direct TCP connectivity (priority 3).
// Dials peer addresses and establishes length-prefixed message framing.
type TCPTransport struct {
	mu       sync.Mutex
	listener net.Listener
	conns    map[string]net.Conn // peerID hex -> conn
}

// NewTCPTransport creates a new TCP transport provider.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{
		conns: make(map[string]net.Conn),
	}
}

// Type returns TransportDirectTCP.
func (t *TCPTransport) Type() TransportType {
	return TransportDirectTCP
}

// IsAvailable always returns true — TCP is universally available.
func (t *TCPTransport) IsAvailable() bool {
	return true
}

// Dial connects to a peer via TCP. Tries each address in order.
// Addresses should be in "host:port" or "/ip4/.../tcp/..." multiaddr format.
func (t *TCPTransport) Dial(ctx context.Context, peerID cairn.PeerID, addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("tcp: no addresses provided")
	}

	var lastErr error
	for _, addr := range addrs {
		tcpAddr := parseTCPAddr(addr)
		if tcpAddr == "" {
			continue
		}

		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", tcpAddr)
		if err != nil {
			lastErr = err
			continue
		}

		t.mu.Lock()
		t.conns[fmt.Sprintf("%x", peerID[:])] = conn
		t.mu.Unlock()

		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("tcp: all addresses failed: %w", lastErr)
	}
	return fmt.Errorf("tcp: no valid TCP addresses in %v", addrs)
}

// Listen starts accepting TCP connections on the given address.
func (t *TCPTransport) Listen(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("tcp listen: %w", err)
	}

	t.mu.Lock()
	t.listener = ln
	t.mu.Unlock()

	return ln.Addr().String(), nil
}

// Accept waits for and returns the next incoming TCP connection.
func (t *TCPTransport) Accept(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	ln := t.listener
	t.mu.Unlock()

	if ln == nil {
		return nil, fmt.Errorf("tcp: not listening")
	}

	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetConn returns the connection for a given peer ID, if any.
func (t *TCPTransport) GetConn(peerID string) (net.Conn, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, ok := t.conns[peerID]
	return conn, ok
}

// Close closes all connections and the listener.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for id, conn := range t.conns {
		conn.Close()
		delete(t.conns, id)
	}
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	return nil
}

// WriteFrame writes a length-prefixed frame to a connection.
// Format: [4-byte big-endian length][payload]
func WriteFrame(w io.Writer, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads a length-prefixed frame from a connection.
// Returns the payload bytes.
func ReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > 16*1024*1024 { // 16MB max frame
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// parseTCPAddr extracts a "host:port" address from various formats.
// Supports: "host:port", "/ip4/1.2.3.4/tcp/1234", "/ip6/.../tcp/1234".
func parseTCPAddr(addr string) string {
	// Already host:port format
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}

	// Multiaddr format: /ip4/1.2.3.4/tcp/1234
	parts := strings.Split(strings.TrimPrefix(addr, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "tcp" {
			port := parts[i+1]
			// Find the IP
			for j := 0; j < i; j++ {
				if parts[j] == "ip4" || parts[j] == "ip6" {
					if j+1 < len(parts) {
						ip := parts[j+1]
						if parts[j] == "ip6" {
							return fmt.Sprintf("[%s]:%s", ip, port)
						}
						return fmt.Sprintf("%s:%s", ip, port)
					}
				}
			}
		}
	}

	return "" // not a valid TCP address
}
