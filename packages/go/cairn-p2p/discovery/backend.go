package discovery

import (
	"context"
	"fmt"
	"sync"
)

// DiscoveryBackend is the interface for all discovery mechanisms.
// Implementations include mDNS (LAN), Kademlia DHT, BitTorrent trackers,
// WebSocket signaling, and custom backends.
type DiscoveryBackend interface {
	// Publish announces reachability info at the given rendezvous ID.
	Publish(ctx context.Context, rendezvousID []byte, reachability []byte) error

	// Query retrieves reachability info published at the given rendezvous ID.
	// Returns a slice of reachability payloads from discovered peers.
	Query(ctx context.Context, rendezvousID []byte) ([][]byte, error)

	// Name returns a human-readable name for this backend (e.g., "mdns", "dht").
	Name() string

	// Close releases resources associated with this backend.
	Close() error
}

// QueryResult holds the result of a parallel discovery query.
type QueryResult struct {
	Backend      string
	Reachability [][]byte
	Err          error
}

// MultiBackendDiscovery orchestrates parallel queries across multiple discovery backends.
// First result wins.
type MultiBackendDiscovery struct {
	mu       sync.RWMutex
	backends []DiscoveryBackend
}

// NewMultiBackendDiscovery creates a discovery orchestrator with the given backends.
func NewMultiBackendDiscovery(backends ...DiscoveryBackend) *MultiBackendDiscovery {
	return &MultiBackendDiscovery{
		backends: backends,
	}
}

// AddBackend adds a discovery backend.
func (m *MultiBackendDiscovery) AddBackend(b DiscoveryBackend) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backends = append(m.backends, b)
}

// Backends returns the registered backends.
func (m *MultiBackendDiscovery) Backends() []DiscoveryBackend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]DiscoveryBackend, len(m.backends))
	copy(result, m.backends)
	return result
}

// PublishAll publishes reachability to all backends concurrently.
// Returns errors from any backends that failed.
func (m *MultiBackendDiscovery) PublishAll(ctx context.Context, rendezvousID, reachability []byte) []error {
	m.mu.RLock()
	backends := make([]DiscoveryBackend, len(m.backends))
	copy(backends, m.backends)
	m.mu.RUnlock()

	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup

	for _, b := range backends {
		wg.Add(1)
		go func(backend DiscoveryBackend) {
			defer wg.Done()
			if err := backend.Publish(ctx, rendezvousID, reachability); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", backend.Name(), err))
				mu.Unlock()
			}
		}(b)
	}

	wg.Wait()
	return errs
}

// QueryFirst queries all backends in parallel and returns the first successful result.
// Cancels remaining queries once one succeeds.
func (m *MultiBackendDiscovery) QueryFirst(ctx context.Context, rendezvousID []byte) (*QueryResult, error) {
	m.mu.RLock()
	backends := make([]DiscoveryBackend, len(m.backends))
	copy(backends, m.backends)
	m.mu.RUnlock()

	if len(backends) == 0 {
		return nil, fmt.Errorf("no discovery backends configured")
	}

	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan QueryResult, len(backends))

	for _, b := range backends {
		go func(backend DiscoveryBackend) {
			reachability, err := backend.Query(queryCtx, rendezvousID)
			resultCh <- QueryResult{
				Backend:      backend.Name(),
				Reachability: reachability,
				Err:          err,
			}
		}(b)
	}

	var errs []error
	for range backends {
		select {
		case r := <-resultCh:
			if r.Err == nil && len(r.Reachability) > 0 {
				cancel() // cancel remaining queries
				return &r, nil
			}
			if r.Err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r.Backend, r.Err))
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all discovery backends failed: %v", errs)
}

// Close closes all backends.
func (m *MultiBackendDiscovery) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, b := range m.backends {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
