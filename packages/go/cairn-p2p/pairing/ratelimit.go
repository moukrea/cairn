package pairing

import (
	"fmt"
	"sync"
	"time"
)

const (
	defaultMaxAttemptsPerWindow = 5
	defaultWindowDuration       = 30 * time.Second
	defaultMaxTotalFailures     = 10
	defaultDelayPerFailure      = 2 * time.Second
)

// sourceState tracks per-source rate limiting state.
type sourceState struct {
	attempts     []time.Time
	failureCount uint32
}

// PairingRateLimiter enforces rate limiting for pairing attempts.
//
// Controls:
//   - 5 attempts per 30-second sliding window (configurable)
//   - 10 total failed attempts -> auto-invalidate current PIN (configurable)
//   - 2-second progressive delay after each failed PAKE attempt (configurable)
//
// Safe for concurrent use via sync.Mutex.
type PairingRateLimiter struct {
	mu sync.Mutex

	maxAttemptsPerWindow uint32
	windowDuration       time.Duration
	maxTotalFailures     uint32
	delayPerFailure      time.Duration

	sources       map[string]*sourceState
	totalFailures uint32
}

// NewPairingRateLimiter creates a rate limiter with default configuration.
func NewPairingRateLimiter() *PairingRateLimiter {
	return &PairingRateLimiter{
		maxAttemptsPerWindow: defaultMaxAttemptsPerWindow,
		windowDuration:       defaultWindowDuration,
		maxTotalFailures:     defaultMaxTotalFailures,
		delayPerFailure:      defaultDelayPerFailure,
		sources:              make(map[string]*sourceState),
	}
}

// NewPairingRateLimiterWithConfig creates a rate limiter with custom configuration.
func NewPairingRateLimiterWithConfig(maxAttempts uint32, window time.Duration, maxFailures uint32, delay time.Duration) *PairingRateLimiter {
	return &PairingRateLimiter{
		maxAttemptsPerWindow: maxAttempts,
		windowDuration:       window,
		maxTotalFailures:     maxFailures,
		delayPerFailure:      delay,
		sources:              make(map[string]*sourceState),
	}
}

// CheckAttempt checks if a new attempt from the given source is allowed.
// Returns the required progressive delay, or an error if rate-limited or invalidated.
func (rl *PairingRateLimiter) CheckAttempt(source string) (time.Duration, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.totalFailures >= rl.maxTotalFailures {
		return 0, fmt.Errorf("pin auto-invalidated after %d total failures", rl.totalFailures)
	}

	now := time.Now()
	ss := rl.getOrCreateSource(source)

	// Remove expired entries from the sliding window
	cutoff := now.Add(-rl.windowDuration)
	filtered := ss.attempts[:0]
	for _, t := range ss.attempts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	ss.attempts = filtered

	// Check window limit
	if uint32(len(ss.attempts)) >= rl.maxAttemptsPerWindow {
		return 0, fmt.Errorf("rate limit exceeded: %d attempts in %v window", len(ss.attempts), rl.windowDuration)
	}

	// Record this attempt
	ss.attempts = append(ss.attempts, now)

	// Compute progressive delay
	delay := rl.delayPerFailure * time.Duration(ss.failureCount)
	return delay, nil
}

// RecordFailure records a failed attempt from the given source.
func (rl *PairingRateLimiter) RecordFailure(source string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	ss := rl.getOrCreateSource(source)
	ss.failureCount++
	rl.totalFailures++
}

// RecordSuccess records a successful attempt, resetting per-source failure count.
func (rl *PairingRateLimiter) RecordSuccess(source string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if ss, ok := rl.sources[source]; ok {
		ss.failureCount = 0
	}
}

// IsInvalidated reports whether the PIN has been auto-invalidated.
func (rl *PairingRateLimiter) IsInvalidated() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.totalFailures >= rl.maxTotalFailures
}

// TotalFailures returns the total failure count.
func (rl *PairingRateLimiter) TotalFailures() uint32 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.totalFailures
}

// ProgressiveDelay returns the current progressive delay for a source.
func (rl *PairingRateLimiter) ProgressiveDelay(source string) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if ss, ok := rl.sources[source]; ok {
		return rl.delayPerFailure * time.Duration(ss.failureCount)
	}
	return 0
}

// Reset clears all rate limiting state (e.g., when a new PIN is generated).
func (rl *PairingRateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sources = make(map[string]*sourceState)
	rl.totalFailures = 0
}

func (rl *PairingRateLimiter) getOrCreateSource(source string) *sourceState {
	if ss, ok := rl.sources[source]; ok {
		return ss
	}
	ss := &sourceState{}
	rl.sources[source] = ss
	return ss
}
