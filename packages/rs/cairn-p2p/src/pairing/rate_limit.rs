use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Default maximum attempts per sliding window.
const DEFAULT_MAX_ATTEMPTS_PER_WINDOW: u32 = 5;
/// Default sliding window duration.
const DEFAULT_WINDOW_DURATION: Duration = Duration::from_secs(30);
/// Default maximum total failures before auto-invalidation.
const DEFAULT_MAX_TOTAL_FAILURES: u32 = 10;
/// Default progressive delay per failure.
const DEFAULT_DELAY_PER_FAILURE: Duration = Duration::from_secs(2);

/// Rate limiting errors.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limit exceeded: {attempts} attempts in {window:?} window")]
    WindowExceeded { attempts: u32, window: Duration },
    #[error("pin auto-invalidated after {failures} total failures")]
    AutoInvalidated { failures: u32 },
}

/// Per-source tracking state.
struct SourceState {
    /// Timestamps of recent attempts within the sliding window.
    attempts: VecDeque<Instant>,
    /// Number of failed attempts from this source.
    failure_count: u32,
}

impl SourceState {
    fn new() -> Self {
        Self {
            attempts: VecDeque::new(),
            failure_count: 0,
        }
    }
}

/// Rate limiter for pairing attempts.
///
/// Enforced by the acceptor (the peer that generates the pin code).
/// Protects the 40-bit entropy of pin codes against brute-force attacks.
///
/// Controls:
/// - 5 attempts per 30-second sliding window from any source (configurable)
/// - 10 total failed attempts -> auto-invalidate current pin (configurable)
/// - 2-second progressive delay after each failed PAKE attempt (configurable)
pub struct RateLimiter {
    /// Maximum attempts per window.
    max_attempts_per_window: u32,
    /// Sliding window duration.
    window_duration: Duration,
    /// Maximum total failures before auto-invalidation.
    max_total_failures: u32,
    /// Progressive delay per failure.
    delay_per_failure: Duration,
    /// Per-source tracking.
    sources: HashMap<String, SourceState>,
    /// Total failure count across all sources.
    total_failures: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            max_attempts_per_window: DEFAULT_MAX_ATTEMPTS_PER_WINDOW,
            window_duration: DEFAULT_WINDOW_DURATION,
            max_total_failures: DEFAULT_MAX_TOTAL_FAILURES,
            delay_per_failure: DEFAULT_DELAY_PER_FAILURE,
            sources: HashMap::new(),
            total_failures: 0,
        }
    }

    /// Create a rate limiter with custom parameters.
    pub fn with_config(
        max_attempts_per_window: u32,
        window_duration: Duration,
        max_total_failures: u32,
        delay_per_failure: Duration,
    ) -> Self {
        Self {
            max_attempts_per_window,
            window_duration,
            max_total_failures,
            delay_per_failure,
            sources: HashMap::new(),
            total_failures: 0,
        }
    }

    /// Check if a new attempt from this source is allowed.
    ///
    /// Returns `Ok(delay)` with the required delay before processing,
    /// or `Err` if rate limited or auto-invalidated.
    ///
    /// The caller (pairing session) should await the returned delay
    /// via `tokio::time::sleep` before processing the next attempt.
    pub fn check_rate_limit(&mut self, source: &str) -> Result<Duration, RateLimitError> {
        // Check if pin has been auto-invalidated.
        if self.is_invalidated() {
            return Err(RateLimitError::AutoInvalidated {
                failures: self.total_failures,
            });
        }

        let now = Instant::now();
        let source_state = self
            .sources
            .entry(source.to_string())
            .or_insert_with(SourceState::new);

        // Remove expired entries from the sliding window.
        while let Some(&front) = source_state.attempts.front() {
            if now.duration_since(front) > self.window_duration {
                source_state.attempts.pop_front();
            } else {
                break;
            }
        }

        // Check window limit.
        let current_attempts = source_state.attempts.len() as u32;
        if current_attempts >= self.max_attempts_per_window {
            return Err(RateLimitError::WindowExceeded {
                attempts: current_attempts,
                window: self.window_duration,
            });
        }

        // Record this attempt.
        source_state.attempts.push_back(now);

        // Compute progressive delay based on failure count.
        let delay = self.delay_per_failure * source_state.failure_count;
        Ok(delay)
    }

    /// Record a failed attempt from this source.
    pub fn record_failure(&mut self, source: &str) {
        let source_state = self
            .sources
            .entry(source.to_string())
            .or_insert_with(SourceState::new);
        source_state.failure_count += 1;
        self.total_failures += 1;
    }

    /// Record a successful attempt (resets per-source failure count).
    pub fn record_success(&mut self, source: &str) {
        if let Some(source_state) = self.sources.get_mut(source) {
            source_state.failure_count = 0;
        }
    }

    /// Check if the pin has been auto-invalidated (>= max_total_failures).
    pub fn is_invalidated(&self) -> bool {
        self.total_failures >= self.max_total_failures
    }

    /// Reset the rate limiter (e.g., when a new pin is generated).
    pub fn reset(&mut self) {
        self.sources.clear();
        self.total_failures = 0;
    }

    /// Get the total failure count.
    pub fn total_failures(&self) -> u32 {
        self.total_failures
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_clean_state() {
        let rl = RateLimiter::new();
        assert_eq!(rl.total_failures(), 0);
        assert!(!rl.is_invalidated());
    }

    #[test]
    fn default_matches_new() {
        let a = RateLimiter::new();
        let b = RateLimiter::default();
        assert_eq!(a.max_attempts_per_window, b.max_attempts_per_window);
        assert_eq!(a.window_duration, b.window_duration);
        assert_eq!(a.max_total_failures, b.max_total_failures);
        assert_eq!(a.delay_per_failure, b.delay_per_failure);
    }

    #[test]
    fn first_attempt_allowed_with_zero_delay() {
        let mut rl = RateLimiter::new();
        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn five_attempts_allowed_within_window() {
        let mut rl = RateLimiter::new();
        for _ in 0..5 {
            assert!(rl.check_rate_limit("source-1").is_ok());
        }
    }

    #[test]
    fn sixth_attempt_rejected_within_window() {
        let mut rl = RateLimiter::new();
        for _ in 0..5 {
            rl.check_rate_limit("source-1").unwrap();
        }
        let err = rl.check_rate_limit("source-1").unwrap_err();
        match err {
            RateLimitError::WindowExceeded { attempts, .. } => {
                assert_eq!(attempts, 5);
            }
            _ => panic!("expected WindowExceeded, got: {err}"),
        }
    }

    #[test]
    fn different_sources_have_independent_windows() {
        let mut rl = RateLimiter::new();
        // Fill up source-1
        for _ in 0..5 {
            rl.check_rate_limit("source-1").unwrap();
        }
        // source-2 should still be allowed
        assert!(rl.check_rate_limit("source-2").is_ok());
    }

    #[test]
    fn progressive_delay_increases_with_failures() {
        let mut rl = RateLimiter::new();

        // First attempt: no failures yet, zero delay
        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::ZERO);

        // Record a failure
        rl.record_failure("source-1");

        // Second attempt: 1 failure * 2s = 2s delay
        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::from_secs(2));

        // Record another failure
        rl.record_failure("source-1");

        // Third attempt: 2 failures * 2s = 4s delay
        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::from_secs(4));
    }

    #[test]
    fn record_success_resets_source_delay() {
        let mut rl = RateLimiter::new();

        rl.check_rate_limit("source-1").unwrap();
        rl.record_failure("source-1");
        rl.record_failure("source-1");

        // 2 failures * 2s = 4s
        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::from_secs(4));

        // Success resets the source failure count
        rl.record_success("source-1");

        let delay = rl.check_rate_limit("source-1").unwrap();
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn auto_invalidation_after_max_failures() {
        let mut rl = RateLimiter::new();

        for i in 0..10 {
            let source = format!("source-{i}");
            rl.check_rate_limit(&source).unwrap();
            rl.record_failure(&source);
        }

        assert!(rl.is_invalidated());
        assert_eq!(rl.total_failures(), 10);

        let err = rl.check_rate_limit("source-new").unwrap_err();
        match err {
            RateLimitError::AutoInvalidated { failures } => {
                assert_eq!(failures, 10);
            }
            _ => panic!("expected AutoInvalidated, got: {err}"),
        }
    }

    #[test]
    fn reset_clears_all_state() {
        let mut rl = RateLimiter::new();

        for i in 0..5 {
            let source = format!("source-{i}");
            rl.check_rate_limit(&source).unwrap();
            rl.record_failure(&source);
        }

        assert_eq!(rl.total_failures(), 5);

        rl.reset();

        assert_eq!(rl.total_failures(), 0);
        assert!(!rl.is_invalidated());
        // Attempts should be allowed again
        assert!(rl.check_rate_limit("source-0").is_ok());
    }

    #[test]
    fn custom_config() {
        let mut rl = RateLimiter::with_config(
            3,                       // 3 attempts per window
            Duration::from_secs(10), // 10-second window
            5,                       // 5 max failures
            Duration::from_secs(1),  // 1-second delay per failure
        );

        // 3 attempts allowed
        for _ in 0..3 {
            rl.check_rate_limit("src").unwrap();
        }
        // 4th rejected
        assert!(rl.check_rate_limit("src").is_err());

        // Custom failure threshold
        rl.reset();
        for i in 0..5 {
            rl.check_rate_limit(&format!("s-{i}")).unwrap();
            rl.record_failure(&format!("s-{i}"));
        }
        assert!(rl.is_invalidated());
    }

    #[test]
    fn custom_delay_per_failure() {
        let mut rl = RateLimiter::with_config(
            10,
            Duration::from_secs(60),
            20,
            Duration::from_secs(3), // 3-second delay per failure
        );

        rl.check_rate_limit("src").unwrap();
        rl.record_failure("src");

        let delay = rl.check_rate_limit("src").unwrap();
        assert_eq!(delay, Duration::from_secs(3));

        rl.record_failure("src");
        let delay = rl.check_rate_limit("src").unwrap();
        assert_eq!(delay, Duration::from_secs(6));
    }

    #[test]
    fn total_failures_across_sources() {
        let mut rl = RateLimiter::new();

        rl.check_rate_limit("a").unwrap();
        rl.record_failure("a");

        rl.check_rate_limit("b").unwrap();
        rl.record_failure("b");

        rl.check_rate_limit("c").unwrap();
        rl.record_failure("c");

        assert_eq!(rl.total_failures(), 3);
    }

    #[test]
    fn success_does_not_reduce_total_failures() {
        let mut rl = RateLimiter::new();

        rl.check_rate_limit("src").unwrap();
        rl.record_failure("src");
        assert_eq!(rl.total_failures(), 1);

        rl.record_success("src");
        // Total failures remain (they accumulate toward auto-invalidation)
        assert_eq!(rl.total_failures(), 1);
    }

    #[test]
    fn record_success_on_unknown_source_is_noop() {
        let mut rl = RateLimiter::new();
        rl.record_success("nonexistent");
        assert_eq!(rl.total_failures(), 0);
    }

    #[test]
    fn error_display() {
        let err = RateLimitError::WindowExceeded {
            attempts: 5,
            window: Duration::from_secs(30),
        };
        let msg = err.to_string();
        assert!(msg.contains("5 attempts"));
        assert!(msg.contains("30"));

        let err = RateLimitError::AutoInvalidated { failures: 10 };
        let msg = err.to_string();
        assert!(msg.contains("10 total failures"));
    }
}
