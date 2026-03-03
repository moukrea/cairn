use std::fmt;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::{CairnError, Result};

// ---------------------------------------------------------------------------
// Transport type (9-level fallback chain)
// ---------------------------------------------------------------------------

/// Transport type in the 9-level fallback chain (spec section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackTransportType {
    /// Priority 1: Direct UDP (QUIC v1, RFC 9000).
    DirectQuic,
    /// Priority 2: STUN-assisted UDP hole punch.
    StunHolePunch,
    /// Priority 3: Direct TCP.
    DirectTcp,
    /// Priority 4: TURN relay (UDP).
    TurnUdp,
    /// Priority 5: TURN relay (TCP).
    TurnTcp,
    /// Priority 6: WebSocket over TLS (port 443).
    WebSocketTls,
    /// Priority 7: WebTransport over HTTP/3 (port 443).
    WebTransportH3,
    /// Priority 8: Circuit Relay v2 (transient, 2 min / 128 KB).
    CircuitRelayV2,
    /// Priority 9: HTTPS long-polling (port 443).
    HttpsLongPoll,
}

impl FallbackTransportType {
    /// Priority number (1 = best, 9 = worst).
    pub fn priority(self) -> u8 {
        match self {
            Self::DirectQuic => 1,
            Self::StunHolePunch => 2,
            Self::DirectTcp => 3,
            Self::TurnUdp => 4,
            Self::TurnTcp => 5,
            Self::WebSocketTls => 6,
            Self::WebTransportH3 => 7,
            Self::CircuitRelayV2 => 8,
            Self::HttpsLongPoll => 9,
        }
    }

    /// Whether this transport is available in Tier 0 (zero-config).
    pub fn tier0_available(self) -> bool {
        matches!(
            self,
            Self::DirectQuic | Self::StunHolePunch | Self::DirectTcp | Self::CircuitRelayV2
        )
    }

    /// All transport types in priority order.
    pub fn all_in_order() -> &'static [FallbackTransportType] {
        &[
            Self::DirectQuic,
            Self::StunHolePunch,
            Self::DirectTcp,
            Self::TurnUdp,
            Self::TurnTcp,
            Self::WebSocketTls,
            Self::WebTransportH3,
            Self::CircuitRelayV2,
            Self::HttpsLongPoll,
        ]
    }
}

impl fmt::Display for FallbackTransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectQuic => write!(f, "Direct QUIC v1"),
            Self::StunHolePunch => write!(f, "STUN-assisted UDP hole punch"),
            Self::DirectTcp => write!(f, "Direct TCP"),
            Self::TurnUdp => write!(f, "TURN relay (UDP)"),
            Self::TurnTcp => write!(f, "TURN relay (TCP)"),
            Self::WebSocketTls => write!(f, "WebSocket/TLS (443)"),
            Self::WebTransportH3 => write!(f, "WebTransport/HTTP3 (443)"),
            Self::CircuitRelayV2 => write!(f, "Circuit Relay v2"),
            Self::HttpsLongPoll => write!(f, "HTTPS long-polling (443)"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransportAttempt — single entry in the fallback chain
// ---------------------------------------------------------------------------

/// Configuration for a single transport attempt in the fallback chain.
#[derive(Debug, Clone)]
pub struct TransportAttempt {
    /// Priority level (1-9).
    pub priority: u8,
    /// Transport type.
    pub transport_type: FallbackTransportType,
    /// Per-transport timeout.
    pub timeout: Duration,
    /// Whether this transport's required infrastructure is configured.
    /// If false, the transport is skipped during fallback.
    pub available: bool,
}

// ---------------------------------------------------------------------------
// TransportAttemptResult — result of a single attempt
// ---------------------------------------------------------------------------

/// Result of attempting a single transport in the fallback chain.
#[derive(Debug, Clone)]
pub struct TransportAttemptResult {
    /// Which transport was attempted.
    pub transport_type: FallbackTransportType,
    /// Error message if the attempt failed.
    pub error: Option<String>,
    /// True if the transport was skipped (infrastructure not configured).
    pub skipped: bool,
    /// How long the attempt took.
    pub duration: Duration,
}

impl fmt::Display for TransportAttemptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.skipped {
            write!(f, "{}: skipped (not configured)", self.transport_type)
        } else if let Some(ref err) = self.error {
            write!(
                f,
                "{}: failed ({err}) [{:?}]",
                self.transport_type, self.duration
            )
        } else {
            write!(f, "{}: success [{:?}]", self.transport_type, self.duration)
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackChain — the 9-level transport priority chain engine
// ---------------------------------------------------------------------------

/// Executes the 9-level transport priority chain (spec section 2).
///
/// Supports both sequential and parallel (ICE-style) probing modes.
/// In parallel mode (FR-4.2), multiple transports are attempted concurrently
/// and the first success wins.
#[derive(Debug, Clone)]
pub struct FallbackChain {
    /// Ordered list of transport attempts.
    transports: Vec<TransportAttempt>,
    /// ICE-style parallel probing mode.
    parallel_mode: bool,
}

impl FallbackChain {
    /// Create a new fallback chain with the full 9-level priority list.
    ///
    /// `has_turn` / `has_relay_443` control whether TURN and port-443 relays
    /// are available (Tier 1+ infrastructure).
    pub fn new(
        per_transport_timeout: Duration,
        has_turn: bool,
        has_relay_443: bool,
        parallel_mode: bool,
    ) -> Self {
        let transports = FallbackTransportType::all_in_order()
            .iter()
            .map(|&tt| {
                let available = match tt {
                    FallbackTransportType::TurnUdp | FallbackTransportType::TurnTcp => has_turn,
                    FallbackTransportType::WebSocketTls
                    | FallbackTransportType::WebTransportH3
                    | FallbackTransportType::HttpsLongPoll => has_relay_443,
                    _ => true,
                };
                TransportAttempt {
                    priority: tt.priority(),
                    transport_type: tt,
                    timeout: per_transport_timeout,
                    available,
                }
            })
            .collect();

        Self {
            transports,
            parallel_mode,
        }
    }

    /// Create a Tier 0 (zero-config) fallback chain.
    /// Only priorities 1-3 and 8 are available.
    pub fn tier0(per_transport_timeout: Duration) -> Self {
        Self::new(per_transport_timeout, false, false, false)
    }

    /// Get the transport attempts in priority order.
    pub fn transports(&self) -> &[TransportAttempt] {
        &self.transports
    }

    /// Whether parallel probing is enabled.
    pub fn parallel_mode(&self) -> bool {
        self.parallel_mode
    }

    /// Execute the fallback chain, attempting each transport in order.
    ///
    /// The `attempt_fn` is called for each available transport and should
    /// return `Ok(T)` on success or `Err` on failure. The first success is
    /// returned. If all transports fail, a `TransportExhausted` error is
    /// returned with detailed diagnostics.
    ///
    /// In parallel mode, available transports are attempted concurrently
    /// and the first success wins.
    pub async fn execute<T, F, Fut>(&self, attempt_fn: F) -> Result<(FallbackTransportType, T)>
    where
        T: Send + 'static,
        F: Fn(FallbackTransportType, Duration) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        if self.parallel_mode {
            self.execute_parallel(attempt_fn).await
        } else {
            self.execute_sequential(attempt_fn).await
        }
    }

    /// Sequential execution: attempt each transport in priority order.
    async fn execute_sequential<T, F, Fut>(
        &self,
        attempt_fn: F,
    ) -> Result<(FallbackTransportType, T)>
    where
        T: Send + 'static,
        F: Fn(FallbackTransportType, Duration) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        let mut results = Vec::new();

        for attempt in &self.transports {
            if !attempt.available {
                results.push(TransportAttemptResult {
                    transport_type: attempt.transport_type,
                    error: None,
                    skipped: true,
                    duration: Duration::ZERO,
                });
                debug!(
                    transport = %attempt.transport_type,
                    "skipped (infrastructure not configured)"
                );
                continue;
            }

            let start = Instant::now();
            info!(
                transport = %attempt.transport_type,
                priority = attempt.priority,
                "attempting transport"
            );

            match attempt_fn(attempt.transport_type, attempt.timeout).await {
                Ok(value) => {
                    info!(
                        transport = %attempt.transport_type,
                        elapsed = ?start.elapsed(),
                        "transport connected"
                    );
                    return Ok((attempt.transport_type, value));
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    warn!(
                        transport = %attempt.transport_type,
                        %e,
                        ?elapsed,
                        "transport failed"
                    );
                    results.push(TransportAttemptResult {
                        transport_type: attempt.transport_type,
                        error: Some(e.to_string()),
                        skipped: false,
                        duration: elapsed,
                    });
                }
            }
        }

        Err(build_transport_exhausted_error(&results))
    }

    /// Parallel (ICE-style) execution: attempt all available transports
    /// concurrently, first success wins (spec FR-4.2).
    async fn execute_parallel<T, F, Fut>(&self, attempt_fn: F) -> Result<(FallbackTransportType, T)>
    where
        T: Send + 'static,
        F: Fn(FallbackTransportType, Duration) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        use tokio::task::JoinSet;

        let mut join_set = JoinSet::new();
        let mut skipped_results = Vec::new();

        for attempt in &self.transports {
            if !attempt.available {
                skipped_results.push(TransportAttemptResult {
                    transport_type: attempt.transport_type,
                    error: None,
                    skipped: true,
                    duration: Duration::ZERO,
                });
                continue;
            }

            let transport_type = attempt.transport_type;
            let timeout = attempt.timeout;
            let fut = attempt_fn(transport_type, timeout);

            join_set.spawn(async move {
                let start = Instant::now();
                let result = fut.await;
                (transport_type, result, start.elapsed())
            });
        }

        let mut failed_results = Vec::new();

        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok((transport_type, Ok(value), elapsed)) => {
                    info!(
                        transport = %transport_type,
                        ?elapsed,
                        "transport connected (parallel mode)"
                    );
                    // Cancel remaining tasks by dropping the JoinSet
                    join_set.shutdown().await;
                    return Ok((transport_type, value));
                }
                Ok((transport_type, Err(e), elapsed)) => {
                    warn!(
                        transport = %transport_type,
                        %e,
                        ?elapsed,
                        "transport failed (parallel mode)"
                    );
                    failed_results.push(TransportAttemptResult {
                        transport_type,
                        error: Some(e.to_string()),
                        skipped: false,
                        duration: elapsed,
                    });
                }
                Err(e) => {
                    warn!(%e, "transport attempt task panicked");
                }
            }
        }

        let mut all_results = skipped_results;
        all_results.extend(failed_results);
        Err(build_transport_exhausted_error(&all_results))
    }
}

/// Build a `CairnError::TransportExhausted` with detailed diagnostics.
fn build_transport_exhausted_error(results: &[TransportAttemptResult]) -> CairnError {
    let details: Vec<String> = results.iter().map(|r| r.to_string()).collect();
    let details_str = details.join("; ");

    let has_unavailable = results.iter().any(|r| r.skipped);
    if has_unavailable {
        CairnError::transport_exhausted_with_suggestion(
            details_str,
            "deploy companion infrastructure (TURN relay, WebSocket relay on port 443) \
             to enable additional transport fallbacks",
        )
    } else {
        CairnError::transport_exhausted(details_str)
    }
}

// ---------------------------------------------------------------------------
// ConnectionQuality — metrics
// ---------------------------------------------------------------------------

/// Connection quality metrics (spec FR-4.5, spec section 6).
#[derive(Debug, Clone, Copy)]
pub struct ConnectionQuality {
    /// Round-trip latency.
    pub latency: Duration,
    /// Jitter (latency variance).
    pub jitter: Duration,
    /// Packet loss ratio (0.0 = none, 1.0 = total loss).
    pub packet_loss_ratio: f64,
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            packet_loss_ratio: 0.0,
        }
    }
}

/// Thresholds that trigger proactive transport migration (spec FR-4.5).
#[derive(Debug, Clone)]
pub struct QualityThresholds {
    /// Trigger probing when latency exceeds this value.
    pub max_latency: Duration,
    /// Trigger probing when jitter exceeds this value.
    pub max_jitter: Duration,
    /// Trigger probing when packet loss exceeds this ratio (e.g. 0.05 = 5%).
    pub max_packet_loss: f64,
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            max_latency: Duration::from_millis(500),
            max_jitter: Duration::from_millis(100),
            max_packet_loss: 0.05,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionQualityMonitor
// ---------------------------------------------------------------------------

/// Degradation event emitted when connection quality drops below thresholds.
#[derive(Debug, Clone)]
pub struct DegradationEvent {
    /// Current quality metrics at the time of degradation.
    pub quality: ConnectionQuality,
    /// Which threshold was exceeded.
    pub reason: DegradationReason,
}

/// Which quality threshold was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradationReason {
    HighLatency,
    HighJitter,
    HighPacketLoss,
}

impl fmt::Display for DegradationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighLatency => write!(f, "high latency"),
            Self::HighJitter => write!(f, "high jitter"),
            Self::HighPacketLoss => write!(f, "high packet loss"),
        }
    }
}

/// Monitors connection quality and emits degradation events (spec FR-4.5).
///
/// Runs as a background task, sampling metrics at a regular interval.
/// When any metric exceeds its threshold, a [`DegradationEvent`] is emitted
/// to trigger the [`TransportMigrator`].
pub struct ConnectionQualityMonitor {
    thresholds: QualityThresholds,
    sample_interval: Duration,
    degradation_tx: mpsc::Sender<DegradationEvent>,
}

impl ConnectionQualityMonitor {
    /// Create a new quality monitor.
    pub fn new(
        thresholds: QualityThresholds,
        sample_interval: Duration,
        degradation_tx: mpsc::Sender<DegradationEvent>,
    ) -> Self {
        Self {
            thresholds,
            sample_interval,
            degradation_tx,
        }
    }

    /// Report a new quality sample. Checks thresholds and emits degradation
    /// events if any are exceeded.
    pub async fn report_sample(&self, quality: ConnectionQuality) {
        if quality.latency > self.thresholds.max_latency {
            let _ = self
                .degradation_tx
                .send(DegradationEvent {
                    quality,
                    reason: DegradationReason::HighLatency,
                })
                .await;
        }

        if quality.jitter > self.thresholds.max_jitter {
            let _ = self
                .degradation_tx
                .send(DegradationEvent {
                    quality,
                    reason: DegradationReason::HighJitter,
                })
                .await;
        }

        if quality.packet_loss_ratio > self.thresholds.max_packet_loss {
            let _ = self
                .degradation_tx
                .send(DegradationEvent {
                    quality,
                    reason: DegradationReason::HighPacketLoss,
                })
                .await;
        }
    }

    /// Get the configured sample interval.
    pub fn sample_interval(&self) -> Duration {
        self.sample_interval
    }

    /// Get the configured thresholds.
    pub fn thresholds(&self) -> &QualityThresholds {
        &self.thresholds
    }

    /// Check whether a quality sample exceeds any threshold (without emitting).
    pub fn is_degraded(&self, quality: &ConnectionQuality) -> bool {
        quality.latency > self.thresholds.max_latency
            || quality.jitter > self.thresholds.max_jitter
            || quality.packet_loss_ratio > self.thresholds.max_packet_loss
    }
}

// ---------------------------------------------------------------------------
// TransportMigrator
// ---------------------------------------------------------------------------

/// Migration event indicating a better transport is available.
#[derive(Debug, Clone)]
pub struct MigrationEvent {
    /// The currently active transport.
    pub from: FallbackTransportType,
    /// The better transport that was found.
    pub to: FallbackTransportType,
}

/// Probes for better transports and triggers mid-session migration
/// (spec FR-4.3, spec section 3).
///
/// > "Once connected, the library continuously probes for better
/// > transports and can migrate mid-session transparently."
///
/// > "Transport migration is invisible to the application." (spec section 3)
///
/// The migrator periodically probes transports with a lower (better)
/// priority number than the currently active transport. When a better
/// transport succeeds, a [`MigrationEvent`] is emitted.
pub struct TransportMigrator {
    /// Probe interval.
    probe_interval: Duration,
    /// Priority level of the currently active transport.
    current_transport_priority: u8,
    /// Currently active transport type.
    current_transport: FallbackTransportType,
    /// Channel for migration events.
    migration_tx: mpsc::Sender<MigrationEvent>,
}

impl TransportMigrator {
    /// Create a new transport migrator.
    pub fn new(
        probe_interval: Duration,
        current_transport: FallbackTransportType,
        migration_tx: mpsc::Sender<MigrationEvent>,
    ) -> Self {
        Self {
            probe_interval,
            current_transport_priority: current_transport.priority(),
            current_transport,
            migration_tx,
        }
    }

    /// Get the probe interval.
    pub fn probe_interval(&self) -> Duration {
        self.probe_interval
    }

    /// Get the current active transport.
    pub fn current_transport(&self) -> FallbackTransportType {
        self.current_transport
    }

    /// Update the active transport after a successful migration.
    pub fn set_current_transport(&mut self, transport: FallbackTransportType) {
        self.current_transport = transport;
        self.current_transport_priority = transport.priority();
    }

    /// Get the list of transports to probe (those with better priority than
    /// the current one).
    pub fn transports_to_probe(&self) -> Vec<FallbackTransportType> {
        FallbackTransportType::all_in_order()
            .iter()
            .copied()
            .filter(|t| t.priority() < self.current_transport_priority)
            .collect()
    }

    /// Report that a probe found a better transport. Emits a migration event.
    pub async fn report_better_transport(
        &self,
        better_transport: FallbackTransportType,
    ) -> Result<()> {
        if better_transport.priority() >= self.current_transport_priority {
            return Err(CairnError::Transport(format!(
                "proposed transport {} (priority {}) is not better than current {} (priority {})",
                better_transport,
                better_transport.priority(),
                self.current_transport,
                self.current_transport_priority,
            )));
        }

        info!(
            from = %self.current_transport,
            to = %better_transport,
            "better transport found, initiating migration"
        );

        self.migration_tx
            .send(MigrationEvent {
                from: self.current_transport,
                to: better_transport,
            })
            .await
            .map_err(|_| CairnError::Transport("migration event receiver dropped".into()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FallbackTransportType --

    #[test]
    fn transport_priorities_are_sequential() {
        let all = FallbackTransportType::all_in_order();
        assert_eq!(all.len(), 9);
        for (i, tt) in all.iter().enumerate() {
            assert_eq!(tt.priority(), (i + 1) as u8);
        }
    }

    #[test]
    fn tier0_availability() {
        assert!(FallbackTransportType::DirectQuic.tier0_available());
        assert!(FallbackTransportType::StunHolePunch.tier0_available());
        assert!(FallbackTransportType::DirectTcp.tier0_available());
        assert!(!FallbackTransportType::TurnUdp.tier0_available());
        assert!(!FallbackTransportType::TurnTcp.tier0_available());
        assert!(!FallbackTransportType::WebSocketTls.tier0_available());
        assert!(!FallbackTransportType::WebTransportH3.tier0_available());
        assert!(FallbackTransportType::CircuitRelayV2.tier0_available());
        assert!(!FallbackTransportType::HttpsLongPoll.tier0_available());
    }

    #[test]
    fn transport_display() {
        assert_eq!(
            FallbackTransportType::DirectQuic.to_string(),
            "Direct QUIC v1"
        );
        assert_eq!(
            FallbackTransportType::HttpsLongPoll.to_string(),
            "HTTPS long-polling (443)"
        );
    }

    // -- FallbackChain construction --

    #[test]
    fn tier0_chain_has_correct_availability() {
        let chain = FallbackChain::tier0(Duration::from_secs(10));
        let transports = chain.transports();
        assert_eq!(transports.len(), 9);

        // Priorities 1-3, 8 should be available
        assert!(transports[0].available); // DirectQuic
        assert!(transports[1].available); // StunHolePunch
        assert!(transports[2].available); // DirectTcp
        assert!(!transports[3].available); // TurnUdp
        assert!(!transports[4].available); // TurnTcp
        assert!(!transports[5].available); // WebSocketTls
        assert!(!transports[6].available); // WebTransportH3
        assert!(transports[7].available); // CircuitRelayV2
        assert!(!transports[8].available); // HttpsLongPoll
    }

    #[test]
    fn full_chain_with_turn_and_relay() {
        let chain = FallbackChain::new(Duration::from_secs(10), true, true, false);
        // All transports should be available
        assert!(chain.transports().iter().all(|t| t.available));
    }

    // -- Sequential fallback execution --

    #[tokio::test]
    async fn sequential_first_transport_succeeds() {
        let chain = FallbackChain::tier0(Duration::from_secs(5));

        let result = chain
            .execute(|tt, _timeout| async move {
                if tt == FallbackTransportType::DirectQuic {
                    Ok(42u32)
                } else {
                    Err(CairnError::Transport("not implemented".into()))
                }
            })
            .await;

        let (transport, value) = result.unwrap();
        assert_eq!(transport, FallbackTransportType::DirectQuic);
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn sequential_falls_back_to_tcp() {
        let chain = FallbackChain::tier0(Duration::from_secs(5));

        let result = chain
            .execute(|tt, _timeout| async move {
                match tt {
                    FallbackTransportType::DirectTcp => Ok("tcp_connected"),
                    _ => Err(CairnError::Transport(format!("{tt} failed"))),
                }
            })
            .await;

        let (transport, value) = result.unwrap();
        assert_eq!(transport, FallbackTransportType::DirectTcp);
        assert_eq!(value, "tcp_connected");
    }

    #[tokio::test]
    async fn sequential_all_fail_returns_exhausted() {
        let chain = FallbackChain::tier0(Duration::from_secs(1));

        let result: Result<(FallbackTransportType, ())> = chain
            .execute(
                |tt, _timeout| async move { Err(CairnError::Transport(format!("{tt} failed"))) },
            )
            .await;

        let err = result.unwrap_err();
        match &err {
            CairnError::TransportExhausted {
                details,
                suggestion,
            } => {
                // Should mention the transports that failed
                assert!(details.contains("Direct QUIC v1"));
                assert!(details.contains("Direct TCP"));
                // Skipped transports should be mentioned
                assert!(details.contains("skipped"));
                // Should suggest deploying infrastructure
                assert!(suggestion.contains("deploy companion infrastructure"));
            }
            _ => panic!("expected TransportExhausted, got: {err:?}"),
        }
    }

    // -- Parallel fallback execution --

    #[tokio::test]
    async fn parallel_first_success_wins() {
        let chain = FallbackChain::new(Duration::from_secs(5), false, false, true);

        let result = chain
            .execute(|tt, _timeout| async move {
                // TCP "connects" faster than QUIC in this mock
                match tt {
                    FallbackTransportType::DirectTcp => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok("tcp")
                    }
                    FallbackTransportType::DirectQuic => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok("quic")
                    }
                    _ => Err(CairnError::Transport(format!("{tt} failed"))),
                }
            })
            .await;

        let (transport, value) = result.unwrap();
        // TCP should win since it's faster in this mock
        assert_eq!(transport, FallbackTransportType::DirectTcp);
        assert_eq!(value, "tcp");
    }

    #[tokio::test]
    async fn parallel_all_fail_returns_exhausted() {
        let chain = FallbackChain::new(Duration::from_secs(1), false, false, true);

        let result: Result<(FallbackTransportType, ())> = chain
            .execute(
                |tt, _timeout| async move { Err(CairnError::Transport(format!("{tt} failed"))) },
            )
            .await;

        assert!(matches!(result, Err(CairnError::TransportExhausted { .. })));
    }

    // -- TransportExhausted error formatting --

    #[test]
    fn transport_exhausted_error_includes_details() {
        let results = vec![
            TransportAttemptResult {
                transport_type: FallbackTransportType::DirectQuic,
                error: Some("connection refused".into()),
                skipped: false,
                duration: Duration::from_millis(100),
            },
            TransportAttemptResult {
                transport_type: FallbackTransportType::TurnUdp,
                error: None,
                skipped: true,
                duration: Duration::ZERO,
            },
        ];

        let err = build_transport_exhausted_error(&results);
        let msg = err.to_string();
        assert!(msg.contains("Direct QUIC v1"));
        assert!(msg.contains("connection refused"));
        assert!(msg.contains("TURN relay (UDP)"));
        assert!(msg.contains("skipped"));
    }

    // -- ConnectionQuality --

    #[test]
    fn connection_quality_defaults() {
        let q = ConnectionQuality::default();
        assert_eq!(q.latency, Duration::ZERO);
        assert_eq!(q.jitter, Duration::ZERO);
        assert!((q.packet_loss_ratio - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quality_thresholds_defaults() {
        let t = QualityThresholds::default();
        assert_eq!(t.max_latency, Duration::from_millis(500));
        assert_eq!(t.max_jitter, Duration::from_millis(100));
        assert!((t.max_packet_loss - 0.05).abs() < f64::EPSILON);
    }

    // -- ConnectionQualityMonitor --

    #[test]
    fn monitor_detects_high_latency() {
        let (tx, _rx) = mpsc::channel(16);
        let monitor =
            ConnectionQualityMonitor::new(QualityThresholds::default(), Duration::from_secs(1), tx);

        let good = ConnectionQuality {
            latency: Duration::from_millis(100),
            ..ConnectionQuality::default()
        };
        assert!(!monitor.is_degraded(&good));

        let bad = ConnectionQuality {
            latency: Duration::from_millis(600),
            ..ConnectionQuality::default()
        };
        assert!(monitor.is_degraded(&bad));
    }

    #[test]
    fn monitor_detects_high_jitter() {
        let (tx, _rx) = mpsc::channel(16);
        let monitor =
            ConnectionQualityMonitor::new(QualityThresholds::default(), Duration::from_secs(1), tx);

        let bad = ConnectionQuality {
            jitter: Duration::from_millis(150),
            ..ConnectionQuality::default()
        };
        assert!(monitor.is_degraded(&bad));
    }

    #[test]
    fn monitor_detects_high_packet_loss() {
        let (tx, _rx) = mpsc::channel(16);
        let monitor =
            ConnectionQualityMonitor::new(QualityThresholds::default(), Duration::from_secs(1), tx);

        let bad = ConnectionQuality {
            packet_loss_ratio: 0.10,
            ..ConnectionQuality::default()
        };
        assert!(monitor.is_degraded(&bad));
    }

    #[tokio::test]
    async fn monitor_emits_degradation_event() {
        let (tx, mut rx) = mpsc::channel(16);
        let monitor =
            ConnectionQualityMonitor::new(QualityThresholds::default(), Duration::from_secs(1), tx);

        let bad = ConnectionQuality {
            latency: Duration::from_millis(600),
            jitter: Duration::from_millis(10),
            packet_loss_ratio: 0.01,
        };

        monitor.report_sample(bad).await;

        let event = rx.recv().await.expect("should receive degradation event");
        assert_eq!(event.reason, DegradationReason::HighLatency);
    }

    #[tokio::test]
    async fn monitor_no_event_for_good_quality() {
        let (tx, mut rx) = mpsc::channel(16);
        let monitor =
            ConnectionQualityMonitor::new(QualityThresholds::default(), Duration::from_secs(1), tx);

        let good = ConnectionQuality {
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            packet_loss_ratio: 0.001,
        };

        monitor.report_sample(good).await;

        // Channel should be empty
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "should not receive event for good quality");
    }

    // -- TransportMigrator --

    #[test]
    fn migrator_probes_better_transports() {
        let (tx, _rx) = mpsc::channel(16);
        let migrator = TransportMigrator::new(
            Duration::from_secs(30),
            FallbackTransportType::WebSocketTls, // priority 6
            tx,
        );

        let to_probe = migrator.transports_to_probe();
        // Should probe 1-5 (DirectQuic, StunHolePunch, DirectTcp, TurnUdp, TurnTcp)
        assert_eq!(to_probe.len(), 5);
        assert_eq!(to_probe[0], FallbackTransportType::DirectQuic);
        assert_eq!(to_probe[4], FallbackTransportType::TurnTcp);
    }

    #[test]
    fn migrator_quic_has_nothing_better() {
        let (tx, _rx) = mpsc::channel(16);
        let migrator = TransportMigrator::new(
            Duration::from_secs(30),
            FallbackTransportType::DirectQuic, // priority 1
            tx,
        );

        let to_probe = migrator.transports_to_probe();
        assert!(to_probe.is_empty());
    }

    #[tokio::test]
    async fn migrator_emits_migration_event() {
        let (tx, mut rx) = mpsc::channel(16);
        let migrator = TransportMigrator::new(
            Duration::from_secs(30),
            FallbackTransportType::DirectTcp, // priority 3
            tx,
        );

        migrator
            .report_better_transport(FallbackTransportType::DirectQuic)
            .await
            .unwrap();

        let event = rx.recv().await.expect("should receive migration event");
        assert_eq!(event.from, FallbackTransportType::DirectTcp);
        assert_eq!(event.to, FallbackTransportType::DirectQuic);
    }

    #[tokio::test]
    async fn migrator_rejects_worse_transport() {
        let (tx, _rx) = mpsc::channel(16);
        let migrator = TransportMigrator::new(
            Duration::from_secs(30),
            FallbackTransportType::DirectTcp, // priority 3
            tx,
        );

        let result = migrator
            .report_better_transport(FallbackTransportType::WebSocketTls) // priority 6
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn migrator_set_current_updates_probes() {
        let (tx, _rx) = mpsc::channel(16);
        let mut migrator = TransportMigrator::new(
            Duration::from_secs(30),
            FallbackTransportType::HttpsLongPoll, // priority 9
            tx,
        );

        assert_eq!(migrator.transports_to_probe().len(), 8);

        migrator.set_current_transport(FallbackTransportType::DirectQuic);
        assert_eq!(
            migrator.current_transport(),
            FallbackTransportType::DirectQuic
        );
        assert!(migrator.transports_to_probe().is_empty());
    }

    // -- DegradationReason Display --

    #[test]
    fn degradation_reason_display() {
        assert_eq!(DegradationReason::HighLatency.to_string(), "high latency");
        assert_eq!(DegradationReason::HighJitter.to_string(), "high jitter");
        assert_eq!(
            DegradationReason::HighPacketLoss.to_string(),
            "high packet loss"
        );
    }
}
