//! Heartbeat and keepalive system (spec/07-reconnection-sessions.md section 6).
//!
//! Both peers send heartbeats independently at a configurable interval. Receipt of
//! any data (not just heartbeats) resets the timeout counter. If no data arrives within
//! the timeout window, the connection transitions to Disconnected.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// Heartbeat configuration (spec section 6).
///
/// Tuning guidance:
/// - Aggressive (5s interval): real-time apps requiring prompt failure detection.
/// - Default (30s interval): balanced detection vs battery/bandwidth.
/// - Relaxed (60s interval): background sync, battery/bandwidth conservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Interval at which heartbeats are sent. Default: 30 seconds.
    pub interval: Duration,
    /// Time without any data before declaring disconnection. Default: 90 seconds (3x interval).
    pub timeout: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(90),
        }
    }
}

impl HeartbeatConfig {
    /// Aggressive preset for real-time applications (5s interval, 15s timeout).
    pub fn aggressive() -> Self {
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(15),
        }
    }

    /// Relaxed preset for background sync (60s interval, 180s timeout).
    pub fn relaxed() -> Self {
        Self {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(180),
        }
    }
}

/// Monitors heartbeat timing and determines connection liveness.
///
/// Tracks the last activity timestamp and determines when a heartbeat should be
/// sent or when the connection should be declared timed out.
pub struct HeartbeatMonitor {
    config: HeartbeatConfig,
    last_activity: Instant,
    last_heartbeat_sent: Instant,
}

impl HeartbeatMonitor {
    /// Create a new heartbeat monitor with the given configuration.
    pub fn new(config: HeartbeatConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            last_activity: now,
            last_heartbeat_sent: now,
        }
    }

    /// Record that data was received (any data, not just heartbeats).
    ///
    /// Resets the timeout counter per spec: "Receipt of any data resets the timeout counter."
    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record that a heartbeat was sent.
    pub fn record_heartbeat_sent(&mut self) {
        self.last_heartbeat_sent = Instant::now();
    }

    /// Check whether the connection has timed out (no data within timeout window).
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() >= self.config.timeout
    }

    /// Check whether it is time to send a heartbeat.
    pub fn should_send_heartbeat(&self) -> bool {
        self.last_heartbeat_sent.elapsed() >= self.config.interval
    }

    /// Get the duration until the next heartbeat should be sent.
    ///
    /// Returns `Duration::ZERO` if a heartbeat is overdue.
    pub fn time_until_next_heartbeat(&self) -> Duration {
        self.config
            .interval
            .checked_sub(self.last_heartbeat_sent.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Get the duration until the connection times out.
    ///
    /// Returns `Duration::ZERO` if already timed out.
    pub fn time_until_timeout(&self) -> Duration {
        self.config
            .timeout
            .checked_sub(self.last_activity.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Get a reference to the heartbeat configuration.
    pub fn config(&self) -> &HeartbeatConfig {
        &self.config
    }

    /// Get the instant of the last recorded activity.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HeartbeatConfig tests ---

    #[test]
    fn test_default_config() {
        let config = HeartbeatConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.timeout, Duration::from_secs(90));
    }

    #[test]
    fn test_aggressive_config() {
        let config = HeartbeatConfig::aggressive();
        assert_eq!(config.interval, Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(15));
    }

    #[test]
    fn test_relaxed_config() {
        let config = HeartbeatConfig::relaxed();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(180));
    }

    #[test]
    fn test_timeout_is_3x_interval_for_all_presets() {
        let default = HeartbeatConfig::default();
        assert_eq!(default.timeout, default.interval * 3);

        let aggressive = HeartbeatConfig::aggressive();
        assert_eq!(aggressive.timeout, aggressive.interval * 3);

        let relaxed = HeartbeatConfig::relaxed();
        assert_eq!(relaxed.timeout, relaxed.interval * 3);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(30),
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: HeartbeatConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.interval, config.interval);
        assert_eq!(decoded.timeout, config.timeout);
    }

    // --- HeartbeatMonitor tests ---

    #[test]
    fn test_monitor_not_timed_out_initially() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        assert!(!monitor.is_timed_out());
    }

    #[test]
    fn test_monitor_not_needing_heartbeat_initially() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        assert!(!monitor.should_send_heartbeat());
    }

    #[test]
    fn test_monitor_time_until_heartbeat_positive_initially() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        let until = monitor.time_until_next_heartbeat();
        assert!(until > Duration::ZERO);
        assert!(until <= Duration::from_secs(30));
    }

    #[test]
    fn test_monitor_time_until_timeout_positive_initially() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        let until = monitor.time_until_timeout();
        assert!(until > Duration::ZERO);
        assert!(until <= Duration::from_secs(90));
    }

    #[test]
    fn test_monitor_timed_out_with_zero_timeout() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(1),
            timeout: Duration::ZERO,
        };
        let monitor = HeartbeatMonitor::new(config);
        assert!(monitor.is_timed_out());
    }

    #[test]
    fn test_monitor_should_send_with_zero_interval() {
        let config = HeartbeatConfig {
            interval: Duration::ZERO,
            timeout: Duration::from_secs(10),
        };
        let monitor = HeartbeatMonitor::new(config);
        assert!(monitor.should_send_heartbeat());
    }

    #[test]
    fn test_record_activity_resets_timeout() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(1),
            timeout: Duration::ZERO,
        };
        let mut monitor = HeartbeatMonitor::new(config);
        // With zero timeout, should already be timed out
        assert!(monitor.is_timed_out());

        // Record activity with a non-zero timeout to verify the reset
        monitor.config.timeout = Duration::from_secs(60);
        monitor.record_activity();
        assert!(!monitor.is_timed_out());
    }

    #[test]
    fn test_record_heartbeat_sent() {
        let config = HeartbeatConfig {
            interval: Duration::ZERO,
            timeout: Duration::from_secs(10),
        };
        let mut monitor = HeartbeatMonitor::new(config);
        // With zero interval, should want to send
        assert!(monitor.should_send_heartbeat());

        // After recording sent with a real interval, should not want to send
        monitor.config.interval = Duration::from_secs(30);
        monitor.record_heartbeat_sent();
        assert!(!monitor.should_send_heartbeat());
    }

    #[test]
    fn test_last_activity_accessible() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        let activity = monitor.last_activity();
        assert!(activity.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_config_accessible() {
        let config = HeartbeatConfig::aggressive();
        let monitor = HeartbeatMonitor::new(config.clone());
        assert_eq!(monitor.config().interval, Duration::from_secs(5));
        assert_eq!(monitor.config().timeout, Duration::from_secs(15));
    }
}
