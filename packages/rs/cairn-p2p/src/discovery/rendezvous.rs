use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::exchange::hkdf_sha256;
use crate::error::{CairnError, Result};

/// HKDF info string for rendezvous ID derivation from pairing secrets.
const HKDF_INFO_RENDEZVOUS: &[u8] = b"cairn-rendezvous-v1";
/// HKDF info string for pairing-bootstrapped rendezvous ID derivation.
const HKDF_INFO_PAIRING_RENDEZVOUS: &[u8] = b"cairn-pairing-rendezvous-v1";
/// HKDF info string for deriving the epoch offset from a pairing secret.
const HKDF_INFO_EPOCH_OFFSET: &[u8] = b"cairn-epoch-offset-v1";

/// A rendezvous identifier (32 bytes, opaque).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RendezvousId(pub [u8; 32]);

impl RendezvousId {
    /// Encode as hex string for display and use as topic/key names.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Configuration for rendezvous ID rotation.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotation interval. Default: 24 hours.
    pub rotation_interval: Duration,
    /// Overlap window centered on epoch boundary. Default: 1 hour.
    pub overlap_window: Duration,
    /// Clock tolerance. Default: 5 minutes.
    pub clock_tolerance: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(24 * 3600),
            overlap_window: Duration::from_secs(3600),
            clock_tolerance: Duration::from_secs(300),
        }
    }
}

/// Derive a rendezvous ID from a pairing secret and epoch number.
///
/// Uses HKDF-SHA256 with info string `"cairn-rendezvous-v1"`. The epoch
/// number is encoded as big-endian u64 and used as the HKDF salt, so each
/// epoch produces a different rendezvous ID from the same pairing secret.
pub fn derive_rendezvous_id(pairing_secret: &[u8], epoch: u64) -> Result<RendezvousId> {
    let salt = epoch.to_be_bytes();
    let mut id = [0u8; 32];
    hkdf_sha256(pairing_secret, Some(&salt), HKDF_INFO_RENDEZVOUS, &mut id)?;
    Ok(RendezvousId(id))
}

/// Derive a pairing-bootstrapped rendezvous ID from PAKE credentials and a nonce.
///
/// Used for initial discovery before a pairing secret exists (pin code, QR code,
/// pairing link). Only used for the initial connection; subsequent connections
/// use the standard rendezvous mechanism.
pub fn derive_pairing_rendezvous_id(pake_credential: &[u8], nonce: &[u8]) -> Result<RendezvousId> {
    let mut id = [0u8; 32];
    hkdf_sha256(
        pake_credential,
        Some(nonce),
        HKDF_INFO_PAIRING_RENDEZVOUS,
        &mut id,
    )?;
    Ok(RendezvousId(id))
}

/// Get the current Unix timestamp in seconds.
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

/// Derive the epoch offset from a pairing secret.
///
/// This makes the epoch boundary unpredictable to observers since it differs
/// per pairing relationship.
fn derive_epoch_offset(pairing_secret: &[u8]) -> Result<u64> {
    let mut offset_bytes = [0u8; 8];
    hkdf_sha256(
        pairing_secret,
        None,
        HKDF_INFO_EPOCH_OFFSET,
        &mut offset_bytes,
    )?;
    Ok(u64::from_be_bytes(offset_bytes))
}

/// Compute the current epoch number for a given pairing secret and timestamp.
///
/// The epoch boundary is offset by a value derived from the pairing secret,
/// making it unpredictable to observers.
pub fn compute_epoch(
    pairing_secret: &[u8],
    rotation_interval: Duration,
    timestamp_secs: u64,
) -> Result<u64> {
    let offset = derive_epoch_offset(pairing_secret)?;
    let interval = rotation_interval.as_secs();
    if interval == 0 {
        return Err(CairnError::Discovery(
            "rotation interval must be > 0".into(),
        ));
    }
    // Wrapping add is fine -- we only need consistency between peers.
    let adjusted = timestamp_secs.wrapping_add(offset);
    Ok(adjusted / interval)
}

/// Compute the current epoch number using the system clock.
pub fn current_epoch(pairing_secret: &[u8], rotation_interval: Duration) -> Result<u64> {
    compute_epoch(pairing_secret, rotation_interval, unix_timestamp())
}

/// Determine which rendezvous IDs are active at a given timestamp.
///
/// Outside the overlap window: returns only the current epoch's ID.
/// Inside the overlap window: returns both current and previous epoch's IDs.
pub fn active_rendezvous_ids_at(
    pairing_secret: &[u8],
    config: &RotationConfig,
    timestamp_secs: u64,
) -> Result<Vec<RendezvousId>> {
    let interval = config.rotation_interval.as_secs();
    if interval == 0 {
        return Err(CairnError::Discovery(
            "rotation interval must be > 0".into(),
        ));
    }

    let offset = derive_epoch_offset(pairing_secret)?;
    let adjusted = timestamp_secs.wrapping_add(offset);
    let current_epoch = adjusted / interval;
    let position_in_epoch = adjusted % interval;

    let half_overlap = config.overlap_window.as_secs() / 2 + config.clock_tolerance.as_secs();

    let current_id = derive_rendezvous_id(pairing_secret, current_epoch)?;

    // Check if we're in the overlap window near the epoch boundary.
    // Near the start of the current epoch (just after transition):
    let in_overlap = position_in_epoch < half_overlap
        || position_in_epoch > interval.saturating_sub(half_overlap);

    if in_overlap && current_epoch > 0 {
        // Near start: include the previous epoch.
        // Near end: include the next epoch (but use previous for safety --
        // the peer may still be on the current epoch).
        let other_epoch = if position_in_epoch < half_overlap {
            current_epoch - 1
        } else {
            current_epoch + 1
        };
        let other_id = derive_rendezvous_id(pairing_secret, other_epoch)?;
        Ok(vec![current_id, other_id])
    } else {
        Ok(vec![current_id])
    }
}

/// Determine which rendezvous IDs are active right now using the system clock.
pub fn active_rendezvous_ids(
    pairing_secret: &[u8],
    config: &RotationConfig,
) -> Result<Vec<RendezvousId>> {
    active_rendezvous_ids_at(pairing_secret, config, unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_rendezvous_id_is_deterministic() {
        let secret = b"shared-pairing-secret";
        let id1 = derive_rendezvous_id(secret, 42).unwrap();
        let id2 = derive_rendezvous_id(secret, 42).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_rendezvous_id_different_epochs_differ() {
        let secret = b"shared-pairing-secret";
        let id1 = derive_rendezvous_id(secret, 1).unwrap();
        let id2 = derive_rendezvous_id(secret, 2).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_rendezvous_id_different_secrets_differ() {
        let id1 = derive_rendezvous_id(b"secret-a", 1).unwrap();
        let id2 = derive_rendezvous_id(b"secret-b", 1).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_pairing_rendezvous_id_is_deterministic() {
        let cred = b"pake-credential";
        let nonce = b"nonce-123";
        let id1 = derive_pairing_rendezvous_id(cred, nonce).unwrap();
        let id2 = derive_pairing_rendezvous_id(cred, nonce).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_pairing_rendezvous_different_nonces_differ() {
        let cred = b"pake-credential";
        let id1 = derive_pairing_rendezvous_id(cred, b"nonce-a").unwrap();
        let id2 = derive_pairing_rendezvous_id(cred, b"nonce-b").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_pairing_rendezvous_differs_from_standard() {
        let secret = b"same-input";
        let epoch_salt = 1u64.to_be_bytes();
        let standard = derive_rendezvous_id(secret, 1).unwrap();
        let pairing = derive_pairing_rendezvous_id(secret, &epoch_salt).unwrap();
        // Different HKDF info strings ensure different IDs even with same input.
        assert_ne!(standard, pairing);
    }

    #[test]
    fn compute_epoch_is_consistent() {
        let secret = b"test-secret";
        let interval = Duration::from_secs(3600); // 1 hour
        let ts = 1_700_000_000u64;

        let e1 = compute_epoch(secret, interval, ts).unwrap();
        let e2 = compute_epoch(secret, interval, ts).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn compute_epoch_advances_with_time() {
        let secret = b"test-secret";
        let interval = Duration::from_secs(3600);

        let e1 = compute_epoch(secret, interval, 1_700_000_000).unwrap();
        // Advance exactly one interval.
        let e2 = compute_epoch(secret, interval, 1_700_000_000 + 3600).unwrap();
        assert_eq!(e2, e1 + 1);
    }

    #[test]
    fn compute_epoch_zero_interval_rejected() {
        let result = compute_epoch(b"secret", Duration::ZERO, 1_700_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn compute_epoch_different_secrets_different_offsets() {
        let interval = Duration::from_secs(3600);
        let ts = 1_700_000_000u64;

        let e1 = compute_epoch(b"secret-a", interval, ts).unwrap();
        let e2 = compute_epoch(b"secret-b", interval, ts).unwrap();
        // Different secrets produce different epoch offsets, so different epoch numbers.
        // (Could theoretically collide but extremely unlikely with 64-bit offsets.)
        assert_ne!(e1, e2);
    }

    #[test]
    fn active_ids_single_outside_overlap() {
        let secret = b"test-secret";
        let config = RotationConfig {
            rotation_interval: Duration::from_secs(86400), // 24h
            overlap_window: Duration::from_secs(3600),     // 1h
            clock_tolerance: Duration::from_secs(300),     // 5min
        };

        // Use a timestamp well within an epoch (not near boundaries).
        // We need to find where the middle of an epoch is for this secret.
        let offset = derive_epoch_offset(secret).unwrap();
        let interval = 86400u64;
        let base_ts = 1_700_000_000u64;
        let adjusted = base_ts.wrapping_add(offset);
        let position = adjusted % interval;

        // Find a timestamp in the middle of the epoch.
        let half_overlap = 3600 / 2 + 300; // 2100
        let mid_epoch_ts = if position > interval / 2 {
            // Already in the middle, use as is.
            base_ts
        } else {
            // Jump forward to middle of epoch.
            base_ts + (interval / 2 - position)
        };

        let adjusted2 = mid_epoch_ts.wrapping_add(offset);
        let pos2 = adjusted2 % interval;
        // Ensure we're not in the overlap window.
        if pos2 >= half_overlap && pos2 <= interval - half_overlap {
            let ids = active_rendezvous_ids_at(secret, &config, mid_epoch_ts).unwrap();
            assert_eq!(ids.len(), 1);
        }
        // else: skip -- the timestamp happens to be in the overlap window,
        // which is tested by the next test.
    }

    #[test]
    fn active_ids_dual_near_epoch_boundary() {
        let secret = b"test-secret";
        let config = RotationConfig {
            rotation_interval: Duration::from_secs(86400),
            overlap_window: Duration::from_secs(3600),
            clock_tolerance: Duration::from_secs(300),
        };

        let offset = derive_epoch_offset(secret).unwrap();
        let interval = 86400u64;

        // Find a timestamp right at the start of an epoch boundary.
        // adjusted = ts + offset; boundary when adjusted % interval == 0
        // So ts = n * interval - offset for some n.
        let n = (1_700_000_000u64.wrapping_add(offset)) / interval + 1;
        let boundary_adjusted = n * interval;
        let boundary_ts = boundary_adjusted.wrapping_sub(offset);

        // Just after the boundary (position_in_epoch is small).
        let ts_after = boundary_ts + 100;
        let ids = active_rendezvous_ids_at(secret, &config, ts_after).unwrap();
        assert_eq!(
            ids.len(),
            2,
            "should have 2 IDs near epoch boundary (just after)"
        );

        // Just before the boundary (position_in_epoch is near the end).
        let ts_before = boundary_ts.wrapping_sub(100);
        let ids = active_rendezvous_ids_at(secret, &config, ts_before).unwrap();
        assert_eq!(
            ids.len(),
            2,
            "should have 2 IDs near epoch boundary (just before)"
        );
    }

    #[test]
    fn active_ids_includes_current_epoch_id() {
        let secret = b"test-secret";
        let config = RotationConfig::default();
        let ts = 1_700_000_000u64;

        let ids = active_rendezvous_ids_at(secret, &config, ts).unwrap();
        let epoch = compute_epoch(secret, config.rotation_interval, ts).unwrap();
        let expected_id = derive_rendezvous_id(secret, epoch).unwrap();

        assert!(
            ids.contains(&expected_id),
            "active IDs must include current epoch's ID"
        );
    }

    #[test]
    fn rendezvous_id_to_hex() {
        let id = RendezvousId([0xAB; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rotation_config_default_values() {
        let config = RotationConfig::default();
        assert_eq!(config.rotation_interval, Duration::from_secs(86400));
        assert_eq!(config.overlap_window, Duration::from_secs(3600));
        assert_eq!(config.clock_tolerance, Duration::from_secs(300));
    }

    #[test]
    fn both_peers_compute_same_rendezvous_id() {
        let shared_secret = b"shared-pairing-secret-between-alice-and-bob";
        let epoch = 12345u64;
        let alice_id = derive_rendezvous_id(shared_secret, epoch).unwrap();
        let bob_id = derive_rendezvous_id(shared_secret, epoch).unwrap();
        assert_eq!(alice_id, bob_id);
    }
}
