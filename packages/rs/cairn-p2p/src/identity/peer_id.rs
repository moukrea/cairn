use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Multihash prefix for SHA2-256: code 0x12, digest length 0x20 (32 bytes).
const MULTIHASH_SHA2_256_CODE: u8 = 0x12;
const MULTIHASH_SHA2_256_LEN: u8 = 0x20;

/// Total length of a PeerId: 2-byte multihash prefix + 32-byte digest.
const PEER_ID_LEN: usize = 34;

/// Error type for identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid peer ID format")]
    InvalidPeerId,

    #[error("invalid base58 encoding: {0}")]
    Base58Decode(String),

    #[error("peer already paired: {0}")]
    AlreadyPaired(PeerId),
}

/// A peer identifier derived from the SHA-256 multihash of an Ed25519 public key.
///
/// Internal representation: `[0x12, 0x20, <32 bytes SHA-256 digest>]` (34 bytes total).
/// Display/FromStr use base58 (Bitcoin alphabet) encoding, matching libp2p convention.
#[derive(Clone, Eq)]
pub struct PeerId {
    bytes: [u8; PEER_ID_LEN],
}

impl PeerId {
    /// Derive a `PeerId` from an Ed25519 public (verifying) key.
    ///
    /// Steps:
    /// 1. SHA-256 hash the raw 32-byte public key.
    /// 2. Wrap in a multihash envelope: `0x12 0x20 <digest>`.
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let digest = Sha256::digest(public_key.as_bytes());
        let mut bytes = [0u8; PEER_ID_LEN];
        bytes[0] = MULTIHASH_SHA2_256_CODE;
        bytes[1] = MULTIHASH_SHA2_256_LEN;
        bytes[2..].copy_from_slice(&digest);
        Self { bytes }
    }

    /// Construct from raw 34-byte multihash bytes. Validates the prefix.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != PEER_ID_LEN {
            return Err(IdentityError::InvalidPeerId);
        }
        if bytes[0] != MULTIHASH_SHA2_256_CODE || bytes[1] != MULTIHASH_SHA2_256_LEN {
            return Err(IdentityError::InvalidPeerId);
        }
        let mut arr = [0u8; PEER_ID_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Returns the raw 34-byte multihash representation.
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.bytes).into_string())
    }
}

impl FromStr for PeerId {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| IdentityError::Base58Decode(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.bytes)
        }
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            PeerId::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            PeerId::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> SigningKey {
        let mut csprng = rand::thread_rng();
        SigningKey::generate(&mut csprng)
    }

    #[test]
    fn from_public_key_produces_34_bytes() {
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        assert_eq!(pid.as_bytes().len(), 34);
        assert_eq!(pid.as_bytes()[0], 0x12);
        assert_eq!(pid.as_bytes()[1], 0x20);
    }

    #[test]
    fn from_public_key_is_deterministic() {
        let kp = test_keypair();
        let pid1 = PeerId::from_public_key(&kp.verifying_key());
        let pid2 = PeerId::from_public_key(&kp.verifying_key());
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn different_keys_produce_different_peer_ids() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let pid1 = PeerId::from_public_key(&kp1.verifying_key());
        let pid2 = PeerId::from_public_key(&kp2.verifying_key());
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn display_and_from_str_roundtrip() {
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        let display = pid.to_string();
        let parsed: PeerId = display.parse().unwrap();
        assert_eq!(pid, parsed);
    }

    #[test]
    fn from_str_rejects_invalid_base58() {
        let result: Result<PeerId, _> = "0OOinvalid!!!".parse();
        assert!(result.is_err());
    }

    #[test]
    fn from_str_rejects_wrong_length() {
        // Valid base58 but wrong byte count
        let result: Result<PeerId, _> = "1234".parse();
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_prefix() {
        let mut bytes = [0u8; 34];
        bytes[0] = 0xFF; // wrong code
        bytes[1] = 0x20;
        assert!(PeerId::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_length_byte() {
        let mut bytes = [0u8; 34];
        bytes[0] = 0x12;
        bytes[1] = 0x10; // wrong length marker
        assert!(PeerId::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        let restored = PeerId::from_bytes(pid.as_bytes()).unwrap();
        assert_eq!(pid, restored);
    }

    #[test]
    fn hash_works_in_hashmap() {
        use std::collections::HashMap;
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        let mut map = HashMap::new();
        map.insert(pid.clone(), "test");
        assert_eq!(map.get(&pid), Some(&"test"));
    }

    #[test]
    fn debug_contains_base58() {
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        let debug = format!("{:?}", pid);
        assert!(debug.starts_with("PeerId("));
        assert!(debug.ends_with(')'));
    }

    #[test]
    fn serde_json_roundtrip() {
        let kp = test_keypair();
        let pid = PeerId::from_public_key(&kp.verifying_key());
        let json = serde_json::to_string(&pid).unwrap();
        let restored: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, restored);
    }
}
