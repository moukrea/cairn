use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::{CairnError, Result};

// Domain separation info strings for HKDF derivations.
pub const HKDF_INFO_SESSION_KEY: &[u8] = b"cairn-session-key-v1";
pub const HKDF_INFO_RENDEZVOUS: &[u8] = b"cairn-rendezvous-id-v1";
pub const HKDF_INFO_SAS: &[u8] = b"cairn-sas-derivation-v1";
pub const HKDF_INFO_CHAIN_KEY: &[u8] = b"cairn-chain-key-v1";
pub const HKDF_INFO_MESSAGE_KEY: &[u8] = b"cairn-message-key-v1";

/// An X25519 keypair for Diffie-Hellman key exchange.
///
/// Uses `StaticSecret` so the keypair can be reused across multiple
/// exchanges (required for Noise framework patterns).
pub struct X25519Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519Keypair {
    /// Generate a new random X25519 keypair.
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut csprng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Restore from a 32-byte secret key.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Export the 32-byte secret key.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    /// Returns the 32-byte shared secret.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// Generate an ephemeral X25519 keypair for one-time use.
pub fn ephemeral_keypair() -> (EphemeralSecret, PublicKey) {
    let mut csprng = rand::thread_rng();
    let secret = EphemeralSecret::random_from_rng(&mut csprng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Derive key material from a shared secret using HKDF-SHA256 (RFC 5869).
///
/// - `ikm`: input keying material (e.g., DH shared secret)
/// - `salt`: optional salt (None uses a zero-filled salt)
/// - `info`: context-specific info string for domain separation
/// - `output`: buffer to fill with derived key material
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], output: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    hkdf.expand(info, output)
        .map_err(|e| CairnError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_matches_both_sides() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn different_peers_produce_different_shared_secrets() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();
        let charlie = X25519Keypair::generate();

        let ab = alice.diffie_hellman(bob.public_key());
        let ac = alice.diffie_hellman(charlie.public_key());

        assert_ne!(ab, ac);
    }

    #[test]
    fn ephemeral_keypair_works() {
        let (secret, public) = ephemeral_keypair();
        let peer = X25519Keypair::generate();

        // Ephemeral DH with peer
        let shared_ephemeral = secret.diffie_hellman(peer.public_key()).to_bytes();
        let shared_peer = peer.diffie_hellman(&public);

        assert_eq!(shared_ephemeral, shared_peer);
    }

    #[test]
    fn hkdf_produces_deterministic_output() {
        let ikm = b"shared-secret-material";
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut out1).unwrap();
        hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn hkdf_domain_separation_produces_different_keys() {
        let ikm = b"same-input-keying-material";
        let mut session_key = [0u8; 32];
        let mut rendezvous_key = [0u8; 32];

        hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut session_key).unwrap();
        hkdf_sha256(ikm, None, HKDF_INFO_RENDEZVOUS, &mut rendezvous_key).unwrap();

        assert_ne!(session_key, rendezvous_key);
    }

    #[test]
    fn hkdf_with_salt_differs_from_without() {
        let ikm = b"input-keying-material";
        let salt = b"some-salt-value";
        let mut with_salt = [0u8; 32];
        let mut without_salt = [0u8; 32];

        hkdf_sha256(ikm, Some(salt), HKDF_INFO_SESSION_KEY, &mut with_salt).unwrap();
        hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut without_salt).unwrap();

        assert_ne!(with_salt, without_salt);
    }

    #[test]
    fn hkdf_can_produce_various_output_lengths() {
        let ikm = b"key-material";
        let mut short = [0u8; 16];
        let mut long = [0u8; 64];

        assert!(hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut short).is_ok());
        assert!(hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut long).is_ok());
    }

    #[test]
    fn hkdf_rejects_too_long_output() {
        let ikm = b"key-material";
        // HKDF-SHA256 max output is 255 * 32 = 8160 bytes
        let mut too_long = vec![0u8; 8161];

        assert!(hkdf_sha256(ikm, None, HKDF_INFO_SESSION_KEY, &mut too_long).is_err());
    }

    #[test]
    fn all_domain_separation_constants_are_unique() {
        let constants: &[&[u8]] = &[
            HKDF_INFO_SESSION_KEY,
            HKDF_INFO_RENDEZVOUS,
            HKDF_INFO_SAS,
            HKDF_INFO_CHAIN_KEY,
            HKDF_INFO_MESSAGE_KEY,
        ];
        for (i, a) in constants.iter().enumerate() {
            for (j, b) in constants.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "domain separation constants at index {i} and {j} collide"
                    );
                }
            }
        }
    }
}
