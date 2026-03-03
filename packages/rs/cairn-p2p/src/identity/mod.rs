pub mod peer_id;
pub mod trust_store;

pub use peer_id::{IdentityError, PeerId};
pub use trust_store::{InMemoryTrustStore, PairedPeerInfo, TrustStore};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// A local peer identity: Ed25519 keypair plus derived PeerId.
///
/// Created once at first initialization and persisted via the key storage backend.
/// The PeerId is the SHA-256 multihash of the Ed25519 public key.
pub struct LocalIdentity {
    keypair: SigningKey,
    peer_id: PeerId,
}

impl LocalIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let keypair = SigningKey::generate(&mut csprng);
        let peer_id = PeerId::from_public_key(&keypair.verifying_key());
        Self { keypair, peer_id }
    }

    /// Construct from an existing signing key.
    pub fn from_keypair(keypair: SigningKey) -> Self {
        let peer_id = PeerId::from_public_key(&keypair.verifying_key());
        Self { keypair, peer_id }
    }

    /// The local peer's identifier.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// The Ed25519 public (verifying) key.
    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }

    /// The Ed25519 signing key. Use with care -- exposes private material.
    pub fn signing_key(&self) -> &SigningKey {
        &self.keypair
    }

    /// Sign a message using the local identity key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Verify a signature against the local identity's public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), crate::error::CairnError> {
        self.keypair
            .verifying_key()
            .verify(message, signature)
            .map_err(|e| crate::error::CairnError::Crypto(e.to_string()))
    }
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_identity() {
        let id = LocalIdentity::generate();
        // PeerId derived from the public key should match
        let expected = PeerId::from_public_key(&id.public_key());
        assert_eq!(*id.peer_id(), expected);
    }

    #[test]
    fn from_keypair_derives_correct_peer_id() {
        let mut csprng = rand::thread_rng();
        let key = SigningKey::generate(&mut csprng);
        let expected_pid = PeerId::from_public_key(&key.verifying_key());
        let id = LocalIdentity::from_keypair(key);
        assert_eq!(*id.peer_id(), expected_pid);
    }

    #[test]
    fn sign_and_verify() {
        let id = LocalIdentity::generate();
        let msg = b"identity test message";
        let sig = id.sign(msg);
        assert!(id.verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let id = LocalIdentity::generate();
        let sig = id.sign(b"correct");
        assert!(id.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn public_key_accessor() {
        let id = LocalIdentity::generate();
        let pk = id.public_key();
        assert_eq!(pk, id.signing_key().verifying_key());
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let id = LocalIdentity::generate();
        let debug = format!("{:?}", id);
        assert!(debug.contains("PeerId"));
        // Should not contain raw key bytes
        assert!(!debug.contains("keypair"));
    }

    #[test]
    fn two_identities_have_different_peer_ids() {
        let id1 = LocalIdentity::generate();
        let id2 = LocalIdentity::generate();
        assert_ne!(id1.peer_id(), id2.peer_id());
    }
}
