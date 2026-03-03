use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{CairnError, Result};

/// An Ed25519 identity keypair used for signing and peer identification.
pub struct IdentityKeypair {
    signing_key: SigningKey,
}

impl IdentityKeypair {
    /// Generate a new random Ed25519 identity keypair.
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Restore from a 32-byte secret key seed.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Export the 32-byte secret key seed.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Derive the Peer ID: SHA-256 hash of the Ed25519 public key bytes.
    pub fn peer_id(&self) -> [u8; 32] {
        peer_id_from_public_key(&self.public_key())
    }

    /// Sign a message. Deterministic — no randomness needed.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Access the underlying signing key (needed for Ed25519-to-X25519 conversion).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        verify_signature(&self.public_key(), message, signature)
    }
}

/// Verify a signature against an arbitrary public key.
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    public_key
        .verify(message, signature)
        .map_err(|e| CairnError::Crypto(e.to_string()))
}

/// Derive Peer ID from a public key (without needing the private key).
pub fn peer_id_from_public_key(public_key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_roundtrip_keypair() {
        let kp = IdentityKeypair::generate();
        let secret = kp.secret_bytes();
        let restored = IdentityKeypair::from_bytes(&secret);
        assert_eq!(kp.public_key(), restored.public_key());
    }

    #[test]
    fn sign_and_verify() {
        let kp = IdentityKeypair::generate();
        let message = b"hello cairn";
        let sig = kp.sign(message);
        assert!(kp.verify(message, &sig).is_ok());
    }

    #[test]
    fn verify_with_wrong_message_fails() {
        let kp = IdentityKeypair::generate();
        let sig = kp.sign(b"correct message");
        assert!(kp.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let kp1 = IdentityKeypair::generate();
        let kp2 = IdentityKeypair::generate();
        let sig = kp1.sign(b"hello");
        assert!(kp2.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn verify_signature_standalone() {
        let kp = IdentityKeypair::generate();
        let message = b"standalone verify";
        let sig = kp.sign(message);
        assert!(verify_signature(&kp.public_key(), message, &sig).is_ok());
        assert!(verify_signature(&kp.public_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn peer_id_is_deterministic() {
        let kp = IdentityKeypair::generate();
        let id1 = kp.peer_id();
        let id2 = kp.peer_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn peer_id_from_public_key_matches() {
        let kp = IdentityKeypair::generate();
        let id_from_kp = kp.peer_id();
        let id_from_pub = peer_id_from_public_key(&kp.public_key());
        assert_eq!(id_from_kp, id_from_pub);
    }

    #[test]
    fn different_keys_produce_different_peer_ids() {
        let kp1 = IdentityKeypair::generate();
        let kp2 = IdentityKeypair::generate();
        assert_ne!(kp1.peer_id(), kp2.peer_id());
    }

    #[test]
    fn signature_is_deterministic() {
        let kp = IdentityKeypair::generate();
        let message = b"deterministic";
        let sig1 = kp.sign(message);
        let sig2 = kp.sign(message);
        assert_eq!(sig1, sig2);
    }
}
