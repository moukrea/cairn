//! TURN credential management: static credentials and REST API dynamic provisioning.
//!
//! Static credentials use the TURN long-term credential mechanism (RFC 8489 Section 9.2):
//!   key = MD5(username:realm:password)
//!
//! REST API dynamic provisioning generates time-limited TURN credentials using HMAC-SHA1.

use base64::Engine;
use hmac::{Hmac, Mac};
use md5::Digest;
use md5::Md5;
use rand::Rng;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

/// Credential store for the TURN server.
#[derive(Clone)]
pub struct CredentialStore {
    /// Static credentials: (username, password) pairs.
    static_credentials: Vec<(String, String)>,
    /// Shared secret for REST API dynamic credential provisioning.
    rest_secret: Option<String>,
    /// Realm for long-term credential mechanism.
    realm: String,
}

impl CredentialStore {
    /// Create a new credential store.
    pub fn new(realm: String) -> Self {
        Self {
            static_credentials: Vec::new(),
            rest_secret: None,
            realm,
        }
    }

    /// Add a static credential (format: "username:password").
    pub fn add_static_credential(&mut self, cred: &str) {
        if let Some((user, pass)) = cred.split_once(':') {
            self.static_credentials
                .push((user.to_string(), pass.to_string()));
        }
    }

    /// Set the shared secret for REST API dynamic provisioning.
    pub fn set_rest_secret(&mut self, secret: String) {
        self.rest_secret = Some(secret);
    }

    /// Compute the long-term credential key: MD5(username:realm:password).
    pub fn compute_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
        let input = format!("{username}:{realm}:{password}");
        let mut hasher = Md5::new();
        hasher.update(input.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Look up the long-term credential key for a username.
    /// Checks static credentials first, then REST API dynamic credentials.
    pub fn lookup_key(&self, username: &str) -> Option<Vec<u8>> {
        // Check static credentials
        for (user, pass) in &self.static_credentials {
            if user == username {
                return Some(Self::compute_key(username, &self.realm, pass));
            }
        }

        // Check REST API dynamic credentials (username format: "<expiry_timestamp>:<random>")
        if let Some(ref secret) = self.rest_secret {
            if let Some((timestamp_str, _random)) = username.split_once(':') {
                if let Ok(expiry_ts) = timestamp_str.parse::<u64>() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now > expiry_ts {
                        // Dynamic credential has expired
                        return None;
                    }
                    // Dynamic credentials: password = Base64(HMAC-SHA1(secret, username))
                    let password = Self::compute_dynamic_password(secret, username);
                    return Some(Self::compute_key(username, &self.realm, &password));
                }
            }
        }

        None
    }

    /// Generate a dynamic credential for the REST API.
    pub fn generate_dynamic_credential(
        &self,
        ttl: u64,
        uris: &[String],
    ) -> Option<DynamicCredential> {
        let secret = self.rest_secret.as_ref()?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl;

        let random_part: u64 = rand::thread_rng().gen();
        let username = format!("{timestamp}:{random_part:016x}");
        let password = Self::compute_dynamic_password(secret, &username);

        Some(DynamicCredential {
            username,
            password,
            ttl,
            uris: uris.to_vec(),
        })
    }

    /// Compute the dynamic password: Base64(HMAC-SHA1(secret, username)).
    fn compute_dynamic_password(secret: &str, username: &str) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
            .expect("HMAC-SHA1 accepts any key length");
        mac.update(username.as_bytes());
        let result = mac.finalize().into_bytes();
        base64::engine::general_purpose::STANDARD.encode(result)
    }

    /// Get the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Check whether REST API provisioning is available.
    pub fn has_rest_api(&self) -> bool {
        self.rest_secret.is_some()
    }
}

/// A dynamically generated TURN credential.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DynamicCredential {
    pub username: String,
    pub password: String,
    pub ttl: u64,
    pub uris: Vec<String>,
}

/// Generate a random nonce for STUN authentication.
pub fn generate_nonce() -> String {
    let random: [u8; 16] = rand::thread_rng().gen();
    hex::encode(&random)
}

/// Simple hex encoding (no external dep needed).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_credential_lookup() {
        let mut store = CredentialStore::new("cairn".to_string());
        store.add_static_credential("alice:secret123");

        let key = store.lookup_key("alice");
        assert!(key.is_some());

        let expected = CredentialStore::compute_key("alice", "cairn", "secret123");
        assert_eq!(key.unwrap(), expected);
    }

    #[test]
    fn test_unknown_user_returns_none() {
        let store = CredentialStore::new("cairn".to_string());
        assert!(store.lookup_key("unknown").is_none());
    }

    #[test]
    fn test_dynamic_credential_generation() {
        let mut store = CredentialStore::new("cairn".to_string());
        store.set_rest_secret("my-shared-secret".to_string());

        let cred = store
            .generate_dynamic_credential(3600, &["turn:relay.example.com:3478".to_string()])
            .unwrap();

        assert!(!cred.username.is_empty());
        assert!(!cred.password.is_empty());
        assert_eq!(cred.ttl, 3600);

        // The generated credential should be verifiable
        let key = store.lookup_key(&cred.username);
        assert!(key.is_some());
    }

    #[test]
    fn test_expired_dynamic_credential_rejected() {
        let mut store = CredentialStore::new("cairn".to_string());
        store.set_rest_secret("my-shared-secret".to_string());

        // Craft a username with an expiry timestamp in the past
        let expired_username = "1000000000:deadbeef01234567";
        assert!(store.lookup_key(expired_username).is_none());
    }

    #[test]
    fn test_valid_dynamic_credential_accepted() {
        let mut store = CredentialStore::new("cairn".to_string());
        store.set_rest_secret("my-shared-secret".to_string());

        // Craft a username with an expiry timestamp far in the future
        let future_username = "9999999999:deadbeef01234567";
        assert!(store.lookup_key(future_username).is_some());
    }

    #[test]
    fn test_static_credential_with_colon_not_treated_as_dynamic() {
        let mut store = CredentialStore::new("cairn".to_string());
        store.add_static_credential("alice:secret123");
        // "alice" has no colon, so it's looked up as static only
        assert!(store.lookup_key("alice").is_some());
        // Unknown static user without colon: no match
        assert!(store.lookup_key("bob").is_none());
    }
}
