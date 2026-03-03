use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::crypto::aead::{self, CipherSuite, NONCE_SIZE};
use crate::error::{CairnError, Result};
use crate::traits::KeyStore;

// ---------------------------------------------------------------------------
// In-Memory Backend
// ---------------------------------------------------------------------------

/// Ephemeral key store backed by an in-memory HashMap. All data is lost on drop.
#[derive(Debug, Clone)]
pub struct InMemoryKeyStore {
    store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        if key_id.is_empty() {
            return Err(CairnError::KeyStore("key_id must not be empty".into()));
        }
        let mut map = self.store.write().await;
        map.insert(key_id.to_string(), data.to_vec());
        Ok(())
    }

    async fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let map = self.store.read().await;
        map.get(key_id)
            .cloned()
            .ok_or_else(|| CairnError::KeyStore(format!("key not found: {key_id}")))
    }

    async fn delete(&self, key_id: &str) -> Result<()> {
        let mut map = self.store.write().await;
        map.remove(key_id);
        Ok(())
    }

    async fn exists(&self, key_id: &str) -> Result<bool> {
        let map = self.store.read().await;
        Ok(map.contains_key(key_id))
    }
}

// ---------------------------------------------------------------------------
// Filesystem Backend
// ---------------------------------------------------------------------------

/// Argon2id parameters for passphrase key derivation.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
/// Salt length for Argon2.
const SALT_LEN: usize = 16;

/// Encrypted filesystem key store. Data is encrypted at rest using AEAD with a
/// passphrase-derived key (Argon2id). Writes are atomic (temp + rename).
///
/// File layout per key: `[12-byte nonce][ciphertext + 16-byte tag]`
/// A separate `salt` file in `base_dir` stores the Argon2 salt.
pub struct FilesystemKeyStore {
    base_dir: PathBuf,
    encryption_key: [u8; 32],
    cipher: CipherSuite,
}

impl std::fmt::Debug for FilesystemKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilesystemKeyStore")
            .field("base_dir", &self.base_dir)
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl FilesystemKeyStore {
    /// Create or open a filesystem key store.
    ///
    /// If the directory does not exist it will be created. A `salt` file is
    /// written on first creation; subsequent opens read the existing salt.
    pub fn new(base_dir: PathBuf, passphrase: &str, cipher: CipherSuite) -> Result<Self> {
        std::fs::create_dir_all(&base_dir)
            .map_err(|e| CairnError::KeyStore(format!("cannot create key store directory: {e}")))?;

        let salt = Self::load_or_create_salt(&base_dir)?;
        let encryption_key = Self::derive_key(passphrase, &salt)?;

        Ok(Self {
            base_dir,
            encryption_key,
            cipher,
        })
    }

    /// Sanitize a key_id into a safe hex-encoded filename.
    fn key_path(&self, key_id: &str) -> PathBuf {
        let hex_name = hex_encode(key_id.as_bytes());
        self.base_dir.join(hex_name)
    }

    /// Load the Argon2 salt from `base_dir/salt`, or create one if missing.
    fn load_or_create_salt(base_dir: &Path) -> Result<[u8; SALT_LEN]> {
        let salt_path = base_dir.join("salt");
        if salt_path.exists() {
            let bytes = std::fs::read(&salt_path)
                .map_err(|e| CairnError::KeyStore(format!("cannot read salt file: {e}")))?;
            if bytes.len() != SALT_LEN {
                return Err(CairnError::KeyStore(
                    "corrupt salt file: wrong length".into(),
                ));
            }
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&bytes);
            Ok(salt)
        } else {
            let mut salt = [0u8; SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            // Atomic write for the salt file too
            let tmp_path = base_dir.join("salt.tmp");
            std::fs::write(&tmp_path, salt)
                .map_err(|e| CairnError::KeyStore(format!("cannot write salt file: {e}")))?;
            std::fs::rename(&tmp_path, &salt_path)
                .map_err(|e| CairnError::KeyStore(format!("cannot rename salt file: {e}")))?;
            Ok(salt)
        }
    }

    /// Derive a 32-byte encryption key from the passphrase using Argon2id.
    fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
        use argon2::Argon2;

        let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| CairnError::KeyStore(format!("argon2 params error: {e}")))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut output = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut output)
            .map_err(|e| CairnError::KeyStore(format!("argon2 key derivation failed: {e}")))?;
        Ok(output)
    }

    /// Encrypt data and write atomically: temp file -> fsync -> rename.
    fn write_encrypted(&self, key_id: &str, data: &[u8]) -> Result<()> {
        let path = self.key_path(key_id);

        // Generate random nonce
        let mut nonce = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        // Encrypt with key_id as AAD to bind ciphertext to its identifier
        let ciphertext = aead::aead_encrypt(
            self.cipher,
            &self.encryption_key,
            &nonce,
            data,
            key_id.as_bytes(),
        )?;

        // Build file content: [nonce][ciphertext+tag]
        let mut file_content = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        file_content.extend_from_slice(&nonce);
        file_content.extend_from_slice(&ciphertext);

        // Atomic write: temp -> fsync -> rename
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &file_content)
            .map_err(|e| CairnError::KeyStore(format!("cannot write temp file: {e}")))?;

        // fsync the temp file
        let file = std::fs::File::open(&tmp_path)
            .map_err(|e| CairnError::KeyStore(format!("cannot open temp file for fsync: {e}")))?;
        file.sync_all()
            .map_err(|e| CairnError::KeyStore(format!("fsync failed: {e}")))?;

        std::fs::rename(&tmp_path, &path)
            .map_err(|e| CairnError::KeyStore(format!("atomic rename failed: {e}")))?;

        Ok(())
    }

    /// Read and decrypt a key file.
    fn read_encrypted(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.key_path(key_id);
        let file_content = std::fs::read(&path)
            .map_err(|e| CairnError::KeyStore(format!("key not found: {key_id} ({e})")))?;

        if file_content.len() < NONCE_SIZE {
            return Err(CairnError::KeyStore(format!(
                "corrupt key file for {key_id}: too short"
            )));
        }

        let (nonce_bytes, ciphertext) = file_content.split_at(NONCE_SIZE);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(nonce_bytes);

        aead::aead_decrypt(
            self.cipher,
            &self.encryption_key,
            &nonce,
            ciphertext,
            key_id.as_bytes(),
        )
    }
}

#[async_trait]
impl KeyStore for FilesystemKeyStore {
    async fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        if key_id.is_empty() {
            return Err(CairnError::KeyStore("key_id must not be empty".into()));
        }
        self.write_encrypted(key_id, data)
    }

    async fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        self.read_encrypted(key_id)
    }

    async fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.key_path(key_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| CairnError::KeyStore(format!("cannot delete key {key_id}: {e}")))?;
        }
        Ok(())
    }

    async fn exists(&self, key_id: &str) -> Result<bool> {
        Ok(self.key_path(key_id).exists())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex-encode bytes into a lowercase hex string (simple, no extra deps).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        s.push(char::from(b"0123456789abcdef"[(b & 0x0f) as usize]));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- InMemoryKeyStore ----

    #[tokio::test]
    async fn inmemory_store_and_retrieve() {
        let store = InMemoryKeyStore::new();
        store.store("test-key", b"secret data").await.unwrap();
        let data = store.retrieve("test-key").await.unwrap();
        assert_eq!(data, b"secret data");
    }

    #[tokio::test]
    async fn inmemory_retrieve_nonexistent() {
        let store = InMemoryKeyStore::new();
        let result = store.retrieve("missing").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key not found"));
    }

    #[tokio::test]
    async fn inmemory_exists() {
        let store = InMemoryKeyStore::new();
        assert!(!store.exists("key1").await.unwrap());
        store.store("key1", b"data").await.unwrap();
        assert!(store.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn inmemory_delete() {
        let store = InMemoryKeyStore::new();
        store.store("key1", b"data").await.unwrap();
        store.delete("key1").await.unwrap();
        assert!(!store.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn inmemory_overwrite() {
        let store = InMemoryKeyStore::new();
        store.store("key1", b"first").await.unwrap();
        store.store("key1", b"second").await.unwrap();
        let data = store.retrieve("key1").await.unwrap();
        assert_eq!(data, b"second");
    }

    #[tokio::test]
    async fn inmemory_empty_key_id_rejected() {
        let store = InMemoryKeyStore::new();
        let result = store.store("", b"data").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn inmemory_delete_nonexistent_is_ok() {
        let store = InMemoryKeyStore::new();
        store.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn inmemory_data_lost_on_drop() {
        let store = InMemoryKeyStore::new();
        store.store("key", b"data").await.unwrap();
        drop(store);
        // After drop, a new instance has no data
        let store2 = InMemoryKeyStore::new();
        assert!(!store2.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn inmemory_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryKeyStore>();
    }

    // ---- FilesystemKeyStore ----

    fn temp_dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-keystore-test-{}", rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn cleanup(dir: &PathBuf) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn fs_store_and_retrieve_aes() {
        let dir = temp_dir();
        let store =
            FilesystemKeyStore::new(dir.clone(), "passphrase", CipherSuite::Aes256Gcm).unwrap();
        store
            .store("identity-key", b"ed25519 secret")
            .await
            .unwrap();
        let data = store.retrieve("identity-key").await.unwrap();
        assert_eq!(data, b"ed25519 secret");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_store_and_retrieve_chacha() {
        let dir = temp_dir();
        let store =
            FilesystemKeyStore::new(dir.clone(), "passphrase", CipherSuite::ChaCha20Poly1305)
                .unwrap();
        store
            .store("session-key", b"ratchet state bytes")
            .await
            .unwrap();
        let data = store.retrieve("session-key").await.unwrap();
        assert_eq!(data, b"ratchet state bytes");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_retrieve_nonexistent() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        let result = store.retrieve("nonexistent").await;
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_exists() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        assert!(!store.exists("k").await.unwrap());
        store.store("k", b"v").await.unwrap();
        assert!(store.exists("k").await.unwrap());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_delete() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        store.store("k", b"v").await.unwrap();
        store.delete("k").await.unwrap();
        assert!(!store.exists("k").await.unwrap());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_overwrite() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        store.store("k", b"first").await.unwrap();
        store.store("k", b"second").await.unwrap();
        let data = store.retrieve("k").await.unwrap();
        assert_eq!(data, b"second");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_empty_key_id_rejected() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        let result = store.store("", b"data").await;
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_wrong_passphrase_rejects() {
        let dir = temp_dir();
        let store1 =
            FilesystemKeyStore::new(dir.clone(), "correct", CipherSuite::Aes256Gcm).unwrap();
        store1.store("secret", b"important data").await.unwrap();

        // Open with wrong passphrase -- same salt, different derived key
        let store2 = FilesystemKeyStore::new(dir.clone(), "wrong", CipherSuite::Aes256Gcm).unwrap();
        let result = store2.retrieve("secret").await;
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_tampered_file_rejected() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        store.store("key", b"data").await.unwrap();

        // Tamper with the encrypted file
        let path = store.key_path("key");
        let mut contents = std::fs::read(&path).unwrap();
        if let Some(byte) = contents.last_mut() {
            *byte ^= 0xFF;
        }
        std::fs::write(&path, &contents).unwrap();

        let result = store.retrieve("key").await;
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_salt_persists_across_opens() {
        let dir = temp_dir();

        // First open: creates salt and stores data
        {
            let store =
                FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
            store.store("key", b"persistent data").await.unwrap();
        }

        // Second open: same passphrase should read the same salt and decrypt
        {
            let store =
                FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
            let data = store.retrieve("key").await.unwrap();
            assert_eq!(data, b"persistent data");
        }

        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_empty_data_roundtrip() {
        let dir = temp_dir();
        let store = FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::Aes256Gcm).unwrap();
        store.store("empty", b"").await.unwrap();
        let data = store.retrieve("empty").await.unwrap();
        assert!(data.is_empty());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn fs_large_data_roundtrip() {
        let dir = temp_dir();
        let store =
            FilesystemKeyStore::new(dir.clone(), "pass", CipherSuite::ChaCha20Poly1305).unwrap();
        let large = vec![0xAB; 100_000];
        store.store("large", &large).await.unwrap();
        let data = store.retrieve("large").await.unwrap();
        assert_eq!(data, large);
        cleanup(&dir);
    }

    // ---- Helpers ----

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(b"\x00\xff"), "00ff");
        assert_eq!(hex_encode(b"abc"), "616263");
    }
}
