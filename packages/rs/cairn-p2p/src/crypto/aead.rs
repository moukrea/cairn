use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{CairnError, Result};

/// Nonce size for both ciphers: 12 bytes.
pub const NONCE_SIZE: usize = 12;
/// Key size for both ciphers: 32 bytes.
pub const KEY_SIZE: usize = 32;
/// AES-256-GCM tag size: 16 bytes.
pub const AES_GCM_TAG_SIZE: usize = 16;
/// ChaCha20-Poly1305 tag size: 16 bytes.
pub const CHACHA_TAG_SIZE: usize = 16;

/// Supported AEAD cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Encrypt plaintext with associated data using the specified cipher.
///
/// - `cipher`: which AEAD to use
/// - `key`: 32-byte encryption key
/// - `nonce`: 12-byte nonce (must be unique per key)
/// - `plaintext`: data to encrypt
/// - `aad`: associated data to authenticate but not encrypt
///
/// Returns ciphertext with appended authentication tag.
pub fn aead_encrypt(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    match cipher {
        CipherSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new(key.into());
            cipher
                .encrypt(nonce.into(), payload)
                .map_err(|e| CairnError::Crypto(e.to_string()))
        }
        CipherSuite::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(key.into());
            cipher
                .encrypt(nonce.into(), payload)
                .map_err(|e| CairnError::Crypto(e.to_string()))
        }
    }
}

/// Decrypt ciphertext with associated data using the specified cipher.
///
/// Returns plaintext on success, or error if authentication fails.
pub fn aead_decrypt(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match cipher {
        CipherSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new(key.into());
            cipher
                .decrypt(nonce.into(), payload)
                .map_err(|e| CairnError::Crypto(e.to_string()))
        }
        CipherSuite::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(key.into());
            cipher
                .decrypt(nonce.into(), payload)
                .map_err(|e| CairnError::Crypto(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        key[31] = 0xFF;
        key
    }

    fn test_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0] = 0x01;
        nonce
    }

    #[test]
    fn aes_gcm_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"hello cairn aes-gcm";
        let aad = b"associated-data";

        let ciphertext =
            aead_encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();
        let decrypted =
            aead_decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"hello cairn chacha20";
        let aad = b"associated-data";

        let ciphertext =
            aead_encrypt(CipherSuite::ChaCha20Poly1305, &key, &nonce, plaintext, aad).unwrap();
        let decrypted = aead_decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            &ciphertext,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"sensitive data";
        let aad = b"aad";

        let mut ciphertext =
            aead_encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = aead_decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn chacha20_tampered_ciphertext_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"sensitive data";
        let aad = b"aad";

        let mut ciphertext =
            aead_encrypt(CipherSuite::ChaCha20Poly1305, &key, &nonce, plaintext, aad).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = aead_decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            &ciphertext,
            aad,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aes_gcm_wrong_aad_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"data";

        let ciphertext = aead_encrypt(
            CipherSuite::Aes256Gcm,
            &key,
            &nonce,
            plaintext,
            b"correct-aad",
        )
        .unwrap();
        let result = aead_decrypt(
            CipherSuite::Aes256Gcm,
            &key,
            &nonce,
            &ciphertext,
            b"wrong-aad",
        );
        assert!(result.is_err());
    }

    #[test]
    fn chacha20_wrong_aad_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"data";

        let ciphertext = aead_encrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            plaintext,
            b"correct-aad",
        )
        .unwrap();
        let result = aead_decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            &ciphertext,
            b"wrong-aad",
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"data";
        let aad = b"aad";

        let ciphertext =
            aead_encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        let mut wrong_key = key;
        wrong_key[0] ^= 0x01;
        let result = aead_decrypt(CipherSuite::Aes256Gcm, &wrong_key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"data";
        let aad = b"aad";

        let ciphertext =
            aead_encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0x01;
        let result = aead_decrypt(CipherSuite::Aes256Gcm, &key, &wrong_nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_includes_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"hello";
        let aad = b"";

        let ct_aes = aead_encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ct_aes.len(), plaintext.len() + AES_GCM_TAG_SIZE);

        let ct_chacha =
            aead_encrypt(CipherSuite::ChaCha20Poly1305, &key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ct_chacha.len(), plaintext.len() + CHACHA_TAG_SIZE);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"";
        let aad = b"some-context";

        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let ciphertext = aead_encrypt(suite, &key, &nonce, plaintext, aad).unwrap();
            let decrypted = aead_decrypt(suite, &key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn empty_aad_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"data with no aad";
        let aad = b"";

        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let ciphertext = aead_encrypt(suite, &key, &nonce, plaintext, aad).unwrap();
            let decrypted = aead_decrypt(suite, &key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }
}
