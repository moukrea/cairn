use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead::{self, CipherSuite};
use crate::crypto::exchange::{self, X25519Keypair};
use crate::error::{CairnError, Result};

/// Domain separation constants for the Double Ratchet KDF chains.
const HKDF_INFO_ROOT_CHAIN: &[u8] = b"cairn-root-chain-v1";
const HKDF_INFO_CHAIN_ADVANCE: &[u8] = b"cairn-chain-advance-v1";
const HKDF_INFO_MESSAGE_ENCRYPT: &[u8] = b"cairn-msg-encrypt-v1";

/// Configuration for the Double Ratchet.
#[derive(Debug, Clone)]
pub struct RatchetConfig {
    /// Maximum number of skipped message keys to cache.
    pub max_skip: usize,
    /// AEAD cipher suite to use for message encryption.
    pub cipher: CipherSuite,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_skip: 100,
            cipher: CipherSuite::Aes256Gcm,
        }
    }
}

/// Serializable form of an X25519 keypair (secret + public).
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
struct X25519KeypairSerializable {
    secret: [u8; 32],
    public: [u8; 32],
}

impl X25519KeypairSerializable {
    fn generate() -> Self {
        let kp = X25519Keypair::generate();
        Self {
            secret: kp.secret_bytes(),
            public: *kp.public_key().as_bytes(),
        }
    }

    fn to_keypair(&self) -> X25519Keypair {
        X25519Keypair::from_bytes(&self.secret)
    }
}

/// The full Double Ratchet session state.
#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetState {
    /// Our current DH ratchet keypair (X25519).
    dh_self: X25519KeypairSerializable,
    /// The peer's current DH public key.
    dh_remote: Option<[u8; 32]>,
    /// Root key (32 bytes).
    #[serde(with = "zeroize_bytes")]
    root_key: [u8; 32],
    /// Sending chain key.
    chain_key_send: Option<[u8; 32]>,
    /// Receiving chain key.
    chain_key_recv: Option<[u8; 32]>,
    /// Sending message number (counter).
    msg_num_send: u32,
    /// Receiving message number (counter).
    msg_num_recv: u32,
    /// Previous sending chain length (for header).
    prev_chain_len: u32,
    /// Skipped message keys: (ratchet_public_key, message_number) -> message_key.
    skipped_keys: HashMap<SkippedKeyId, [u8; 32]>,
}

/// Key for the skipped message keys map: (dh_public_key, message_number).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
struct SkippedKeyId {
    dh_public: [u8; 32],
    msg_num: u32,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut k) = self.chain_key_send {
            k.zeroize();
        }
        if let Some(ref mut k) = self.chain_key_recv {
            k.zeroize();
        }
        for v in self.skipped_keys.values_mut() {
            v.zeroize();
        }
    }
}

/// Helper module for serde of zeroizable byte arrays.
mod zeroize_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        val.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        <[u8; 32]>::deserialize(de)
    }
}

/// Header sent alongside each Double Ratchet encrypted message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key.
    pub dh_public: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
    /// Message number in the current sending chain.
    pub msg_num: u32,
}

/// The Signal Double Ratchet session.
///
/// Combines DH ratcheting (X25519), root chain KDF, and symmetric chain
/// KDF to provide forward secrecy and break-in recovery for each message.
pub struct DoubleRatchet {
    state: RatchetState,
    config: RatchetConfig,
}

impl DoubleRatchet {
    /// Initialize as the initiator (Alice) after a shared secret has been
    /// established (e.g., from Noise XX handshake).
    ///
    /// - `shared_secret`: 32-byte shared secret from key agreement
    /// - `remote_public`: Bob's initial DH ratchet public key
    pub fn init_initiator(
        shared_secret: [u8; 32],
        remote_public: [u8; 32],
        config: RatchetConfig,
    ) -> Result<Self> {
        let dh_self = X25519KeypairSerializable::generate();

        // Perform initial DH ratchet step
        let kp = dh_self.to_keypair();
        let remote_pk = x25519_dalek::PublicKey::from(remote_public);
        let dh_output = kp.diffie_hellman(&remote_pk);

        let (root_key, chain_key_send) = kdf_rk(&shared_secret, &dh_output)?;

        let state = RatchetState {
            dh_self,
            dh_remote: Some(remote_public),
            root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            msg_num_send: 0,
            msg_num_recv: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        };

        Ok(Self { state, config })
    }

    /// Initialize as the responder (Bob) after a shared secret has been
    /// established.
    ///
    /// - `shared_secret`: 32-byte shared secret from key agreement
    /// - `dh_keypair`: Bob's initial DH ratchet keypair
    pub fn init_responder(
        shared_secret: [u8; 32],
        dh_keypair: X25519Keypair,
        config: RatchetConfig,
    ) -> Result<Self> {
        let dh_self = X25519KeypairSerializable {
            secret: dh_keypair.secret_bytes(),
            public: *dh_keypair.public_key().as_bytes(),
        };

        let state = RatchetState {
            dh_self,
            dh_remote: None,
            root_key: shared_secret,
            chain_key_send: None,
            chain_key_recv: None,
            msg_num_send: 0,
            msg_num_recv: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        };

        Ok(Self { state, config })
    }

    /// Encrypt a message. Returns (header, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
        let chain_key = self
            .state
            .chain_key_send
            .ok_or_else(|| CairnError::Crypto("no sending chain key established".into()))?;

        let (new_chain_key, message_key) = kdf_ck(&chain_key)?;
        self.state.chain_key_send = Some(new_chain_key);

        let header = RatchetHeader {
            dh_public: self.state.dh_self.public,
            prev_chain_len: self.state.prev_chain_len,
            msg_num: self.state.msg_num_send,
        };

        self.state.msg_num_send += 1;

        // Derive a nonce from the message key and message number.
        let nonce = derive_nonce(&message_key, header.msg_num);

        // Use the header as associated data for AEAD.
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| CairnError::Crypto(format!("header serialization: {e}")))?;

        let ciphertext = aead::aead_encrypt(
            self.config.cipher,
            &message_key,
            &nonce,
            plaintext,
            &header_bytes,
        )?;

        Ok((header, ciphertext))
    }

    /// Decrypt a message given the header and ciphertext.
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Try skipped keys first.
        let skipped_id = SkippedKeyId {
            dh_public: header.dh_public,
            msg_num: header.msg_num,
        };
        if let Some(mk) = self.state.skipped_keys.remove(&skipped_id) {
            return decrypt_with_key(self.config.cipher, &mk, header, ciphertext);
        }

        // Check if peer's DH key changed (DH ratchet step needed).
        let need_dh_ratchet = match self.state.dh_remote {
            Some(remote) => remote != header.dh_public,
            None => true,
        };

        if need_dh_ratchet {
            // Skip remaining messages in the current receiving chain.
            self.skip_message_keys(header.prev_chain_len)?;
            // Perform DH ratchet step.
            self.dh_ratchet(&header.dh_public)?;
        }

        // Skip ahead in the current receiving chain if needed.
        self.skip_message_keys(header.msg_num)?;

        // Derive the message key from the receiving chain.
        let chain_key = self
            .state
            .chain_key_recv
            .ok_or_else(|| CairnError::Crypto("no receiving chain key established".into()))?;
        let (new_chain_key, message_key) = kdf_ck(&chain_key)?;
        self.state.chain_key_recv = Some(new_chain_key);
        self.state.msg_num_recv += 1;

        decrypt_with_key(self.config.cipher, &message_key, header, ciphertext)
    }

    /// Export the ratchet state for persistence.
    pub fn export_state(&self) -> Vec<u8> {
        serde_json::to_vec(&self.state).expect("ratchet state serialization should not fail")
    }

    /// Import ratchet state from persisted bytes.
    pub fn import_state(data: &[u8], config: RatchetConfig) -> Result<Self> {
        let state: RatchetState = serde_json::from_slice(data)
            .map_err(|e| CairnError::Crypto(format!("ratchet state deserialization: {e}")))?;
        Ok(Self { state, config })
    }

    /// Skip message keys up to (but not including) the given message number
    /// in the current receiving chain, caching them for out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let chain_key = match self.state.chain_key_recv {
            Some(ck) => ck,
            None => return Ok(()),
        };

        let to_skip = until.saturating_sub(self.state.msg_num_recv) as usize;
        if to_skip > self.config.max_skip {
            return Err(CairnError::Crypto("max skip threshold exceeded".into()));
        }

        let mut ck = chain_key;
        for _ in self.state.msg_num_recv..until {
            let (new_ck, mk) = kdf_ck(&ck)?;
            let dh_remote = self
                .state
                .dh_remote
                .ok_or_else(|| CairnError::Crypto("no remote DH key for skipping".into()))?;
            let id = SkippedKeyId {
                dh_public: dh_remote,
                msg_num: self.state.msg_num_recv,
            };
            self.state.skipped_keys.insert(id, mk);
            ck = new_ck;
            self.state.msg_num_recv += 1;
        }
        self.state.chain_key_recv = Some(ck);
        Ok(())
    }

    /// Perform a DH ratchet step when the peer's public key changes.
    fn dh_ratchet(&mut self, new_remote_public: &[u8; 32]) -> Result<()> {
        self.state.prev_chain_len = self.state.msg_num_send;
        self.state.msg_num_send = 0;
        self.state.msg_num_recv = 0;
        self.state.dh_remote = Some(*new_remote_public);

        // Derive receiving chain key from current DH keypair + new remote key.
        let kp = self.state.dh_self.to_keypair();
        let remote_pk = x25519_dalek::PublicKey::from(*new_remote_public);
        let dh_output = kp.diffie_hellman(&remote_pk);
        let (root_key, chain_key_recv) = kdf_rk(&self.state.root_key, &dh_output)?;
        self.state.root_key = root_key;
        self.state.chain_key_recv = Some(chain_key_recv);

        // Generate new DH keypair and derive sending chain key.
        self.state.dh_self = X25519KeypairSerializable::generate();
        let new_kp = self.state.dh_self.to_keypair();
        let dh_output2 = new_kp.diffie_hellman(&remote_pk);
        let (root_key2, chain_key_send) = kdf_rk(&self.state.root_key, &dh_output2)?;
        self.state.root_key = root_key2;
        self.state.chain_key_send = Some(chain_key_send);

        Ok(())
    }
}

/// Derive new root key and chain key from DH output.
/// root_key, dh_output -> (new_root_key, new_chain_key)
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut output = [0u8; 64];
    exchange::hkdf_sha256(dh_output, Some(root_key), HKDF_INFO_ROOT_CHAIN, &mut output)?;
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&output[..32]);
    ck.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok((rk, ck))
}

/// Derive message key from chain key and advance the chain.
/// chain_key -> (new_chain_key, message_key)
fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    exchange::hkdf_sha256(chain_key, None, HKDF_INFO_CHAIN_ADVANCE, &mut new_ck)?;
    exchange::hkdf_sha256(chain_key, None, HKDF_INFO_MESSAGE_ENCRYPT, &mut mk)?;
    Ok((new_ck, mk))
}

/// Derive a 12-byte nonce from a message key and message number.
fn derive_nonce(message_key: &[u8; 32], msg_num: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // Use first 8 bytes from message key, last 4 from message number.
    nonce[..8].copy_from_slice(&message_key[..8]);
    nonce[8..].copy_from_slice(&msg_num.to_be_bytes());
    nonce
}

/// Decrypt ciphertext with a specific message key.
fn decrypt_with_key(
    cipher: CipherSuite,
    message_key: &[u8; 32],
    header: &RatchetHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = derive_nonce(message_key, header.msg_num);
    let header_bytes = serde_json::to_vec(header)
        .map_err(|e| CairnError::Crypto(format!("header serialization: {e}")))?;
    aead::aead_decrypt(cipher, message_key, &nonce, ciphertext, &header_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: set up an Alice-Bob ratchet pair.
    fn setup_pair() -> (DoubleRatchet, DoubleRatchet) {
        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let alice =
            DoubleRatchet::init_initiator(shared_secret, bob_public, RatchetConfig::default())
                .unwrap();

        let bob =
            DoubleRatchet::init_responder(shared_secret, bob_kp, RatchetConfig::default()).unwrap();

        (alice, bob)
    }

    #[test]
    fn alice_sends_bob_receives() {
        let (mut alice, mut bob) = setup_pair();

        let plaintext = b"hello bob";
        let (header, ciphertext) = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multiple_messages_one_direction() {
        let (mut alice, mut bob) = setup_pair();

        for i in 0..10u8 {
            let msg = format!("message {i}");
            let (header, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&header, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn bidirectional_messages() {
        let (mut alice, mut bob) = setup_pair();

        // Alice -> Bob
        let (h1, ct1) = alice.encrypt(b"hello bob").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"hello bob");

        // Bob -> Alice
        let (h2, ct2) = bob.encrypt(b"hello alice").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"hello alice");

        // Alice -> Bob again (second ratchet step)
        let (h3, ct3) = alice.encrypt(b"how are you?").unwrap();
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"how are you?");
    }

    #[test]
    fn out_of_order_messages() {
        let (mut alice, mut bob) = setup_pair();

        let (h1, ct1) = alice.encrypt(b"msg 0").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg 1").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg 2").unwrap();

        // Deliver out of order: 2, 0, 1
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"msg 2");

        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"msg 0");

        let pt2 = bob.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"msg 1");
    }

    #[test]
    fn max_skip_threshold_respected() {
        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let config = RatchetConfig {
            max_skip: 2,
            cipher: CipherSuite::Aes256Gcm,
        };

        let mut alice =
            DoubleRatchet::init_initiator(shared_secret, bob_public, config.clone()).unwrap();

        let mut bob = DoubleRatchet::init_responder(shared_secret, bob_kp, config).unwrap();

        // Send 4 messages, only try to decrypt the last one.
        let _ = alice.encrypt(b"skip 0").unwrap();
        let _ = alice.encrypt(b"skip 1").unwrap();
        let _ = alice.encrypt(b"skip 2").unwrap();
        let (h4, ct4) = alice.encrypt(b"msg 3").unwrap();

        // Should fail: need to skip 3 keys but max_skip is 2.
        let result = bob.decrypt(&h4, &ct4);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("max skip threshold exceeded"));
    }

    #[test]
    fn state_export_import_roundtrip() {
        let (mut alice, mut bob) = setup_pair();

        // Exchange some messages to advance the ratchet state.
        let (h1, ct1) = alice.encrypt(b"before persist").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"before persist");

        // Export and reimport Alice's state.
        let exported = alice.export_state();
        let mut alice2 = DoubleRatchet::import_state(&exported, RatchetConfig::default()).unwrap();

        // Alice2 should be able to continue sending.
        let (h2, ct2) = alice2.encrypt(b"after persist").unwrap();
        let pt2 = bob.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"after persist");
    }

    #[test]
    fn multiple_ratchet_turns() {
        let (mut alice, mut bob) = setup_pair();

        // Multiple turn changes: A->B, B->A, A->B, B->A
        for round in 0..5 {
            let msg_ab = format!("alice round {round}");
            let (h, ct) = alice.encrypt(msg_ab.as_bytes()).unwrap();
            let pt = bob.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg_ab.as_bytes());

            let msg_ba = format!("bob round {round}");
            let (h, ct) = bob.encrypt(msg_ba.as_bytes()).unwrap();
            let pt = alice.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg_ba.as_bytes());
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut alice, mut bob) = setup_pair();

        let (header, mut ciphertext) = alice.encrypt(b"tamper test").unwrap();
        // Flip a bit in the ciphertext.
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let result = bob.decrypt(&header, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn chacha20_cipher_suite() {
        let shared_secret = [0x42u8; 32];
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();

        let config = RatchetConfig {
            max_skip: 100,
            cipher: CipherSuite::ChaCha20Poly1305,
        };

        let mut alice =
            DoubleRatchet::init_initiator(shared_secret, bob_public, config.clone()).unwrap();

        let mut bob = DoubleRatchet::init_responder(shared_secret, bob_kp, config).unwrap();

        let (h, ct) = alice.encrypt(b"chacha20 test").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"chacha20 test");
    }

    #[test]
    fn empty_plaintext() {
        let (mut alice, mut bob) = setup_pair();

        let (h, ct) = alice.encrypt(b"").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn message_numbers_increment() {
        let (mut alice, _bob) = setup_pair();

        let (h1, _) = alice.encrypt(b"msg0").unwrap();
        let (h2, _) = alice.encrypt(b"msg1").unwrap();
        let (h3, _) = alice.encrypt(b"msg2").unwrap();

        assert_eq!(h1.msg_num, 0);
        assert_eq!(h2.msg_num, 1);
        assert_eq!(h3.msg_num, 2);
    }

    #[test]
    fn dh_public_key_changes_on_ratchet() {
        let (mut alice, mut bob) = setup_pair();

        // Alice sends (her DH key is established at init)
        let (h1, ct1) = alice.encrypt(b"from alice").unwrap();
        let alice_pk_1 = h1.dh_public;
        bob.decrypt(&h1, &ct1).unwrap();

        // Bob replies -> Alice will DH ratchet
        let (h2, ct2) = bob.encrypt(b"from bob").unwrap();
        alice.decrypt(&h2, &ct2).unwrap();

        // Alice sends again -> should have a new DH key
        let (h3, _ct3) = alice.encrypt(b"from alice again").unwrap();
        let alice_pk_2 = h3.dh_public;

        assert_ne!(
            alice_pk_1, alice_pk_2,
            "DH public key should change after ratchet step"
        );
    }

    #[test]
    fn import_state_invalid_data() {
        let result = DoubleRatchet::import_state(b"not valid json", RatchetConfig::default());
        assert!(result.is_err());
    }
}
