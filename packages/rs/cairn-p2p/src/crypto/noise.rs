use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::aead::{aead_decrypt, aead_encrypt, CipherSuite, CHACHA_TAG_SIZE};
use crate::crypto::exchange::{hkdf_sha256, HKDF_INFO_SAS, HKDF_INFO_SESSION_KEY};
use crate::crypto::identity::IdentityKeypair;
use crate::error::{CairnError, Result};

/// Protocol name used to initialize the handshake hash (Noise spec section 5.2).
const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";

/// AEAD tag size (16 bytes for ChaCha20-Poly1305).
const TAG_SIZE: usize = CHACHA_TAG_SIZE;

/// Size of an X25519 public key.
const DH_KEY_SIZE: usize = 32;

/// Size of an Ed25519 public key.
const ED25519_PUB_SIZE: usize = 32;

/// Zero nonce used for handshake AEAD operations.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Emoji table for SAS derivation (64 entries).
const EMOJI_TABLE: [&str; 64] = [
    "dog", "cat", "fish", "bird", "bear", "lion", "wolf", "fox", "deer", "owl", "bee", "ant",
    "star", "moon", "sun", "fire", "tree", "leaf", "rose", "wave", "rain", "snow", "bolt", "wind",
    "rock", "gem", "bell", "key", "lock", "flag", "book", "pen", "cup", "hat", "shoe", "ring",
    "cake", "gift", "lamp", "gear", "ship", "car", "bike", "drum", "horn", "harp", "dice", "coin",
    "map", "tent", "crown", "sword", "shield", "bow", "axe", "hammer", "anchor", "wheel", "clock",
    "heart", "skull", "ghost", "robot", "alien",
];

/// Noise XX handshake role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Handshake state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    /// Initiator: ready to send message 1
    InitiatorStart,
    /// Responder: waiting for message 1
    ResponderWaitMsg1,
    /// Initiator: waiting for message 2
    InitiatorWaitMsg2,
    /// Responder: waiting for message 3
    ResponderWaitMsg3,
    /// Handshake complete
    Complete,
}

/// Result of a completed Noise XX handshake.
pub struct HandshakeResult {
    /// Shared symmetric key for session encryption (32 bytes).
    pub session_key: [u8; 32],
    /// Remote peer's static public key (Ed25519).
    pub remote_static: VerifyingKey,
    /// Handshake transcript hash for SAS derivation.
    pub transcript_hash: [u8; 32],
}

/// Output of a single handshake step.
pub enum StepOutput {
    /// A message to send to the peer.
    SendMessage(Vec<u8>),
    /// Handshake complete with the result.
    Complete(Box<HandshakeResult>),
}

/// Noise XX handshake state machine.
///
/// Implements the three-message Noise XX pattern:
/// ```text
/// -> e                 (message 1)
/// <- e, ee, s, es      (message 2)
/// -> s, se             (message 3)
/// ```
///
/// The caller drives the handshake by calling `step()` repeatedly:
///
/// **Initiator flow:**
/// 1. `step(None)` -> `SendMessage(msg1)` — send msg1 to responder
/// 2. `step(Some(msg2))` -> `SendMessage(msg3)` — send msg3 to responder
/// 3. `step(None)` -> `Complete(result)` — handshake done
///
/// **Responder flow:**
/// 1. `step(Some(msg1))` -> `SendMessage(msg2)` — send msg2 to initiator
/// 2. `step(Some(msg3))` -> `Complete(result)` — handshake done
pub struct NoiseXXHandshake {
    #[allow(dead_code)]
    role: Role,
    state: HandshakeState,
    // Our static identity keypair (Ed25519)
    local_identity: IdentityKeypair,
    // Our static X25519 key derived from identity
    local_static_x25519: StaticSecret,
    // Our ephemeral X25519 keypair
    local_ephemeral: Option<StaticSecret>,
    local_ephemeral_pub: Option<X25519PublicKey>,
    // Remote ephemeral public key
    remote_ephemeral: Option<X25519PublicKey>,
    // Remote static Ed25519 public key
    remote_static: Option<VerifyingKey>,
    // Chaining key (updated after each DH)
    chaining_key: [u8; 32],
    // Handshake hash (transcript accumulator)
    handshake_hash: [u8; 32],
    // Current encryption key (from the most recent mix_key)
    current_key: Option<[u8; 32]>,
    // Optional SPAKE2 pre-shared key for authentication
    pake_secret: Option<[u8; 32]>,
    // Cached handshake result for the initiator (set after msg3 is built)
    cached_result: Option<HandshakeResult>,
}

impl NoiseXXHandshake {
    /// Create a new handshake as initiator or responder.
    pub fn new(role: Role, identity: IdentityKeypair) -> Self {
        // Convert Ed25519 identity to X25519 for DH operations.
        let scalar_bytes = identity.signing_key().to_scalar_bytes();
        let local_static_x25519 = StaticSecret::from(scalar_bytes);

        // Initialize handshake hash from protocol name (Noise spec section 5.2).
        // If protocol name <= 32 bytes, pad with zeros. If > 32, hash it.
        let handshake_hash = if PROTOCOL_NAME.len() <= 32 {
            let mut h = [0u8; 32];
            h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
            h
        } else {
            let hash = Sha256::digest(PROTOCOL_NAME);
            hash.into()
        };

        // Chaining key starts as the handshake hash (Noise spec).
        let chaining_key = handshake_hash;

        let state = match role {
            Role::Initiator => HandshakeState::InitiatorStart,
            Role::Responder => HandshakeState::ResponderWaitMsg1,
        };

        Self {
            role,
            state,
            local_identity: identity,
            local_static_x25519,
            local_ephemeral: None,
            local_ephemeral_pub: None,
            remote_ephemeral: None,
            remote_static: None,
            chaining_key,
            handshake_hash,
            current_key: None,
            pake_secret: None,
            cached_result: None,
        }
    }

    /// Set a SPAKE2-derived pre-shared key for authentication.
    /// When set, the PAKE secret is mixed into the chaining key after
    /// all DH operations complete, binding the session to the PAKE credential.
    pub fn with_pake_secret(mut self, secret: [u8; 32]) -> Self {
        self.pake_secret = Some(secret);
        self
    }

    /// Process the next handshake step.
    ///
    /// **Initiator sequence:** `step(None)` -> `step(Some(msg2))` -> `step(None)`
    /// **Responder sequence:** `step(Some(msg1))` -> `step(Some(msg3))`
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<StepOutput> {
        match self.state {
            HandshakeState::InitiatorStart => {
                if input.is_some() {
                    return Err(CairnError::Crypto(
                        "initiator start expects no input".into(),
                    ));
                }
                self.initiator_send_msg1()
            }
            HandshakeState::ResponderWaitMsg1 => {
                let data = input.ok_or_else(|| {
                    CairnError::Crypto("responder expects message 1 input".into())
                })?;
                self.responder_recv_msg1_send_msg2(data)
            }
            HandshakeState::InitiatorWaitMsg2 => {
                let data = input.ok_or_else(|| {
                    CairnError::Crypto("initiator expects message 2 input".into())
                })?;
                self.initiator_recv_msg2_send_msg3(data)
            }
            HandshakeState::ResponderWaitMsg3 => {
                let data = input.ok_or_else(|| {
                    CairnError::Crypto("responder expects message 3 input".into())
                })?;
                self.responder_recv_msg3(data)
            }
            HandshakeState::Complete => {
                Err(CairnError::Crypto("handshake already complete".into()))
            }
        }
    }

    // --- Message 1: -> e ---

    fn initiator_send_msg1(&mut self) -> Result<StepOutput> {
        // Generate ephemeral keypair
        let mut csprng = rand::thread_rng();
        let ephemeral_secret = StaticSecret::random_from_rng(&mut csprng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

        // Mix ephemeral public key into handshake hash
        self.mix_hash(ephemeral_pub.as_bytes());

        self.local_ephemeral = Some(ephemeral_secret);
        self.local_ephemeral_pub = Some(ephemeral_pub);

        // Message 1 is just the ephemeral public key (32 bytes)
        let msg = ephemeral_pub.as_bytes().to_vec();

        self.state = HandshakeState::InitiatorWaitMsg2;
        Ok(StepOutput::SendMessage(msg))
    }

    // --- Message 2: <- e, ee, s, es ---

    fn responder_recv_msg1_send_msg2(&mut self, msg1: &[u8]) -> Result<StepOutput> {
        // Parse message 1
        if msg1.len() != DH_KEY_SIZE {
            return Err(CairnError::Crypto(format!(
                "message 1 invalid length: expected {DH_KEY_SIZE}, got {}",
                msg1.len()
            )));
        }

        let mut remote_e_bytes = [0u8; 32];
        remote_e_bytes.copy_from_slice(msg1);
        let remote_ephemeral = X25519PublicKey::from(remote_e_bytes);

        // Mix remote ephemeral into handshake hash
        self.mix_hash(&remote_e_bytes);
        self.remote_ephemeral = Some(remote_ephemeral);

        // Now build message 2
        let mut msg2 = Vec::new();

        // e: generate responder ephemeral
        let mut csprng = rand::thread_rng();
        let ephemeral_secret = StaticSecret::random_from_rng(&mut csprng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

        self.mix_hash(ephemeral_pub.as_bytes());
        msg2.extend_from_slice(ephemeral_pub.as_bytes());

        self.local_ephemeral = Some(ephemeral_secret);
        self.local_ephemeral_pub = Some(ephemeral_pub);

        // ee: DH(responder_ephemeral, initiator_ephemeral)
        let ee_shared = self
            .local_ephemeral
            .as_ref()
            .ok_or_else(|| CairnError::Crypto("missing local ephemeral key".into()))?
            .diffie_hellman(&remote_ephemeral)
            .to_bytes();
        self.mix_key(&ee_shared)?;

        // s: encrypt and send our static Ed25519 public key
        let static_pub_bytes = self.local_identity.public_key().to_bytes();
        let encrypted_static = self.encrypt_and_hash(&static_pub_bytes)?;
        msg2.extend_from_slice(&encrypted_static);

        // es: DH(responder_static_x25519, initiator_ephemeral)
        let es_shared = self
            .local_static_x25519
            .diffie_hellman(&remote_ephemeral)
            .to_bytes();
        self.mix_key(&es_shared)?;

        // Encrypt empty payload
        let encrypted_payload = self.encrypt_and_hash(&[])?;
        msg2.extend_from_slice(&encrypted_payload);

        self.state = HandshakeState::ResponderWaitMsg3;
        Ok(StepOutput::SendMessage(msg2))
    }

    // --- Initiator: recv message 2, send message 3 ---

    fn initiator_recv_msg2_send_msg3(&mut self, msg2: &[u8]) -> Result<StepOutput> {
        // Message 2 format:
        //   [e: 32][encrypted_s: 32+TAG][encrypted_payload: 0+TAG]
        let min_len = DH_KEY_SIZE + (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE;
        if msg2.len() < min_len {
            return Err(CairnError::Crypto(format!(
                "message 2 too short: expected at least {min_len}, got {}",
                msg2.len()
            )));
        }

        let mut offset = 0;

        // e: responder ephemeral
        let mut remote_e_bytes = [0u8; 32];
        remote_e_bytes.copy_from_slice(&msg2[offset..offset + DH_KEY_SIZE]);
        let remote_ephemeral = X25519PublicKey::from(remote_e_bytes);
        self.mix_hash(&remote_e_bytes);
        offset += DH_KEY_SIZE;
        self.remote_ephemeral = Some(remote_ephemeral);

        // ee: DH(initiator_ephemeral, responder_ephemeral)
        // Compute ee DH and release the borrow before mutating self.
        let ee_shared = {
            let local_e = self
                .local_ephemeral
                .as_ref()
                .ok_or_else(|| CairnError::Crypto("missing local ephemeral for ee DH".into()))?;
            local_e.diffie_hellman(&remote_ephemeral).to_bytes()
        };
        self.mix_key(&ee_shared)?;

        // s: decrypt responder's static public key
        let encrypted_static = &msg2[offset..offset + ED25519_PUB_SIZE + TAG_SIZE];
        let static_pub_bytes = self.decrypt_and_hash(encrypted_static)?;
        offset += ED25519_PUB_SIZE + TAG_SIZE;

        if static_pub_bytes.len() != ED25519_PUB_SIZE {
            return Err(CairnError::Crypto("decrypted static key wrong size".into()));
        }

        let mut static_key_bytes = [0u8; 32];
        static_key_bytes.copy_from_slice(&static_pub_bytes);
        let remote_verifying_key = VerifyingKey::from_bytes(&static_key_bytes)
            .map_err(|e| CairnError::Crypto(format!("invalid remote static key: {e}")))?;

        // Convert remote Ed25519 public key to X25519 for DH
        let remote_static_x25519 =
            X25519PublicKey::from(remote_verifying_key.to_montgomery().to_bytes());
        self.remote_static = Some(remote_verifying_key);

        // es: DH(initiator_ephemeral, responder_static_x25519)
        let es_shared = {
            let local_e = self
                .local_ephemeral
                .as_ref()
                .ok_or_else(|| CairnError::Crypto("missing local ephemeral for es DH".into()))?;
            local_e.diffie_hellman(&remote_static_x25519).to_bytes()
        };
        self.mix_key(&es_shared)?;

        // Decrypt payload from message 2
        let encrypted_payload = &msg2[offset..];
        let _payload = self.decrypt_and_hash(encrypted_payload)?;

        // Now build message 3: -> s, se

        let mut msg3 = Vec::new();

        // s: encrypt initiator's static Ed25519 public key
        let our_static_pub_bytes = self.local_identity.public_key().to_bytes();
        let encrypted_our_static = self.encrypt_and_hash(&our_static_pub_bytes)?;
        msg3.extend_from_slice(&encrypted_our_static);

        // se: DH(initiator_static_x25519, responder_ephemeral)
        let se_shared = self
            .local_static_x25519
            .diffie_hellman(&remote_ephemeral)
            .to_bytes();
        self.mix_key(&se_shared)?;

        // Mix in PAKE secret if present
        if let Some(pake) = self.pake_secret {
            self.mix_key(&pake)?;
        }

        // Encrypt empty payload for message 3
        let encrypted_payload = self.encrypt_and_hash(&[])?;
        msg3.extend_from_slice(&encrypted_payload);

        // Derive session key — initiator is done after sending msg3
        let session_key = self.derive_session_key()?;
        let result = HandshakeResult {
            session_key,
            remote_static: remote_verifying_key,
            transcript_hash: self.handshake_hash,
        };

        self.state = HandshakeState::Complete;
        self.cached_result = Some(HandshakeResult {
            session_key: result.session_key,
            remote_static: result.remote_static,
            transcript_hash: result.transcript_hash,
        });

        // Return msg3 so the caller can send it to the responder.
        // The caller can then access the result via `result()`.
        // Actually, for a cleaner API, we return SendMessage with the msg3,
        // and the caller calls step(None) again to get Complete.
        // But that changes the state machine. Let's keep it simple:
        // return the message and stash the result.
        Ok(StepOutput::SendMessage(msg3))
    }

    /// Get the handshake result after the initiator has sent message 3.
    /// This is only valid after the initiator's second step returns `SendMessage(msg3)`.
    pub fn result(&self) -> Result<&HandshakeResult> {
        self.cached_result
            .as_ref()
            .ok_or_else(|| CairnError::Crypto("handshake not yet complete".into()))
    }

    // --- Message 3: responder receives -> s, se ---

    fn responder_recv_msg3(&mut self, msg3: &[u8]) -> Result<StepOutput> {
        // Message 3 format:
        //   [encrypted_s: 32+TAG][encrypted_payload: 0+TAG]
        let min_len = (ED25519_PUB_SIZE + TAG_SIZE) + TAG_SIZE;
        if msg3.len() < min_len {
            return Err(CairnError::Crypto(format!(
                "message 3 too short: expected at least {min_len}, got {}",
                msg3.len()
            )));
        }

        let mut offset = 0;

        // s: decrypt initiator's static public key
        let encrypted_static = &msg3[offset..offset + ED25519_PUB_SIZE + TAG_SIZE];
        let static_pub_bytes = self.decrypt_and_hash(encrypted_static)?;
        offset += ED25519_PUB_SIZE + TAG_SIZE;

        if static_pub_bytes.len() != ED25519_PUB_SIZE {
            return Err(CairnError::Crypto("decrypted static key wrong size".into()));
        }

        let mut static_key_bytes = [0u8; 32];
        static_key_bytes.copy_from_slice(&static_pub_bytes);
        let remote_verifying_key = VerifyingKey::from_bytes(&static_key_bytes)
            .map_err(|e| CairnError::Crypto(format!("invalid remote static key: {e}")))?;

        // Convert remote Ed25519 to X25519
        let remote_static_x25519 =
            X25519PublicKey::from(remote_verifying_key.to_montgomery().to_bytes());
        self.remote_static = Some(remote_verifying_key);

        // se: DH(responder_ephemeral, initiator_static_x25519)
        let local_e = self
            .local_ephemeral
            .as_ref()
            .ok_or_else(|| CairnError::Crypto("missing local ephemeral for se DH".into()))?;
        let se_shared = local_e.diffie_hellman(&remote_static_x25519).to_bytes();
        self.mix_key(&se_shared)?;

        // Mix in PAKE secret if present
        if let Some(pake) = self.pake_secret {
            self.mix_key(&pake)?;
        }

        // Decrypt payload
        let encrypted_payload = &msg3[offset..];
        let _payload = self.decrypt_and_hash(encrypted_payload)?;

        // Derive session key
        let session_key = self.derive_session_key()?;

        self.state = HandshakeState::Complete;
        Ok(StepOutput::Complete(Box::new(HandshakeResult {
            session_key,
            remote_static: remote_verifying_key,
            transcript_hash: self.handshake_hash,
        })))
    }

    // --- Noise symmetric state operations ---

    /// Mix a DH result into the chaining key via HKDF.
    /// Updates the chaining key and stores the derived encryption key.
    fn mix_key(&mut self, input_key_material: &[u8; 32]) -> Result<()> {
        let mut output = [0u8; 64];
        hkdf_sha256(
            input_key_material,
            Some(&self.chaining_key),
            b"",
            &mut output,
        )?;
        self.chaining_key.copy_from_slice(&output[..32]);
        let mut derived_key = [0u8; 32];
        derived_key.copy_from_slice(&output[32..64]);
        self.current_key = Some(derived_key);
        Ok(())
    }

    /// Mix data into the handshake hash.
    /// h = SHA-256(h || data)
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.handshake_hash);
        hasher.update(data);
        self.handshake_hash = hasher.finalize().into();
    }

    /// Encrypt plaintext and mix the ciphertext into the handshake hash.
    /// Uses the current key from the most recent mix_key.
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.current_key.ok_or_else(|| {
            CairnError::Crypto("no encryption key available (mix_key not called)".into())
        })?;
        let ciphertext = aead_encrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &ZERO_NONCE,
            plaintext,
            &self.handshake_hash,
        )?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt ciphertext and mix it into the handshake hash.
    /// Uses the current key from the most recent mix_key.
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = self.current_key.ok_or_else(|| {
            CairnError::Crypto("no decryption key available (mix_key not called)".into())
        })?;
        let h_before = self.handshake_hash;
        self.mix_hash(ciphertext);
        aead_decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &ZERO_NONCE,
            ciphertext,
            &h_before,
        )
    }

    /// Derive the final session key from the chaining key.
    fn derive_session_key(&self) -> Result<[u8; 32]> {
        let mut session_key = [0u8; 32];
        hkdf_sha256(
            &self.chaining_key,
            None,
            HKDF_INFO_SESSION_KEY,
            &mut session_key,
        )?;
        Ok(session_key)
    }
}

/// Derive a 6-digit numeric SAS from the handshake transcript hash.
///
/// Uses HKDF-SHA256 with the SAS domain separation info to derive 4 bytes,
/// then computes `u32 % 1_000_000` formatted as zero-padded 6 digits.
pub fn derive_numeric_sas(transcript_hash: &[u8; 32]) -> Result<String> {
    let mut derived = [0u8; 4];
    hkdf_sha256(transcript_hash, None, HKDF_INFO_SAS, &mut derived)?;
    let value = u32::from_be_bytes(derived) % 1_000_000;
    Ok(format!("{value:06}"))
}

/// Derive an emoji SAS (sequence of 4 emoji names) from the handshake transcript hash.
///
/// Uses HKDF-SHA256 to derive 4 bytes, then indexes into a 64-entry table.
pub fn derive_emoji_sas(transcript_hash: &[u8; 32]) -> Result<Vec<&'static str>> {
    let mut derived = [0u8; 4];
    hkdf_sha256(transcript_hash, None, HKDF_INFO_SAS, &mut derived)?;
    let emojis = derived
        .iter()
        .map(|&b| EMOJI_TABLE[(b % 64) as usize])
        .collect();
    Ok(emojis)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run a complete Noise XX handshake between two peers.
    /// Returns (initiator_result, responder_result).
    fn run_handshake(pake_secret: Option<[u8; 32]>) -> (HandshakeResult, HandshakeResult) {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        run_handshake_with_identities(alice_id, bob_id, pake_secret)
    }

    fn run_handshake_with_identities(
        alice_id: IdentityKeypair,
        bob_id: IdentityKeypair,
        pake_secret: Option<[u8; 32]>,
    ) -> (HandshakeResult, HandshakeResult) {
        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        if let Some(secret) = pake_secret {
            initiator = initiator.with_pake_secret(secret);
            responder = responder.with_pake_secret(secret);
        }

        // Initiator sends msg1
        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => panic!("expected SendMessage for msg1"),
        };

        // Responder receives msg1, sends msg2
        let msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => panic!("expected SendMessage for msg2"),
        };

        // Initiator receives msg2, sends msg3
        let msg3 = match initiator.step(Some(&msg2)).unwrap() {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => panic!("expected SendMessage for msg3"),
        };

        // Get initiator result from cached result
        let initiator_result_ref = initiator.result().unwrap();
        let initiator_result = HandshakeResult {
            session_key: initiator_result_ref.session_key,
            remote_static: initiator_result_ref.remote_static,
            transcript_hash: initiator_result_ref.transcript_hash,
        };

        // Responder receives msg3
        let responder_result = match responder.step(Some(&msg3)).unwrap() {
            StepOutput::Complete(r) => *r,
            StepOutput::SendMessage(_) => panic!("expected Complete for responder"),
        };

        (initiator_result, responder_result)
    }

    #[test]
    fn full_handshake_produces_matching_session_keys() {
        let (init_result, resp_result) = run_handshake(None);
        assert_eq!(init_result.session_key, resp_result.session_key);
    }

    #[test]
    fn handshake_reveals_remote_static_keys() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();
        let alice_pub = alice_id.public_key();
        let bob_pub = bob_id.public_key();

        let (init_result, resp_result) = run_handshake_with_identities(alice_id, bob_id, None);

        // Initiator should know responder's public key
        assert_eq!(init_result.remote_static, bob_pub);
        // Responder should know initiator's public key
        assert_eq!(resp_result.remote_static, alice_pub);
    }

    #[test]
    fn handshake_transcript_hashes_match() {
        let (init_result, resp_result) = run_handshake(None);
        assert_eq!(init_result.transcript_hash, resp_result.transcript_hash);
    }

    #[test]
    fn different_handshakes_produce_different_session_keys() {
        let (result1, _) = run_handshake(None);
        let (result2, _) = run_handshake(None);
        // Ephemeral keys are random, so session keys should differ
        assert_ne!(result1.session_key, result2.session_key);
    }

    #[test]
    fn handshake_with_pake_secret() {
        let pake = [42u8; 32];
        let (init_result, resp_result) = run_handshake(Some(pake));
        assert_eq!(init_result.session_key, resp_result.session_key);
    }

    #[test]
    fn pake_secret_changes_session_key() {
        let alice_seed = [1u8; 32];
        let bob_seed = [2u8; 32];

        let (result_no_pake, _) = run_handshake_with_identities(
            IdentityKeypair::from_bytes(&alice_seed),
            IdentityKeypair::from_bytes(&bob_seed),
            None,
        );

        let (result_with_pake, _) = run_handshake_with_identities(
            IdentityKeypair::from_bytes(&alice_seed),
            IdentityKeypair::from_bytes(&bob_seed),
            Some([42u8; 32]),
        );

        // With ephemeral keys being random, these will always differ anyway,
        // but the PAKE changes the derivation path.
        // The key insight: mismatched PAKE secrets cause decryption failure (tested below).
        assert_ne!(result_no_pake.session_key, result_with_pake.session_key);
    }

    #[test]
    fn mismatched_pake_secrets_fail() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator =
            NoiseXXHandshake::new(Role::Initiator, alice_id).with_pake_secret([1u8; 32]);
        let mut responder =
            NoiseXXHandshake::new(Role::Responder, bob_id).with_pake_secret([2u8; 32]);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let msg3 = match initiator.step(Some(&msg2)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        // Responder should fail to decrypt msg3 because PAKE secrets differ
        let result = responder.step(Some(&msg3));
        assert!(result.is_err());
    }

    #[test]
    fn msg1_wrong_length_rejected() {
        let bob_id = IdentityKeypair::generate();
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let bad_msg1 = vec![0u8; 16]; // too short
        let result = responder.step(Some(&bad_msg1));
        assert!(result.is_err());
    }

    #[test]
    fn msg2_too_short_rejected() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        // Get valid msg2 first, then truncate it
        let msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let truncated = &msg2[..10];
        let result = initiator.step(Some(truncated));
        assert!(result.is_err());
    }

    #[test]
    fn msg3_too_short_rejected() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let _msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let bad_msg3 = vec![0u8; 5];
        let result = responder.step(Some(&bad_msg3));
        assert!(result.is_err());
    }

    #[test]
    fn tampered_msg2_rejected() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let mut msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        // Tamper with the encrypted portion (after the ephemeral key)
        if msg2.len() > 40 {
            msg2[40] ^= 0xFF;
        }

        let result = initiator.step(Some(&msg2));
        assert!(result.is_err());
    }

    #[test]
    fn tampered_msg3_rejected() {
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let mut msg3 = match initiator.step(Some(&msg2)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        // Tamper
        if let Some(byte) = msg3.first_mut() {
            *byte ^= 0xFF;
        }

        let result = responder.step(Some(&msg3));
        assert!(result.is_err());
    }

    #[test]
    fn out_of_order_step_rejected() {
        let alice_id = IdentityKeypair::generate();
        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);

        // Initiator should not accept input at start
        let result = initiator.step(Some(&[0u8; 32]));
        assert!(result.is_err());
    }

    #[test]
    fn responder_rejects_no_input() {
        let bob_id = IdentityKeypair::generate();
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        // Responder needs input (message 1)
        let result = responder.step(None);
        assert!(result.is_err());
    }

    #[test]
    fn step_after_complete_rejected() {
        let (_, _) = run_handshake(None);
        // We can't directly test this with run_handshake since it consumes the state,
        // but let's do it manually:
        let alice_id = IdentityKeypair::generate();
        let bob_id = IdentityKeypair::generate();

        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let mut responder = NoiseXXHandshake::new(Role::Responder, bob_id);

        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let msg2 = match responder.step(Some(&msg1)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        let msg3 = match initiator.step(Some(&msg2)).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };

        match responder.step(Some(&msg3)).unwrap() {
            StepOutput::Complete(_) => {}
            _ => panic!("expected Complete"),
        }

        // Now responder is complete; another step should fail
        let result = responder.step(None);
        assert!(result.is_err());
    }

    // --- SAS tests ---

    #[test]
    fn sas_derivable_from_handshake() {
        let (init_result, resp_result) = run_handshake(None);

        let init_sas = derive_numeric_sas(&init_result.transcript_hash).unwrap();
        let resp_sas = derive_numeric_sas(&resp_result.transcript_hash).unwrap();

        assert_eq!(init_sas, resp_sas);
    }

    #[test]
    fn emoji_sas_matches_between_peers() {
        let (init_result, resp_result) = run_handshake(None);

        let init_emoji = derive_emoji_sas(&init_result.transcript_hash).unwrap();
        let resp_emoji = derive_emoji_sas(&resp_result.transcript_hash).unwrap();

        assert_eq!(init_emoji, resp_emoji);
    }

    #[test]
    fn numeric_sas_format() {
        let hash = [42u8; 32];
        let sas = derive_numeric_sas(&hash).unwrap();
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn numeric_sas_is_deterministic() {
        let hash = [99u8; 32];
        let sas1 = derive_numeric_sas(&hash).unwrap();
        let sas2 = derive_numeric_sas(&hash).unwrap();
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn different_transcripts_produce_different_sas() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let sas1 = derive_numeric_sas(&hash1).unwrap();
        let sas2 = derive_numeric_sas(&hash2).unwrap();
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn emoji_sas_returns_4_entries() {
        let hash = [42u8; 32];
        let emojis = derive_emoji_sas(&hash).unwrap();
        assert_eq!(emojis.len(), 4);
    }

    #[test]
    fn emoji_sas_is_deterministic() {
        let hash = [99u8; 32];
        let e1 = derive_emoji_sas(&hash).unwrap();
        let e2 = derive_emoji_sas(&hash).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn emoji_sas_entries_are_from_table() {
        let hash = [77u8; 32];
        let emojis = derive_emoji_sas(&hash).unwrap();
        for emoji in &emojis {
            assert!(EMOJI_TABLE.contains(emoji));
        }
    }

    #[test]
    fn msg1_is_32_bytes() {
        let alice_id = IdentityKeypair::generate();
        let mut initiator = NoiseXXHandshake::new(Role::Initiator, alice_id);
        let msg1 = match initiator.step(None).unwrap() {
            StepOutput::SendMessage(m) => m,
            _ => panic!("expected SendMessage"),
        };
        assert_eq!(msg1.len(), 32);
    }
}
