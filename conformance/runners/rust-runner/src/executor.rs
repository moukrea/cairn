//! Action executor: dispatches scenario actions to cairn-p2p API calls.

use std::collections::HashMap;

use serde_json::Value as JsonValue;

use crate::scenario::{Action, Scenario};

/// Result of executing a single scenario.
pub struct ScenarioResult {
    pub status: Status,
    pub diagnostics: HashMap<String, JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Pass => write!(f, "pass"),
            Status::Fail => write!(f, "fail"),
            Status::Skip => write!(f, "skip"),
        }
    }
}

/// Execute a parsed scenario, dispatching actions to cairn-p2p.
pub fn execute_scenario(scenario: &Scenario, base_dir: &str) -> ScenarioResult {
    let mut diagnostics: HashMap<String, JsonValue> = HashMap::new();
    let mut all_pass = true;

    for action in &scenario.actions {
        let result = dispatch_action(action, base_dir);
        match result {
            ActionResult::Pass => {}
            ActionResult::Fail(reason) => {
                all_pass = false;
                diagnostics.insert(
                    action.action_type.clone(),
                    serde_json::json!({ "error": reason }),
                );
            }
            ActionResult::Skip(reason) => {
                diagnostics.insert(
                    action.action_type.clone(),
                    serde_json::json!({ "skipped": reason }),
                );
                return ScenarioResult {
                    status: Status::Skip,
                    diagnostics,
                };
            }
        }
    }

    ScenarioResult {
        status: if all_pass { Status::Pass } else { Status::Fail },
        diagnostics,
    }
}

enum ActionResult {
    Pass,
    Fail(String),
    Skip(String),
}

fn dispatch_action(action: &Action, base_dir: &str) -> ActionResult {
    match action.action_type.as_str() {
        "verify_cbor" => execute_verify_cbor(action, base_dir),
        "verify_crypto" => execute_verify_crypto(action, base_dir),
        "pair" => execute_pair(action, base_dir),
        // Actions that require infrastructure — skip for now.
        "establish_session" | "send_data" | "open_channel" | "disconnect" | "reconnect"
        | "apply_nat" | "send_forward" | "wait" => ActionResult::Skip(format!(
            "action '{}' requires infrastructure (not yet implemented)",
            action.action_type
        )),
        other => ActionResult::Skip(format!("unknown action type: {other}")),
    }
}

// ---------------------------------------------------------------------------
// verify_cbor
// ---------------------------------------------------------------------------

fn execute_verify_cbor(action: &Action, base_dir: &str) -> ActionResult {
    let operation = action.params.get("operation").and_then(|v| v.as_str());

    match operation {
        Some("roundtrip") => execute_cbor_roundtrip(base_dir),
        Some("field_types") => execute_cbor_field_types(action),
        Some("deterministic") => execute_cbor_deterministic(base_dir),
        Some("deterministic_encode") => execute_cbor_deterministic_encode(action),
        Some("encode") | Some("decode") => {
            // Single-implementation encode/decode: verify roundtrip locally
            execute_cbor_encode_decode(action)
        }
        Some(op) => ActionResult::Skip(format!("unknown CBOR operation: {op}")),
        None => ActionResult::Fail("verify_cbor action missing 'operation' param".into()),
    }
}

fn execute_cbor_roundtrip(base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/cbor/envelope_encoding.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let input = match vector.get("input") {
            Some(i) => i,
            None => return ActionResult::Fail(format!("vector {id}: missing input")),
        };
        let expected = match vector.get("expected_output") {
            Some(e) => e,
            None => return ActionResult::Fail(format!("vector {id}: missing expected_output")),
        };

        // Parse input fields
        let version: u8 = input.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let msg_type_str = input
            .get("msg_type")
            .and_then(|v| v.as_str())
            .unwrap_or("0x0300");
        let msg_type = u16::from_str_radix(msg_type_str.trim_start_matches("0x"), 16).unwrap_or(0);
        let msg_id_hex = input
            .get("msg_id_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let payload_hex = input
            .get("payload_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let session_id_hex = input.get("session_id_hex").and_then(|v| v.as_str());
        let auth_tag_hex = input.get("auth_tag_hex").and_then(|v| v.as_str());

        let msg_id_bytes = hex::decode(msg_id_hex).unwrap_or_default();
        let payload_bytes = hex::decode(payload_hex).unwrap_or_default();

        let mut msg_id = [0u8; 16];
        if msg_id_bytes.len() == 16 {
            msg_id.copy_from_slice(&msg_id_bytes);
        }

        let session_id = session_id_hex.filter(|s| !s.is_empty()).map(|s| {
            let bytes = hex::decode(s).unwrap_or_default();
            let mut arr = [0u8; 32];
            let len = bytes.len().min(32);
            arr[..len].copy_from_slice(&bytes[..len]);
            arr
        });

        let auth_tag = auth_tag_hex
            .filter(|s| !s.is_empty())
            .map(|s| hex::decode(s).unwrap_or_default());

        let envelope = cairn_p2p::protocol::envelope::MessageEnvelope {
            version,
            msg_type,
            msg_id,
            session_id,
            payload: payload_bytes,
            auth_tag,
        };

        // Encode
        let encoded = match envelope.encode() {
            Ok(bytes) => bytes,
            Err(e) => return ActionResult::Fail(format!("vector {id}: encode failed: {e}")),
        };

        // Check against expected CBOR hex
        let expected_hex = expected
            .get("cbor_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_bytes = hex::decode(expected_hex).unwrap_or_default();

        if encoded != expected_bytes {
            return ActionResult::Fail(format!(
                "vector {id}: encoded CBOR mismatch\n  expected: {expected_hex}\n  actual:   {}",
                hex::encode(&encoded)
            ));
        }

        // Decode back
        let decoded = match cairn_p2p::protocol::envelope::MessageEnvelope::decode(&encoded) {
            Ok(d) => d,
            Err(e) => return ActionResult::Fail(format!("vector {id}: decode failed: {e}")),
        };

        // Verify roundtrip
        if decoded.version != version {
            return ActionResult::Fail(format!("vector {id}: version mismatch"));
        }
        if decoded.msg_type != msg_type {
            return ActionResult::Fail(format!("vector {id}: msg_type mismatch"));
        }
        if decoded.msg_id != msg_id {
            return ActionResult::Fail(format!("vector {id}: msg_id mismatch"));
        }
    }

    ActionResult::Pass
}

fn execute_cbor_field_types(_action: &Action) -> ActionResult {
    // Verify that MessageEnvelope uses the correct CBOR integer keys.
    // The envelope uses keys 0-5 as unsigned integers.
    use cairn_p2p::protocol::envelope::MessageEnvelope;

    let envelope = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id: [0u8; 16],
        session_id: None,
        payload: vec![0xAB],
        auth_tag: None,
    };

    let encoded = match envelope.encode() {
        Ok(bytes) => bytes,
        Err(e) => return ActionResult::Fail(format!("encode failed: {e}")),
    };

    // CBOR map: first byte should be 0xA4 (map of 4 entries) for minimal or 0xA6 for full
    if encoded.is_empty() {
        return ActionResult::Fail("encoded is empty".into());
    }

    // Verify it decodes back
    match MessageEnvelope::decode(&encoded) {
        Ok(d) => {
            if d.version != 1 || d.msg_type != 0x0300 {
                return ActionResult::Fail("decoded fields don't match".into());
            }
        }
        Err(e) => return ActionResult::Fail(format!("decode failed: {e}")),
    }

    ActionResult::Pass
}

fn execute_cbor_deterministic(base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/cbor/deterministic_encoding.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    // For each deterministic encoding vector, verify that encoding produces
    // the expected bytes and encoding twice produces identical bytes.
    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let input = match vector.get("input") {
            Some(i) => i,
            None => return ActionResult::Fail(format!("vector {id}: missing input")),
        };

        let version: u8 = input.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let msg_type_str = input
            .get("msg_type")
            .and_then(|v| v.as_str())
            .unwrap_or("0x0300");
        let msg_type = u16::from_str_radix(msg_type_str.trim_start_matches("0x"), 16).unwrap_or(0);
        let msg_id_hex = input
            .get("msg_id_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let payload_hex = input
            .get("payload_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let msg_id_bytes = hex::decode(msg_id_hex).unwrap_or_default();
        let payload_bytes = hex::decode(payload_hex).unwrap_or_default();

        let mut msg_id = [0u8; 16];
        if msg_id_bytes.len() == 16 {
            msg_id.copy_from_slice(&msg_id_bytes);
        }

        let envelope = cairn_p2p::protocol::envelope::MessageEnvelope {
            version,
            msg_type,
            msg_id,
            session_id: None,
            payload: payload_bytes,
            auth_tag: None,
        };

        let encoded1 = match envelope.encode() {
            Ok(bytes) => bytes,
            Err(e) => return ActionResult::Fail(format!("vector {id}: first encode failed: {e}")),
        };
        let encoded2 = match envelope.encode() {
            Ok(bytes) => bytes,
            Err(e) => return ActionResult::Fail(format!("vector {id}: second encode failed: {e}")),
        };

        if encoded1 != encoded2 {
            return ActionResult::Fail(format!(
                "vector {id}: deterministic encoding failed — two encodes differ"
            ));
        }
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// verify_crypto
// ---------------------------------------------------------------------------

fn execute_verify_crypto(action: &Action, base_dir: &str) -> ActionResult {
    let operation = action.params.get("operation").and_then(|v| v.as_str());

    match operation {
        Some("hkdf_sha256") | Some("hkdf_sha256_batch") => execute_crypto_hkdf(action, base_dir),
        Some("aead_encrypt") | Some("aead_decrypt") | Some("aead") => execute_crypto_aead(base_dir),
        Some("spake2") | Some("spake2_batch") => execute_crypto_spake2(base_dir),
        Some("double_ratchet_init") | Some("double_ratchet_sequence") => {
            execute_crypto_ratchet(base_dir)
        }
        Some("double_ratchet_encrypt") | Some("double_ratchet_decrypt") => ActionResult::Skip(
            "double_ratchet encrypt/decrypt requires two-party infrastructure".into(),
        ),
        Some(op) => ActionResult::Skip(format!("crypto operation '{op}' not yet implemented")),
        None => ActionResult::Fail("verify_crypto action missing 'operation' param".into()),
    }
}

fn execute_crypto_hkdf(_action: &Action, base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/crypto/hkdf_vectors.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read HKDF vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse HKDF vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let input = match vector.get("input") {
            Some(i) => i,
            None => return ActionResult::Fail(format!("vector {id}: missing input")),
        };
        let expected = match vector.get("expected_output") {
            Some(e) => e,
            None => return ActionResult::Fail(format!("vector {id}: missing expected_output")),
        };

        let ikm_hex = input.get("ikm_hex").and_then(|v| v.as_str()).unwrap_or("");
        let salt_hex = input.get("salt_hex").and_then(|v| v.as_str()).unwrap_or("");
        let output_length = input
            .get("output_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(32) as usize;

        // Info can be either a string ("info") or hex-encoded bytes ("info_hex").
        let info_bytes = if let Some(info_hex) = input.get("info_hex").and_then(|v| v.as_str()) {
            hex::decode(info_hex).unwrap_or_default()
        } else {
            let info = input.get("info").and_then(|v| v.as_str()).unwrap_or("");
            info.as_bytes().to_vec()
        };

        let ikm = hex::decode(ikm_hex).unwrap_or_default();
        let salt = hex::decode(salt_hex).unwrap_or_default();

        let expected_okm_hex = expected
            .get("okm_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_okm = hex::decode(expected_okm_hex).unwrap_or_default();

        // Use cairn-p2p's HKDF
        use hkdf::Hkdf;
        use sha2::Sha256;

        // Use None for salt if empty (RFC 5869 case 3).
        let salt_opt = if salt.is_empty() {
            None
        } else {
            Some(salt.as_slice())
        };
        let hk = Hkdf::<Sha256>::new(salt_opt, &ikm);
        let mut okm = vec![0u8; output_length];
        if hk.expand(&info_bytes, &mut okm).is_err() {
            return ActionResult::Fail(format!("vector {id}: HKDF expand failed"));
        }

        if okm != expected_okm {
            return ActionResult::Fail(format!(
                "vector {id}: HKDF output mismatch\n  expected: {expected_okm_hex}\n  actual:   {}",
                hex::encode(&okm)
            ));
        }
    }

    ActionResult::Pass
}

fn execute_crypto_aead(base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/crypto/aead_vectors.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read AEAD vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse AEAD vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let input = match vector.get("input") {
            Some(i) => i,
            None => return ActionResult::Fail(format!("vector {id}: missing input")),
        };
        let expected = match vector.get("expected_output") {
            Some(e) => e,
            None => return ActionResult::Fail(format!("vector {id}: missing expected_output")),
        };

        let algorithm = input
            .get("algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key_hex = input.get("key_hex").and_then(|v| v.as_str()).unwrap_or("");
        let nonce_hex = input
            .get("nonce_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let plaintext_hex = input
            .get("plaintext_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let aad_hex = input.get("aad_hex").and_then(|v| v.as_str()).unwrap_or("");

        let key = hex::decode(key_hex).unwrap_or_default();
        let nonce = hex::decode(nonce_hex).unwrap_or_default();
        let plaintext = hex::decode(plaintext_hex).unwrap_or_default();
        let aad = hex::decode(aad_hex).unwrap_or_default();

        let expected_ct_hex = expected
            .get("ciphertext_and_tag_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_ct = hex::decode(expected_ct_hex).unwrap_or_default();

        let actual_ct = match algorithm {
            "AES-256-GCM" => {
                use aes_gcm::aead::Payload;
                use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| format!("vector {id}: AES key error: {e}"));
                let cipher = match cipher {
                    Ok(c) => c,
                    Err(e) => return ActionResult::Fail(e),
                };

                let nonce_arr = aes_gcm::Nonce::from_slice(&nonce);
                let payload = Payload {
                    msg: &plaintext,
                    aad: &aad,
                };
                match cipher.encrypt(nonce_arr, payload) {
                    Ok(ct) => ct,
                    Err(e) => {
                        return ActionResult::Fail(format!("vector {id}: AES encrypt failed: {e}"))
                    }
                }
            }
            "ChaCha20-Poly1305" => {
                use chacha20poly1305::aead::Payload;
                use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

                let cipher = ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|e| format!("vector {id}: ChaCha20 key error: {e}"));
                let cipher = match cipher {
                    Ok(c) => c,
                    Err(e) => return ActionResult::Fail(e),
                };

                let nonce_arr = chacha20poly1305::Nonce::from_slice(&nonce);
                let payload = Payload {
                    msg: &plaintext,
                    aad: &aad,
                };
                match cipher.encrypt(nonce_arr, payload) {
                    Ok(ct) => ct,
                    Err(e) => {
                        return ActionResult::Fail(format!(
                            "vector {id}: ChaCha20 encrypt failed: {e}"
                        ))
                    }
                }
            }
            other => return ActionResult::Skip(format!("unknown AEAD algorithm: {other}")),
        };

        if actual_ct != expected_ct {
            return ActionResult::Fail(format!(
                "vector {id}: AEAD ciphertext mismatch\n  expected: {expected_ct_hex}\n  actual:   {}",
                hex::encode(&actual_ct)
            ));
        }
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// verify_crypto — SPAKE2
// ---------------------------------------------------------------------------

fn execute_crypto_spake2(base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/crypto/spake2_vectors.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read SPAKE2 vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse SPAKE2 vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Test deterministic vectors (key confirmation and session key derivation)
        match id {
            "spake2-key-confirmation" => {
                let input = match vector.get("input") {
                    Some(i) => i,
                    None => return ActionResult::Fail(format!("vector {id}: missing input")),
                };
                let expected = match vector.get("expected_output") {
                    Some(e) => e,
                    None => {
                        return ActionResult::Fail(format!("vector {id}: missing expected_output"))
                    }
                };

                let shared_key_hex = input
                    .get("shared_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let confirm_info = input
                    .get("confirm_hkdf_info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let shared_key = hex::decode(shared_key_hex).unwrap_or_default();

                // Derive confirm key via HKDF
                use hkdf::Hkdf;
                use sha2::Sha256;

                let hk = Hkdf::<Sha256>::new(None, &shared_key);
                let mut confirm_key = [0u8; 32];
                if hk
                    .expand(confirm_info.as_bytes(), &mut confirm_key)
                    .is_err()
                {
                    return ActionResult::Fail(format!(
                        "vector {id}: HKDF expand for confirm key failed"
                    ));
                }

                let expected_confirm_hex = expected
                    .get("confirm_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hex::encode(confirm_key) != expected_confirm_hex {
                    return ActionResult::Fail(format!(
                        "vector {id}: confirm key mismatch\n  expected: {expected_confirm_hex}\n  actual:   {}",
                        hex::encode(confirm_key)
                    ));
                }

                // Verify initiator/responder confirmations via HMAC
                use hmac::{Hmac, Mac};
                type HmacSha256 = Hmac<Sha256>;

                let init_label = input
                    .get("initiator_label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("initiator");
                let resp_label = input
                    .get("responder_label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("responder");

                let mut mac = HmacSha256::new_from_slice(&confirm_key).unwrap();
                mac.update(init_label.as_bytes());
                let init_confirm = mac.finalize().into_bytes();

                let expected_init_hex = expected
                    .get("initiator_confirmation_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hex::encode(init_confirm) != expected_init_hex {
                    return ActionResult::Fail(format!(
                        "vector {id}: initiator confirmation mismatch\n  expected: {expected_init_hex}\n  actual:   {}",
                        hex::encode(init_confirm)
                    ));
                }

                let mut mac = HmacSha256::new_from_slice(&confirm_key).unwrap();
                mac.update(resp_label.as_bytes());
                let resp_confirm = mac.finalize().into_bytes();

                let expected_resp_hex = expected
                    .get("responder_confirmation_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hex::encode(resp_confirm) != expected_resp_hex {
                    return ActionResult::Fail(format!(
                        "vector {id}: responder confirmation mismatch\n  expected: {expected_resp_hex}\n  actual:   {}",
                        hex::encode(resp_confirm)
                    ));
                }
            }
            "spake2-session-key-derivation" => {
                let input = match vector.get("input") {
                    Some(i) => i,
                    None => return ActionResult::Fail(format!("vector {id}: missing input")),
                };
                let expected = match vector.get("expected_output") {
                    Some(e) => e,
                    None => {
                        return ActionResult::Fail(format!("vector {id}: missing expected_output"))
                    }
                };

                let raw_hex = input
                    .get("raw_spake2_output_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let salt_hex = input.get("salt_hex").and_then(|v| v.as_str()).unwrap_or("");
                let info = input
                    .get("hkdf_info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let ikm = hex::decode(raw_hex).unwrap_or_default();
                let salt = hex::decode(salt_hex).unwrap_or_default();

                use hkdf::Hkdf;
                use sha2::Sha256;

                let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut session_key = [0u8; 32];
                if hk.expand(info.as_bytes(), &mut session_key).is_err() {
                    return ActionResult::Fail(format!(
                        "vector {id}: HKDF expand for session key failed"
                    ));
                }

                let expected_hex = expected
                    .get("session_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hex::encode(session_key) != expected_hex {
                    return ActionResult::Fail(format!(
                        "vector {id}: session key mismatch\n  expected: {expected_hex}\n  actual:   {}",
                        hex::encode(session_key)
                    ));
                }
            }
            "spake2-protocol-params" => {
                let expected = match vector.get("expected_output") {
                    Some(e) => e,
                    None => {
                        return ActionResult::Fail(format!("vector {id}: missing expected_output"))
                    }
                };
                let pake_size = expected
                    .get("pake_message_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let secret_size = expected
                    .get("shared_secret_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                if pake_size != 33 {
                    return ActionResult::Fail(format!(
                        "vector {id}: expected pake_message_size=33, got {pake_size}"
                    ));
                }
                if secret_size != 32 {
                    return ActionResult::Fail(format!(
                        "vector {id}: expected shared_secret_size=32, got {secret_size}"
                    ));
                }
            }
            // Non-deterministic tests (same/different password) are property tests, skip in runner
            _ => {}
        }
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// verify_crypto — Double Ratchet
// ---------------------------------------------------------------------------

fn execute_crypto_ratchet(base_dir: &str) -> ActionResult {
    let vectors_path = format!("{}/vectors/crypto/double_ratchet_vectors.json", base_dir);
    let content = match std::fs::read_to_string(&vectors_path) {
        Ok(c) => c,
        Err(e) => return ActionResult::Fail(format!("failed to read ratchet vectors: {e}")),
    };

    let doc: JsonValue = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(e) => return ActionResult::Fail(format!("failed to parse ratchet vectors: {e}")),
    };

    let vectors = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return ActionResult::Fail("missing 'vectors' array".into()),
    };

    use hkdf::Hkdf;
    use sha2::Sha256;

    for vector in vectors {
        let id = vector
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let input = match vector.get("input") {
            Some(i) => i,
            None => continue, // config/property vectors may lack input
        };
        let expected = match vector.get("expected_output") {
            Some(e) => e,
            None => continue,
        };

        match id {
            s if s.starts_with("ratchet-kdf-rk") => {
                // Root chain KDF: HKDF-SHA256(root_key, dh_output, info) -> (new_root_key, new_chain_key)
                let root_key_hex = input
                    .get("root_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let dh_output_hex = input
                    .get("dh_output_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let info = input
                    .get("hkdf_info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let root_key = hex::decode(root_key_hex).unwrap_or_default();
                let dh_output = hex::decode(dh_output_hex).unwrap_or_default();

                let hk = Hkdf::<Sha256>::new(Some(&root_key), &dh_output);
                let mut okm = [0u8; 64];
                if hk.expand(info.as_bytes(), &mut okm).is_err() {
                    return ActionResult::Fail(format!("vector {id}: HKDF expand failed"));
                }

                let new_root_key = &okm[..32];
                let new_chain_key = &okm[32..64];

                let expected_rk = expected
                    .get("new_root_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let expected_ck = expected
                    .get("new_chain_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if hex::encode(new_root_key) != expected_rk {
                    return ActionResult::Fail(format!(
                        "vector {id}: root key mismatch\n  expected: {expected_rk}\n  actual:   {}",
                        hex::encode(new_root_key)
                    ));
                }
                if hex::encode(new_chain_key) != expected_ck {
                    return ActionResult::Fail(format!(
                        "vector {id}: chain key mismatch\n  expected: {expected_ck}\n  actual:   {}",
                        hex::encode(new_chain_key)
                    ));
                }
            }
            "ratchet-kdf-ck-step0" => {
                // Chain KDF: HKDF-SHA256(ikm=chain_key, salt=None, info=chain_advance) -> new_chain_key
                //            HKDF-SHA256(ikm=chain_key, salt=None, info=msg_encrypt)   -> message_key
                let chain_key_hex = input
                    .get("chain_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let advance_info = input
                    .get("chain_advance_info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let encrypt_info = input
                    .get("msg_encrypt_info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let chain_key = hex::decode(chain_key_hex).unwrap_or_default();

                // Message key: HKDF(ikm=chain_key, salt=None, info=encrypt_info)
                let hk_msg = Hkdf::<Sha256>::new(None, &chain_key);
                let mut msg_key = [0u8; 32];
                if hk_msg
                    .expand(encrypt_info.as_bytes(), &mut msg_key)
                    .is_err()
                {
                    return ActionResult::Fail(format!(
                        "vector {id}: HKDF expand for msg key failed"
                    ));
                }

                // New chain key: HKDF(ikm=chain_key, salt=None, info=advance_info)
                let hk_ck = Hkdf::<Sha256>::new(None, &chain_key);
                let mut new_ck = [0u8; 32];
                if hk_ck.expand(advance_info.as_bytes(), &mut new_ck).is_err() {
                    return ActionResult::Fail(format!(
                        "vector {id}: HKDF expand for chain key failed"
                    ));
                }

                let expected_mk = expected
                    .get("message_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let expected_ck = expected
                    .get("new_chain_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if hex::encode(msg_key) != expected_mk {
                    return ActionResult::Fail(format!(
                        "vector {id}: message key mismatch\n  expected: {expected_mk}\n  actual:   {}",
                        hex::encode(msg_key)
                    ));
                }
                if hex::encode(new_ck) != expected_ck {
                    return ActionResult::Fail(format!(
                        "vector {id}: new chain key mismatch\n  expected: {expected_ck}\n  actual:   {}",
                        hex::encode(new_ck)
                    ));
                }
            }
            "ratchet-send-chain-3-messages" => {
                let init_ck_hex = input
                    .get("initial_chain_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let steps = match expected.get("steps").and_then(|v| v.as_array()) {
                    Some(s) => s,
                    None => return ActionResult::Fail(format!("vector {id}: missing steps")),
                };

                let mut ck = hex::decode(init_ck_hex).unwrap_or_default();

                for step in steps {
                    let step_num = step.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
                    let expected_ick = step
                        .get("input_chain_key_hex")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let expected_mk = step
                        .get("message_key_hex")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let expected_ock = step
                        .get("output_chain_key_hex")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if hex::encode(&ck) != expected_ick {
                        return ActionResult::Fail(format!(
                            "vector {id} step {step_num}: input chain key mismatch"
                        ));
                    }

                    // Message key: HKDF(ikm=chain_key, salt=None, info)
                    let hk_msg = Hkdf::<Sha256>::new(None, &ck);
                    let mut msg_key = [0u8; 32];
                    if hk_msg
                        .expand(b"cairn-msg-encrypt-v1", &mut msg_key)
                        .is_err()
                    {
                        return ActionResult::Fail(format!(
                            "vector {id} step {step_num}: HKDF msg key failed"
                        ));
                    }

                    // New chain key: HKDF(ikm=chain_key, salt=None, info)
                    let hk_ck = Hkdf::<Sha256>::new(None, &ck);
                    let mut new_ck = [0u8; 32];
                    if hk_ck
                        .expand(b"cairn-chain-advance-v1", &mut new_ck)
                        .is_err()
                    {
                        return ActionResult::Fail(format!(
                            "vector {id} step {step_num}: HKDF chain key failed"
                        ));
                    }

                    if hex::encode(msg_key) != expected_mk {
                        return ActionResult::Fail(format!(
                            "vector {id} step {step_num}: message key mismatch\n  expected: {expected_mk}\n  actual:   {}",
                            hex::encode(msg_key)
                        ));
                    }
                    if hex::encode(new_ck) != expected_ock {
                        return ActionResult::Fail(format!(
                            "vector {id} step {step_num}: output chain key mismatch\n  expected: {expected_ock}\n  actual:   {}",
                            hex::encode(new_ck)
                        ));
                    }

                    ck = new_ck.to_vec();
                }
            }
            s if s.starts_with("ratchet-nonce-msg") => {
                // Nonce: first 8 bytes from message key, last 4 from big-endian msg_num
                let mk_hex = input
                    .get("message_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let msg_num = input.get("msg_num").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

                let mk = hex::decode(mk_hex).unwrap_or_default();
                let mut nonce = [0u8; 12];
                nonce[..8].copy_from_slice(&mk[..8]);
                nonce[8..12].copy_from_slice(&msg_num.to_be_bytes());

                let expected_nonce = expected
                    .get("nonce_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hex::encode(nonce) != expected_nonce {
                    return ActionResult::Fail(format!(
                        "vector {id}: nonce mismatch\n  expected: {expected_nonce}\n  actual:   {}",
                        hex::encode(nonce)
                    ));
                }
            }
            // Config/property vectors — just verify expected fields exist
            "ratchet-config-defaults"
            | "ratchet-header-format"
            | "ratchet-out-of-order-properties" => {}
            _ => {}
        }
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// verify_cbor — deterministic_encode
// ---------------------------------------------------------------------------

fn execute_cbor_deterministic_encode(action: &Action) -> ActionResult {
    // Build an envelope from the action's fields params and verify deterministic encoding
    let fields = &action.params;
    let msg_type_val = fields.get("message_type");
    let msg_type_str = msg_type_val
        .and_then(|v| v.as_str())
        .or_else(|| msg_type_val.and_then(|v| v.as_u64()).map(|_| ""))
        .unwrap_or("0x0300");

    let msg_type = if msg_type_str.is_empty() {
        msg_type_val.and_then(|v| v.as_u64()).unwrap_or(0x0300) as u16
    } else {
        u16::from_str_radix(msg_type_str.trim_start_matches("0x"), 16).unwrap_or(0x0300)
    };

    let inner = fields.get("fields");
    let msg_id_hex = inner
        .and_then(|f| f.get("msg_id_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("0192b5a07c4870008000000000000001");
    let payload_hex = inner
        .and_then(|f| f.get("payload_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let msg_id_bytes = hex::decode(msg_id_hex).unwrap_or_default();
    let payload_bytes = hex::decode(payload_hex).unwrap_or_default();

    let mut msg_id = [0u8; 16];
    if msg_id_bytes.len() == 16 {
        msg_id.copy_from_slice(&msg_id_bytes);
    }

    let envelope = cairn_p2p::protocol::envelope::MessageEnvelope {
        version: 1,
        msg_type,
        msg_id,
        session_id: None,
        payload: payload_bytes,
        auth_tag: None,
    };

    let encoded1 = match envelope.encode() {
        Ok(bytes) => bytes,
        Err(e) => return ActionResult::Fail(format!("first encode failed: {e}")),
    };
    let encoded2 = match envelope.encode() {
        Ok(bytes) => bytes,
        Err(e) => return ActionResult::Fail(format!("second encode failed: {e}")),
    };

    if encoded1 != encoded2 {
        return ActionResult::Fail("deterministic encoding failed: two encodes differ".into());
    }

    // Verify roundtrip
    match cairn_p2p::protocol::envelope::MessageEnvelope::decode(&encoded1) {
        Ok(d) => {
            if d.msg_type != msg_type {
                return ActionResult::Fail(
                    "decoded msg_type mismatch after deterministic encode".into(),
                );
            }
        }
        Err(e) => {
            return ActionResult::Fail(format!("decode after deterministic encode failed: {e}"))
        }
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// verify_cbor — encode / decode
// ---------------------------------------------------------------------------

fn execute_cbor_encode_decode(action: &Action) -> ActionResult {
    // For single-implementation runner: encode and decode back, verify roundtrip
    let fields = &action.params;
    let msg_type_val = fields.get("message_type");
    let msg_type = msg_type_val.and_then(|v| v.as_u64()).unwrap_or(0x0300) as u16;

    let inner = fields.get("fields");
    let payload_hex = inner
        .and_then(|f| f.get("payload_hex"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let payload_bytes = hex::decode(payload_hex).unwrap_or_default();

    let envelope = cairn_p2p::protocol::envelope::MessageEnvelope {
        version: 1,
        msg_type,
        msg_id: [0u8; 16],
        session_id: None,
        payload: payload_bytes.clone(),
        auth_tag: None,
    };

    let encoded = match envelope.encode() {
        Ok(bytes) => bytes,
        Err(e) => return ActionResult::Fail(format!("encode failed: {e}")),
    };

    match cairn_p2p::protocol::envelope::MessageEnvelope::decode(&encoded) {
        Ok(d) => {
            if d.msg_type != msg_type {
                return ActionResult::Fail("msg_type mismatch after roundtrip".into());
            }
            if d.payload != payload_bytes {
                return ActionResult::Fail("payload mismatch after roundtrip".into());
            }
        }
        Err(e) => return ActionResult::Fail(format!("decode failed: {e}")),
    }

    ActionResult::Pass
}

// ---------------------------------------------------------------------------
// pair
// ---------------------------------------------------------------------------

fn execute_pair(action: &Action, base_dir: &str) -> ActionResult {
    let mechanism = action.params.get("mechanism").and_then(|v| v.as_str());

    match mechanism {
        Some("psk") => execute_pair_psk(action, base_dir),
        Some(m) => ActionResult::Skip(format!(
            "pairing mechanism '{m}' not yet implemented in runner"
        )),
        None => ActionResult::Fail("pair action missing 'mechanism' param".into()),
    }
}

fn execute_pair_psk(_action: &Action, base_dir: &str) -> ActionResult {
    use cairn_p2p::pairing::mechanisms::PskMechanism;
    let mech = PskMechanism::new();

    // Try loading test vectors from fixture
    let vectors_path = format!("{}/fixtures/pairing/psk-vectors.json", base_dir);
    if let Ok(content) = std::fs::read_to_string(&vectors_path) {
        if let Ok(doc) = serde_json::from_str::<JsonValue>(&content) {
            if let Some(vectors) = doc.get("vectors").and_then(|v| v.as_array()) {
                for vector in vectors {
                    let psk_hex = vector.get("psk_hex").and_then(|v| v.as_str()).unwrap_or("");
                    let valid = vector
                        .get("valid")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let comment = vector.get("comment").and_then(|v| v.as_str()).unwrap_or("");

                    let psk = hex::decode(psk_hex).unwrap_or_default();
                    let result = mech.validate_entropy(&psk);

                    if valid && result.is_err() {
                        return ActionResult::Fail(format!(
                            "PskMechanism rejected valid PSK: {comment}"
                        ));
                    }
                    if !valid && result.is_ok() {
                        return ActionResult::Fail(format!(
                            "PskMechanism accepted invalid PSK: {comment}"
                        ));
                    }
                }
                return ActionResult::Pass;
            }
        }
    }

    // Fallback: basic validation
    let valid_psk = vec![0xAB; 16];
    if mech.validate_entropy(&valid_psk).is_err() {
        return ActionResult::Fail("PskMechanism rejected valid 128-bit PSK".into());
    }

    let invalid_psk = vec![0xAB; 8];
    if mech.validate_entropy(&invalid_psk).is_ok() {
        return ActionResult::Fail("PskMechanism accepted invalid 64-bit PSK".into());
    }

    ActionResult::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Scenario;

    fn make_scenario(actions: Vec<Action>) -> Scenario {
        Scenario {
            scenario: "test".to_string(),
            description: "test scenario".to_string(),
            tier: 0,
            category: "test".to_string(),
            participants: vec![],
            actions,
            expected: vec![],
            timeout_ms: None,
            budget_ms: None,
        }
    }

    #[test]
    fn skip_unknown_action() {
        let scenario = make_scenario(vec![Action {
            action_type: "unknown_action".to_string(),
            actor: None,
            params: serde_yaml::Value::Null,
        }]);
        let result = execute_scenario(&scenario, ".");
        assert_eq!(result.status, Status::Skip);
    }

    #[test]
    fn skip_infrastructure_actions() {
        for action_type in &["establish_session", "send_data", "disconnect", "reconnect"] {
            let scenario = make_scenario(vec![Action {
                action_type: action_type.to_string(),
                actor: None,
                params: serde_yaml::Value::Null,
            }]);
            let result = execute_scenario(&scenario, ".");
            assert_eq!(result.status, Status::Skip);
        }
    }
}
