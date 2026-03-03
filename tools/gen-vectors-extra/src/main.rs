use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use serde_json::json;
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;

fn main() {
    gen_crypto_spake2();
    gen_crypto_noise_xx();
    gen_crypto_double_ratchet();
    eprintln!("All extra vectors generated successfully.");
}

fn gen_crypto_spake2() {
    let mut vectors = Vec::new();

    // 1. Protocol parameters
    vectors.push(json!({
        "id": "spake2-protocol-params",
        "input": {
            "group": "Ed25519Group",
            "initiator_identity": "cairn-initiator",
            "responder_identity": "cairn-responder",
            "session_key_derivation_info": "cairn-pairing-session-key-v1",
            "key_confirmation_info": "cairn-pairing-key-confirm-v1"
        },
        "expected_output": {
            "pake_message_size": 33,
            "shared_secret_size": 32
        },
        "description": "SPAKE2 protocol parameters for cairn pairing (Ed25519Group)"
    }));

    // 2. Same password -> matching keys (property)
    vectors.push(json!({
        "id": "spake2-same-password-match",
        "input": {
            "password": "test-password-123",
            "initiator_identity": "cairn-initiator",
            "responder_identity": "cairn-responder"
        },
        "expected_output": {
            "keys_match": true,
            "note": "Both parties using the same password must derive identical shared secrets"
        },
        "description": "SPAKE2: same password on both sides produces matching shared secrets"
    }));

    // 3. Different password -> mismatch (property)
    vectors.push(json!({
        "id": "spake2-different-password-mismatch",
        "input": {
            "password_a": "correct-password",
            "password_b": "wrong-password",
            "initiator_identity": "cairn-initiator",
            "responder_identity": "cairn-responder"
        },
        "expected_output": {
            "keys_match": false,
            "note": "Different passwords produce different shared secrets (PAKE failure detectable via key confirmation)"
        },
        "description": "SPAKE2: different passwords produce mismatched shared secrets"
    }));

    // 4. Key confirmation HMAC derivation (deterministic from known shared key)
    {
        let shared_key = [0x42u8; 32];
        let hk = Hkdf::<Sha256>::new(None, &shared_key);
        let mut confirm_key = [0u8; 32];
        hk.expand(b"cairn-pairing-key-confirm-v1", &mut confirm_key).unwrap();

        let mut mac_init = <HmacSha256 as KeyInit>::new_from_slice(&confirm_key).unwrap();
        mac_init.update(b"initiator");
        let init_confirm = mac_init.finalize().into_bytes();

        let mut mac_resp = <HmacSha256 as KeyInit>::new_from_slice(&confirm_key).unwrap();
        mac_resp.update(b"responder");
        let resp_confirm = mac_resp.finalize().into_bytes();

        vectors.push(json!({
            "id": "spake2-key-confirmation",
            "input": {
                "shared_key_hex": hex::encode(shared_key),
                "confirm_hkdf_info": "cairn-pairing-key-confirm-v1",
                "initiator_label": "initiator",
                "responder_label": "responder"
            },
            "expected_output": {
                "confirm_key_hex": hex::encode(confirm_key),
                "initiator_confirmation_hex": hex::encode(init_confirm),
                "responder_confirmation_hex": hex::encode(resp_confirm)
            },
            "description": "Key confirmation HMAC derivation from known shared key"
        }));
    }

    // 5. Session key derivation from SPAKE2 output
    {
        let raw_spake2_output = [0xAAu8; 32];
        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &raw_spake2_output);
        let mut session_key = [0u8; 32];
        hk.expand(b"cairn-pairing-session-key-v1", &mut session_key).unwrap();

        vectors.push(json!({
            "id": "spake2-session-key-derivation",
            "input": {
                "raw_spake2_output_hex": hex::encode(raw_spake2_output),
                "salt_hex": hex::encode(salt),
                "hkdf_info": "cairn-pairing-session-key-v1"
            },
            "expected_output": {
                "session_key_hex": hex::encode(session_key)
            },
            "description": "Session key derived from SPAKE2 raw output via HKDF-SHA256"
        }));
    }

    let result = json!({
        "description": "SPAKE2 test vectors for cairn pairing. SPAKE2 uses random ephemerals so byte-level output is non-deterministic; vectors test protocol parameters, properties, and deterministic key derivation steps.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/spake2_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_noise_xx() {
    let mut vectors = Vec::new();

    let protocol_name = b"Noise_XX_25519_ChaChaPoly_SHA256";
    let mut initial_hash = [0u8; 32];
    initial_hash[..protocol_name.len()].copy_from_slice(protocol_name);

    // 1. Protocol parameters
    vectors.push(json!({
        "id": "noise-xx-protocol-params",
        "input": {
            "protocol_name": "Noise_XX_25519_ChaChaPoly_SHA256",
            "dh_key_size": 32,
            "aead_tag_size": 16,
            "hash_size": 32,
            "nonce_size": 12,
            "zero_nonce_hex": hex::encode([0u8; 12])
        },
        "expected_output": {
            "initial_handshake_hash_hex": hex::encode(initial_hash),
            "initial_chaining_key_hex": hex::encode(initial_hash),
            "note": "Protocol name is padded with zeros to 32 bytes since it is <= 32 bytes"
        },
        "description": "Noise XX protocol initialization parameters"
    }));

    // 2. Message sizes
    vectors.push(json!({
        "id": "noise-xx-message-sizes",
        "input": {
            "pattern": "XX: -> e, <- e ee s es, -> s se"
        },
        "expected_output": {
            "msg1_size": 32,
            "msg1_content": "ephemeral public key (32 bytes)",
            "msg2_size": 96,
            "msg2_content": "ephemeral(32) + encrypted_static(32+16tag) + encrypted_payload(0+16tag)",
            "msg3_size": 64,
            "msg3_content": "encrypted_static(32+16tag) + encrypted_payload(0+16tag)"
        },
        "description": "Noise XX handshake message sizes (empty payload)"
    }));

    // 3. mix_hash operation (deterministic)
    {
        let h0 = initial_hash;
        let test_data: [u8; 32] = [0x01; 32];
        let mut hasher = Sha256::new();
        hasher.update(h0);
        hasher.update(test_data);
        let h1: [u8; 32] = hasher.finalize().into();

        vectors.push(json!({
            "id": "noise-xx-mix-hash",
            "input": {
                "handshake_hash_hex": hex::encode(h0),
                "data_hex": hex::encode(test_data)
            },
            "expected_output": {
                "new_handshake_hash_hex": hex::encode(h1)
            },
            "description": "mix_hash operation: h = SHA-256(h || data)"
        }));
    }

    // 4. mix_key operation (deterministic)
    {
        let ck = initial_hash;
        let ikm: [u8; 32] = [0xAA; 32];
        let hk = Hkdf::<Sha256>::new(Some(&ck), &ikm);
        let mut output = [0u8; 64];
        hk.expand(b"", &mut output).unwrap();
        let new_ck: [u8; 32] = output[..32].try_into().unwrap();
        let enc_key: [u8; 32] = output[32..64].try_into().unwrap();

        vectors.push(json!({
            "id": "noise-xx-mix-key",
            "input": {
                "chaining_key_hex": hex::encode(ck),
                "input_key_material_hex": hex::encode(ikm),
                "hkdf_info": ""
            },
            "expected_output": {
                "new_chaining_key_hex": hex::encode(new_ck),
                "encryption_key_hex": hex::encode(enc_key)
            },
            "description": "mix_key operation: HKDF(ikm, salt=ck, info='') -> (new_ck, enc_key)"
        }));
    }

    // 5. Session key derivation from chaining key
    {
        let ck: [u8; 32] = [0xBB; 32];
        let hk = Hkdf::<Sha256>::new(None, &ck);
        let mut session_key = [0u8; 32];
        hk.expand(b"cairn-session-key-v1", &mut session_key).unwrap();

        vectors.push(json!({
            "id": "noise-xx-session-key-derivation",
            "input": {
                "chaining_key_hex": hex::encode(ck),
                "hkdf_info": "cairn-session-key-v1"
            },
            "expected_output": {
                "session_key_hex": hex::encode(session_key)
            },
            "description": "Session key derived from final chaining key via HKDF-SHA256"
        }));
    }

    // 6. Handshake properties
    vectors.push(json!({
        "id": "noise-xx-handshake-properties",
        "input": {
            "note": "These properties must hold for any valid Noise XX handshake"
        },
        "expected_output": {
            "initiator_session_key_equals_responder": true,
            "initiator_transcript_hash_equals_responder": true,
            "initiator_knows_responder_static": true,
            "responder_knows_initiator_static": true,
            "different_handshakes_produce_different_keys": true,
            "mismatched_pake_secrets_cause_decryption_failure": true
        },
        "description": "Noise XX handshake invariant properties that all implementations must satisfy"
    }));

    let result = json!({
        "description": "Noise XX handshake test vectors for cairn. Since ephemeral keys are random, full transcripts are non-deterministic. Vectors cover protocol parameters, sub-operations (mix_hash, mix_key), and invariant properties.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/noise_xx_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_double_ratchet() {
    let mut vectors = Vec::new();

    // 1. Root chain KDF (kdf_rk)
    {
        let root_key: [u8; 32] = [0x01; 32];
        let dh_output: [u8; 32] = [0x02; 32];
        let hk = Hkdf::<Sha256>::new(Some(&root_key), &dh_output);
        let mut output = [0u8; 64];
        hk.expand(b"cairn-root-chain-v1", &mut output).unwrap();
        let new_rk: [u8; 32] = output[..32].try_into().unwrap();
        let new_ck: [u8; 32] = output[32..64].try_into().unwrap();

        vectors.push(json!({
            "id": "ratchet-kdf-rk-1",
            "input": {
                "root_key_hex": hex::encode(root_key),
                "dh_output_hex": hex::encode(dh_output),
                "hkdf_info": "cairn-root-chain-v1"
            },
            "expected_output": {
                "new_root_key_hex": hex::encode(new_rk),
                "new_chain_key_hex": hex::encode(new_ck)
            },
            "description": "Root chain KDF: derive new root key and chain key from DH output"
        }));
    }

    // 2. Another root chain KDF with different inputs
    {
        let root_key: [u8; 32] = [0xAA; 32];
        let dh_output: [u8; 32] = [0xBB; 32];
        let hk = Hkdf::<Sha256>::new(Some(&root_key), &dh_output);
        let mut output = [0u8; 64];
        hk.expand(b"cairn-root-chain-v1", &mut output).unwrap();
        let new_rk: [u8; 32] = output[..32].try_into().unwrap();
        let new_ck: [u8; 32] = output[32..64].try_into().unwrap();

        vectors.push(json!({
            "id": "ratchet-kdf-rk-2",
            "input": {
                "root_key_hex": hex::encode([0xAAu8; 32]),
                "dh_output_hex": hex::encode([0xBBu8; 32]),
                "hkdf_info": "cairn-root-chain-v1"
            },
            "expected_output": {
                "new_root_key_hex": hex::encode(new_rk),
                "new_chain_key_hex": hex::encode(new_ck)
            },
            "description": "Root chain KDF: second test with different inputs"
        }));
    }

    // 3. Chain advance KDF (kdf_ck)
    {
        let chain_key: [u8; 32] = [0x03; 32];
        let hk_ck = Hkdf::<Sha256>::new(None, &chain_key);
        let mut new_ck = [0u8; 32];
        hk_ck.expand(b"cairn-chain-advance-v1", &mut new_ck).unwrap();

        let hk_mk = Hkdf::<Sha256>::new(None, &chain_key);
        let mut mk = [0u8; 32];
        hk_mk.expand(b"cairn-msg-encrypt-v1", &mut mk).unwrap();

        vectors.push(json!({
            "id": "ratchet-kdf-ck-step0",
            "input": {
                "chain_key_hex": hex::encode(chain_key),
                "chain_advance_info": "cairn-chain-advance-v1",
                "msg_encrypt_info": "cairn-msg-encrypt-v1"
            },
            "expected_output": {
                "new_chain_key_hex": hex::encode(new_ck),
                "message_key_hex": hex::encode(mk)
            },
            "description": "Chain KDF step 0: derive new chain key and message key from initial chain key"
        }));
    }

    // 4. Send chain progression: 3 steps
    {
        let mut ck: [u8; 32] = [0x03; 32];
        let mut steps = Vec::new();

        for i in 0..3 {
            let hk_ck = Hkdf::<Sha256>::new(None, &ck);
            let mut new_ck = [0u8; 32];
            hk_ck.expand(b"cairn-chain-advance-v1", &mut new_ck).unwrap();

            let hk_mk = Hkdf::<Sha256>::new(None, &ck);
            let mut mk = [0u8; 32];
            hk_mk.expand(b"cairn-msg-encrypt-v1", &mut mk).unwrap();

            steps.push(json!({
                "step": i,
                "input_chain_key_hex": hex::encode(ck),
                "output_chain_key_hex": hex::encode(new_ck),
                "message_key_hex": hex::encode(mk)
            }));

            ck = new_ck;
        }

        vectors.push(json!({
            "id": "ratchet-send-chain-3-messages",
            "input": {
                "initial_chain_key_hex": hex::encode([0x03u8; 32]),
                "num_messages": 3
            },
            "expected_output": {
                "steps": steps
            },
            "description": "Send chain progression: 3 consecutive messages showing chain key and message key at each step"
        }));
    }

    // 5. Nonce derivation
    {
        let mk: [u8; 32] = [0x55; 32];
        for msg_num in [0u32, 1, 2, 100, 0xFFFFFFFF] {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&mk[..8]);
            nonce[8..].copy_from_slice(&msg_num.to_be_bytes());

            vectors.push(json!({
                "id": format!("ratchet-nonce-msg{}", msg_num),
                "input": {
                    "message_key_hex": hex::encode(mk),
                    "msg_num": msg_num
                },
                "expected_output": {
                    "nonce_hex": hex::encode(nonce)
                },
                "description": format!("Nonce derivation for message number {}: first 8 bytes from message key, last 4 from big-endian msg_num", msg_num)
            }));
        }
    }

    // 6. Configuration defaults
    vectors.push(json!({
        "id": "ratchet-config-defaults",
        "input": {},
        "expected_output": {
            "max_skip": 100,
            "default_cipher": "AES-256-GCM",
            "supported_ciphers": ["AES-256-GCM", "ChaCha20-Poly1305"]
        },
        "description": "Double Ratchet default configuration values"
    }));

    // 7. Header structure
    vectors.push(json!({
        "id": "ratchet-header-format",
        "input": {
            "dh_public_hex": hex::encode([0x42u8; 32]),
            "prev_chain_len": 5,
            "msg_num": 3
        },
        "expected_output": {
            "fields": ["dh_public (32 bytes)", "prev_chain_len (u32)", "msg_num (u32)"],
            "note": "Header is sent alongside each encrypted message and used as AEAD associated data"
        },
        "description": "Double Ratchet message header structure"
    }));

    // 8. Out-of-order delivery property
    vectors.push(json!({
        "id": "ratchet-out-of-order-properties",
        "input": {
            "messages_sent": ["msg0", "msg1", "msg2"],
            "delivery_order": [2, 0, 1]
        },
        "expected_output": {
            "all_decrypted_successfully": true,
            "note": "Skipped message keys are cached (up to max_skip) for out-of-order delivery"
        },
        "description": "Double Ratchet must support out-of-order message delivery via skipped key caching"
    }));

    let result = json!({
        "description": "Double Ratchet test vectors for cairn session encryption. Covers KDF chain operations (kdf_rk, kdf_ck), nonce derivation, and protocol properties.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/double_ratchet_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}
