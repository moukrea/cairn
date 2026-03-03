use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use cairn_p2p::protocol::envelope::MessageEnvelope;

fn main() {
    gen_cbor_envelope_encoding();
    gen_cbor_message_types();
    gen_cbor_deterministic_encoding();
    gen_cbor_fixture_files();
    gen_crypto_ed25519();
    gen_crypto_x25519();
    gen_crypto_hkdf();
    gen_crypto_aead();
    gen_pairing_pin_codes();
    gen_pairing_crockford_base32();
    gen_pairing_sas();
    gen_crypto_spake2();
    gen_protocol_version_negotiation();
    gen_protocol_rendezvous_id();
    gen_crypto_noise_xx();
    gen_crypto_double_ratchet();

    eprintln!("All vectors generated successfully.");
}

fn encode_envelope(env: &MessageEnvelope) -> String {
    hex::encode(env.encode().unwrap())
}

fn gen_cbor_envelope_encoding() {
    let msg_id_1: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let msg_id_2: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let msg_id_3: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    ];
    let session_id: [u8; 32] = [0xAB; 32];
    let auth_tag_16: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let mut vectors = Vec::new();

    // 1. Minimal HEARTBEAT (no session_id, no auth_tag, empty payload)
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id: msg_id_1,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-minimal-heartbeat",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "Minimal HEARTBEAT envelope: version + msg_type + msg_id + empty payload, no session_id or auth_tag"
    }));

    // 2. Full envelope with all 6 fields
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id: msg_id_2,
        session_id: Some(session_id),
        payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        auth_tag: Some(auth_tag_16.clone()),
    };
    vectors.push(json!({
        "id": "envelope-full-data-message",
        "input": {
            "version": 1,
            "msg_type": "0x0300",
            "msg_id_hex": hex::encode(msg_id_2),
            "session_id_hex": hex::encode(session_id),
            "payload_hex": "cafebabe",
            "auth_tag_hex": hex::encode(&auth_tag_16)
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 6
        },
        "description": "Full DATA_MESSAGE envelope with all 6 fields present including session_id and auth_tag"
    }));

    // 3. Absent session_id, present auth_tag
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0100,
        msg_id: msg_id_3,
        session_id: None,
        payload: vec![0x01],
        auth_tag: Some(vec![0xFF, 0x00]),
    };
    vectors.push(json!({
        "id": "envelope-no-session-with-auth",
        "input": {
            "version": 1,
            "msg_type": "0x0100",
            "msg_id_hex": hex::encode(msg_id_3),
            "session_id_hex": null,
            "payload_hex": "01",
            "auth_tag_hex": "ff00"
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 5
        },
        "description": "PAIR_REQUEST with auth_tag but no session_id"
    }));

    // 4. Present session_id, absent auth_tag
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0200,
        msg_id: msg_id_1,
        session_id: Some(session_id),
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-session-no-auth",
        "input": {
            "version": 1,
            "msg_type": "0x0200",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": hex::encode(session_id),
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 5
        },
        "description": "SESSION_RESUME with session_id but no auth_tag"
    }));

    // 5. Version 0 (edge case)
    let env = MessageEnvelope {
        version: 0,
        msg_type: 0x0400,
        msg_id: msg_id_1,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-version-zero",
        "input": {
            "version": 0,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "Edge case: version 0"
    }));

    // 6. Version 255 (max uint8)
    let env = MessageEnvelope {
        version: 255,
        msg_type: 0x0400,
        msg_id: msg_id_1,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-version-max",
        "input": {
            "version": 255,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "Edge case: version 255 (max uint8)"
    }));

    // 7. VERSION_NEGOTIATE (0x0001)
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0001,
        msg_id: msg_id_1,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-version-negotiate",
        "input": {
            "version": 1,
            "msg_type": "0x0001",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "VERSION_NEGOTIATE message type (0x0001)"
    }));

    // 8. Large payload (256 bytes)
    let large_payload: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id: msg_id_1,
        session_id: None,
        payload: large_payload.clone(),
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-large-payload",
        "input": {
            "version": 1,
            "msg_type": "0x0300",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": hex::encode(&large_payload),
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "DATA_MESSAGE with 256-byte payload"
    }));

    // 9. msg_id as all zeros
    let zero_id = [0u8; 16];
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id: zero_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-zero-msg-id",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(zero_id),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "HEARTBEAT with all-zero msg_id"
    }));

    // 10. msg_id as all 0xFF
    let ff_id = [0xFFu8; 16];
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id: ff_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-max-msg-id",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(ff_id),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "HEARTBEAT with all-0xFF msg_id"
    }));

    // 11. Payload containing nested CBOR (a CBOR map inside payload bytes)
    let nested_cbor = {
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(vec![
            (ciborium::Value::Text("hello".into()), ciborium::Value::Text("world".into())),
        ]), &mut buf).unwrap();
        buf
    };
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id: msg_id_1,
        session_id: None,
        payload: nested_cbor.clone(),
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-nested-cbor-payload",
        "input": {
            "version": 1,
            "msg_type": "0x0300",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": hex::encode(&nested_cbor),
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "DATA_MESSAGE with nested CBOR map as payload"
    }));

    // 12. Application-range message type (0xF000)
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0xF000,
        msg_id: msg_id_1,
        session_id: None,
        payload: vec![0x42],
        auth_tag: None,
    };
    vectors.push(json!({
        "id": "envelope-app-extension-type",
        "input": {
            "version": 1,
            "msg_type": "0xF000",
            "msg_id_hex": hex::encode(msg_id_1),
            "session_id_hex": null,
            "payload_hex": "42",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": encode_envelope(&env),
            "map_entry_count": 4
        },
        "description": "Application extension message type (0xF000)"
    }));

    let result = json!({
        "description": "CBOR envelope encoding test vectors for cairn wire protocol. All implementations must produce byte-identical output for deterministic CBOR encoding.",
        "vectors": vectors
    });

    let path = "conformance/vectors/cbor/envelope_encoding.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_cbor_message_types() {
    let msg_id: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let types: Vec<(u16, &str)> = vec![
        (0x0001, "VERSION_NEGOTIATE"),
        (0x0100, "PAIR_REQUEST"),
        (0x0101, "PAIR_CHALLENGE"),
        (0x0102, "PAIR_RESPONSE"),
        (0x0103, "PAIR_CONFIRM"),
        (0x0104, "PAIR_REJECT"),
        (0x0105, "PAIR_REVOKE"),
        (0x0200, "SESSION_RESUME"),
        (0x0201, "SESSION_RESUME_ACK"),
        (0x0202, "SESSION_EXPIRED"),
        (0x0203, "SESSION_CLOSE"),
        (0x0300, "DATA_MESSAGE"),
        (0x0301, "DATA_ACK"),
        (0x0302, "DATA_NACK"),
        (0x0303, "CHANNEL_INIT"),
        (0x0400, "HEARTBEAT"),
        (0x0401, "HEARTBEAT_ACK"),
        (0x0402, "TRANSPORT_MIGRATE"),
        (0x0403, "TRANSPORT_MIGRATE_ACK"),
        (0x0500, "ROUTE_REQUEST"),
        (0x0501, "ROUTE_RESPONSE"),
        (0x0502, "RELAY_DATA"),
        (0x0503, "RELAY_ACK"),
        (0x0600, "RENDEZVOUS_PUBLISH"),
        (0x0601, "RENDEZVOUS_QUERY"),
        (0x0602, "RENDEZVOUS_RESPONSE"),
        (0x0700, "FORWARD_REQUEST"),
        (0x0701, "FORWARD_ACK"),
        (0x0702, "FORWARD_DELIVER"),
        (0x0703, "FORWARD_PURGE"),
    ];

    let mut vectors = Vec::new();
    for (code, name) in &types {
        let env = MessageEnvelope {
            version: 1,
            msg_type: *code,
            msg_id,
            session_id: None,
            payload: vec![],
            auth_tag: None,
        };
        let category = cairn_p2p::protocol::message_category(*code);
        vectors.push(json!({
            "id": format!("msg-type-{}", name.to_lowercase()),
            "input": {
                "msg_type_code": format!("0x{:04X}", code),
                "msg_type_name": name,
                "version": 1,
                "msg_id_hex": hex::encode(msg_id),
                "payload_hex": ""
            },
            "expected_output": {
                "cbor_hex": encode_envelope(&env),
                "category": category
            },
            "description": format!("{} (0x{:04X}) — {} category", name, code, category)
        }));
    }

    let result = json!({
        "description": "CBOR encoding vectors for all 30 cairn message type codes. Each vector encodes a minimal envelope with the given message type.",
        "vectors": vectors
    });

    let path = "conformance/vectors/cbor/message_types.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_cbor_deterministic_encoding() {
    let msg_id: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let session_id: [u8; 32] = [0xAB; 32];

    let mut vectors = Vec::new();

    // 1. Keys must be sorted ascending (0,1,2,3,4,5)
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id,
        session_id: Some(session_id),
        payload: vec![0xFF],
        auth_tag: Some(vec![0x00, 0x01]),
    };
    let encoded = env.encode().unwrap();
    let encoded2 = env.encode_deterministic().unwrap();
    vectors.push(json!({
        "id": "deterministic-key-order",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": hex::encode(session_id),
            "payload_hex": "ff",
            "auth_tag_hex": "0001"
        },
        "expected_output": {
            "cbor_hex": hex::encode(&encoded),
            "encode_equals_encode_deterministic": encoded == encoded2,
            "key_order": [0, 1, 2, 3, 4, 5]
        },
        "description": "Full envelope: keys must appear in ascending order 0,1,2,3,4,5"
    }));

    // 2. Shortest integer encoding for small values
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0001,
        msg_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    let encoded = env.encode().unwrap();
    vectors.push(json!({
        "id": "deterministic-shortest-int-small",
        "input": {
            "version": 1,
            "msg_type": "0x0001",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": hex::encode(&encoded)
        },
        "description": "version=1 must use 1-byte CBOR encoding (0x01), msg_type=1 must use 1-byte (0x01)"
    }));

    // 3. Shortest integer encoding for uint16 values
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0703,
        msg_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    let encoded = env.encode().unwrap();
    vectors.push(json!({
        "id": "deterministic-shortest-int-u16",
        "input": {
            "version": 1,
            "msg_type": "0x0703",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": hex::encode(&encoded)
        },
        "description": "msg_type=0x0703 must use 2-byte CBOR encoding (0x19 0x0703)"
    }));

    // 4. Re-encoding produces byte-identical output
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id,
        session_id: Some(session_id),
        payload: vec![0xDE, 0xAD],
        auth_tag: Some(vec![0xBE, 0xEF]),
    };
    let enc1 = env.encode().unwrap();
    let enc2 = env.encode().unwrap();
    assert_eq!(enc1, enc2);
    vectors.push(json!({
        "id": "deterministic-re-encode-identical",
        "input": {
            "version": 1,
            "msg_type": "0x0300",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": hex::encode(session_id),
            "payload_hex": "dead",
            "auth_tag_hex": "beef"
        },
        "expected_output": {
            "cbor_hex": hex::encode(&enc1),
            "re_encode_identical": true
        },
        "description": "Encoding the same envelope twice must produce byte-identical CBOR"
    }));

    // 5. Minimal envelope deterministic (4 keys only)
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    let encoded = env.encode().unwrap();
    vectors.push(json!({
        "id": "deterministic-minimal-4-keys",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": null,
            "payload_hex": "",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": hex::encode(&encoded),
            "key_order": [0, 1, 2, 4]
        },
        "description": "Minimal envelope with 4 keys (0,1,2,4) — absent keys 3,5 must not appear"
    }));

    // 6. Byte string shortest encoding
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id,
        session_id: None,
        payload: vec![0x42],
        auth_tag: None,
    };
    let encoded = env.encode().unwrap();
    vectors.push(json!({
        "id": "deterministic-shortest-bstr",
        "input": {
            "version": 1,
            "msg_type": "0x0400",
            "msg_id_hex": hex::encode(msg_id),
            "session_id_hex": null,
            "payload_hex": "42",
            "auth_tag_hex": null
        },
        "expected_output": {
            "cbor_hex": hex::encode(&encoded)
        },
        "description": "1-byte payload must use shortest byte string encoding (0x41 0x42)"
    }));

    let result = json!({
        "description": "Deterministic CBOR encoding test vectors (RFC 8949 section 4.2). Verifies key ordering, shortest-form encoding, and re-encode stability.",
        "vectors": vectors
    });

    let path = "conformance/vectors/cbor/deterministic_encoding.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_cbor_fixture_files() {
    let msg_id: [u8; 16] = [
        0x01, 0x93, 0xA5, 0x4D, 0x00, 0x00, 0x70, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // HEARTBEAT 0x0400
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0400,
        msg_id,
        session_id: None,
        payload: vec![],
        auth_tag: None,
    };
    let path = "conformance/fixtures/cbor/0400.cbor";
    std::fs::write(path, env.encode().unwrap()).unwrap();
    eprintln!("Wrote {path}");

    // DATA_MESSAGE 0x0300
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0300,
        msg_id,
        session_id: Some([0xAB; 32]),
        payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        auth_tag: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let path = "conformance/fixtures/cbor/0300.cbor";
    std::fs::write(path, env.encode().unwrap()).unwrap();
    eprintln!("Wrote {path}");

    // PAIR_REQUEST 0x0100
    let env = MessageEnvelope {
        version: 1,
        msg_type: 0x0100,
        msg_id,
        session_id: None,
        payload: vec![0x01, 0x02, 0x03],
        auth_tag: None,
    };
    let path = "conformance/fixtures/cbor/0100.cbor";
    std::fs::write(path, env.encode().unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_ed25519() {
    // Use a known 32-byte seed
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_bytes();

    let seed2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    ];
    let signing_key2 = SigningKey::from_bytes(&seed2);
    let verifying_key2 = signing_key2.verifying_key();
    let public_bytes2 = verifying_key2.to_bytes();

    let mut vectors = Vec::new();

    // 1. Known keypair from seed
    vectors.push(json!({
        "id": "ed25519-keypair-1",
        "input": {
            "seed_hex": hex::encode(seed)
        },
        "expected_output": {
            "public_key_hex": hex::encode(public_bytes)
        },
        "description": "Ed25519 public key derived from known seed (RFC 8032 test vector 1)"
    }));

    // 2. Known keypair 2
    vectors.push(json!({
        "id": "ed25519-keypair-2",
        "input": {
            "seed_hex": hex::encode(seed2)
        },
        "expected_output": {
            "public_key_hex": hex::encode(public_bytes2)
        },
        "description": "Ed25519 public key derived from known seed 2"
    }));

    // 3. Sign empty message
    let msg_empty = b"";
    let sig_empty = signing_key.sign(msg_empty);
    vectors.push(json!({
        "id": "ed25519-sign-empty",
        "input": {
            "seed_hex": hex::encode(seed),
            "message_hex": ""
        },
        "expected_output": {
            "signature_hex": hex::encode(sig_empty.to_bytes())
        },
        "description": "Ed25519 signature of empty message"
    }));

    // 4. Sign known message
    let msg = b"cairn test message";
    let sig = signing_key.sign(msg);
    vectors.push(json!({
        "id": "ed25519-sign-known-message",
        "input": {
            "seed_hex": hex::encode(seed),
            "message_hex": hex::encode(msg)
        },
        "expected_output": {
            "signature_hex": hex::encode(sig.to_bytes()),
            "public_key_hex": hex::encode(public_bytes)
        },
        "description": "Ed25519 signature of 'cairn test message'"
    }));

    // 5. Deterministic: same key+message must give same signature
    let sig2 = signing_key.sign(msg);
    vectors.push(json!({
        "id": "ed25519-deterministic",
        "input": {
            "seed_hex": hex::encode(seed),
            "message_hex": hex::encode(msg)
        },
        "expected_output": {
            "signature_hex": hex::encode(sig.to_bytes()),
            "signature_is_deterministic": sig.to_bytes() == sig2.to_bytes()
        },
        "description": "Ed25519 signatures are deterministic: same key + message always produces same signature"
    }));

    // 6. Sign 72 bytes (longer message)
    let msg_long: Vec<u8> = (0..72).collect();
    let sig_long = signing_key.sign(&msg_long);
    vectors.push(json!({
        "id": "ed25519-sign-72bytes",
        "input": {
            "seed_hex": hex::encode(seed),
            "message_hex": hex::encode(&msg_long)
        },
        "expected_output": {
            "signature_hex": hex::encode(sig_long.to_bytes())
        },
        "description": "Ed25519 signature of 72-byte sequential message"
    }));

    let result = json!({
        "description": "Ed25519 test vectors for cairn identity keypair generation and signing. Uses ed25519-dalek as reference implementation.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/ed25519_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_x25519() {
    // Known static secrets
    let secret_a_bytes: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];
    let secret_b_bytes: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ];

    let secret_a = X25519Secret::from(secret_a_bytes);
    let public_a = X25519Public::from(&secret_a);
    let secret_b = X25519Secret::from(secret_b_bytes);
    let public_b = X25519Public::from(&secret_b);

    let shared_ab = secret_a.diffie_hellman(&public_b);
    let shared_ba = secret_b.diffie_hellman(&public_a);

    let mut vectors = Vec::new();

    // 1. Public key derivation from static secret A
    vectors.push(json!({
        "id": "x25519-pubkey-a",
        "input": {
            "static_secret_hex": hex::encode(secret_a_bytes)
        },
        "expected_output": {
            "public_key_hex": hex::encode(public_a.as_bytes())
        },
        "description": "X25519 public key derived from static secret A (RFC 7748 test value)"
    }));

    // 2. Public key derivation from static secret B
    vectors.push(json!({
        "id": "x25519-pubkey-b",
        "input": {
            "static_secret_hex": hex::encode(secret_b_bytes)
        },
        "expected_output": {
            "public_key_hex": hex::encode(public_b.as_bytes())
        },
        "description": "X25519 public key derived from static secret B"
    }));

    // 3. Shared secret computation (both directions must match)
    vectors.push(json!({
        "id": "x25519-shared-secret",
        "input": {
            "secret_a_hex": hex::encode(secret_a_bytes),
            "public_b_hex": hex::encode(public_b.as_bytes()),
            "secret_b_hex": hex::encode(secret_b_bytes),
            "public_a_hex": hex::encode(public_a.as_bytes())
        },
        "expected_output": {
            "shared_secret_hex": hex::encode(shared_ab.as_bytes()),
            "commutative": shared_ab.as_bytes() == shared_ba.as_bytes()
        },
        "description": "X25519 shared secret: DH(a, B) == DH(b, A)"
    }));

    // 4. Another keypair with all-zeros (testing edge behavior)
    let secret_c_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        b
    };
    let secret_c = X25519Secret::from(secret_c_bytes);
    let public_c = X25519Public::from(&secret_c);
    let shared_ac = secret_a.diffie_hellman(&public_c);

    vectors.push(json!({
        "id": "x25519-shared-secret-2",
        "input": {
            "secret_a_hex": hex::encode(secret_a_bytes),
            "public_c_hex": hex::encode(public_c.as_bytes()),
            "secret_c_hex": hex::encode(secret_c_bytes),
            "public_a_hex": hex::encode(public_a.as_bytes())
        },
        "expected_output": {
            "shared_secret_a_c_hex": hex::encode(shared_ac.as_bytes()),
            "public_c_hex": hex::encode(public_c.as_bytes())
        },
        "description": "X25519 shared secret with minimal secret (0x01 followed by zeros)"
    }));

    let result = json!({
        "description": "X25519 key exchange test vectors for cairn. Uses x25519-dalek as reference implementation.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/x25519_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_hkdf() {
    let mut vectors = Vec::new();

    // Known IKM for all cairn vectors
    let ikm: [u8; 32] = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];
    let salt: [u8; 32] = [0u8; 32];

    // Cairn domain separation constants
    let cairn_infos = vec![
        ("cairn-session-key-v1", "Session key derivation"),
        ("cairn-rendezvous-id-v1", "Rendezvous ID derivation"),
        ("cairn-sas-derivation-v1", "SAS code derivation (generic)"),
        ("cairn-chain-key-v1", "Double Ratchet chain key"),
        ("cairn-message-key-v1", "Double Ratchet message key"),
        ("cairn-sas-numeric-v1", "SAS numeric code derivation"),
        ("cairn-sas-emoji-v1", "SAS emoji derivation"),
        ("cairn-pairing-session-key-v1", "Pairing session key from SPAKE2"),
        ("cairn-pairing-key-confirm-v1", "Pairing key confirmation HMAC"),
        ("cairn-root-chain-v1", "Double Ratchet root chain"),
        ("cairn-chain-advance-v1", "Double Ratchet chain advance"),
        ("cairn-msg-encrypt-v1", "Double Ratchet message encryption"),
    ];

    for (info, desc) in &cairn_infos {
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm).unwrap();

        vectors.push(json!({
            "id": format!("hkdf-{}", info.replace("cairn-", "").replace("-v1", "")),
            "input": {
                "ikm_hex": hex::encode(ikm),
                "salt_hex": hex::encode(salt),
                "info": info,
                "output_length": 32
            },
            "expected_output": {
                "okm_hex": hex::encode(okm)
            },
            "description": format!("HKDF-SHA256 with cairn info '{}' — {}", info, desc)
        }));
    }

    // RFC 5869 Test Case 1
    {
        let ikm_rfc: Vec<u8> = vec![0x0b; 22];
        let salt_rfc = hex::decode("000102030405060708090a0b0c").unwrap();
        let info_rfc = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&salt_rfc), &ikm_rfc);
        let mut okm = [0u8; 42];
        hk.expand(&info_rfc, &mut okm).unwrap();

        vectors.push(json!({
            "id": "hkdf-rfc5869-case1",
            "input": {
                "ikm_hex": hex::encode(&ikm_rfc),
                "salt_hex": hex::encode(&salt_rfc),
                "info_hex": hex::encode(&info_rfc),
                "output_length": 42
            },
            "expected_output": {
                "okm_hex": hex::encode(okm)
            },
            "description": "RFC 5869 Test Case 1 (SHA-256)"
        }));
    }

    // RFC 5869 Test Case 2
    {
        let ikm_rfc: Vec<u8> = (0x00..=0x4fu8).collect();
        let salt_rfc: Vec<u8> = (0x60..=0xafu8).collect();
        let info_rfc: Vec<u8> = (0xb0..=0xffu8).collect();
        let hk = Hkdf::<Sha256>::new(Some(&salt_rfc), &ikm_rfc);
        let mut okm = [0u8; 82];
        hk.expand(&info_rfc, &mut okm).unwrap();

        vectors.push(json!({
            "id": "hkdf-rfc5869-case2",
            "input": {
                "ikm_hex": hex::encode(&ikm_rfc),
                "salt_hex": hex::encode(&salt_rfc),
                "info_hex": hex::encode(&info_rfc),
                "output_length": 82
            },
            "expected_output": {
                "okm_hex": hex::encode(okm)
            },
            "description": "RFC 5869 Test Case 2 (SHA-256)"
        }));
    }

    // RFC 5869 Test Case 3 (zero-length salt and info)
    {
        let ikm_rfc: Vec<u8> = vec![0x0b; 22];
        let hk = Hkdf::<Sha256>::new(None, &ikm_rfc);
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();

        vectors.push(json!({
            "id": "hkdf-rfc5869-case3",
            "input": {
                "ikm_hex": hex::encode(&ikm_rfc),
                "salt_hex": "",
                "info_hex": "",
                "output_length": 42
            },
            "expected_output": {
                "okm_hex": hex::encode(okm)
            },
            "description": "RFC 5869 Test Case 3 (SHA-256, zero-length salt and info)"
        }));
    }

    let result = json!({
        "description": "HKDF-SHA256 test vectors for all cairn domain separation constants plus RFC 5869 reference vectors.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/hkdf_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_aead() {
    let mut vectors = Vec::new();

    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce_12: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ];
    let plaintext = b"cairn test data for AEAD";
    let aad = b"cairn-aad-v1";

    // AES-256-GCM vectors
    {
        use aes_gcm::aead::Payload;
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = AesNonce::from_slice(&nonce_12);

        // With AAD
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad }).unwrap();
        vectors.push(json!({
            "id": "aes256gcm-encrypt-with-aad",
            "input": {
                "algorithm": "AES-256-GCM",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": hex::encode(plaintext),
                "aad_hex": hex::encode(aad)
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ciphertext),
                "ciphertext_len": plaintext.len(),
                "tag_len": 16
            },
            "description": "AES-256-GCM encryption with AAD"
        }));

        // Without AAD
        let ciphertext_no_aad = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &[] }).unwrap();
        vectors.push(json!({
            "id": "aes256gcm-encrypt-no-aad",
            "input": {
                "algorithm": "AES-256-GCM",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": hex::encode(plaintext),
                "aad_hex": ""
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ciphertext_no_aad)
            },
            "description": "AES-256-GCM encryption without AAD"
        }));

        // Empty plaintext
        let ct_empty = cipher.encrypt(nonce, Payload { msg: &[], aad }).unwrap();
        vectors.push(json!({
            "id": "aes256gcm-empty-plaintext",
            "input": {
                "algorithm": "AES-256-GCM",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": "",
                "aad_hex": hex::encode(aad)
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ct_empty)
            },
            "description": "AES-256-GCM encryption of empty plaintext (tag only)"
        }));
    }

    // ChaCha20-Poly1305 vectors
    {
        use chacha20poly1305::aead::Payload;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = ChaNonce::from_slice(&nonce_12);

        // With AAD
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad }).unwrap();
        vectors.push(json!({
            "id": "chacha20poly1305-encrypt-with-aad",
            "input": {
                "algorithm": "ChaCha20-Poly1305",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": hex::encode(plaintext),
                "aad_hex": hex::encode(aad)
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ciphertext),
                "ciphertext_len": plaintext.len(),
                "tag_len": 16
            },
            "description": "ChaCha20-Poly1305 encryption with AAD"
        }));

        // Without AAD
        let ct_no_aad = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &[] }).unwrap();
        vectors.push(json!({
            "id": "chacha20poly1305-encrypt-no-aad",
            "input": {
                "algorithm": "ChaCha20-Poly1305",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": hex::encode(plaintext),
                "aad_hex": ""
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ct_no_aad)
            },
            "description": "ChaCha20-Poly1305 encryption without AAD"
        }));

        // Empty plaintext
        let ct_empty = cipher.encrypt(nonce, Payload { msg: &[], aad }).unwrap();
        vectors.push(json!({
            "id": "chacha20poly1305-empty-plaintext",
            "input": {
                "algorithm": "ChaCha20-Poly1305",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_12),
                "plaintext_hex": "",
                "aad_hex": hex::encode(aad)
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ct_empty)
            },
            "description": "ChaCha20-Poly1305 encryption of empty plaintext (tag only)"
        }));
    }

    // Different nonce
    let nonce_2: [u8; 12] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    {
        use aes_gcm::aead::Payload;
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = AesNonce::from_slice(&nonce_2);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad }).unwrap();
        vectors.push(json!({
            "id": "aes256gcm-different-nonce",
            "input": {
                "algorithm": "AES-256-GCM",
                "key_hex": hex::encode(key),
                "nonce_hex": hex::encode(nonce_2),
                "plaintext_hex": hex::encode(plaintext),
                "aad_hex": hex::encode(aad)
            },
            "expected_output": {
                "ciphertext_and_tag_hex": hex::encode(&ciphertext)
            },
            "description": "AES-256-GCM with different nonce produces different ciphertext"
        }));
    }

    let result = json!({
        "description": "AEAD test vectors for AES-256-GCM and ChaCha20-Poly1305 used in cairn session encryption.",
        "vectors": vectors
    });

    let path = "conformance/vectors/crypto/aead_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_pairing_pin_codes() {
    let mut vectors = Vec::new();

    // The Crockford Base32 alphabet
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    // 1. Deterministic pin from known entropy bytes
    // 5 bytes of entropy = 40 bits = 8 Crockford Base32 chars
    let entropy_1: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];
    let pin_1 = bytes_to_crockford(&entropy_1);
    vectors.push(json!({
        "id": "pin-from-zero-entropy",
        "input": {
            "entropy_hex": hex::encode(entropy_1),
            "entropy_bits": 40
        },
        "expected_output": {
            "pin_raw": &pin_1,
            "pin_formatted": format!("{}-{}", &pin_1[..4], &pin_1[4..])
        },
        "description": "PIN generated from all-zero entropy (5 bytes)"
    }));

    // 2. Max entropy
    let entropy_2: [u8; 5] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let pin_2 = bytes_to_crockford(&entropy_2);
    vectors.push(json!({
        "id": "pin-from-max-entropy",
        "input": {
            "entropy_hex": hex::encode(entropy_2),
            "entropy_bits": 40
        },
        "expected_output": {
            "pin_raw": &pin_2,
            "pin_formatted": format!("{}-{}", &pin_2[..4], &pin_2[4..])
        },
        "description": "PIN generated from max entropy (5 bytes of 0xFF)"
    }));

    // 3-6. Various entropy values
    let test_entropies: Vec<([u8; 5], &str)> = vec![
        ([0x01, 0x23, 0x45, 0x67, 0x89], "sequential-bytes"),
        ([0xAB, 0xCD, 0xEF, 0x01, 0x23], "mixed-bytes"),
        ([0x80, 0x00, 0x00, 0x00, 0x00], "high-bit-set"),
        ([0x55, 0xAA, 0x55, 0xAA, 0x55], "alternating-bits"),
    ];
    for (ent, label) in &test_entropies {
        let pin = bytes_to_crockford(ent);
        vectors.push(json!({
            "id": format!("pin-from-{}", label),
            "input": {
                "entropy_hex": hex::encode(ent),
                "entropy_bits": 40
            },
            "expected_output": {
                "pin_raw": &pin,
                "pin_formatted": format!("{}-{}", &pin[..4], &pin[4..])
            },
            "description": format!("PIN from entropy: {}", label)
        }));
    }

    // 7-10. Normalization vectors
    let normalization_cases = vec![
        ("abcd-ef01", "ABCD-EF01", "lowercase to uppercase"),
        ("ABCD-EFOl", "ABCD-EF01", "O->0, l->1"),
        ("aBcD-eFiL", "ABCD-EF11", "mixed case with i->1, L->1"),
        ("0oO0-1iIl", "0000-1111", "all ambiguous character normalization"),
    ];
    for (input, normalized, desc) in &normalization_cases {
        vectors.push(json!({
            "id": format!("pin-normalize-{}", desc.replace(" ", "-").replace(",", "").replace("->", "to")),
            "input": {
                "pin_raw": input
            },
            "expected_output": {
                "normalized": normalized
            },
            "description": format!("PIN normalization: {}", desc)
        }));
    }

    // 11-12. Invalid pin rejection
    vectors.push(json!({
        "id": "pin-invalid-too-short",
        "input": {
            "pin_raw": "ABCD-EF0"
        },
        "expected_output": {
            "valid": false,
            "error": "wrong_length"
        },
        "description": "Invalid PIN: too short (7 chars instead of 8)"
    }));

    vectors.push(json!({
        "id": "pin-invalid-bad-chars",
        "input": {
            "pin_raw": "ABCD-EFU0"
        },
        "expected_output": {
            "valid": false,
            "error": "invalid_character"
        },
        "description": "Invalid PIN: 'U' is not in Crockford Base32 alphabet"
    }));

    let result = json!({
        "description": "PIN code test vectors for cairn pairing. Covers deterministic generation from known entropy, Crockford Base32 encoding, normalization, and validation.",
        "vectors": vectors
    });

    let path = "conformance/vectors/pairing/pin_code_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

/// Convert 5 bytes (40 bits) to 8-char Crockford Base32 string
fn bytes_to_crockford(bytes: &[u8; 5]) -> String {
    let alphabet: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    // 40 bits -> 8 groups of 5 bits
    let val: u64 = ((bytes[0] as u64) << 32)
        | ((bytes[1] as u64) << 24)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 8)
        | (bytes[4] as u64);

    let mut result = String::with_capacity(8);
    for i in (0..8).rev() {
        let idx = ((val >> (i * 5)) & 0x1F) as usize;
        result.push(alphabet[idx] as char);
    }
    result
}

fn gen_pairing_crockford_base32() {
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    let mut vectors = Vec::new();

    // 1. All 32 valid symbols
    vectors.push(json!({
        "id": "crockford-alphabet",
        "input": {},
        "expected_output": {
            "alphabet": alphabet,
            "size": 32
        },
        "description": "Complete Crockford Base32 alphabet (excludes I, L, O, U)"
    }));

    // 2-5. Encode/decode roundtrip with known values
    let roundtrip_cases: Vec<([u8; 5], &str)> = vec![
        ([0x00, 0x00, 0x00, 0x00, 0x00], "all zeros"),
        ([0xFF, 0xFF, 0xFF, 0xFF, 0xFF], "all ones"),
        ([0x01, 0x23, 0x45, 0x67, 0x89], "sequential"),
        ([0x80, 0x40, 0x20, 0x10, 0x08], "power-of-two bits"),
    ];
    for (bytes, label) in &roundtrip_cases {
        let encoded = bytes_to_crockford(bytes);
        vectors.push(json!({
            "id": format!("crockford-roundtrip-{}", label.replace(" ", "-")),
            "input": {
                "bytes_hex": hex::encode(bytes)
            },
            "expected_output": {
                "encoded": encoded
            },
            "description": format!("Crockford Base32 encode/decode roundtrip: {}", label)
        }));
    }

    // 6. Case insensitivity
    vectors.push(json!({
        "id": "crockford-case-insensitive",
        "input": {
            "lowercase": "abcdefgh",
            "uppercase": "ABCDEFGH"
        },
        "expected_output": {
            "equivalent": true
        },
        "description": "Crockford Base32 is case-insensitive: lowercase and uppercase represent same value"
    }));

    // 7. Ambiguous character substitution table
    vectors.push(json!({
        "id": "crockford-ambiguous-chars",
        "input": {
            "substitutions": [
                {"from": "i", "to": "1"},
                {"from": "I", "to": "1"},
                {"from": "l", "to": "1"},
                {"from": "L", "to": "1"},
                {"from": "o", "to": "0"},
                {"from": "O", "to": "0"}
            ]
        },
        "expected_output": {
            "normalized": true
        },
        "description": "Crockford Base32 ambiguous character normalization: i/I/l/L -> 1, o/O -> 0"
    }));

    // 8. Excluded characters
    vectors.push(json!({
        "id": "crockford-excluded-chars",
        "input": {
            "excluded_from_alphabet": ["I", "L", "O", "U"],
            "reason": "I/L confused with 1, O confused with 0, U excluded for profanity avoidance"
        },
        "expected_output": {
            "valid": false
        },
        "description": "Characters I, L, O, U are excluded from the Crockford Base32 encoding alphabet"
    }));

    // 9. Single-character values (0-31)
    let mut single_char_map = Vec::new();
    for (i, ch) in alphabet.chars().enumerate() {
        single_char_map.push(json!({
            "value": i,
            "character": ch.to_string()
        }));
    }
    vectors.push(json!({
        "id": "crockford-value-mapping",
        "input": {},
        "expected_output": {
            "mapping": single_char_map
        },
        "description": "Complete value-to-character mapping for all 32 Crockford Base32 symbols"
    }));

    let result = json!({
        "description": "Crockford Base32 encoding test vectors for cairn PIN code system.",
        "vectors": vectors
    });

    let path = "conformance/vectors/pairing/crockford_base32.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_pairing_sas() {
    let mut vectors = Vec::new();

    let emoji_table = [
        "dog", "cat", "fish", "bird", "bear", "lion", "wolf", "fox",
        "deer", "owl", "bee", "ant", "star", "moon", "sun", "fire",
        "tree", "leaf", "rose", "wave", "rain", "snow", "bolt", "wind",
        "rock", "gem", "bell", "key", "lock", "flag", "book", "pen",
        "cup", "hat", "shoe", "ring", "cake", "gift", "lamp", "gear",
        "ship", "car", "bike", "drum", "horn", "harp", "dice", "coin",
        "map", "tent", "crown", "sword", "shield", "bow", "axe", "hammer",
        "anchor", "wheel", "clock", "heart", "skull", "ghost", "robot", "alien",
    ];

    // Test shared secrets
    let shared_secrets: Vec<([u8; 32], &str)> = vec![
        ([0xAA; 32], "all-0xAA"),
        ([0x00; 32], "all-zeros"),
        ({
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() { *b = i as u8; }
            s
        }, "sequential"),
    ];

    for (secret, label) in &shared_secrets {
        // Numeric SAS
        {
            let hk = Hkdf::<Sha256>::new(None, secret);
            let mut okm = [0u8; 4];
            hk.expand(b"cairn-sas-numeric-v1", &mut okm).unwrap();
            let value = u32::from_be_bytes(okm);
            let code = value % 1_000_000;
            let code_str = format!("{:06}", code);

            vectors.push(json!({
                "id": format!("sas-numeric-{}", label),
                "input": {
                    "shared_secret_hex": hex::encode(secret),
                    "info": "cairn-sas-numeric-v1",
                    "salt": null
                },
                "expected_output": {
                    "sas_bytes_hex": hex::encode(okm),
                    "sas_u32": value,
                    "numeric_code": code_str
                },
                "description": format!("Numeric SAS derivation from shared secret ({})", label)
            }));
        }

        // Emoji SAS
        {
            let hk = Hkdf::<Sha256>::new(None, secret);
            let mut okm = [0u8; 8];
            hk.expand(b"cairn-sas-emoji-v1", &mut okm).unwrap();

            let mut emoji_indices = Vec::new();
            let mut emojis = Vec::new();
            for i in 0..4 {
                let val = u16::from_be_bytes([okm[i * 2], okm[i * 2 + 1]]);
                let idx = (val % 64) as usize;
                emoji_indices.push(idx);
                emojis.push(emoji_table[idx]);
            }

            vectors.push(json!({
                "id": format!("sas-emoji-{}", label),
                "input": {
                    "shared_secret_hex": hex::encode(secret),
                    "info": "cairn-sas-emoji-v1",
                    "salt": null
                },
                "expected_output": {
                    "sas_bytes_hex": hex::encode(okm),
                    "emoji_indices": emoji_indices,
                    "emojis": emojis
                },
                "description": format!("Emoji SAS derivation from shared secret ({})", label)
            }));
        }
    }

    // Both parties must derive identical SAS from same input
    let shared = [0x42u8; 32];
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut okm_num = [0u8; 4];
    hk.expand(b"cairn-sas-numeric-v1", &mut okm_num).unwrap();
    let value = u32::from_be_bytes(okm_num);
    let code = format!("{:06}", value % 1_000_000);

    vectors.push(json!({
        "id": "sas-both-parties-identical",
        "input": {
            "shared_secret_hex": hex::encode(shared),
            "info": "cairn-sas-numeric-v1",
            "note": "Both initiator and responder compute SAS from the same shared secret and info string"
        },
        "expected_output": {
            "numeric_code": code,
            "both_parties_match": true
        },
        "description": "Both peers derive identical SAS code from the same shared secret"
    }));

    let result = json!({
        "description": "SAS (Short Authentication String) derivation test vectors. Covers numeric (6-digit) and emoji (4-emoji) variants.",
        "vectors": vectors
    });

    let path = "conformance/vectors/pairing/sas_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_protocol_version_negotiation() {
    let mut vectors = Vec::new();

    // 1. Both support v1
    vectors.push(json!({
        "id": "version-both-v1",
        "input": {
            "initiator_versions": [1],
            "responder_versions": [1]
        },
        "expected_output": {
            "selected_version": 1,
            "error": null
        },
        "description": "Both peers support only v1"
    }));

    // 2. Initiator higher version, both support v1
    vectors.push(json!({
        "id": "version-initiator-higher",
        "input": {
            "initiator_versions": [3, 2, 1],
            "responder_versions": [1]
        },
        "expected_output": {
            "selected_version": 1,
            "error": null
        },
        "description": "Initiator supports v3,v2,v1 but responder only v1 — select v1"
    }));

    // 3. Highest mutual version selected
    vectors.push(json!({
        "id": "version-highest-mutual",
        "input": {
            "initiator_versions": [5, 3, 1],
            "responder_versions": [4, 3, 2, 1]
        },
        "expected_output": {
            "selected_version": 3,
            "error": null
        },
        "description": "Select highest mutually supported version (v3)"
    }));

    // 4. No common version (error case)
    vectors.push(json!({
        "id": "version-no-common",
        "input": {
            "initiator_versions": [3, 2],
            "responder_versions": [5, 4]
        },
        "expected_output": {
            "selected_version": null,
            "error": "VersionMismatch"
        },
        "description": "No common version — must return VersionMismatch error"
    }));

    // 5. Empty initiator version list
    vectors.push(json!({
        "id": "version-empty-initiator",
        "input": {
            "initiator_versions": [],
            "responder_versions": [1]
        },
        "expected_output": {
            "selected_version": null,
            "error": "VersionMismatch"
        },
        "description": "Empty initiator version list — must return error"
    }));

    // 6. Empty responder version list
    vectors.push(json!({
        "id": "version-empty-responder",
        "input": {
            "initiator_versions": [1],
            "responder_versions": []
        },
        "expected_output": {
            "selected_version": null,
            "error": "VersionMismatch"
        },
        "description": "Empty responder version list — must return error"
    }));

    // 7. Single version match
    vectors.push(json!({
        "id": "version-single-match",
        "input": {
            "initiator_versions": [2],
            "responder_versions": [2]
        },
        "expected_output": {
            "selected_version": 2,
            "error": null
        },
        "description": "Both peers support exactly one version and it matches"
    }));

    // 8. Many versions, one match
    vectors.push(json!({
        "id": "version-many-one-match",
        "input": {
            "initiator_versions": [10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            "responder_versions": [20, 19, 18, 17, 5]
        },
        "expected_output": {
            "selected_version": 5,
            "error": null
        },
        "description": "Many versions offered, only v5 in common"
    }));

    let result = json!({
        "description": "Version negotiation test vectors. The select_version algorithm iterates the initiator's versions (highest first) and returns the first match in the responder's list.",
        "vectors": vectors
    });

    let path = "conformance/vectors/protocol/version_negotiation.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_protocol_rendezvous_id() {
    let mut vectors = Vec::new();

    let shared_secret: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    // Rendezvous ID is HKDF with info "cairn-rendezvous-id-v1"
    // Salt = epoch timestamp (floored to 24h boundary) as big-endian u64 bytes

    // Epoch T = 1700000000 (2023-11-14 22:13:20 UTC)
    // 24h = 86400 seconds
    // Floor: 1700000000 / 86400 * 86400 = 1699920000
    let epoch_t: u64 = 1700000000;
    let day_seconds: u64 = 86400;
    let floored_t = (epoch_t / day_seconds) * day_seconds;
    let floored_t_next = floored_t + day_seconds;

    // 1. Known shared secret + epoch -> rendezvous ID
    {
        let salt = floored_t.to_be_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
        let mut rid = [0u8; 32];
        hk.expand(b"cairn-rendezvous-id-v1", &mut rid).unwrap();

        vectors.push(json!({
            "id": "rendezvous-known-epoch",
            "input": {
                "shared_secret_hex": hex::encode(shared_secret),
                "epoch_timestamp": epoch_t,
                "floored_epoch": floored_t,
                "day_seconds": day_seconds,
                "info": "cairn-rendezvous-id-v1"
            },
            "expected_output": {
                "salt_hex": hex::encode(salt),
                "rendezvous_id_hex": hex::encode(rid)
            },
            "description": "Rendezvous ID derived from known shared secret and epoch (floored to 24h boundary)"
        }));
    }

    // 2. Rotation boundary: next 24h period produces different ID
    {
        let salt_next = floored_t_next.to_be_bytes();
        let hk_next = Hkdf::<Sha256>::new(Some(&salt_next), &shared_secret);
        let mut rid_next = [0u8; 32];
        hk_next.expand(b"cairn-rendezvous-id-v1", &mut rid_next).unwrap();

        let salt_curr = floored_t.to_be_bytes();
        let hk_curr = Hkdf::<Sha256>::new(Some(&salt_curr), &shared_secret);
        let mut rid_curr = [0u8; 32];
        hk_curr.expand(b"cairn-rendezvous-id-v1", &mut rid_curr).unwrap();

        vectors.push(json!({
            "id": "rendezvous-rotation-boundary",
            "input": {
                "shared_secret_hex": hex::encode(shared_secret),
                "current_epoch_floored": floored_t,
                "next_epoch_floored": floored_t_next
            },
            "expected_output": {
                "current_rendezvous_id_hex": hex::encode(rid_curr),
                "next_rendezvous_id_hex": hex::encode(rid_next),
                "ids_are_different": rid_curr != rid_next
            },
            "description": "Rotation: IDs from adjacent 24h periods must be different"
        }));
    }

    // 3. Overlap window (1h): during the overlap both current and previous IDs are valid
    {
        let overlap_seconds: u64 = 3600; // 1 hour
        let overlap_timestamp = floored_t_next + 1800; // 30 min into new period

        let salt_new = floored_t_next.to_be_bytes();
        let salt_old = floored_t.to_be_bytes();

        let hk_new = Hkdf::<Sha256>::new(Some(&salt_new), &shared_secret);
        let mut rid_new = [0u8; 32];
        hk_new.expand(b"cairn-rendezvous-id-v1", &mut rid_new).unwrap();

        let hk_old = Hkdf::<Sha256>::new(Some(&salt_old), &shared_secret);
        let mut rid_old = [0u8; 32];
        hk_old.expand(b"cairn-rendezvous-id-v1", &mut rid_old).unwrap();

        vectors.push(json!({
            "id": "rendezvous-overlap-window",
            "input": {
                "shared_secret_hex": hex::encode(shared_secret),
                "timestamp": overlap_timestamp,
                "overlap_duration_seconds": overlap_seconds,
                "current_period_start": floored_t_next,
                "previous_period_start": floored_t
            },
            "expected_output": {
                "current_rendezvous_id_hex": hex::encode(rid_new),
                "previous_rendezvous_id_hex": hex::encode(rid_old),
                "both_valid_during_overlap": true
            },
            "description": "During 1h overlap window after rotation, both current and previous rendezvous IDs are valid"
        }));
    }

    // 4. Clock tolerance (5 minutes)
    {
        let tolerance_seconds: u64 = 300; // 5 minutes
        let near_boundary = floored_t_next - 120; // 2 minutes before boundary
        let after_boundary = floored_t_next + 120; // 2 minutes after boundary

        vectors.push(json!({
            "id": "rendezvous-clock-tolerance",
            "input": {
                "shared_secret_hex": hex::encode(shared_secret),
                "clock_tolerance_seconds": tolerance_seconds,
                "near_boundary_timestamp": near_boundary,
                "after_boundary_timestamp": after_boundary,
                "period_boundary": floored_t_next
            },
            "expected_output": {
                "note": "Peers with clocks within 5-minute tolerance of the rotation boundary should check both current and previous rendezvous IDs",
                "tolerance_window": format!("{} seconds", tolerance_seconds)
            },
            "description": "Clock tolerance: peers within 5 minutes of rotation boundary should try both period IDs"
        }));
    }

    // 5. Different shared secret produces different ID
    {
        let secret2: [u8; 32] = [0xFF; 32];
        let salt = floored_t.to_be_bytes();

        let hk1 = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
        let mut rid1 = [0u8; 32];
        hk1.expand(b"cairn-rendezvous-id-v1", &mut rid1).unwrap();

        let hk2 = Hkdf::<Sha256>::new(Some(&salt), &secret2);
        let mut rid2 = [0u8; 32];
        hk2.expand(b"cairn-rendezvous-id-v1", &mut rid2).unwrap();

        vectors.push(json!({
            "id": "rendezvous-different-secrets",
            "input": {
                "shared_secret_1_hex": hex::encode(shared_secret),
                "shared_secret_2_hex": hex::encode(secret2),
                "epoch_floored": floored_t
            },
            "expected_output": {
                "rendezvous_id_1_hex": hex::encode(rid1),
                "rendezvous_id_2_hex": hex::encode(rid2),
                "ids_are_different": rid1 != rid2
            },
            "description": "Different shared secrets produce different rendezvous IDs for the same epoch"
        }));
    }

    let result = json!({
        "description": "Rendezvous ID derivation test vectors. Rendezvous IDs use HKDF-SHA256 with shared secret as IKM, epoch timestamp (floored to 24h boundary, big-endian u64) as salt, and 'cairn-rendezvous-id-v1' as info.",
        "vectors": vectors
    });

    let path = "conformance/vectors/protocol/rendezvous_id_vectors.json";
    std::fs::write(path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    eprintln!("Wrote {path}");
}

fn gen_crypto_spake2() {
    let mut vectors = Vec::new();

    // SPAKE2 uses random ephemeral values internally, so we can't produce
    // deterministic byte-level outputs. Instead we document the protocol
    // parameters and test properties that conformance runners must verify.

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

    // 2. Same password -> same derived key (property test)
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

    // 3. Different password -> different key (property test)
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

    // 4. Key confirmation HMAC derivation
    {
        // Given a known shared key, derive the confirmation HMAC
        let shared_key = [0x42u8; 32];
        let hk = Hkdf::<Sha256>::new(None, &shared_key);
        let mut confirm_key = [0u8; 32];
        hk.expand(b"cairn-pairing-key-confirm-v1", &mut confirm_key).unwrap();

        // HMAC-SHA256(confirm_key, "initiator")
        type HmacSha256 = Hmac<Sha256>;
        let mut mac_init = <HmacSha256 as KeyInit>::new_from_slice(&confirm_key).unwrap();
        mac_init.update(b"initiator");
        let init_confirm = mac_init.finalize().into_bytes();

        // HMAC-SHA256(confirm_key, "responder")
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
        let raw_spake2_output = [0xAA; 32];
        let salt = [0u8; 32]; // empty salt for this test
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

    // Noise XX uses random ephemeral keys, so full deterministic handshake
    // transcripts are not possible without internal randomness injection.
    // We document protocol parameters, message sizes, and deterministic
    // sub-operations (mix_hash, mix_key, session key derivation).

    // 1. Protocol parameters
    let protocol_name = b"Noise_XX_25519_ChaChaPoly_SHA256";
    let mut initial_hash = [0u8; 32];
    initial_hash[..protocol_name.len()].copy_from_slice(protocol_name);

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
        use sha2::{Sha256, Digest};
        let h0 = initial_hash;
        // mix_hash(h, data) = SHA-256(h || data)
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
        // mix_key uses HKDF(ikm, salt=ck, info="", output=64 bytes)
        // first 32 bytes = new chaining key, next 32 = encryption key
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

    // 6. Handshake properties (non-deterministic, property-based)
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

    // Double Ratchet KDF operations are deterministic given known inputs.
    // We can generate vectors for kdf_rk and kdf_ck.

    // 1. Root chain KDF (kdf_rk): HKDF(dh_output, salt=root_key, info="cairn-root-chain-v1") -> 64 bytes
    // First 32 = new root key, next 32 = new chain key
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

    // 3. Chain advance KDF (kdf_ck): HKDF(chain_key, salt=None, info="cairn-chain-advance-v1") -> new_chain_key
    // Message key: HKDF(chain_key, salt=None, info="cairn-msg-encrypt-v1") -> message_key
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

    // 4. Send chain progression: 3 steps from known initial chain key
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

    // 5. Nonce derivation from message key and message number
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

    // 6. Ratchet configuration defaults
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

    // 7. Ratchet header structure
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

    // 8. Property: out-of-order delivery with skipped keys
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
