//! Pairing flow integration tests.

use cairn_p2p::identity::LocalIdentity;
use cairn_p2p::pairing::mechanisms::{
    PairingLinkMechanism, PairingMechanism, PairingPayload, PinCodeMechanism, PskMechanism,
    QrCodeMechanism,
};
use cairn_p2p::{ApiNode, CairnConfig, StorageBackend};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn test_payload() -> PairingPayload {
    let id = LocalIdentity::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    PairingPayload {
        peer_id: id.peer_id().clone(),
        nonce: [0xAB; 16],
        pake_credential: vec![0x42; 32],
        connection_hints: None,
        created_at: now,
        expires_at: now + 300,
    }
}

#[test]
fn qr_code_generate_and_consume_roundtrip() {
    let mechanism = QrCodeMechanism::with_ttl(Duration::from_secs(300));
    let payload = test_payload();

    let raw = mechanism.generate_payload(&payload).unwrap();
    assert!(!raw.is_empty());
    assert!(raw.len() <= 256, "QR payload must be <= 256 bytes");

    let restored = mechanism.consume_payload(&raw).unwrap();
    assert_eq!(restored.peer_id, payload.peer_id);
    assert_eq!(restored.nonce, payload.nonce);
    assert_eq!(restored.pake_credential, payload.pake_credential);
}

#[test]
fn pin_code_generate_and_consume_roundtrip() {
    let mechanism = PinCodeMechanism::with_ttl(Duration::from_secs(300));
    let payload = test_payload();

    let raw = mechanism.generate_payload(&payload).unwrap();
    let pin_str = String::from_utf8(raw.clone()).unwrap();

    assert_eq!(pin_str.len(), 9);
    assert_eq!(pin_str.as_bytes()[4], b'-');

    for ch in pin_str.replace('-', "").chars() {
        assert!(
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
            "invalid Crockford char: {ch}"
        );
    }
}

#[test]
fn pairing_link_generate_and_consume_roundtrip() {
    let mechanism = PairingLinkMechanism::new("cairn", Duration::from_secs(300));
    let payload = test_payload();

    let raw = mechanism.generate_payload(&payload).unwrap();
    let uri = String::from_utf8(raw.clone()).unwrap();

    assert!(uri.starts_with("cairn://pair?"));
    assert!(uri.contains("pid="));
    assert!(uri.contains("nonce="));
    assert!(uri.contains("pake="));

    let restored = mechanism.consume_payload(&raw).unwrap();
    assert_eq!(restored.peer_id, payload.peer_id);
}

#[test]
fn psk_mechanism_validates_entropy() {
    let psk = PskMechanism::new();
    assert!(psk.validate_entropy(&vec![0u8; 16]).is_ok());
    assert!(psk.validate_entropy(&vec![0u8; 15]).is_err());
}

#[test]
fn psk_rendezvous_id_is_deterministic() {
    let psk = PskMechanism::new();
    let key = vec![0xAB; 32];
    let id1 = psk.derive_rendezvous_id(&key).unwrap();
    let id2 = psk.derive_rendezvous_id(&key).unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn psk_different_keys_produce_different_rendezvous() {
    let psk = PskMechanism::new();
    let id1 = psk.derive_rendezvous_id(&[0x01; 32]).unwrap();
    let id2 = psk.derive_rendezvous_id(&[0x02; 32]).unwrap();
    assert_ne!(id1, id2);
}

#[tokio::test]
async fn api_node_pair_generate_qr() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    let qr_data = node.pair_generate_qr().await.unwrap();
    assert_eq!(qr_data.expires_in, Duration::from_secs(300));
}

#[tokio::test]
async fn api_node_pair_generate_pin() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    let pin_data = node.pair_generate_pin().await.unwrap();
    assert!(!pin_data.pin.is_empty());
}

#[tokio::test]
async fn api_node_pair_generate_link() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    let link_data = node.pair_generate_link().await.unwrap();
    assert!(link_data.uri.starts_with("cairn://"));
}

#[tokio::test]
async fn pairing_scan_qr_rejects_invalid_cbor() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    assert!(node.pair_scan_qr(&[1, 2, 3]).await.is_err());
}

#[tokio::test]
async fn pairing_enter_pin_succeeds_with_valid_pin() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    let result = node.pair_enter_pin("ABCD-EFGH").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn pairing_enter_pin_rejects_invalid_chars() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    assert!(node.pair_enter_pin("!!!").await.is_err());
}

#[tokio::test]
async fn pairing_from_link_rejects_invalid_uri() {
    let node = ApiNode::new(CairnConfig::default()).unwrap();
    assert!(node
        .pair_from_link("cairn://pair?placeholder=true")
        .await
        .is_err());
}
