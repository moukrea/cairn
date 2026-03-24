//! Integration tests for the transport wiring between ApiNode and the libp2p swarm.

use cairn_p2p::create_and_start;

#[tokio::test]
async fn node_starts_transport_and_listens() {
    let node = create_and_start().await.unwrap();
    let addrs = node.listen_addresses().await;
    assert!(
        !addrs.is_empty(),
        "node should have at least one listen address after start_transport"
    );
    // Must have at least TCP addresses
    let has_tcp = addrs.iter().any(|a| a.contains("/tcp/"));
    assert!(has_tcp, "should listen on TCP: {addrs:?}");
}

#[tokio::test]
async fn node_without_transport_has_no_addresses() {
    let node = cairn_p2p::create().unwrap();
    let addrs = node.listen_addresses().await;
    assert!(
        addrs.is_empty(),
        "node without transport should have no listen addresses"
    );
}

#[tokio::test]
async fn pairing_payload_includes_connection_hints() {
    let node = create_and_start().await.unwrap();
    let qr = node.pair_generate_qr().await.unwrap();
    assert!(
        !qr.payload.is_empty(),
        "QR payload should not be empty"
    );
    // Payload with connection hints should be larger than a bare payload
    assert!(
        qr.payload.len() > 50,
        "QR payload with hints should be substantial: {} bytes",
        qr.payload.len()
    );
}

#[tokio::test]
async fn swarm_sender_available_after_transport_start() {
    let node = create_and_start().await.unwrap();
    assert!(
        node.swarm_sender().is_some(),
        "swarm_sender should be Some after start_transport"
    );
}

#[tokio::test]
async fn swarm_sender_none_without_transport() {
    let node = cairn_p2p::create().unwrap();
    assert!(
        node.swarm_sender().is_none(),
        "swarm_sender should be None without transport"
    );
}
