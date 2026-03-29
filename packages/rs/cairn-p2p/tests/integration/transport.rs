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
    assert!(!qr.payload.is_empty(), "QR payload should not be empty");
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

/// End-to-end transport test: two ApiNodes on localhost exchange real
/// messages over the libp2p swarm in both directions.
///
/// Flow:
/// 1. Both nodes start transport and listen.
/// 2. Node B dials Node A using its libp2p PeerId and listen addresses.
/// 3. Noise XX handshake is performed over the request-response protocol.
/// 4. Node B sends a message — Node A receives it.
/// 5. Node A sends a reply — Node B receives it (bidirectional).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_exchange_messages_over_transport() {
    use cairn_p2p::Event;

    // Create and start two nodes with transport.
    let node_a = create_and_start().await.unwrap();
    let node_b = create_and_start().await.unwrap();

    let a_peer_id = node_a
        .libp2p_peer_id()
        .expect("node A should have libp2p peer ID")
        .to_string();
    let a_addrs = node_a.listen_addresses().await;
    assert!(!a_addrs.is_empty(), "node A should have listen addresses");

    // Node B connects to Node A over the transport (handshake + session).
    let session_b = node_b
        .connect_transport(&a_peer_id, &a_addrs)
        .await
        .expect("connect_transport should succeed");

    // --- B → A ---
    let channel_b = session_b
        .open_channel("chat")
        .await
        .expect("open_channel should succeed");
    session_b
        .send(&channel_b, b"hello from B")
        .await
        .expect("send should succeed");

    // Node A should receive the message via its event channel.
    let a_received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Event::MessageReceived { data, .. }) = node_a.recv_event().await {
                return data;
            }
        }
    })
    .await
    .expect("A should receive message within 5 seconds");

    assert_eq!(
        a_received, b"hello from B",
        "B→A message content should match"
    );

    // --- A → B (bidirectional) ---
    // Node A's session was auto-created during the handshake, keyed by B's libp2p PeerId.
    let b_peer_id = node_b.libp2p_peer_id().unwrap().to_string();
    let a_sessions = node_a.sessions().await;
    let session_a = a_sessions
        .get(&b_peer_id)
        .expect("Node A should have a session for Node B");

    let channel_a = session_a.open_channel("data").await.unwrap();
    session_a.send(&channel_a, b"hello from A").await.unwrap();

    let b_received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Event::MessageReceived { data, .. }) = node_b.recv_event().await {
                return data;
            }
        }
    })
    .await
    .expect("B should receive message within 5 seconds");

    assert_eq!(
        b_received, b"hello from A",
        "A→B message content should match"
    );
}
