//! Session lifecycle integration tests.

use cairn_p2p::{ApiNode, CairnConfig, ConnectionState, Event, StorageBackend};

fn test_node() -> ApiNode {
    let config = CairnConfig {
        storage_backend: StorageBackend::InMemory,
        ..Default::default()
    };
    ApiNode::new(config).unwrap()
}

#[tokio::test]
async fn connect_creates_session_in_connected_state() {
    let node = test_node();
    let session = node.connect("test-peer").await.unwrap();
    assert_eq!(session.state().await, ConnectionState::Connected);
    assert_eq!(session.peer_id(), "test-peer");
}

#[tokio::test]
async fn session_open_channel_and_send() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();
    let channel = session.open_channel("data").await.unwrap();

    assert_eq!(channel.name(), "data");
    assert!(channel.is_open());

    let result = session.send(&channel, b"hello world").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn session_close_transitions_to_disconnected() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();
    assert_eq!(session.state().await, ConnectionState::Connected);

    session.close().await.unwrap();
    assert_eq!(session.state().await, ConnectionState::Disconnected);
}

#[tokio::test]
async fn send_on_closed_channel_fails() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();
    let channel = session.open_channel("data").await.unwrap();

    channel.close();
    assert!(!channel.is_open());

    let result = session.send(&channel, b"should fail").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn custom_message_handler_rejects_invalid_range() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();

    assert!(session.on_custom_message(0xF000, |_| {}).await.is_ok());
    assert!(session.on_custom_message(0xFFFF, |_| {}).await.is_ok());
    assert!(session.on_custom_message(0x0100, |_| {}).await.is_err());
    assert!(session.on_custom_message(0x0000, |_| {}).await.is_err());
}

#[tokio::test]
async fn multiple_channels_on_session() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();

    let ch1 = session.open_channel("chat").await.unwrap();
    let ch2 = session.open_channel("files").await.unwrap();
    let ch3 = session.open_channel("voice").await.unwrap();

    assert_eq!(ch1.name(), "chat");
    assert_eq!(ch2.name(), "files");
    assert_eq!(ch3.name(), "voice");
    assert!(ch1.is_open());
    assert!(ch2.is_open());
    assert!(ch3.is_open());
}

#[tokio::test]
async fn reserved_channel_name_rejected() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();
    assert!(session.open_channel("__cairn_internal").await.is_err());
}

#[tokio::test]
async fn empty_channel_name_rejected() {
    let node = test_node();
    let session = node.connect("peer-1").await.unwrap();
    assert!(session.open_channel("").await.is_err());
}

#[tokio::test]
async fn unpair_removes_session() {
    let node = test_node();
    let _session = node.connect("peer-to-unpair").await.unwrap();
    node.unpair("peer-to-unpair").await.unwrap();
}

#[tokio::test]
async fn network_info_returns_unknown_nat_by_default() {
    let node = test_node();
    let info = node.network_info().await;
    assert_eq!(info.nat_type, cairn_p2p::transport::nat::NatType::Unknown);
}

#[tokio::test]
async fn recv_event_delivers_state_change() {
    let node = test_node();
    let _session = node.connect("peer-events").await.unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(1), node.recv_event()).await;

    assert!(event.is_ok());
    let event = event.unwrap().unwrap();
    match event {
        Event::StateChanged { peer_id, state } => {
            assert_eq!(peer_id, "peer-events");
            assert_eq!(state, ConnectionState::Connected);
        }
        other => panic!("expected StateChanged, got: {other:?}"),
    }
}

#[tokio::test]
async fn transport_fallback_types_exist() {
    use cairn_p2p::transport::fallback::FallbackTransportType;
    use cairn_p2p::transport::nat::NatType;

    let _nat = NatType::Symmetric;
    let _tt = FallbackTransportType::DirectQuic;
}

#[tokio::test]
async fn store_forward_types_accessible() {
    use cairn_p2p::server::store_forward::{MessageQueue, RetentionPolicy};

    let _policy = RetentionPolicy::default();
    let queue = MessageQueue::new();
    assert_eq!(queue.total_messages(), 0);
}
