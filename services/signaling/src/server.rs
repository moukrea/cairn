use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

use crate::auth;

/// Connection-local peer identifier (not the cairn cryptographic PeerId).
type ConnId = u64;

/// Control messages exchanged between client and signaling server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SignalMessage {
    /// Subscribe to a rendezvous topic.
    Subscribe { topic: String },
    /// Unsubscribe from a rendezvous topic.
    Unsubscribe { topic: String },
    /// Relay an opaque payload to all other subscribers of a topic.
    Relay {
        topic: String,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
}

/// Shared server state protected by a RwLock.
pub struct SignalState {
    /// topic -> set of connection IDs subscribed to that topic.
    topics: HashMap<String, HashSet<ConnId>>,
    /// connection ID -> sender handle for forwarding messages.
    peers: HashMap<ConnId, mpsc::UnboundedSender<Vec<u8>>>,
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            topics: HashMap::new(),
            peers: HashMap::new(),
        }
    }

    /// Number of active peer connections.
    #[cfg(test)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active topics.
    #[cfg(test)]
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }
}

pub type SharedState = Arc<RwLock<SignalState>>;

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    pub auth_token: Option<String>,
}

/// Next connection ID generator.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Run the signaling server. Returns when the shutdown signal is received.
pub async fn run(
    config: ServerConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
    let listener = TcpListener::bind(config.listen_addr).await?;

    tracing::info!("signaling server listening on {}", config.listen_addr);
    if config.tls_config.is_some() {
        tracing::info!("TLS enabled");
    } else {
        tracing::info!("TLS disabled (plaintext WebSocket mode)");
    }
    if config.auth_token.is_some() {
        tracing::info!("bearer token authentication enabled");
    }

    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = accept_result?;
                let state = Arc::clone(&state);
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr, state, &config).await {
                        tracing::warn!("connection from {addr} failed: {e}");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("shutdown signal received, draining connections");
                    break;
                }
            }
        }
    }

    // Graceful shutdown: close all peer senders (they'll see channel closed
    // and drop their WebSocket connections).
    {
        let mut st = state.write().await;
        st.peers.clear();
        st.topics.clear();
    }

    // Give connections time to drain.
    tokio::time::sleep(Duration::from_secs(2)).await;
    tracing::info!("signaling server shut down");
    Ok(())
}

/// Handle a single incoming TCP connection (upgrade to WebSocket).
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: SharedState,
    config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    tracing::debug!("new connection from {addr} (id={conn_id})");

    let auth_token = config.auth_token.clone();

    if let Some(ref tls_config) = config.tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(tls_config));
        let tls_stream = acceptor.accept(stream).await?;
        let ws_stream = tokio_tungstenite::accept_hdr_async(
            tls_stream,
            |req: &tokio_tungstenite::tungstenite::http::Request<()>, resp| {
                if !auth::validate_bearer_token(req, auth_token.as_deref()) {
                    tracing::warn!("rejected connection from {addr}: invalid bearer token");
                    let resp = tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(401)
                        .body(None)
                        .unwrap();
                    Err(resp)
                } else {
                    Ok(resp)
                }
            },
        )
        .await?;
        handle_websocket(ws_stream, conn_id, state).await;
    } else {
        let ws_stream = tokio_tungstenite::accept_hdr_async(
            stream,
            |req: &tokio_tungstenite::tungstenite::http::Request<()>, resp| {
                if !auth::validate_bearer_token(req, auth_token.as_deref()) {
                    tracing::warn!("rejected connection from {addr}: invalid bearer token");
                    let resp = tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(401)
                        .body(None)
                        .unwrap();
                    Err(resp)
                } else {
                    Ok(resp)
                }
            },
        )
        .await?;
        handle_websocket(ws_stream, conn_id, state).await;
    }

    Ok(())
}

/// Handle a connected WebSocket peer: read messages, route them.
async fn handle_websocket<S>(ws_stream: S, conn_id: ConnId, state: SharedState)
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + SinkExt<Message>
        + Unpin
        + Send
        + 'static,
{
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Register this peer.
    {
        let mut st = state.write().await;
        st.peers.insert(conn_id, tx);
    }

    // Spawn a task to forward messages from the channel to the WebSocket.
    let send_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if ws_sender.send(Message::Binary(data)).await.is_err() {
                break;
            }
        }
    });

    // Read messages from the WebSocket and process them.
    while let Some(msg_result) = ws_receiver.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("ws read error for conn {conn_id}: {e}");
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                if let Err(e) = process_message(&data, conn_id, &state).await {
                    tracing::debug!("message processing error for conn {conn_id}: {e}");
                }
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {
                // tokio-tungstenite handles pings automatically.
            }
            _ => {
                // Ignore text frames and other types.
            }
        }
    }

    // Peer disconnected: remove from all topics and peer map.
    remove_peer(conn_id, &state).await;
    send_task.abort();
    tracing::debug!("connection {conn_id} closed");
}

/// Process a single CBOR-encoded SignalMessage from a peer.
async fn process_message(
    data: &[u8],
    conn_id: ConnId,
    state: &SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg: SignalMessage =
        ciborium::from_reader(data).map_err(|e| format!("CBOR decode error: {e}"))?;

    match msg {
        SignalMessage::Subscribe { topic } => {
            tracing::debug!("conn {conn_id} subscribing to topic '{topic}'");
            let mut st = state.write().await;
            st.topics.entry(topic).or_default().insert(conn_id);
        }
        SignalMessage::Unsubscribe { topic } => {
            tracing::debug!("conn {conn_id} unsubscribing from topic '{topic}'");
            let mut st = state.write().await;
            if let Some(peers) = st.topics.get_mut(&topic) {
                peers.remove(&conn_id);
                if peers.is_empty() {
                    st.topics.remove(&topic);
                }
            }
        }
        SignalMessage::Relay { topic, payload } => {
            let st = state.read().await;
            if let Some(subscribers) = st.topics.get(&topic) {
                // Re-encode the relay message to forward to subscribers.
                let mut forward_buf = Vec::new();
                ciborium::into_writer(&SignalMessage::Relay { topic, payload }, &mut forward_buf)
                    .map_err(|e| format!("CBOR encode error: {e}"))?;

                for &sub_id in subscribers {
                    if sub_id == conn_id {
                        continue; // Don't echo back to sender.
                    }
                    if let Some(sender) = st.peers.get(&sub_id) {
                        let _ = sender.send(forward_buf.clone());
                    }
                }
            }
        }
    }

    Ok(())
}

/// Remove a peer from all topics and the peer map.
async fn remove_peer(conn_id: ConnId, state: &SharedState) {
    let mut st = state.write().await;
    st.peers.remove(&conn_id);

    // Remove this connection from all topic sets, cleaning up empty topics.
    st.topics.retain(|_topic, peers| {
        peers.remove(&conn_id);
        !peers.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_signal_msg(msg: &SignalMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).unwrap();
        buf
    }

    #[tokio::test]
    async fn signal_state_new_is_empty() {
        let state = SignalState::new();
        assert_eq!(state.peer_count(), 0);
        assert_eq!(state.topic_count(), 0);
    }

    #[tokio::test]
    async fn subscribe_adds_peer_to_topic() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx, _rx) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx);
        }

        let msg = encode_signal_msg(&SignalMessage::Subscribe {
            topic: "test-topic".into(),
        });
        process_message(&msg, 1, &state).await.unwrap();

        let st = state.read().await;
        assert!(st.topics.get("test-topic").unwrap().contains(&1));
    }

    #[tokio::test]
    async fn unsubscribe_removes_peer_from_topic() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx, _rx) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx);
            st.topics.entry("topic-a".into()).or_default().insert(1);
        }

        let msg = encode_signal_msg(&SignalMessage::Unsubscribe {
            topic: "topic-a".into(),
        });
        process_message(&msg, 1, &state).await.unwrap();

        let st = state.read().await;
        assert!(!st.topics.contains_key("topic-a"));
    }

    #[tokio::test]
    async fn relay_forwards_to_other_subscribers() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx1);
            st.peers.insert(2, tx2);
            st.topics
                .entry("shared-topic".into())
                .or_default()
                .insert(1);
            st.topics
                .entry("shared-topic".into())
                .or_default()
                .insert(2);
        }

        let msg = encode_signal_msg(&SignalMessage::Relay {
            topic: "shared-topic".into(),
            payload: vec![0xCA, 0xFE],
        });
        process_message(&msg, 1, &state).await.unwrap();

        // Peer 2 should have received the forwarded message.
        let forwarded = rx2.recv().await.unwrap();
        let decoded: SignalMessage = ciborium::from_reader(&forwarded[..]).unwrap();
        match decoded {
            SignalMessage::Relay { topic, payload } => {
                assert_eq!(topic, "shared-topic");
                assert_eq!(payload, vec![0xCA, 0xFE]);
            }
            _ => panic!("expected Relay message"),
        }
    }

    #[tokio::test]
    async fn relay_does_not_echo_to_sender() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx1, mut rx1) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx1);
            st.topics.entry("solo-topic".into()).or_default().insert(1);
        }

        let msg = encode_signal_msg(&SignalMessage::Relay {
            topic: "solo-topic".into(),
            payload: vec![0x01],
        });
        process_message(&msg, 1, &state).await.unwrap();

        // Sender should NOT receive their own message.
        assert!(rx1.try_recv().is_err());
    }

    #[tokio::test]
    async fn remove_peer_cleans_up_topics() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx, _rx) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx);
            st.topics.entry("topic-1".into()).or_default().insert(1);
            st.topics.entry("topic-2".into()).or_default().insert(1);
        }

        remove_peer(1, &state).await;

        let st = state.read().await;
        assert_eq!(st.peer_count(), 0);
        assert_eq!(st.topic_count(), 0);
    }

    #[tokio::test]
    async fn remove_peer_preserves_other_peers_topics() {
        let state: SharedState = Arc::new(RwLock::new(SignalState::new()));
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();

        {
            let mut st = state.write().await;
            st.peers.insert(1, tx1);
            st.peers.insert(2, tx2);
            st.topics.entry("shared".into()).or_default().insert(1);
            st.topics.entry("shared".into()).or_default().insert(2);
        }

        remove_peer(1, &state).await;

        let st = state.read().await;
        assert_eq!(st.peer_count(), 1);
        assert!(st.topics.get("shared").unwrap().contains(&2));
        assert!(!st.topics.get("shared").unwrap().contains(&1));
    }

    #[tokio::test]
    async fn signal_message_cbor_roundtrip() {
        let messages = vec![
            SignalMessage::Subscribe {
                topic: "test".into(),
            },
            SignalMessage::Unsubscribe {
                topic: "test".into(),
            },
            SignalMessage::Relay {
                topic: "test".into(),
                payload: vec![1, 2, 3],
            },
        ];

        for msg in &messages {
            let encoded = encode_signal_msg(msg);
            let decoded: SignalMessage = ciborium::from_reader(&encoded[..]).unwrap();
            match (msg, &decoded) {
                (SignalMessage::Subscribe { topic: a }, SignalMessage::Subscribe { topic: b }) => {
                    assert_eq!(a, b);
                }
                (
                    SignalMessage::Unsubscribe { topic: a },
                    SignalMessage::Unsubscribe { topic: b },
                ) => {
                    assert_eq!(a, b);
                }
                (
                    SignalMessage::Relay {
                        topic: ta,
                        payload: pa,
                    },
                    SignalMessage::Relay {
                        topic: tb,
                        payload: pb,
                    },
                ) => {
                    assert_eq!(ta, tb);
                    assert_eq!(pa, pb);
                }
                _ => panic!("message type mismatch after roundtrip"),
            }
        }
    }
}
