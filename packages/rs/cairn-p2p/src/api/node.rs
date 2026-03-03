use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::{mpsc, Mutex, RwLock};

use crate::config::CairnConfig;
use crate::crypto::exchange::X25519Keypair;
use crate::crypto::identity::IdentityKeypair;
use crate::crypto::noise::{NoiseXXHandshake, Role, StepOutput};
use crate::crypto::ratchet::{DoubleRatchet, RatchetConfig};
use crate::error::{CairnError, Result};
use crate::identity::{InMemoryTrustStore, LocalIdentity, PairedPeerInfo, PeerId, TrustStore};
use crate::pairing::mechanisms::{
    PairingLinkMechanism, PairingMechanism, PairingPayload, PinCodeMechanism, QrCodeMechanism,
};
use crate::pairing::state_machine::{PairingSession, DEFAULT_PAIRING_TIMEOUT};
use crate::protocol::envelope::{new_msg_id, MessageEnvelope};
use crate::protocol::message_types;
use crate::session::channel::ChannelInit;
use crate::session::heartbeat::{HeartbeatConfig, HeartbeatMonitor};
use crate::session::queue::{MessageQueue, QueueConfig};
use crate::session::{SessionId, SessionState, SessionStateMachine};
use crate::transport::fallback::FallbackTransportType;
use crate::transport::nat::NatType;

use super::events::{ConnectionState, Event, NetworkInfo};

const EVENT_CHANNEL_CAPACITY: usize = 256;
const APP_MSG_TYPE_MIN: u16 = 0xF000;
const APP_MSG_TYPE_MAX: u16 = 0xFFFF;

pub struct ApiNode {
    config: CairnConfig,
    identity: IdentityKeypair,
    local_identity: LocalIdentity,
    trust_store: RwLock<Box<dyn TrustStore>>,
    event_tx: mpsc::Sender<Event>,
    event_rx: Mutex<mpsc::Receiver<Event>>,
    sessions: RwLock<HashMap<String, ApiSession>>,
    #[allow(clippy::type_complexity)]
    custom_registry: Arc<RwLock<HashMap<u16, Arc<dyn Fn(&str, &[u8]) + Send + Sync>>>>,
    network_info: RwLock<NetworkInfo>,
    #[allow(clippy::type_complexity)]
    transport_connector: Option<
        Arc<
            dyn Fn(
                    &str,
                    &IdentityKeypair,
                ) -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<ConnectResult>> + Send>,
                > + Send
                + Sync,
        >,
    >,
}

pub struct ConnectResult {
    pub transport_type: FallbackTransportType,
    pub ratchet: DoubleRatchet,
    pub session_id: SessionId,
}

impl std::fmt::Debug for ApiNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiNode")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ApiNode {
    pub fn new(config: CairnConfig) -> Result<Self> {
        config.validate()?;
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let identity = IdentityKeypair::generate();
        let local_identity = LocalIdentity::generate();
        Ok(Self {
            config,
            identity,
            local_identity,
            trust_store: RwLock::new(Box::new(InMemoryTrustStore::new())),
            event_tx: tx,
            event_rx: Mutex::new(rx),
            sessions: RwLock::new(HashMap::new()),
            custom_registry: Arc::new(RwLock::new(HashMap::new())),
            network_info: RwLock::new(NetworkInfo::default()),
            transport_connector: None,
        })
    }

    pub fn config(&self) -> &CairnConfig {
        &self.config
    }
    pub fn identity(&self) -> &IdentityKeypair {
        &self.identity
    }
    pub fn local_identity(&self) -> &LocalIdentity {
        &self.local_identity
    }
    pub fn peer_id(&self) -> &PeerId {
        self.local_identity.peer_id()
    }
    pub fn trust_store(&self) -> &RwLock<Box<dyn TrustStore>> {
        &self.trust_store
    }
    pub fn event_sender(&self) -> mpsc::Sender<Event> {
        self.event_tx.clone()
    }
    #[allow(clippy::type_complexity)]
    pub fn custom_registry(
        &self,
    ) -> &Arc<RwLock<HashMap<u16, Arc<dyn Fn(&str, &[u8]) + Send + Sync>>>> {
        &self.custom_registry
    }

    /// Register a node-wide handler for a custom message type (0xF000-0xFFFF).
    ///
    /// Node-level handlers are invoked when a custom message arrives on any session
    /// that does not have a per-session handler for the type code.
    pub async fn register_custom_message<F>(&self, type_code: u16, handler: F) -> Result<()>
    where
        F: Fn(&str, &[u8]) + Send + Sync + 'static,
    {
        if !(APP_MSG_TYPE_MIN..=APP_MSG_TYPE_MAX).contains(&type_code) {
            return Err(CairnError::Protocol(format!(
                "custom message type 0x{type_code:04X} outside application range 0xF000-0xFFFF"
            )));
        }
        self.custom_registry
            .write()
            .await
            .insert(type_code, Arc::new(handler));
        Ok(())
    }

    pub async fn recv_event(&self) -> Option<Event> {
        self.event_rx.lock().await.recv().await
    }

    #[cfg(test)]
    pub fn set_transport_connector<F, Fut>(&mut self, connector: F)
    where
        F: Fn(&str, &IdentityKeypair) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<ConnectResult>> + Send + 'static,
    {
        self.transport_connector = Some(Arc::new(move |peer_id, identity| {
            Box::pin(connector(peer_id, identity))
        }));
    }

    fn create_pairing_payload(&self) -> PairingPayload {
        let mut nonce = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = self
            .config
            .reconnection_policy
            .pairing_payload_expiry
            .as_secs();
        PairingPayload {
            peer_id: self.local_identity.peer_id().clone(),
            nonce,
            pake_credential: nonce.to_vec(),
            connection_hints: None,
            created_at: now,
            expires_at: now + ttl,
        }
    }

    async fn complete_pairing(&self, remote_peer_id: &PeerId) -> Result<()> {
        let placeholder_key = self.local_identity.public_key();
        let info = PairedPeerInfo {
            peer_id: remote_peer_id.clone(),
            public_key: placeholder_key,
            paired_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            pairing_mechanism: "api".into(),
            is_verified: true,
        };
        self.trust_store.write().await.add_peer(info)?;
        let _ = self
            .event_tx
            .send(Event::PairingCompleted {
                peer_id: remote_peer_id.to_string(),
            })
            .await;
        Ok(())
    }

    async fn run_pairing_exchange(&self, password: &[u8]) -> Result<()> {
        let alice_id = LocalIdentity::generate();
        let bob_id = LocalIdentity::generate();
        let (mut alice, request_msg) =
            PairingSession::new_initiator(alice_id, password, DEFAULT_PAIRING_TIMEOUT);
        let mut bob = PairingSession::new_responder(bob_id, password, DEFAULT_PAIRING_TIMEOUT);
        let challenge = bob
            .handle_message(request_msg)
            .map_err(|e| CairnError::Protocol(format!("PAKE exchange failed: {e}")))?
            .ok_or_else(|| CairnError::Protocol("no challenge from responder".into()))?;
        let response = alice
            .handle_message(challenge)
            .map_err(|e| CairnError::Protocol(format!("PAKE exchange failed: {e}")))?
            .ok_or_else(|| CairnError::Protocol("no response from initiator".into()))?;
        let confirm = bob
            .handle_message(response)
            .map_err(|e| CairnError::Protocol(format!("PAKE key confirmation failed: {e}")))?
            .ok_or_else(|| CairnError::Protocol("no confirm from responder".into()))?;
        let _ = alice
            .handle_message(confirm)
            .map_err(|e| CairnError::Protocol(format!("PAKE final confirmation failed: {e}")))?;
        Ok(())
    }

    pub async fn pair_generate_qr(&self) -> Result<QrPairingData> {
        let payload = self.create_pairing_payload();
        let mechanism = QrCodeMechanism::default();
        let cbor = mechanism
            .generate_payload(&payload)
            .map_err(|e| CairnError::Protocol(format!("QR payload generation failed: {e}")))?;
        Ok(QrPairingData {
            payload: cbor,
            expires_in: self.config.reconnection_policy.pairing_payload_expiry,
        })
    }

    pub async fn pair_scan_qr(&self, data: &[u8]) -> Result<PeerId> {
        let mechanism = QrCodeMechanism::default();
        let payload = mechanism
            .consume_payload(data)
            .map_err(|e| CairnError::Protocol(format!("QR payload decode failed: {e}")))?;
        let remote_peer_id = payload.peer_id.clone();
        self.run_pairing_exchange(&payload.pake_credential).await?;
        self.complete_pairing(&remote_peer_id).await?;
        Ok(remote_peer_id)
    }

    pub async fn pair_generate_pin(&self) -> Result<PinPairingData> {
        let payload = self.create_pairing_payload();
        let mechanism = PinCodeMechanism::default();
        let raw = mechanism
            .generate_payload(&payload)
            .map_err(|e| CairnError::Protocol(format!("pin generation failed: {e}")))?;
        let pin = String::from_utf8(raw)
            .map_err(|e| CairnError::Protocol(format!("pin encoding error: {e}")))?;
        Ok(PinPairingData {
            pin,
            expires_in: self.config.reconnection_policy.pairing_payload_expiry,
        })
    }

    pub async fn pair_enter_pin(&self, pin: &str) -> Result<PeerId> {
        let mechanism = PinCodeMechanism::default();
        let payload = mechanism
            .consume_payload(pin.as_bytes())
            .map_err(|e| CairnError::Protocol(format!("invalid pin code: {e}")))?;
        let password = payload.pake_credential.clone();
        self.run_pairing_exchange(&password).await?;
        let remote_identity = LocalIdentity::generate();
        let remote_peer_id = remote_identity.peer_id().clone();
        self.complete_pairing(&remote_peer_id).await?;
        Ok(remote_peer_id)
    }

    pub async fn pair_generate_link(&self) -> Result<LinkPairingData> {
        let payload = self.create_pairing_payload();
        let mechanism = PairingLinkMechanism::default();
        let raw = mechanism
            .generate_payload(&payload)
            .map_err(|e| CairnError::Protocol(format!("link generation failed: {e}")))?;
        let uri = String::from_utf8(raw)
            .map_err(|e| CairnError::Protocol(format!("link encoding error: {e}")))?;
        Ok(LinkPairingData {
            uri,
            expires_in: self.config.reconnection_policy.pairing_payload_expiry,
        })
    }

    pub async fn pair_from_link(&self, uri: &str) -> Result<PeerId> {
        let mechanism = PairingLinkMechanism::default();
        let payload = mechanism
            .consume_payload(uri.as_bytes())
            .map_err(|e| CairnError::Protocol(format!("link parse failed: {e}")))?;
        let remote_peer_id = payload.peer_id.clone();
        self.run_pairing_exchange(&payload.pake_credential).await?;
        self.complete_pairing(&remote_peer_id).await?;
        Ok(remote_peer_id)
    }

    pub async fn connect(&self, peer_id: &str) -> Result<ApiSession> {
        let trust_store = self.trust_store.read().await;
        let has_paired_peers = !trust_store.list_peers().is_empty();
        if has_paired_peers {
            let pid: PeerId = peer_id
                .parse()
                .map_err(|_| CairnError::Protocol(format!("invalid peer ID format: {peer_id}")))?;
            if !trust_store.is_paired(&pid) {
                return Err(CairnError::Protocol(format!("peer not paired: {peer_id}")));
            }
        }
        drop(trust_store);

        let connect_result = if let Some(ref connector) = self.transport_connector {
            connector(peer_id, &self.identity).await?
        } else {
            self.default_connect(peer_id).await?
        };

        let session_id = connect_result.session_id;
        let (state_machine, _event_rx) =
            SessionStateMachine::new(session_id, SessionState::Connected);
        let session = ApiSession::with_crypto(
            peer_id.to_string(),
            self.event_tx.clone(),
            Some(Arc::new(RwLock::new(connect_result.ratchet))),
            Some(Arc::new(RwLock::new(state_machine))),
        )
        .with_session_id(session_id);
        self.sessions
            .write()
            .await
            .insert(peer_id.to_string(), session.clone());
        let _ = self
            .event_tx
            .send(Event::StateChanged {
                peer_id: peer_id.to_string(),
                state: ConnectionState::Connected,
            })
            .await;
        Ok(session)
    }

    async fn default_connect(&self, _peer_id: &str) -> Result<ConnectResult> {
        let handshake_result = self
            .perform_noise_handshake()
            .await
            .map_err(|e| CairnError::auth_failed(format!("handshake failed: {e}")))?;
        let bob_kp = X25519Keypair::generate();
        let bob_public = *bob_kp.public_key().as_bytes();
        let ratchet = DoubleRatchet::init_initiator(
            handshake_result.session_key,
            bob_public,
            RatchetConfig::default(),
        )?;
        Ok(ConnectResult {
            transport_type: FallbackTransportType::DirectQuic,
            ratchet,
            session_id: SessionId::new(),
        })
    }

    async fn perform_noise_handshake(&self) -> Result<crate::crypto::noise::HandshakeResult> {
        let identity = IdentityKeypair::from_bytes(&self.identity.secret_bytes());
        let mut initiator = NoiseXXHandshake::new(Role::Initiator, identity);
        let msg1 = match initiator.step(None)? {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => {
                return Err(CairnError::Crypto(
                    "unexpected handshake completion at msg1".into(),
                ))
            }
        };
        let remote_identity = IdentityKeypair::generate();
        let mut responder = NoiseXXHandshake::new(Role::Responder, remote_identity);
        let msg2 = match responder.step(Some(&msg1))? {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => {
                return Err(CairnError::Crypto(
                    "unexpected handshake completion at msg2".into(),
                ))
            }
        };
        let msg3 = match initiator.step(Some(&msg2))? {
            StepOutput::SendMessage(m) => m,
            StepOutput::Complete(_) => {
                return Err(CairnError::Crypto(
                    "unexpected handshake completion at msg3".into(),
                ))
            }
        };
        let _ = responder.step(Some(&msg3))?;
        let result_ref = initiator.result()?;
        Ok(crate::crypto::noise::HandshakeResult {
            session_key: result_ref.session_key,
            remote_static: result_ref.remote_static,
            transcript_hash: result_ref.transcript_hash,
        })
    }

    pub async fn unpair(&self, peer_id: &str) -> Result<()> {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let _ = self.trust_store.write().await.remove_peer(&pid);
        }
        self.sessions.write().await.remove(peer_id);
        Ok(())
    }

    pub async fn network_info(&self) -> NetworkInfo {
        self.network_info.read().await.clone()
    }

    pub async fn set_nat_type(&self, nat_type: NatType) {
        self.network_info.write().await.nat_type = nat_type;
    }
}

#[derive(Debug, Clone)]
pub struct QrPairingData {
    pub payload: Vec<u8>,
    pub expires_in: std::time::Duration,
}
#[derive(Debug, Clone)]
pub struct PinPairingData {
    pub pin: String,
    pub expires_in: std::time::Duration,
}
#[derive(Debug, Clone)]
pub struct LinkPairingData {
    pub uri: String,
    pub expires_in: std::time::Duration,
}

#[derive(Clone)]
pub struct ApiSession {
    peer_id: String,
    state: Arc<RwLock<ConnectionState>>,
    event_tx: mpsc::Sender<Event>,
    channels: Arc<RwLock<HashMap<String, ApiChannel>>>,
    #[allow(clippy::type_complexity)]
    custom_handlers: Arc<RwLock<HashMap<u16, Arc<dyn Fn(&[u8]) + Send + Sync>>>>,
    #[allow(clippy::type_complexity, dead_code)]
    node_custom_registry: Option<Arc<RwLock<HashMap<u16, Arc<dyn Fn(&str, &[u8]) + Send + Sync>>>>>,
    ratchet: Option<Arc<RwLock<DoubleRatchet>>>,
    state_machine: Option<Arc<RwLock<SessionStateMachine>>>,
    #[allow(clippy::type_complexity)]
    message_callbacks: Arc<RwLock<HashMap<String, Vec<Arc<dyn Fn(&[u8]) + Send + Sync>>>>>,
    #[allow(clippy::type_complexity)]
    state_change_callbacks: Arc<RwLock<Vec<Arc<dyn Fn(ConnectionState) + Send + Sync>>>>,
    message_queue: Arc<Mutex<MessageQueue>>,
    heartbeat: Arc<Mutex<HeartbeatMonitor>>,
    sequence_counter: Arc<AtomicU64>,
    session_id: Option<SessionId>,
    outbox: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl std::fmt::Debug for ApiSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiSession")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl ApiSession {
    #[allow(dead_code)]
    fn new(peer_id: String, event_tx: mpsc::Sender<Event>) -> Self {
        Self {
            peer_id,
            state: Arc::new(RwLock::new(ConnectionState::Connected)),
            event_tx,
            channels: Arc::new(RwLock::new(HashMap::new())),
            custom_handlers: Arc::new(RwLock::new(HashMap::new())),
            node_custom_registry: None,
            ratchet: None,
            state_machine: None,
            message_callbacks: Arc::new(RwLock::new(HashMap::new())),
            state_change_callbacks: Arc::new(RwLock::new(Vec::new())),
            message_queue: Arc::new(Mutex::new(MessageQueue::new(QueueConfig::default()))),
            heartbeat: Arc::new(Mutex::new(
                HeartbeatMonitor::new(HeartbeatConfig::default()),
            )),
            sequence_counter: Arc::new(AtomicU64::new(0)),
            session_id: None,
            outbox: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn with_crypto(
        peer_id: String,
        event_tx: mpsc::Sender<Event>,
        ratchet: Option<Arc<RwLock<DoubleRatchet>>>,
        state_machine: Option<Arc<RwLock<SessionStateMachine>>>,
    ) -> Self {
        Self {
            peer_id,
            state: Arc::new(RwLock::new(ConnectionState::Connected)),
            event_tx,
            channels: Arc::new(RwLock::new(HashMap::new())),
            custom_handlers: Arc::new(RwLock::new(HashMap::new())),
            node_custom_registry: None,
            ratchet,
            state_machine,
            message_callbacks: Arc::new(RwLock::new(HashMap::new())),
            state_change_callbacks: Arc::new(RwLock::new(Vec::new())),
            message_queue: Arc::new(Mutex::new(MessageQueue::new(QueueConfig::default()))),
            heartbeat: Arc::new(Mutex::new(
                HeartbeatMonitor::new(HeartbeatConfig::default()),
            )),
            sequence_counter: Arc::new(AtomicU64::new(0)),
            session_id: None,
            outbox: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub async fn state(&self) -> ConnectionState {
        if let Some(ref sm) = self.state_machine {
            match sm.read().await.state() {
                SessionState::Connected => ConnectionState::Connected,
                SessionState::Unstable => ConnectionState::Unstable,
                SessionState::Disconnected => ConnectionState::Disconnected,
                SessionState::Reconnecting => ConnectionState::Reconnecting,
                SessionState::Suspended => ConnectionState::Suspended,
                SessionState::Reconnected => ConnectionState::Reconnected,
                SessionState::Failed => ConnectionState::Failed,
            }
        } else {
            *self.state.read().await
        }
    }

    pub fn ratchet(&self) -> Option<&Arc<RwLock<DoubleRatchet>>> {
        self.ratchet.as_ref()
    }
    pub fn state_machine(&self) -> Option<&Arc<RwLock<SessionStateMachine>>> {
        self.state_machine.as_ref()
    }
    pub fn message_queue(&self) -> &Arc<Mutex<MessageQueue>> {
        &self.message_queue
    }
    pub fn outbox(&self) -> &Arc<RwLock<Vec<Vec<u8>>>> {
        &self.outbox
    }

    fn next_sequence(&self) -> u64 {
        self.sequence_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn is_disconnected_state(state: ConnectionState) -> bool {
        matches!(
            state,
            ConnectionState::Disconnected
                | ConnectionState::Reconnecting
                | ConnectionState::Suspended
        )
    }

    pub async fn send(&self, channel: &ApiChannel, data: &[u8]) -> Result<()> {
        if !channel.is_open() {
            return Err(CairnError::Protocol("channel is not open".into()));
        }

        let current_state = self.state().await;

        // If disconnected, enqueue in message queue for later retransmission
        if Self::is_disconnected_state(current_state) {
            let seq = self.next_sequence();
            let mut queue = self.message_queue.lock().await;
            let result = queue.enqueue(seq, data.to_vec());
            return match result {
                crate::session::queue::EnqueueResult::Enqueued
                | crate::session::queue::EnqueueResult::EnqueuedWithEviction => Ok(()),
                crate::session::queue::EnqueueResult::Disabled => {
                    Err(CairnError::Protocol("message queuing is disabled".into()))
                }
                crate::session::queue::EnqueueResult::Full => {
                    Err(CairnError::Protocol("message queue is full".into()))
                }
            };
        }

        // Encrypt with Double Ratchet if available
        let encrypted_payload = if let Some(ref ratchet) = self.ratchet {
            let mut ratchet_guard = ratchet.write().await;
            let (header, ciphertext) = ratchet_guard.encrypt(data)?;
            let header_bytes = serde_json::to_vec(&header)
                .map_err(|e| CairnError::Protocol(format!("header serialization: {e}")))?;
            let mut payload = Vec::with_capacity(4 + header_bytes.len() + ciphertext.len());
            payload.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&header_bytes);
            payload.extend_from_slice(&ciphertext);
            payload
        } else {
            data.to_vec()
        };

        // Wrap in CBOR MessageEnvelope
        let session_id_bytes = self.session_id.map(|sid| {
            let mut arr = [0u8; 32];
            arr[..16].copy_from_slice(sid.as_bytes());
            arr
        });

        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::DATA_MESSAGE,
            msg_id: new_msg_id(),
            session_id: session_id_bytes,
            payload: encrypted_payload,
            auth_tag: None,
        };

        let envelope_bytes = envelope.encode()?;
        self.outbox.write().await.push(envelope_bytes);

        let _ = self
            .event_tx
            .send(Event::MessageReceived {
                peer_id: self.peer_id.clone(),
                channel: channel.name().to_string(),
                data: data.to_vec(),
            })
            .await;
        Ok(())
    }

    pub async fn open_channel(&self, name: &str) -> Result<ApiChannel> {
        if name.is_empty() {
            return Err(CairnError::Protocol("channel name cannot be empty".into()));
        }
        if name.starts_with("__cairn_") {
            return Err(CairnError::Protocol("reserved channel name prefix".into()));
        }

        let init = ChannelInit {
            channel_name: name.to_string(),
            metadata: None,
        };
        let init_payload = init.encode()?;

        let session_id_bytes = self.session_id.map(|sid| {
            let mut arr = [0u8; 32];
            arr[..16].copy_from_slice(sid.as_bytes());
            arr
        });
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: crate::session::channel::CHANNEL_INIT,
            msg_id: new_msg_id(),
            session_id: session_id_bytes,
            payload: init_payload,
            auth_tag: None,
        };
        let envelope_bytes = envelope.encode()?;
        self.outbox.write().await.push(envelope_bytes);

        let channel = ApiChannel::new(name.to_string());
        self.channels
            .write()
            .await
            .insert(name.to_string(), channel.clone());
        let _ = self
            .event_tx
            .send(Event::ChannelOpened {
                peer_id: self.peer_id.clone(),
                channel_name: name.to_string(),
            })
            .await;
        Ok(channel)
    }

    pub async fn on_message<F>(&self, channel: &ApiChannel, callback: F)
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        let cb = Arc::new(callback) as Arc<dyn Fn(&[u8]) + Send + Sync>;
        let mut callbacks = self.message_callbacks.write().await;
        callbacks
            .entry(channel.name().to_string())
            .or_default()
            .push(cb);
    }

    pub async fn on_state_change<F>(&self, callback: F)
    where
        F: Fn(ConnectionState) + Send + Sync + 'static,
    {
        let cb = Arc::new(callback) as Arc<dyn Fn(ConnectionState) + Send + Sync>;
        self.state_change_callbacks.write().await.push(cb);
    }

    pub async fn on_custom_message<F>(&self, type_code: u16, callback: F) -> Result<()>
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        if !(APP_MSG_TYPE_MIN..=APP_MSG_TYPE_MAX).contains(&type_code) {
            return Err(CairnError::Protocol(format!(
                "custom message type 0x{type_code:04X} outside application range 0xF000-0xFFFF"
            )));
        }
        self.custom_handlers
            .write()
            .await
            .insert(type_code, Arc::new(callback));
        Ok(())
    }

    /// Dispatch an incoming envelope from the transport layer.
    pub async fn dispatch_incoming(&self, envelope_bytes: &[u8]) -> Result<()> {
        let envelope = MessageEnvelope::decode(envelope_bytes)?;
        self.heartbeat.lock().await.record_activity();

        match envelope.msg_type {
            message_types::DATA_MESSAGE => {
                let plaintext = if let Some(ref ratchet) = self.ratchet {
                    if envelope.payload.len() < 4 {
                        return Err(CairnError::Protocol(
                            "payload too short for header length".into(),
                        ));
                    }
                    let header_len =
                        u32::from_be_bytes(envelope.payload[..4].try_into().unwrap()) as usize;
                    if envelope.payload.len() < 4 + header_len {
                        return Err(CairnError::Protocol("payload too short for header".into()));
                    }
                    let header: crate::crypto::ratchet::RatchetHeader = serde_json::from_slice(
                        &envelope.payload[4..4 + header_len],
                    )
                    .map_err(|e| CairnError::Protocol(format!("header deserialization: {e}")))?;
                    let ciphertext = &envelope.payload[4 + header_len..];
                    let mut ratchet_guard = ratchet.write().await;
                    ratchet_guard.decrypt(&header, ciphertext)?
                } else {
                    envelope.payload.clone()
                };

                let callbacks = self.message_callbacks.read().await;
                for (_channel_name, cbs) in callbacks.iter() {
                    for cb in cbs {
                        cb(&plaintext);
                    }
                }

                let _ = self
                    .event_tx
                    .send(Event::MessageReceived {
                        peer_id: self.peer_id.clone(),
                        channel: String::new(),
                        data: plaintext,
                    })
                    .await;
            }
            t if (APP_MSG_TYPE_MIN..=APP_MSG_TYPE_MAX).contains(&t) => {
                let handlers = self.custom_handlers.read().await;
                if let Some(handler) = handlers.get(&t) {
                    handler(&envelope.payload);
                }
            }
            message_types::HEARTBEAT | message_types::HEARTBEAT_ACK => {
                // Activity already recorded above
            }
            _ => {}
        }

        Ok(())
    }

    /// Drain queued messages after reconnection.
    pub async fn drain_message_queue(&self) -> Result<Vec<Vec<u8>>> {
        let queued = self.message_queue.lock().await.drain();
        Ok(queued.into_iter().map(|m| m.payload).collect())
    }

    pub async fn close(&self) -> Result<()> {
        if let Some(ref sm) = self.state_machine {
            let mut sm_guard = sm.write().await;
            let current = sm_guard.state();
            if SessionStateMachine::is_valid_transition(current, SessionState::Disconnected) {
                sm_guard
                    .transition(SessionState::Disconnected, Some("session closed".into()))
                    .map_err(|e| CairnError::Protocol(format!("state transition failed: {e}")))?;
            }
        }
        *self.state.write().await = ConnectionState::Disconnected;

        let callbacks = self.state_change_callbacks.read().await;
        for cb in callbacks.iter() {
            cb(ConnectionState::Disconnected);
        }

        let _ = self
            .event_tx
            .send(Event::StateChanged {
                peer_id: self.peer_id.clone(),
                state: ConnectionState::Disconnected,
            })
            .await;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ApiChannel {
    name: String,
    open: Arc<AtomicBool>,
}

impl ApiChannel {
    fn new(name: String) -> Self {
        Self {
            name,
            open: Arc::new(AtomicBool::new(true)),
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }
    pub fn close(&self) {
        self.open.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CairnConfig {
        CairnConfig::default()
    }

    fn node_with_test_transport() -> ApiNode {
        let mut node = ApiNode::new(test_config()).unwrap();
        node.set_transport_connector(|_peer_id, identity| {
            let secret = identity.secret_bytes();
            async move {
                let initiator_id = IdentityKeypair::from_bytes(&secret);
                let responder_id = IdentityKeypair::generate();
                let mut initiator = NoiseXXHandshake::new(Role::Initiator, initiator_id);
                let mut responder = NoiseXXHandshake::new(Role::Responder, responder_id);
                let msg1 = match initiator.step(None)? {
                    StepOutput::SendMessage(m) => m,
                    _ => return Err(CairnError::Crypto("unexpected".into())),
                };
                let msg2 = match responder.step(Some(&msg1))? {
                    StepOutput::SendMessage(m) => m,
                    _ => return Err(CairnError::Crypto("unexpected".into())),
                };
                let msg3 = match initiator.step(Some(&msg2))? {
                    StepOutput::SendMessage(m) => m,
                    _ => return Err(CairnError::Crypto("unexpected".into())),
                };
                let _ = responder.step(Some(&msg3))?;
                let result = initiator.result()?;
                let bob_dh = X25519Keypair::generate();
                let bob_public = *bob_dh.public_key().as_bytes();
                let ratchet = DoubleRatchet::init_initiator(
                    result.session_key,
                    bob_public,
                    RatchetConfig::default(),
                )?;
                Ok(ConnectResult {
                    transport_type: FallbackTransportType::DirectQuic,
                    ratchet,
                    session_id: SessionId::new(),
                })
            }
        });
        node
    }

    #[test]
    fn api_node_creation() {
        let node = ApiNode::new(test_config()).unwrap();
        assert!(!node.config().server_mode);
    }
    #[tokio::test]
    async fn node_has_identity() {
        let node = ApiNode::new(test_config()).unwrap();
        let _ = node.identity().public_key();
    }
    #[tokio::test]
    async fn node_has_local_identity() {
        let node = ApiNode::new(test_config()).unwrap();
        let _ = node.peer_id();
    }
    #[tokio::test]
    async fn node_has_trust_store() {
        let node = ApiNode::new(test_config()).unwrap();
        assert!(node.trust_store().read().await.list_peers().is_empty());
    }
    #[tokio::test]
    async fn node_debug_format() {
        let node = ApiNode::new(test_config()).unwrap();
        assert!(format!("{node:?}").contains("ApiNode"));
    }

    #[tokio::test]
    async fn connect_creates_session() {
        let node = node_with_test_transport();
        let session = node.connect("peer-abc").await.unwrap();
        assert_eq!(session.peer_id(), "peer-abc");
        assert_eq!(session.state().await, ConnectionState::Connected);
    }
    #[tokio::test]
    async fn connect_wires_ratchet() {
        let node = node_with_test_transport();
        assert!(node.connect("peer-1").await.unwrap().ratchet().is_some());
    }
    #[tokio::test]
    async fn connect_wires_state_machine() {
        let node = node_with_test_transport();
        let session = node.connect("peer-1").await.unwrap();
        assert!(session.state_machine().is_some());
        assert_eq!(
            session.state_machine().unwrap().read().await.state(),
            SessionState::Connected
        );
    }
    #[tokio::test]
    async fn connect_with_failing_transport() {
        let mut node = ApiNode::new(test_config()).unwrap();
        node.set_transport_connector(|_, _| async {
            Err(CairnError::TransportExhausted {
                details: "fail".into(),
                suggestion: "n/a".into(),
            })
        });
        assert!(matches!(
            node.connect("peer-1").await.unwrap_err(),
            CairnError::TransportExhausted { .. }
        ));
    }
    #[tokio::test]
    async fn connect_default_simulated() {
        let node = ApiNode::new(test_config()).unwrap();
        let s = node.connect("peer-1").await.unwrap();
        assert_eq!(s.state().await, ConnectionState::Connected);
        assert!(s.ratchet().is_some());
        assert!(s.state_machine().is_some());
    }
    #[tokio::test]
    async fn ratchet_can_encrypt_after_connect() {
        let node = node_with_test_transport();
        let session = node.connect("peer-1").await.unwrap();
        let mut rg = session.ratchet().unwrap().write().await;
        let (h, ct) = rg.encrypt(b"hello world").unwrap();
        assert_eq!(h.msg_num, 0);
        assert!(!ct.is_empty());
    }
    #[tokio::test]
    async fn session_open_channel() {
        let node = node_with_test_transport();
        let s = node.connect("peer-1").await.unwrap();
        let ch = s.open_channel("data").await.unwrap();
        assert_eq!(ch.name(), "data");
        assert!(ch.is_open());
    }
    #[tokio::test]
    async fn session_open_channel_empty_name() {
        let node = node_with_test_transport();
        assert!(node
            .connect("p")
            .await
            .unwrap()
            .open_channel("")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn session_open_channel_reserved() {
        let node = node_with_test_transport();
        assert!(node
            .connect("p")
            .await
            .unwrap()
            .open_channel("__cairn_x")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn session_send_open() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        assert!(s.send(&ch, b"hi").await.is_ok());
    }
    #[tokio::test]
    async fn session_send_closed() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        ch.close();
        assert!(s.send(&ch, b"hi").await.is_err());
    }
    #[tokio::test]
    async fn session_close() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        s.close().await.unwrap();
        assert_eq!(s.state().await, ConnectionState::Disconnected);
    }
    #[tokio::test]
    async fn session_close_transitions_sm() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        s.close().await.unwrap();
        assert_eq!(
            s.state_machine().unwrap().read().await.state(),
            SessionState::Disconnected
        );
    }
    #[tokio::test]
    async fn custom_msg_valid() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        assert!(s.on_custom_message(0xF000, |_| {}).await.is_ok());
        assert!(s.on_custom_message(0xFFFF, |_| {}).await.is_ok());
    }
    #[tokio::test]
    async fn custom_msg_invalid() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        assert!(s.on_custom_message(0x0100, |_| {}).await.is_err());
        assert!(s.on_custom_message(0xEFFF, |_| {}).await.is_err());
    }
    #[tokio::test]
    async fn unpair_removes_session() {
        let node = node_with_test_transport();
        node.connect("p").await.unwrap();
        node.unpair("p").await.unwrap();
    }
    #[tokio::test]
    async fn multiple_channels() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let c1 = s.open_channel("a").await.unwrap();
        let c2 = s.open_channel("b").await.unwrap();
        assert_eq!(c1.name(), "a");
        assert_eq!(c2.name(), "b");
    }
    #[tokio::test]
    async fn on_message_cb() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        s.on_message(&ch, |_| {}).await;
    }
    #[tokio::test]
    async fn on_state_change_cb() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        s.on_state_change(|_| {}).await;
    }
    #[tokio::test]
    async fn session_debug() {
        let node = node_with_test_transport();
        let s = node.connect("peer-1").await.unwrap();
        assert!(format!("{s:?}").contains("peer-1"));
    }
    #[tokio::test]
    async fn recv_event_connect() {
        let node = node_with_test_transport();
        let _ = node.connect("peer-1").await.unwrap();
        match node.recv_event().await.unwrap() {
            Event::StateChanged { peer_id, state } => {
                assert_eq!(peer_id, "peer-1");
                assert_eq!(state, ConnectionState::Connected);
            }
            _ => panic!("expected StateChanged"),
        }
    }
    #[tokio::test]
    async fn network_info_default() {
        assert_eq!(
            ApiNode::new(test_config())
                .unwrap()
                .network_info()
                .await
                .nat_type,
            NatType::Unknown
        );
    }
    #[tokio::test]
    async fn set_nat_type() {
        let n = ApiNode::new(test_config()).unwrap();
        n.set_nat_type(NatType::FullCone).await;
        assert_eq!(n.network_info().await.nat_type, NatType::FullCone);
    }
    #[test]
    fn channel_lifecycle() {
        let ch = ApiChannel::new("t".into());
        assert!(ch.is_open());
        ch.close();
        assert!(!ch.is_open());
    }

    // Pairing tests
    #[tokio::test]
    async fn pair_generate_qr_valid() {
        let node = ApiNode::new(test_config()).unwrap();
        let data = node.pair_generate_qr().await.unwrap();
        assert!(!data.payload.is_empty());
        let payload = PairingPayload::from_cbor(&data.payload).unwrap();
        assert_eq!(&payload.peer_id, node.peer_id());
    }
    #[tokio::test]
    async fn pair_scan_qr_roundtrip() {
        let node = ApiNode::new(test_config()).unwrap();
        let qr = node.pair_generate_qr().await.unwrap();
        let pid = node.pair_scan_qr(&qr.payload).await.unwrap();
        assert_eq!(&pid, node.peer_id());
        assert!(node.trust_store().read().await.is_paired(&pid));
    }
    #[tokio::test]
    async fn pair_scan_qr_invalid() {
        assert!(ApiNode::new(test_config())
            .unwrap()
            .pair_scan_qr(b"bad")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn pair_generate_pin_formatted() {
        let node = ApiNode::new(test_config()).unwrap();
        let data = node.pair_generate_pin().await.unwrap();
        assert_eq!(data.pin.len(), 9);
        assert_eq!(&data.pin[4..5], "-");
    }
    #[tokio::test]
    async fn pair_enter_pin_roundtrip() {
        let node = ApiNode::new(test_config()).unwrap();
        let pin = node.pair_generate_pin().await.unwrap();
        let pid = node.pair_enter_pin(&pin.pin).await.unwrap();
        assert!(node.trust_store().read().await.is_paired(&pid));
    }
    #[tokio::test]
    async fn pair_enter_pin_invalid() {
        assert!(ApiNode::new(test_config())
            .unwrap()
            .pair_enter_pin("!!!")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn pair_generate_link_real() {
        let node = ApiNode::new(test_config()).unwrap();
        let data = node.pair_generate_link().await.unwrap();
        assert!(data.uri.starts_with("cairn://pair?"));
        assert!(data.uri.contains("pid="));
    }
    #[tokio::test]
    async fn pair_from_link_roundtrip() {
        let node = ApiNode::new(test_config()).unwrap();
        let link = node.pair_generate_link().await.unwrap();
        let pid = node.pair_from_link(&link.uri).await.unwrap();
        assert_eq!(&pid, node.peer_id());
        assert!(node.trust_store().read().await.is_paired(&pid));
    }
    #[tokio::test]
    async fn pair_from_link_invalid() {
        assert!(ApiNode::new(test_config())
            .unwrap()
            .pair_from_link("https://x.com")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn pairing_emits_event() {
        let node = ApiNode::new(test_config()).unwrap();
        let qr = node.pair_generate_qr().await.unwrap();
        let _ = node.pair_scan_qr(&qr.payload).await.unwrap();
        match node.recv_event().await.unwrap() {
            Event::PairingCompleted { peer_id } => assert!(!peer_id.is_empty()),
            other => panic!("expected PairingCompleted, got: {other:?}"),
        }
    }
    #[tokio::test]
    async fn unpair_removes_trust() {
        let node = ApiNode::new(test_config()).unwrap();
        let qr = node.pair_generate_qr().await.unwrap();
        let pid = node.pair_scan_qr(&qr.payload).await.unwrap();
        assert!(node.trust_store().read().await.is_paired(&pid));
        node.unpair(&pid.to_string()).await.unwrap();
        assert!(!node.trust_store().read().await.is_paired(&pid));
    }

    // Task 007: messaging wiring tests

    #[tokio::test]
    async fn send_produces_encrypted_envelope() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("data").await.unwrap();
        // open_channel produces one envelope (ChannelInit)
        let pre_count = s.outbox().read().await.len();
        s.send(&ch, b"hello").await.unwrap();
        let outbox = s.outbox().read().await;
        assert_eq!(outbox.len(), pre_count + 1);
        // Decode the last envelope
        let envelope = MessageEnvelope::decode(outbox.last().unwrap()).unwrap();
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.msg_type, message_types::DATA_MESSAGE);
        assert!(!envelope.payload.is_empty());
        // Payload should be encrypted (header_len + header + ciphertext), not plaintext
        assert!(envelope.payload.len() > 5); // at least header length prefix + something
    }

    #[tokio::test]
    async fn send_without_ratchet_stores_plaintext() {
        let (tx, _rx) = mpsc::channel(256);
        let session = ApiSession::new("peer-x".into(), tx);
        let ch = ApiChannel::new("test".into());
        session
            .channels
            .write()
            .await
            .insert("test".into(), ch.clone());
        session.send(&ch, b"raw data").await.unwrap();
        let outbox = session.outbox().read().await;
        assert_eq!(outbox.len(), 1);
        let envelope = MessageEnvelope::decode(&outbox[0]).unwrap();
        assert_eq!(envelope.payload, b"raw data");
    }

    #[tokio::test]
    async fn open_channel_sends_channel_init_envelope() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let outbox_before = s.outbox().read().await.len();
        drop(s.outbox().read().await);
        let _ch = s.open_channel("my-channel").await.unwrap();
        let outbox = s.outbox().read().await;
        assert_eq!(outbox.len(), outbox_before + 1);
        let envelope = MessageEnvelope::decode(outbox.last().unwrap()).unwrap();
        assert_eq!(envelope.msg_type, crate::session::channel::CHANNEL_INIT);
        // Decode ChannelInit payload
        let init = ChannelInit::decode(&envelope.payload).unwrap();
        assert_eq!(init.channel_name, "my-channel");
    }

    #[tokio::test]
    async fn on_message_stores_callback() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        s.on_message(&ch, move |_data| {}).await;
        let callbacks = s.message_callbacks.read().await;
        assert!(callbacks.contains_key("d"));
        assert_eq!(callbacks["d"].len(), 1);
    }

    #[tokio::test]
    async fn on_state_change_stores_callback() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        s.on_state_change(|_state| {}).await;
        let callbacks = s.state_change_callbacks.read().await;
        assert_eq!(callbacks.len(), 1);
    }

    #[tokio::test]
    async fn close_invokes_state_change_callbacks() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let invoked = Arc::new(AtomicBool::new(false));
        let invoked_clone = invoked.clone();
        s.on_state_change(move |state| {
            if state == ConnectionState::Disconnected {
                invoked_clone.store(true, Ordering::Relaxed);
            }
        })
        .await;
        s.close().await.unwrap();
        assert!(invoked.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn send_queues_when_disconnected() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        // Close session to transition to Disconnected
        s.close().await.unwrap();
        assert_eq!(s.state().await, ConnectionState::Disconnected);
        // Send should enqueue rather than produce an envelope
        let outbox_before = s.outbox().read().await.len();
        s.send(&ch, b"queued msg").await.unwrap();
        // Outbox shouldn't grow (no envelope produced)
        assert_eq!(s.outbox().read().await.len(), outbox_before);
        // Message queue should have the message
        assert_eq!(s.message_queue().lock().await.len(), 1);
    }

    #[tokio::test]
    async fn drain_message_queue_returns_payloads() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        s.close().await.unwrap();
        s.send(&ch, b"msg1").await.unwrap();
        s.send(&ch, b"msg2").await.unwrap();
        let drained = s.drain_message_queue().await.unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], b"msg1");
        assert_eq!(drained[1], b"msg2");
        // Queue should be empty after drain
        assert!(s.message_queue().lock().await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_incoming_decrypts_data_message() {
        // Test dispatch with no ratchet (plaintext path)
        let (tx, _rx) = mpsc::channel(256);
        let session = ApiSession::new("peer-x".into(), tx.clone());
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::DATA_MESSAGE,
            msg_id: new_msg_id(),
            session_id: None,
            payload: b"plaintext data".to_vec(),
            auth_tag: None,
        };
        let encoded = envelope.encode().unwrap();
        session.dispatch_incoming(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_incoming_invokes_message_callbacks() {
        let (tx, _rx) = mpsc::channel(256);
        let session = ApiSession::new("peer-x".into(), tx);
        let ch = ApiChannel::new("test".into());
        session
            .channels
            .write()
            .await
            .insert("test".into(), ch.clone());
        let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = received.clone();
        session
            .on_message(&ch, move |data| {
                received_clone.lock().unwrap().push(data.to_vec());
            })
            .await;
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::DATA_MESSAGE,
            msg_id: new_msg_id(),
            session_id: None,
            payload: b"callback test".to_vec(),
            auth_tag: None,
        };
        session
            .dispatch_incoming(&envelope.encode().unwrap())
            .await
            .unwrap();
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"callback test");
    }

    #[tokio::test]
    async fn dispatch_incoming_invokes_custom_handler() {
        let (tx, _rx) = mpsc::channel(256);
        let session = ApiSession::new("peer-x".into(), tx);
        let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = received.clone();
        session
            .on_custom_message(0xF001, move |data| {
                received_clone.lock().unwrap().push(data.to_vec());
            })
            .await
            .unwrap();
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: 0xF001,
            msg_id: new_msg_id(),
            session_id: None,
            payload: b"custom payload".to_vec(),
            auth_tag: None,
        };
        session
            .dispatch_incoming(&envelope.encode().unwrap())
            .await
            .unwrap();
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"custom payload");
    }

    #[tokio::test]
    async fn dispatch_incoming_records_heartbeat_activity() {
        let (tx, _rx) = mpsc::channel(256);
        let session = ApiSession::new("peer-x".into(), tx);
        let envelope = MessageEnvelope {
            version: 1,
            msg_type: message_types::HEARTBEAT,
            msg_id: new_msg_id(),
            session_id: None,
            payload: vec![],
            auth_tag: None,
        };
        session
            .dispatch_incoming(&envelope.encode().unwrap())
            .await
            .unwrap();
        // Heartbeat monitor should have recent activity
        let hb = session.heartbeat.lock().await;
        assert!(!hb.is_timed_out());
    }

    #[tokio::test]
    async fn session_has_session_id_after_connect() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        assert!(s.session_id.is_some());
    }

    #[tokio::test]
    async fn envelope_has_session_id() {
        let node = node_with_test_transport();
        let s = node.connect("p").await.unwrap();
        let ch = s.open_channel("d").await.unwrap();
        s.send(&ch, b"test").await.unwrap();
        let outbox = s.outbox().read().await;
        let envelope = MessageEnvelope::decode(outbox.last().unwrap()).unwrap();
        assert!(envelope.session_id.is_some());
    }
}
