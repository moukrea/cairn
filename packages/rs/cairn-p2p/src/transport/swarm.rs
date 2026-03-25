use std::fmt;

use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use super::TransportConfig;
use crate::crypto::IdentityKeypair;
use crate::error::{CairnError, Result};

// ---------------------------------------------------------------------------
// Swarm events forwarded to the caller
// ---------------------------------------------------------------------------

/// Events forwarded from the libp2p swarm event loop to the caller.
#[derive(Debug)]
pub enum SwarmEvent {
    /// A new listening address was established.
    ListeningOn { address: Multiaddr },
    /// An inbound connection was established.
    InboundConnection { peer_id: PeerId },
    /// An outbound connection was established.
    OutboundConnection { peer_id: PeerId },
    /// A connection was closed.
    ConnectionClosed { peer_id: PeerId },
    /// A listener encountered an error.
    ListenerError { error: String },
    /// A listener was closed.
    ListenerClosed { addresses: Vec<Multiaddr> },
    /// An outgoing dial failed.
    DialFailure {
        peer_id: Option<PeerId>,
        error: String,
    },
    /// A peer was discovered via mDNS on the local network.
    MdnsPeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    /// An mDNS-discovered peer expired (no longer on LAN).
    MdnsPeerExpired { peer_id: PeerId },
    /// An incoming request-response message was received.
    RequestReceived {
        peer_id: PeerId,
        request_id: libp2p::request_response::InboundRequestId,
        request: Vec<u8>,
    },
    /// A response to an outgoing request was received.
    ResponseReceived {
        peer_id: PeerId,
        request_id: libp2p::request_response::OutboundRequestId,
        response: Vec<u8>,
    },
    /// An outgoing request failed.
    RequestFailed {
        peer_id: PeerId,
        request_id: libp2p::request_response::OutboundRequestId,
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Commands sent from the controller to the event loop
// ---------------------------------------------------------------------------

pub(crate) enum SwarmCommand {
    ListenOn {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<()>>,
    },
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Send a request to a connected peer via the request-response protocol.
    SendRequest {
        peer_id: PeerId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<libp2p::request_response::OutboundRequestId>>,
    },
    /// Send a response to an inbound request.
    SendResponse {
        request_id: libp2p::request_response::InboundRequestId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Store a record in the Kademlia DHT.
    KadPutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Retrieve a record from the Kademlia DHT.
    KadGetRecord {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// SwarmController — handle returned to the caller
// ---------------------------------------------------------------------------

/// Handle for controlling the libp2p swarm from outside the event loop.
///
/// Provides `listen_on`, `dial`, and `shutdown` methods. The controller
/// communicates with the event loop via an `mpsc` channel.
pub struct SwarmController {
    command_tx: mpsc::Sender<SwarmCommand>,
    event_rx: mpsc::Receiver<SwarmEvent>,
}

/// A cloneable handle for sending commands to the swarm event loop.
///
/// Discovery backends use this to issue Kademlia put/get commands
/// through the composed swarm instead of spawning their own swarms.
#[derive(Clone)]
pub struct SwarmCommandSender {
    command_tx: mpsc::Sender<SwarmCommand>,
}

impl fmt::Debug for SwarmController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwarmController").finish_non_exhaustive()
    }
}

impl SwarmController {
    /// Start listening on the given multiaddr.
    pub async fn listen_on(&self, addr: Multiaddr) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::ListenOn {
                addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Dial the given multiaddr.
    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::Dial {
                addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Send a request to a connected peer via the request-response protocol.
    pub async fn send_request(
        &self,
        peer_id: PeerId,
        data: Vec<u8>,
    ) -> Result<libp2p::request_response::OutboundRequestId> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::SendRequest {
                peer_id,
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Send a response to an inbound request.
    pub async fn send_response(
        &self,
        request_id: libp2p::request_response::InboundRequestId,
        data: Vec<u8>,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::SendResponse {
                request_id,
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Gracefully shut down the swarm event loop.
    pub async fn shutdown(&self) -> Result<()> {
        self.command_tx
            .send(SwarmCommand::Shutdown)
            .await
            .map_err(|_| CairnError::Transport("swarm event loop already shut down".into()))
    }

    /// Receive the next swarm event. Returns `None` when the event loop exits.
    pub async fn next_event(&mut self) -> Option<SwarmEvent> {
        self.event_rx.recv().await
    }

    /// Get a cloneable command sender for discovery backends.
    ///
    /// Discovery backends use this to send Kademlia put/get commands through
    /// the composed swarm instead of spawning their own dedicated swarms.
    pub fn command_sender(&self) -> SwarmCommandSender {
        SwarmCommandSender {
            command_tx: self.command_tx.clone(),
        }
    }
}

impl SwarmCommandSender {
    /// Send a request to a connected peer via the request-response protocol.
    pub async fn send_request(
        &self,
        peer_id: PeerId,
        data: Vec<u8>,
    ) -> Result<libp2p::request_response::OutboundRequestId> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::SendRequest {
                peer_id,
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Store a record in the Kademlia DHT via the composed swarm.
    pub async fn kad_put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::KadPutRecord {
                key,
                value,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Retrieve a record from the Kademlia DHT via the composed swarm.
    pub async fn kad_get_record(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::KadGetRecord {
                key,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }
}

// ---------------------------------------------------------------------------
// CairnCodec — request-response codec for cairn's CBOR protocol
// ---------------------------------------------------------------------------

/// Cairn protocol stream protocol identifier.
pub const CAIRN_PROTOCOL: &str = "/cairn/1.0.0";

/// Request-response codec for cairn's CBOR-framed protocol messages.
///
/// Messages are length-prefixed (4 bytes big-endian) followed by the raw
/// CBOR payload. Both requests and responses use the same framing.
#[derive(Debug, Clone, Default)]
pub struct CairnCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for CairnCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures_util::AsyncRead + Unpin + Send,
    {
        use futures_util::AsyncReadExt;

        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Cap at 1 MiB to prevent memory exhaustion.
        if len > 1_048_576 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }

        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures_util::AsyncRead + Unpin + Send,
    {
        use futures_util::AsyncReadExt;

        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1_048_576 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response too large",
            ));
        }

        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures_util::AsyncWrite + Unpin + Send,
    {
        use futures_util::AsyncWriteExt;

        let len = (req.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&req).await?;
        io.flush().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures_util::AsyncWrite + Unpin + Send,
    {
        use futures_util::AsyncWriteExt;

        let len = (resp.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&resp).await?;
        io.flush().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Composed NetworkBehaviour
// ---------------------------------------------------------------------------

// Isolated in a submodule so the `NetworkBehaviour` derive macro doesn't
// conflict with our crate-level `Result` type alias.
mod behaviour {
    use libp2p::swarm::NetworkBehaviour;

    /// Composed behaviour for the cairn swarm, including:
    /// - mDNS for LAN peer discovery
    /// - Kademlia DHT for distributed peer/record lookup
    /// - Request-response for cairn's application-level CBOR protocol
    #[derive(NetworkBehaviour)]
    pub(super) struct CairnBehaviour {
        pub(super) mdns: libp2p::mdns::tokio::Behaviour,
        pub(super) kademlia: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
        pub(super) request_response: libp2p::request_response::Behaviour<super::CairnCodec>,
    }
}

use behaviour::CairnBehaviour;
#[allow(unused_imports)]
use behaviour::CairnBehaviourEvent;

// ---------------------------------------------------------------------------
// build_swarm — construct the libp2p Swarm and spawn the event loop
// ---------------------------------------------------------------------------

/// Build a libp2p Swarm with the configured transports and spawn an async
/// event loop. Returns a [`SwarmController`] for interacting with the swarm.
///
/// The swarm is constructed using libp2p's `SwarmBuilder` with:
/// - QUIC v1 (priority 1 in the transport fallback chain)
/// - TCP with Noise encryption and Yamux multiplexing (priority 3)
/// - WebSocket/TLS with Noise encryption and Yamux multiplexing (priority 6)
///
/// The composed behaviour includes mDNS, Kademlia DHT, and request-response
/// for cairn's application protocol.
///
/// # Arguments
/// * `identity` - The Ed25519 identity keypair used for Noise authentication
/// * `config` - Transport configuration controlling which transports are active
pub async fn build_swarm(
    identity: &IdentityKeypair,
    config: &TransportConfig,
) -> Result<SwarmController> {
    let keypair = libp2p_keypair_from_identity(identity)?;

    let swarm = build_swarm_inner(keypair, config).await?;

    let (command_tx, command_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(256);

    tokio::spawn(run_event_loop(swarm, command_rx, event_tx));

    Ok(SwarmController {
        command_tx,
        event_rx,
    })
}

/// Convert our IdentityKeypair to a libp2p Keypair.
fn libp2p_keypair_from_identity(identity: &IdentityKeypair) -> Result<libp2p::identity::Keypair> {
    let secret = identity.secret_bytes();
    libp2p::identity::Keypair::ed25519_from_bytes(secret)
        .map_err(|e| CairnError::Crypto(format!("failed to create libp2p keypair: {e}")))
}

/// Inner swarm construction using the SwarmBuilder API.
///
/// The SwarmBuilder uses a type-state pattern that requires a fixed call
/// chain: identity -> runtime -> tcp -> quic -> dns -> websocket -> behaviour -> build.
/// All transports are always composed; the `TransportConfig` flags will be
/// used at the transport-fallback layer to skip disabled transports.
async fn build_swarm_inner(
    keypair: libp2p::identity::Keypair,
    config: &TransportConfig,
) -> Result<Swarm<CairnBehaviour>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| CairnError::Transport(format!("failed to configure TCP: {e}")))?
        .with_quic()
        .with_dns()
        .map_err(|e| CairnError::Transport(format!("failed to configure DNS: {e}")))?
        .with_websocket(
            (libp2p::tls::Config::new, libp2p::noise::Config::new),
            libp2p::yamux::Config::default,
        )
        .await
        .map_err(|e| CairnError::Transport(format!("failed to configure WebSocket: {e}")))?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            // mDNS for LAN discovery.
            let mdns =
                libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer_id)
                    .map_err(|e| format!("mDNS init failed: {e}"))?;

            // Kademlia DHT.
            let store = libp2p::kad::store::MemoryStore::new(peer_id);
            let kademlia = libp2p::kad::Behaviour::new(peer_id, store);

            // Request-response for cairn's CBOR protocol.
            let request_response = libp2p::request_response::Behaviour::new(
                [(
                    StreamProtocol::new(CAIRN_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                libp2p::request_response::Config::default(),
            );

            Ok(CairnBehaviour {
                mdns,
                kademlia,
                request_response,
            })
        })
        .map_err(|e| CairnError::Transport(format!("failed to create behaviour: {e}")))?
        .with_swarm_config(|cfg: libp2p::swarm::Config| {
            cfg.with_idle_connection_timeout(config.per_transport_timeout)
        })
        .build();

    Ok(swarm)
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Main swarm event loop. Processes libp2p SwarmEvents and commands from the
/// SwarmController.
async fn run_event_loop(
    mut swarm: Swarm<CairnBehaviour>,
    mut command_rx: mpsc::Receiver<SwarmCommand>,
    event_tx: mpsc::Sender<SwarmEvent>,
) {
    use libp2p::swarm::SwarmEvent as LibSwarmEvent;

    // Pending Kademlia GET queries: query_id -> reply sender.
    type KadGetReply = oneshot::Sender<Result<Option<Vec<u8>>>>;
    let mut pending_kad_gets: std::collections::HashMap<libp2p::kad::QueryId, KadGetReply> =
        std::collections::HashMap::new();

    // Pending inbound request-response channels for deferred responses.
    let mut pending_inbound_requests: std::collections::HashMap<
        libp2p::request_response::InboundRequestId,
        libp2p::request_response::ResponseChannel<Vec<u8>>,
    > = std::collections::HashMap::new();

    loop {
        tokio::select! {
            cmd = command_rx.recv() => {
                match cmd {
                    Some(SwarmCommand::ListenOn { addr, reply }) => {
                        let result = swarm
                            .listen_on(addr)
                            .map(|_| ())
                            .map_err(|e| {
                                CairnError::Transport(format!("listen_on failed: {e}"))
                            });
                        let _ = reply.send(result);
                    }
                    Some(SwarmCommand::Dial { addr, reply }) => {
                        let result = swarm
                            .dial(addr)
                            .map_err(|e| {
                                CairnError::Transport(format!("dial failed: {e}"))
                            });
                        let _ = reply.send(result);
                    }
                    Some(SwarmCommand::SendRequest { peer_id, data, reply }) => {
                        let request_id = swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer_id, data);
                        let _ = reply.send(Ok(request_id));
                    }
                    Some(SwarmCommand::SendResponse { request_id, data, reply }) => {
                        // The request-response behaviour keeps pending inbound
                        // requests in its internal state. We need to retrieve
                        // the response channel for this request_id.
                        // Note: libp2p request_response sends response via the
                        // channel stored during Event::Message::Request.
                        // We store these channels in pending_inbound_requests.
                        if let Some(channel) = pending_inbound_requests.remove(&request_id) {
                            let result = swarm
                                .behaviour_mut()
                                .request_response
                                .send_response(channel, data)
                                .map_err(|_| CairnError::Transport("failed to send response".into()));
                            let _ = reply.send(result);
                        } else {
                            let _ = reply.send(Err(CairnError::Transport(
                                "no pending inbound request for this ID".into(),
                            )));
                        }
                    }
                    Some(SwarmCommand::KadPutRecord { key, value, reply }) => {
                        let record_key = libp2p::kad::RecordKey::new(&key);
                        let record = libp2p::kad::Record {
                            key: record_key,
                            value,
                            publisher: None,
                            expires: None,
                        };
                        let result = swarm
                            .behaviour_mut()
                            .kademlia
                            .put_record(record, libp2p::kad::Quorum::One)
                            .map(|_| ())
                            .map_err(|e| {
                                CairnError::Transport(format!("kad put_record failed: {e:?}"))
                            });
                        let _ = reply.send(result);
                    }
                    Some(SwarmCommand::KadGetRecord { key, reply }) => {
                        let record_key = libp2p::kad::RecordKey::new(&key);
                        let query_id = swarm
                            .behaviour_mut()
                            .kademlia
                            .get_record(record_key);
                        pending_kad_gets.insert(query_id, reply);
                    }
                    Some(SwarmCommand::Shutdown) => {
                        info!("swarm event loop shutting down");
                        break;
                    }
                    None => {
                        debug!("command channel closed, shutting down event loop");
                        break;
                    }
                }
            }

            event = libp2p::futures::StreamExt::select_next_some(&mut swarm) => {
                let forwarded = match event {
                    LibSwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "listening on new address");
                        Some(SwarmEvent::ListeningOn { address })
                    }
                    LibSwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        ..
                    } => {
                        if endpoint.is_dialer() {
                            debug!(%peer_id, "outbound connection established");
                            Some(SwarmEvent::OutboundConnection { peer_id })
                        } else {
                            debug!(%peer_id, "inbound connection established");
                            Some(SwarmEvent::InboundConnection { peer_id })
                        }
                    }
                    LibSwarmEvent::ConnectionClosed { peer_id, .. } => {
                        debug!(%peer_id, "connection closed");
                        Some(SwarmEvent::ConnectionClosed { peer_id })
                    }
                    LibSwarmEvent::ListenerError { error, .. } => {
                        warn!(%error, "listener error");
                        Some(SwarmEvent::ListenerError {
                            error: error.to_string(),
                        })
                    }
                    LibSwarmEvent::ListenerClosed { addresses, .. } => {
                        debug!(?addresses, "listener closed");
                        Some(SwarmEvent::ListenerClosed { addresses })
                    }
                    LibSwarmEvent::OutgoingConnectionError {
                        peer_id, error, ..
                    } => {
                        warn!(?peer_id, %error, "dial failure");
                        Some(SwarmEvent::DialFailure {
                            peer_id,
                            error: error.to_string(),
                        })
                    }
                    // --- mDNS behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Discovered(peers),
                    )) => {
                        // Collect discovered peers and add their addresses to Kademlia.
                        let mut grouped: std::collections::HashMap<PeerId, Vec<Multiaddr>> =
                            std::collections::HashMap::new();
                        for (peer_id, addr) in peers {
                            debug!(%peer_id, %addr, "mDNS discovered peer");
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            grouped.entry(peer_id).or_default().push(addr);
                        }
                        // Send one event per discovered peer.
                        for (peer_id, addresses) in grouped {
                            let evt = SwarmEvent::MdnsPeerDiscovered { peer_id, addresses };
                            if event_tx.send(evt).await.is_err() {
                                debug!("event receiver dropped, shutting down event loop");
                                return;
                            }
                        }
                        None // Already sent events manually.
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Expired(peers),
                    )) => {
                        let mut expired_peers: std::collections::HashSet<PeerId> =
                            std::collections::HashSet::new();
                        for (peer_id, _addr) in peers {
                            debug!(%peer_id, "mDNS peer expired");
                            expired_peers.insert(peer_id);
                        }
                        for peer_id in expired_peers {
                            let evt = SwarmEvent::MdnsPeerExpired { peer_id };
                            if event_tx.send(evt).await.is_err() {
                                debug!("event receiver dropped, shutting down event loop");
                                return;
                            }
                        }
                        None
                    }
                    // --- Kademlia behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            id,
                            result: libp2p::kad::QueryResult::GetRecord(result),
                            ..
                        },
                    )) => {
                        if let Some(reply) = pending_kad_gets.remove(&id) {
                            match result {
                                Ok(libp2p::kad::GetRecordOk::FoundRecord(peer_record)) => {
                                    debug!("Kademlia GET found record");
                                    let _ = reply.send(Ok(Some(peer_record.record.value)));
                                }
                                Ok(libp2p::kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                                    // Already replied via FoundRecord or this is a no-result finish.
                                }
                                Err(_e) => {
                                    debug!("Kademlia GET query failed, returning None");
                                    let _ = reply.send(Ok(None));
                                }
                            }
                        }
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            result: libp2p::kad::QueryResult::PutRecord(result),
                            ..
                        },
                    )) => {
                        match result {
                            Ok(_) => debug!("Kademlia PUT record stored"),
                            Err(e) => warn!(?e, "Kademlia PUT failed"),
                        }
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(event)) => {
                        debug!(?event, "Kademlia event");
                        None
                    }
                    // --- Request-response behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::Message { peer, message },
                    )) => {
                        match message {
                            libp2p::request_response::Message::Request {
                                request_id,
                                request,
                                channel,
                            } => {
                                debug!(%peer, ?request_id, "received request");
                                // Store the response channel for deferred SendResponse
                                pending_inbound_requests.insert(request_id, channel);
                                Some(SwarmEvent::RequestReceived {
                                    peer_id: peer,
                                    request_id,
                                    request,
                                })
                            }
                            libp2p::request_response::Message::Response {
                                request_id,
                                response,
                            } => {
                                debug!(%peer, ?request_id, "received response");
                                Some(SwarmEvent::ResponseReceived {
                                    peer_id: peer,
                                    request_id,
                                    response,
                                })
                            }
                        }
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::OutboundFailure {
                            peer,
                            request_id,
                            error,
                            ..
                        },
                    )) => {
                        warn!(%peer, ?request_id, %error, "outbound request failed");
                        Some(SwarmEvent::RequestFailed {
                            peer_id: peer,
                            request_id,
                            error: error.to_string(),
                        })
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::InboundFailure {
                            peer, error, ..
                        },
                    )) => {
                        warn!(%peer, %error, "inbound request failed");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::ResponseSent { .. },
                    )) => None,
                    _ => None,
                };

                if let Some(evt) = forwarded {
                    if event_tx.send(evt).await.is_err() {
                        debug!("event receiver dropped, shutting down event loop");
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_swarm_with_default_config() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let controller = build_swarm(&identity, &config).await;
        assert!(
            controller.is_ok(),
            "swarm construction should succeed with default config"
        );
        let controller = controller.unwrap();
        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn listen_on_tcp_produces_event() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let mut controller = build_swarm(&identity, &config).await.unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        controller.listen_on(addr).await.unwrap();

        let event =
            tokio::time::timeout(std::time::Duration::from_secs(5), controller.next_event())
                .await
                .expect("should receive event within timeout")
                .expect("event should not be None");

        match event {
            SwarmEvent::ListeningOn { address } => {
                let addr_str = address.to_string();
                assert!(
                    addr_str.contains("127.0.0.1"),
                    "address should contain 127.0.0.1, got: {addr_str}"
                );
            }
            other => panic!("expected ListeningOn event, got: {other:?}"),
        }

        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn listen_on_quic_produces_event() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let mut controller = build_swarm(&identity, &config).await.unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        controller.listen_on(addr).await.unwrap();

        let event =
            tokio::time::timeout(std::time::Duration::from_secs(5), controller.next_event())
                .await
                .expect("should receive event within timeout")
                .expect("event should not be None");

        match event {
            SwarmEvent::ListeningOn { address } => {
                let addr_str = address.to_string();
                assert!(
                    addr_str.contains("quic-v1"),
                    "address should contain quic-v1, got: {addr_str}"
                );
            }
            other => panic!("expected ListeningOn event, got: {other:?}"),
        }

        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn dial_unreachable_produces_failure() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let mut controller = build_swarm(&identity, &config).await.unwrap();

        let addr: Multiaddr = "/ip4/192.0.2.1/tcp/1".parse().unwrap();
        controller.dial(addr).await.unwrap();

        // We should eventually get a DialFailure event.
        // Skip any non-DialFailure events (e.g., mDNS discoveries from
        // other test instances running in parallel).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let event = tokio::time::timeout_at(deadline, controller.next_event())
                .await
                .expect("should receive DialFailure within timeout")
                .expect("event should not be None");
            match event {
                SwarmEvent::DialFailure { .. } => break,
                _ => continue, // skip mDNS, listening, etc.
            }
        }

        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_terminates_event_loop() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let mut controller = build_swarm(&identity, &config).await.unwrap();
        controller.shutdown().await.unwrap();

        let event =
            tokio::time::timeout(std::time::Duration::from_secs(2), controller.next_event())
                .await
                .expect("should return within timeout");
        assert!(event.is_none(), "expected None after shutdown");
    }

    #[test]
    fn transport_config_defaults() {
        let config = TransportConfig::default();
        assert!(config.quic_enabled);
        assert!(config.tcp_enabled);
        assert!(config.websocket_enabled);
        assert!(config.webtransport_enabled);
        assert_eq!(
            config.per_transport_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn libp2p_keypair_conversion() {
        let identity = IdentityKeypair::generate();
        let keypair = libp2p_keypair_from_identity(&identity);
        assert!(keypair.is_ok(), "keypair conversion should succeed");
    }
}
