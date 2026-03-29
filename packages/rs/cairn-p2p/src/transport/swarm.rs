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
    /// An external (public) address was discovered via Identify or AutoNAT.
    ExternalAddressDiscovered { address: Multiaddr },
    /// DHT peer discovery is ready: our PeerId has been published.
    DhtReady,
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
    /// Announce ourselves as a provider for a key in the Kademlia DHT.
    /// Used for DHT-based peer discovery: the key is derived from our PeerId.
    KadStartProviding {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Find providers for a key in the Kademlia DHT.
    /// Returns a list of PeerIds that have announced themselves as providers.
    KadGetProviders {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<PeerId>>>,
    },
    /// Get all known external addresses of the local node.
    GetExternalAddresses {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// SwarmController -- handle returned to the caller
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

    /// Announce this node as a provider for the given key in the Kademlia DHT.
    ///
    /// Used for DHT-based peer discovery: the host publishes its PeerId-derived
    /// key so clients can find it via `kad_get_providers`.
    pub async fn kad_start_providing(&self, key: Vec<u8>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::KadStartProviding {
                key,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Find providers for a key in the Kademlia DHT.
    ///
    /// Used by clients to discover a host's PeerId and addresses on the DHT.
    /// Returns the PeerIds of nodes that have announced themselves as providers.
    pub async fn kad_get_providers(&self, key: Vec<u8>) -> Result<Vec<PeerId>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::KadGetProviders {
                key,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CairnError::Transport("swarm event loop shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| CairnError::Transport("swarm event loop dropped reply".into()))?
    }

    /// Get all known external addresses of the local node.
    pub async fn get_external_addresses(&self) -> Vec<Multiaddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .command_tx
            .send(SwarmCommand::GetExternalAddresses { reply: reply_tx })
            .await
            .is_err()
        {
            return Vec::new();
        }
        reply_rx.await.unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// CairnCodec -- request-response codec for cairn's CBOR protocol
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
    /// - Identify for learning observed external addresses
    /// - AutoNAT for NAT type detection and public address discovery
    /// - Relay client for connecting through relay nodes (symmetric NAT fallback)
    /// - DCUtR for upgrading relayed connections to direct via hole punching
    /// - UPnP for automatic port mapping on supported routers
    #[derive(NetworkBehaviour)]
    pub(super) struct CairnBehaviour {
        pub(super) mdns: libp2p::mdns::tokio::Behaviour,
        pub(super) kademlia: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
        pub(super) request_response: libp2p::request_response::Behaviour<super::CairnCodec>,
        pub(super) identify: libp2p::identify::Behaviour,
        pub(super) autonat: libp2p::autonat::Behaviour,
        pub(super) relay_client: libp2p::relay::client::Behaviour,
        pub(super) dcutr: libp2p::dcutr::Behaviour,
        pub(super) upnp: libp2p::upnp::tokio::Behaviour,
    }
}

use behaviour::CairnBehaviour;
#[allow(unused_imports)]
use behaviour::CairnBehaviourEvent;

// ---------------------------------------------------------------------------
// Default bootstrap nodes (public IPFS DHT)
// ---------------------------------------------------------------------------

/// Public IPFS bootstrap nodes for joining the global Kademlia DHT.
/// These allow cairn peers to find each other across the internet without
/// any cairn-specific infrastructure.
///
/// Uses resolved `/dns/` addresses instead of `/dnsaddr/` — the dnsaddr protocol
/// requires TXT record resolution that libp2p's transport layer does not perform.
/// Each node has QUIC (preferred) + TCP + WSS fallback addresses.
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    // sv15 — San Jose
    "/dns/sv15.bootstrap.libp2p.io/udp/4001/quic-v1/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dns/sv15.bootstrap.libp2p.io/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dns/sv15.bootstrap.libp2p.io/tcp/443/wss/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    // ny5 — New York
    "/dns/ny5.bootstrap.libp2p.io/udp/4001/quic-v1/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dns/ny5.bootstrap.libp2p.io/tcp/4001/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dns/ny5.bootstrap.libp2p.io/tcp/443/wss/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    // am6 — Amsterdam
    "/dns/am6.bootstrap.libp2p.io/udp/4001/quic-v1/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dns/am6.bootstrap.libp2p.io/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dns/am6.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    // sg1 — Singapore
    "/dns/sg1.bootstrap.libp2p.io/udp/4001/quic-v1/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dns/sg1.bootstrap.libp2p.io/tcp/4001/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dns/sg1.bootstrap.libp2p.io/tcp/443/wss/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

/// Extract the PeerId from the last `/p2p/<peer_id>` component of a multiaddr.
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })
}

/// Strip the trailing `/p2p/<peer_id>` component from a multiaddr, returning
/// the address without the peer ID (needed for `kademlia.add_address`).
fn strip_peer_id(addr: &Multiaddr) -> Multiaddr {
    let mut clean = Multiaddr::empty();
    for proto in addr.iter() {
        if !matches!(proto, libp2p::multiaddr::Protocol::P2p(_)) {
            clean.push(proto);
        }
    }
    clean
}

// ---------------------------------------------------------------------------
// build_swarm -- construct the libp2p Swarm and spawn the event loop
// ---------------------------------------------------------------------------

/// Build a libp2p Swarm with the configured transports and spawn an async
/// event loop. Returns a [`SwarmController`] for interacting with the swarm.
///
/// The swarm is constructed using libp2p's `SwarmBuilder` with:
/// - QUIC v1 (priority 1 in the transport fallback chain)
/// - TCP with Noise encryption and Yamux multiplexing (priority 3)
/// - WebSocket/TLS with Noise encryption and Yamux multiplexing (priority 6)
/// - Circuit Relay v2 client (fallback for symmetric NAT)
///
/// The composed behaviour includes mDNS, Kademlia DHT, request-response,
/// Identify, AutoNAT, Relay Client, DCUtR, and UPnP.
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
/// chain: identity -> runtime -> tcp -> quic -> dns -> websocket ->
/// relay_client -> behaviour -> build.
///
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
        // Circuit Relay v2 client -- enables connecting through relay nodes
        // when direct connections fail (e.g., symmetric NAT on both sides).
        // The relay client transport is composed into the transport stack so
        // /p2p-circuit addresses can be dialed.
        .with_relay_client(
            (libp2p::tls::Config::new, libp2p::noise::Config::new),
            libp2p::yamux::Config::default,
        )
        .map_err(|e| CairnError::Transport(format!("failed to configure relay client: {e}")))?
        .with_behaviour(|key, relay_client| {
            let peer_id = key.public().to_peer_id();

            // mDNS for LAN discovery.
            // When disabled, use a very long query interval to suppress traffic.
            let mdns_config = if config.mdns_enabled {
                libp2p::mdns::Config::default()
            } else {
                libp2p::mdns::Config {
                    query_interval: std::time::Duration::from_secs(86400 * 365),
                    ttl: std::time::Duration::from_secs(1),
                    ..Default::default()
                }
            };
            let mdns = libp2p::mdns::tokio::Behaviour::new(mdns_config, peer_id)
                .map_err(|e| format!("mDNS init failed: {e}"))?;

            // Kademlia DHT with bootstrap nodes for internet-wide peer discovery.
            let store = libp2p::kad::store::MemoryStore::new(peer_id);
            let mut kad_config =
                libp2p::kad::Config::new(libp2p::StreamProtocol::new("/ipfs/kad/1.0.0"));
            // Set a reasonable record TTL (24 hours) and provider record TTL.
            kad_config.set_record_ttl(Some(std::time::Duration::from_secs(86400)));
            kad_config.set_provider_record_ttl(Some(std::time::Duration::from_secs(86400)));
            // Re-publish provider records periodically (every 12 hours).
            kad_config
                .set_provider_publication_interval(Some(std::time::Duration::from_secs(43200)));
            let mut kademlia = libp2p::kad::Behaviour::with_config(peer_id, store, kad_config);
            // Set mode to Server so this node participates fully in the DHT
            // (stores and serves records for other peers).
            kademlia.set_mode(Some(libp2p::kad::Mode::Server));

            // Add bootstrap nodes (either from config or defaults).
            let bootstrap_addrs: Vec<String> = if config.bootstrap_nodes.is_empty() {
                DEFAULT_BOOTSTRAP_NODES
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                config.bootstrap_nodes.clone()
            };

            let mut has_bootstrap_peers = false;
            for addr_str in &bootstrap_addrs {
                if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                    if let Some(peer_id) = extract_peer_id(&ma) {
                        let addr = strip_peer_id(&ma);
                        kademlia.add_address(&peer_id, addr);
                        has_bootstrap_peers = true;
                    }
                }
            }

            // Start a Kademlia bootstrap query if we have peers to connect to.
            if has_bootstrap_peers {
                if let Err(e) = kademlia.bootstrap() {
                    // Not fatal -- bootstrap may fail if no peers respond.
                    debug!(?e, "Kademlia bootstrap initiation failed (will retry)");
                }
            }

            // Request-response for cairn's CBOR protocol.
            let request_response = libp2p::request_response::Behaviour::new(
                [(
                    StreamProtocol::new(CAIRN_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                libp2p::request_response::Config::default()
                    .with_request_timeout(std::time::Duration::from_secs(30)),
            );

            // Identify -- peers exchange observed addresses on connect.
            // This is how a node behind NAT learns its public address.
            let identify = libp2p::identify::Behaviour::new(
                libp2p::identify::Config::new("/cairn/1.0.0".into(), key.public())
                    .with_push_listen_addr_updates(true),
            );

            // AutoNAT -- probe whether we are publicly reachable.
            // Uses connected peers to dial us back and determine NAT status.
            let autonat =
                libp2p::autonat::Behaviour::new(peer_id, libp2p::autonat::Config::default());

            // DCUtR -- Direct Connection Upgrade through Relay.
            // When two peers are connected via a relay, DCUtR coordinates
            // a simultaneous connection attempt (hole punch) to establish
            // a direct connection.
            let dcutr = libp2p::dcutr::Behaviour::new(peer_id);

            // UPnP -- automatically map ports on UPnP-capable routers.
            let upnp = libp2p::upnp::tokio::Behaviour::default();

            Ok(CairnBehaviour {
                mdns,
                kademlia,
                request_response,
                identify,
                autonat,
                relay_client,
                dcutr,
                upnp,
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

    // Pending Kademlia START_PROVIDING queries: query_id -> reply sender.
    type KadStartProvidingReply = oneshot::Sender<Result<()>>;
    let mut pending_kad_start_providing: std::collections::HashMap<
        libp2p::kad::QueryId,
        KadStartProvidingReply,
    > = std::collections::HashMap::new();

    // Pending Kademlia GET_PROVIDERS queries: query_id -> (reply sender, accumulated providers).
    type KadGetProvidersReply = oneshot::Sender<Result<Vec<PeerId>>>;
    let mut pending_kad_get_providers: std::collections::HashMap<
        libp2p::kad::QueryId,
        (KadGetProvidersReply, Vec<PeerId>),
    > = std::collections::HashMap::new();

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
                    Some(SwarmCommand::KadStartProviding { key, reply }) => {
                        let record_key = libp2p::kad::RecordKey::new(&key);
                        match swarm
                            .behaviour_mut()
                            .kademlia
                            .start_providing(record_key)
                        {
                            Ok(query_id) => {
                                // Defer reply until the StartProviding event confirms
                                // the record was actually propagated to DHT peers.
                                pending_kad_start_providing.insert(query_id, reply);
                            }
                            Err(e) => {
                                let _ = reply.send(Err(CairnError::Transport(
                                    format!("kad start_providing failed: {e:?}"),
                                )));
                            }
                        }
                    }
                    Some(SwarmCommand::KadGetProviders { key, reply }) => {
                        let record_key = libp2p::kad::RecordKey::new(&key);
                        let query_id = swarm
                            .behaviour_mut()
                            .kademlia
                            .get_providers(record_key);
                        pending_kad_get_providers.insert(query_id, (reply, Vec::new()));
                    }
                    Some(SwarmCommand::GetExternalAddresses { reply }) => {
                        let addrs: Vec<Multiaddr> = swarm.external_addresses().cloned().collect();
                        let _ = reply.send(addrs);
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
                    LibSwarmEvent::ExternalAddrConfirmed { address } => {
                        info!(%address, "external address confirmed");
                        Some(SwarmEvent::ExternalAddressDiscovered { address })
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
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            result: libp2p::kad::QueryResult::Bootstrap(result),
                            ..
                        },
                    )) => {
                        match result {
                            Ok(ok) => info!(
                                num_remaining = ok.num_remaining,
                                "Kademlia bootstrap progress"
                            ),
                            Err(e) => warn!(?e, "Kademlia bootstrap failed"),
                        }
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            id,
                            result: libp2p::kad::QueryResult::StartProviding(result),
                            ..
                        },
                    )) => {
                        match &result {
                            Ok(ok) => info!(
                                key = ?ok.key,
                                "Kademlia: provider record propagated to DHT"
                            ),
                            Err(e) => warn!(?e, "Kademlia: start providing failed"),
                        }
                        if let Some(reply) = pending_kad_start_providing.remove(&id) {
                            match result {
                                Ok(_) => { let _ = reply.send(Ok(())); }
                                Err(e) => {
                                    let _ = reply.send(Err(CairnError::Transport(
                                        format!("DHT provider record propagation failed: {e:?}"),
                                    )));
                                }
                            }
                        }
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            id,
                            result: libp2p::kad::QueryResult::GetProviders(result),
                            ..
                        },
                    )) => {
                        match result {
                            Ok(libp2p::kad::GetProvidersOk::FoundProviders { providers, .. }) => {
                                debug!(count = providers.len(), "Kademlia: found providers");
                                if let Some((_reply, accumulated)) = pending_kad_get_providers.get_mut(&id) {
                                    for provider in providers {
                                        if !accumulated.contains(&provider) {
                                            accumulated.push(provider);
                                        }
                                    }
                                }
                            }
                            Ok(libp2p::kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                                // Query finished — send accumulated results.
                                if let Some((reply, accumulated)) = pending_kad_get_providers.remove(&id) {
                                    info!(count = accumulated.len(), "Kademlia: get_providers finished");
                                    let _ = reply.send(Ok(accumulated));
                                }
                            }
                            Err(e) => {
                                warn!(?e, "Kademlia: get_providers failed");
                                if let Some((reply, _)) = pending_kad_get_providers.remove(&id) {
                                    let _ = reply.send(Err(CairnError::Transport(
                                        format!("get_providers failed: {e:?}"),
                                    )));
                                }
                            }
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
                    // --- Identify behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. },
                    )) => {
                        debug!(
                            %peer_id,
                            protocol_version = %info.protocol_version,
                            observed_addr = %info.observed_addr,
                            "identify: received peer info"
                        );
                        // Add the remote peer's listen addresses to Kademlia
                        // so we can route to them through the DHT.
                        for addr in &info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                        }
                        // Register our observed address as an external address
                        // candidate. libp2p will confirm it after multiple
                        // observations and emit ExternalAddrConfirmed.
                        swarm.add_external_address(info.observed_addr);
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Identify(
                        libp2p::identify::Event::Sent { peer_id, .. },
                    )) => {
                        debug!(%peer_id, "identify: sent our info");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Identify(
                        libp2p::identify::Event::Error { peer_id, error, .. },
                    )) => {
                        debug!(%peer_id, %error, "identify: error");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Identify(
                        libp2p::identify::Event::Pushed { peer_id, .. },
                    )) => {
                        debug!(%peer_id, "identify: pushed updated info");
                        None
                    }
                    // --- AutoNAT behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Autonat(
                        libp2p::autonat::Event::InboundProbe(probe),
                    )) => {
                        debug!(?probe, "autonat: inbound probe");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Autonat(
                        libp2p::autonat::Event::OutboundProbe(probe),
                    )) => {
                        debug!(?probe, "autonat: outbound probe");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Autonat(
                        libp2p::autonat::Event::StatusChanged { old, new },
                    )) => {
                        info!(?old, ?new, "autonat: NAT status changed");
                        None
                    }
                    // --- Relay client behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::RelayClient(event)) => {
                        debug!(?event, "relay client event");
                        None
                    }
                    // --- DCUtR (hole punching) behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Dcutr(event)) => {
                        let remote = event.remote_peer_id;
                        match event.result {
                            Ok(connection_id) => {
                                info!(
                                    %remote,
                                    ?connection_id,
                                    "dcutr: direct connection upgrade succeeded (hole punch!)"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    %remote,
                                    %error,
                                    "dcutr: direct connection upgrade failed"
                                );
                            }
                        }
                        None
                    }
                    // --- UPnP behaviour events ---
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Upnp(
                        libp2p::upnp::Event::NewExternalAddr(addr),
                    )) => {
                        info!(%addr, "upnp: new external address mapped");
                        Some(SwarmEvent::ExternalAddressDiscovered { address: addr })
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Upnp(
                        libp2p::upnp::Event::GatewayNotFound,
                    )) => {
                        debug!("upnp: no gateway found");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Upnp(
                        libp2p::upnp::Event::NonRoutableGateway,
                    )) => {
                        debug!("upnp: gateway is not routable");
                        None
                    }
                    LibSwarmEvent::Behaviour(CairnBehaviourEvent::Upnp(
                        libp2p::upnp::Event::ExpiredExternalAddr(addr),
                    )) => {
                        debug!(%addr, "upnp: external address mapping expired");
                        None
                    }
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
        assert!(config.bootstrap_nodes.is_empty());
    }

    #[test]
    fn libp2p_keypair_conversion() {
        let identity = IdentityKeypair::generate();
        let keypair = libp2p_keypair_from_identity(&identity);
        assert!(keypair.is_ok(), "keypair conversion should succeed");
    }

    #[test]
    fn extract_peer_id_from_multiaddr() {
        let addr: Multiaddr =
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
                .parse()
                .unwrap();
        let peer_id = extract_peer_id(&addr);
        assert!(peer_id.is_some(), "should extract peer ID from multiaddr");
    }

    #[test]
    fn strip_peer_id_from_multiaddr() {
        let addr: Multiaddr =
            "/ip4/1.2.3.4/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
                .parse()
                .unwrap();
        let stripped = strip_peer_id(&addr);
        let stripped_str = stripped.to_string();
        assert!(
            !stripped_str.contains("/p2p/"),
            "should not contain /p2p/ after stripping, got: {stripped_str}"
        );
        assert!(
            stripped_str.contains("/ip4/1.2.3.4/tcp/4001"),
            "should retain address components, got: {stripped_str}"
        );
    }

    #[test]
    fn default_bootstrap_nodes_parse() {
        for addr_str in DEFAULT_BOOTSTRAP_NODES {
            let ma: Multiaddr = addr_str
                .parse()
                .expect("default bootstrap node should parse");
            assert!(
                extract_peer_id(&ma).is_some(),
                "bootstrap node should contain a peer ID: {addr_str}"
            );
        }
    }

    #[tokio::test]
    async fn build_swarm_with_custom_bootstrap_nodes() {
        let identity = IdentityKeypair::generate();
        let config = TransportConfig {
            bootstrap_nodes: vec![
                "/ip4/1.2.3.4/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".into(),
            ],
            ..TransportConfig::default()
        };
        let controller = build_swarm(&identity, &config).await;
        assert!(
            controller.is_ok(),
            "swarm construction should succeed with custom bootstrap nodes"
        );
        controller.unwrap().shutdown().await.unwrap();
    }
}
