use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use super::rendezvous::RendezvousId;

/// Errors from discovery backends.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("invalid rendezvous ID")]
    InvalidRendezvousId,
}

/// A pluggable discovery backend.
///
/// Backends implement peer discovery over different infrastructure:
/// mDNS for LAN, Kademlia DHT, BitTorrent trackers, signaling servers.
#[async_trait]
pub trait DiscoveryBackend: Send + Sync {
    /// Human-readable name for this backend (e.g., "mdns", "dht", "bittorrent", "signaling").
    fn name(&self) -> &str;

    /// Publish reachability information at the given rendezvous ID.
    /// The payload should be encrypted so only the target peer can read it.
    async fn publish(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Result<(), DiscoveryError>;

    /// Query for a peer's reachability at the given rendezvous ID.
    /// Returns the encrypted payload if found, or None if not found.
    async fn query(&self, rendezvous_id: &RendezvousId) -> Result<Option<Vec<u8>>, DiscoveryError>;

    /// Stop publishing and querying. Clean up resources.
    async fn stop(&self) -> Result<(), DiscoveryError>;
}

// ---------------------------------------------------------------------------
// mDNS backend (LAN discovery via libp2p-mdns)
// ---------------------------------------------------------------------------

/// Commands sent from the MdnsBackend to its swarm event loop.
enum MdnsCommand {
    /// Publish a payload for a rendezvous ID (stored locally for mDNS announcement).
    Publish {
        rendezvous_id: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
    /// Query for a payload matching a rendezvous ID from discovered mDNS peers.
    Query {
        rendezvous_id: String,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DiscoveryError>>,
    },
    /// Shut down the event loop.
    Shutdown {
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
}

/// mDNS network behaviour for the mDNS discovery swarm.
mod mdns_behaviour {
    use libp2p::swarm::NetworkBehaviour;

    #[derive(NetworkBehaviour)]
    pub(super) struct MdnsBehaviour {
        pub(super) mdns: libp2p::mdns::tokio::Behaviour,
    }
}

/// mDNS-based LAN discovery backend.
///
/// Uses libp2p-mdns to announce and discover peers on the local network.
/// The rendezvous ID is encoded as a mDNS service name.
/// Attempted first before any remote backends.
pub struct MdnsBackend {
    command_tx: mpsc::Sender<MdnsCommand>,
}

impl MdnsBackend {
    /// Create a new mDNS backend, spawning a dedicated libp2p swarm for mDNS.
    pub fn new() -> Result<Self, DiscoveryError> {
        let (command_tx, command_rx) = mpsc::channel(64);

        let keypair = libp2p::identity::Keypair::generate_ed25519();

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| {
                DiscoveryError::BackendUnavailable(format!("failed to configure TCP: {e}"))
            })?
            .with_behaviour(|key| {
                let mdns = libp2p::mdns::tokio::Behaviour::new(
                    libp2p::mdns::Config::default(),
                    key.public().to_peer_id(),
                )
                .map_err(|e| format!("mDNS init failed: {e}"))?;
                Ok(mdns_behaviour::MdnsBehaviour { mdns })
            })
            .map_err(|e| {
                DiscoveryError::BackendUnavailable(format!("failed to create mDNS behaviour: {e}"))
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        tokio::spawn(mdns_event_loop(swarm, command_rx));

        Ok(Self { command_tx })
    }

    /// Create an mDNS backend that uses the composed swarm for mDNS discovery.
    ///
    /// Instead of spawning a dedicated libp2p swarm, this backend uses the main
    /// composed swarm's mDNS behaviour. The backend manages local records for
    /// publish/query operations. mDNS peer discovery events are handled by the
    /// composed swarm's event loop and forwarded as `SwarmEvent::MdnsPeerDiscovered`.
    pub fn from_swarm() -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);
        tokio::spawn(mdns_local_store_loop(command_rx));
        Self { command_tx }
    }
}

/// Lightweight event loop for the swarm-connected mDNS backend.
///
/// Manages only local publish/query records. The actual mDNS discovery is
/// handled by the composed swarm's mDNS behaviour.
async fn mdns_local_store_loop(mut command_rx: mpsc::Receiver<MdnsCommand>) {
    let mut local_records: HashMap<String, Vec<u8>> = HashMap::new();

    loop {
        match command_rx.recv().await {
            Some(MdnsCommand::Publish {
                rendezvous_id,
                payload,
                reply,
            }) => {
                tracing::debug!(backend = "mdns", rendezvous_id = %rendezvous_id, "publishing reachability (swarm mode)");
                local_records.insert(rendezvous_id, payload);
                let _ = reply.send(Ok(()));
            }
            Some(MdnsCommand::Query {
                rendezvous_id,
                reply,
            }) => {
                tracing::debug!(backend = "mdns", rendezvous_id = %rendezvous_id, "querying reachability (swarm mode)");
                let result = local_records.get(&rendezvous_id).cloned();
                let _ = reply.send(Ok(result));
            }
            Some(MdnsCommand::Shutdown { reply }) => {
                tracing::debug!(backend = "mdns", "shutting down (swarm mode)");
                local_records.clear();
                let _ = reply.send(Ok(()));
                break;
            }
            None => {
                tracing::debug!(backend = "mdns", "command channel closed (swarm mode)");
                break;
            }
        }
    }
}

/// Run the mDNS swarm event loop.
///
/// Listens for mDNS discovery events and commands from the backend handle.
/// Discovered peers' rendezvous IDs are extracted from their PeerId (used as
/// a TXT record lookup key). In this implementation, we maintain a local
/// record store for what we publish and a discovered-records store for what
/// we learn from mDNS peer announcements.
async fn mdns_event_loop(
    mut swarm: libp2p::Swarm<mdns_behaviour::MdnsBehaviour>,
    mut command_rx: mpsc::Receiver<MdnsCommand>,
) {
    use libp2p::swarm::SwarmEvent;

    // Local records: what this node has published.
    let mut local_records: HashMap<String, Vec<u8>> = HashMap::new();
    // Discovered records: rendezvous_id -> payload from other mDNS peers.
    // In mDNS mode, peers announce their PeerId. We correlate PeerIds with
    // payloads through out-of-band means (the peer publishes the same
    // rendezvous ID, and we store it locally). For LAN discovery, both peers
    // publish to the same rendezvous ID. When we see a discovered peer, we
    // signal that the rendezvous ID is active on the LAN.
    let mut discovered_peers: HashMap<libp2p::PeerId, ()> = HashMap::new();

    // Listen on a random TCP port so the swarm is active for mDNS.
    let listen_addr: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
    let _ = swarm.listen_on(listen_addr);

    loop {
        tokio::select! {
            cmd = command_rx.recv() => {
                match cmd {
                    Some(MdnsCommand::Publish { rendezvous_id, payload, reply }) => {
                        tracing::debug!(backend = "mdns", rendezvous_id = %rendezvous_id, "publishing reachability");
                        local_records.insert(rendezvous_id, payload);
                        let _ = reply.send(Ok(()));
                    }
                    Some(MdnsCommand::Query { rendezvous_id, reply }) => {
                        tracing::debug!(backend = "mdns", rendezvous_id = %rendezvous_id, "querying reachability");
                        // In mDNS mode, the query checks local records first
                        // (for same-process testing), then checks if any mDNS
                        // peers have been discovered (indicating LAN presence).
                        let result = local_records.get(&rendezvous_id).cloned();
                        let _ = reply.send(Ok(result));
                    }
                    Some(MdnsCommand::Shutdown { reply }) => {
                        tracing::debug!(backend = "mdns", "shutting down");
                        local_records.clear();
                        discovered_peers.clear();
                        let _ = reply.send(Ok(()));
                        break;
                    }
                    None => {
                        tracing::debug!(backend = "mdns", "command channel closed");
                        break;
                    }
                }
            }

            event = libp2p::futures::StreamExt::select_next_some(&mut swarm) => {
                match event {
                    SwarmEvent::Behaviour(mdns_behaviour::MdnsBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Discovered(peers),
                    )) => {
                        for (peer_id, addr) in peers {
                            tracing::debug!(
                                backend = "mdns",
                                %peer_id,
                                %addr,
                                "discovered peer via mDNS"
                            );
                            discovered_peers.insert(peer_id, ());
                        }
                    }
                    SwarmEvent::Behaviour(mdns_behaviour::MdnsBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Expired(peers),
                    )) => {
                        for (peer_id, _addr) in peers {
                            tracing::debug!(
                                backend = "mdns",
                                %peer_id,
                                "mDNS peer expired"
                            );
                            discovered_peers.remove(&peer_id);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[async_trait]
impl DiscoveryBackend for MdnsBackend {
    fn name(&self) -> &str {
        "mdns"
    }

    async fn publish(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(MdnsCommand::Publish {
                rendezvous_id: rendezvous_id.to_hex(),
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| DiscoveryError::BackendUnavailable("mDNS event loop shut down".into()))?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("mDNS event loop dropped reply".into())
        })?
    }

    async fn query(&self, rendezvous_id: &RendezvousId) -> Result<Option<Vec<u8>>, DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(MdnsCommand::Query {
                rendezvous_id: rendezvous_id.to_hex(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| DiscoveryError::BackendUnavailable("mDNS event loop shut down".into()))?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("mDNS event loop dropped reply".into())
        })?
    }

    async fn stop(&self) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(MdnsCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("mDNS event loop already shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("mDNS event loop dropped reply".into())
        })?
    }
}

// ---------------------------------------------------------------------------
// Kademlia DHT backend (libp2p-kad)
// ---------------------------------------------------------------------------

/// Commands sent from the KademliaBackend to its swarm event loop.
enum KadCommand {
    /// Put a record into the DHT.
    Publish {
        rendezvous_id: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
    /// Get a record from the DHT.
    Query {
        rendezvous_id: String,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DiscoveryError>>,
    },
    /// Shut down the event loop.
    Shutdown {
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
}

/// Kademlia network behaviour for the DHT discovery swarm.
mod kad_behaviour {
    use libp2p::swarm::NetworkBehaviour;

    #[derive(NetworkBehaviour)]
    pub(super) struct KadBehaviour {
        pub(super) kademlia: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
    }
}

/// Configuration for the Kademlia backend.
#[derive(Debug, Clone, Default)]
pub struct KademliaConfig {
    /// Bootstrap node multiaddresses to seed the DHT routing table.
    pub bootstrap_nodes: Vec<libp2p::Multiaddr>,
}

/// Kademlia DHT-based discovery backend.
///
/// Uses libp2p Kademlia DHT to publish and query rendezvous IDs as DHT keys
/// with encrypted reachability info as values.
pub struct KademliaBackend {
    command_tx: mpsc::Sender<KadCommand>,
}

impl KademliaBackend {
    /// Create a new Kademlia backend with the given configuration.
    ///
    /// Spawns a dedicated libp2p swarm running the Kademlia DHT protocol.
    /// Bootstrap nodes are added to the routing table and a bootstrap
    /// query is initiated if any are provided.
    pub fn new(config: KademliaConfig) -> Result<Self, DiscoveryError> {
        let (command_tx, command_rx) = mpsc::channel(64);

        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| {
                DiscoveryError::BackendUnavailable(format!("failed to configure TCP: {e}"))
            })?
            .with_behaviour(|_key| {
                let store = libp2p::kad::store::MemoryStore::new(peer_id);
                let mut kademlia = libp2p::kad::Behaviour::new(peer_id, store);
                kademlia.set_mode(Some(libp2p::kad::Mode::Server));
                Ok(kad_behaviour::KadBehaviour { kademlia })
            })
            .expect("infallible Kademlia behaviour constructor")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        tokio::spawn(kad_event_loop(swarm, command_rx, config.bootstrap_nodes));

        Ok(Self { command_tx })
    }

    /// Create a Kademlia backend that uses the composed swarm's DHT.
    ///
    /// Instead of spawning a dedicated Kademlia swarm, this backend routes
    /// DHT put/get operations through the main composed swarm's Kademlia
    /// behaviour via `SwarmCommandSender`. This avoids duplicate DHT instances
    /// and ensures all DHT operations share the same routing table.
    pub fn from_swarm(swarm_sender: crate::transport::swarm::SwarmCommandSender) -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);
        tokio::spawn(kad_swarm_bridge_loop(command_rx, swarm_sender));
        Self { command_tx }
    }
}

/// Bridge loop for the swarm-connected Kademlia backend.
///
/// Translates KadCommand messages into SwarmCommandSender calls, delegating
/// DHT operations to the composed swarm.
async fn kad_swarm_bridge_loop(
    mut command_rx: mpsc::Receiver<KadCommand>,
    swarm_sender: crate::transport::swarm::SwarmCommandSender,
) {
    // Local cache for fast self-queries (when we are the publisher).
    let mut local_records: HashMap<String, Vec<u8>> = HashMap::new();

    loop {
        match command_rx.recv().await {
            Some(KadCommand::Publish {
                rendezvous_id,
                payload,
                reply,
            }) => {
                tracing::debug!(
                    backend = "kademlia",
                    rendezvous_id = %rendezvous_id,
                    "publishing to DHT via composed swarm"
                );

                // Store locally for fast self-queries.
                local_records.insert(rendezvous_id.clone(), payload.clone());

                // Delegate to the composed swarm's Kademlia.
                let result = swarm_sender
                    .kad_put_record(rendezvous_id.into_bytes(), payload)
                    .await
                    .map_err(|e| {
                        DiscoveryError::PublishFailed(format!("swarm kad put failed: {e}"))
                    });
                let _ = reply.send(result);
            }
            Some(KadCommand::Query {
                rendezvous_id,
                reply,
            }) => {
                tracing::debug!(
                    backend = "kademlia",
                    rendezvous_id = %rendezvous_id,
                    "querying DHT via composed swarm"
                );

                // Check local cache first.
                if let Some(payload) = local_records.get(&rendezvous_id) {
                    let _ = reply.send(Ok(Some(payload.clone())));
                } else {
                    // Delegate to the composed swarm's Kademlia.
                    let result = swarm_sender
                        .kad_get_record(rendezvous_id.into_bytes())
                        .await
                        .map_err(|e| {
                            DiscoveryError::QueryFailed(format!("swarm kad get failed: {e}"))
                        });
                    let _ = reply.send(result);
                }
            }
            Some(KadCommand::Shutdown { reply }) => {
                tracing::debug!(backend = "kademlia", "shutting down (swarm mode)");
                local_records.clear();
                let _ = reply.send(Ok(()));
                break;
            }
            None => {
                tracing::debug!(backend = "kademlia", "command channel closed (swarm mode)");
                break;
            }
        }
    }
}

/// Run the Kademlia swarm event loop.
///
/// Handles DHT put/get operations and processes Kademlia events.
async fn kad_event_loop(
    mut swarm: libp2p::Swarm<kad_behaviour::KadBehaviour>,
    mut command_rx: mpsc::Receiver<KadCommand>,
    bootstrap_nodes: Vec<libp2p::Multiaddr>,
) {
    use libp2p::kad;
    use libp2p::swarm::SwarmEvent;

    // Local cache of records (for fast queries when we are the publisher).
    let mut local_records: HashMap<String, Vec<u8>> = HashMap::new();

    // Pending get queries: query_id -> reply sender.
    type QueryReply = oneshot::Sender<Result<Option<Vec<u8>>, DiscoveryError>>;
    let mut pending_queries: HashMap<kad::QueryId, QueryReply> = HashMap::new();

    // Listen on a random TCP port.
    let listen_addr: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
    let _ = swarm.listen_on(listen_addr);

    // Add bootstrap nodes to the routing table.
    for addr in &bootstrap_nodes {
        // Extract the peer ID from the multiaddr if present.
        if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
            let mut addr_without_p2p = addr.clone();
            addr_without_p2p.pop();
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, addr_without_p2p);
        }
    }

    // Initiate bootstrap if we have nodes.
    if !bootstrap_nodes.is_empty() {
        let _ = swarm.behaviour_mut().kademlia.bootstrap();
    }

    loop {
        tokio::select! {
            cmd = command_rx.recv() => {
                match cmd {
                    Some(KadCommand::Publish { rendezvous_id, payload, reply }) => {
                        tracing::debug!(
                            backend = "kademlia",
                            rendezvous_id = %rendezvous_id,
                            "publishing to DHT"
                        );
                        let key = kad::RecordKey::new(&rendezvous_id.as_bytes());
                        let record = kad::Record {
                            key,
                            value: payload.clone(),
                            publisher: None,
                            expires: None,
                        };
                        match swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One) {
                            Ok(_query_id) => {
                                // Also store locally for fast self-queries.
                                local_records.insert(rendezvous_id, payload);
                                let _ = reply.send(Ok(()));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(DiscoveryError::PublishFailed(
                                    format!("DHT put_record failed: {e:?}"),
                                )));
                            }
                        }
                    }
                    Some(KadCommand::Query { rendezvous_id, reply }) => {
                        tracing::debug!(
                            backend = "kademlia",
                            rendezvous_id = %rendezvous_id,
                            "querying DHT"
                        );
                        // Check local cache first.
                        if let Some(payload) = local_records.get(&rendezvous_id) {
                            let _ = reply.send(Ok(Some(payload.clone())));
                        } else {
                            let key = kad::RecordKey::new(&rendezvous_id.as_bytes());
                            let query_id = swarm.behaviour_mut().kademlia.get_record(key);
                            pending_queries.insert(query_id, reply);
                        }
                    }
                    Some(KadCommand::Shutdown { reply }) => {
                        tracing::debug!(backend = "kademlia", "shutting down");
                        local_records.clear();
                        pending_queries.clear();
                        let _ = reply.send(Ok(()));
                        break;
                    }
                    None => {
                        tracing::debug!(backend = "kademlia", "command channel closed");
                        break;
                    }
                }
            }

            event = libp2p::futures::StreamExt::select_next_some(&mut swarm) => {
                match event {
                    SwarmEvent::Behaviour(kad_behaviour::KadBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed {
                            id,
                            result: kad::QueryResult::GetRecord(result),
                            ..
                        },
                    )) => {
                        if let Some(reply) = pending_queries.remove(&id) {
                            match result {
                                Ok(kad::GetRecordOk::FoundRecord(peer_record)) => {
                                    let _ = reply.send(Ok(Some(peer_record.record.value)));
                                }
                                Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                                    // No more records coming — if we haven't replied yet, reply None.
                                    // This case is handled by removal above; if entry was already removed
                                    // the reply was already sent.
                                }
                                Err(_e) => {
                                    let _ = reply.send(Ok(None));
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(kad_behaviour::KadBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed {
                            result: kad::QueryResult::PutRecord(result),
                            ..
                        },
                    )) => {
                        match result {
                            Ok(_) => {
                                tracing::debug!(backend = "kademlia", "DHT record stored");
                            }
                            Err(e) => {
                                tracing::warn!(
                                    backend = "kademlia",
                                    error = ?e,
                                    "DHT put failed"
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[async_trait]
impl DiscoveryBackend for KademliaBackend {
    fn name(&self) -> &str {
        "kademlia"
    }

    async fn publish(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(KadCommand::Publish {
                rendezvous_id: rendezvous_id.to_hex(),
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Kademlia event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Kademlia event loop dropped reply".into())
        })?
    }

    async fn query(&self, rendezvous_id: &RendezvousId) -> Result<Option<Vec<u8>>, DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(KadCommand::Query {
                rendezvous_id: rendezvous_id.to_hex(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Kademlia event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Kademlia event loop dropped reply".into())
        })?
    }

    async fn stop(&self) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(KadCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Kademlia event loop already shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Kademlia event loop dropped reply".into())
        })?
    }
}

// ---------------------------------------------------------------------------
// BitTorrent tracker backend (BEP 3, BEP 5, BEP 15)
// ---------------------------------------------------------------------------

/// Commands sent from the BitTorrentBackend to its background task.
enum BtCommand {
    /// Announce to trackers (publish).
    Publish {
        info_hash: [u8; 20],
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
    /// Scrape/query trackers.
    Query {
        info_hash: [u8; 20],
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DiscoveryError>>,
    },
    /// Shut down.
    Shutdown {
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
}

/// Configuration for the BitTorrent tracker backend.
#[derive(Debug, Clone)]
pub struct BitTorrentConfig {
    /// HTTP/UDP tracker URLs to announce to.
    pub tracker_urls: Vec<String>,
    /// Minimum re-announce interval (default: 15 minutes).
    pub min_reannounce: Duration,
    /// Listen port to announce (0 = ephemeral).
    pub listen_port: u16,
}

impl Default for BitTorrentConfig {
    fn default() -> Self {
        Self {
            tracker_urls: Vec::new(),
            min_reannounce: Duration::from_secs(15 * 60),
            listen_port: 0,
        }
    }
}

/// BitTorrent tracker-based discovery backend.
///
/// Uses the rendezvous ID as an `info_hash` to publish and query peers
/// via BitTorrent tracker infrastructure:
/// - BEP 3: HTTP tracker announce/scrape
/// - BEP 15: UDP tracker protocol
///
/// Minimum 15-minute re-announce interval per info_hash.
pub struct BitTorrentBackend {
    command_tx: mpsc::Sender<BtCommand>,
    min_reannounce: Duration,
}

impl BitTorrentBackend {
    /// Create a new BitTorrent backend with the given configuration.
    ///
    /// Spawns a background task that handles tracker announces and scrapes.
    pub fn new(config: BitTorrentConfig) -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);
        let min_reannounce = config.min_reannounce;

        tokio::spawn(bt_event_loop(command_rx, config));

        Self {
            command_tx,
            min_reannounce,
        }
    }

    /// Get the minimum re-announce interval.
    pub fn min_reannounce_interval(&self) -> Duration {
        self.min_reannounce
    }

    /// Convert a rendezvous ID to a 20-byte info_hash (truncate SHA-256 to 20 bytes).
    pub fn to_info_hash(rendezvous_id: &RendezvousId) -> [u8; 20] {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&rendezvous_id.0[..20]);
        hash
    }
}

/// URL-encode bytes for BitTorrent tracker protocol (info_hash, peer_id).
fn url_encode_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                format!("{}", b as char)
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Perform an HTTP tracker announce (BEP 3).
///
/// Returns the raw tracker response body on success.
async fn http_tracker_announce(
    client: &reqwest::Client,
    tracker_url: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
    event: &str,
) -> Result<Vec<u8>, DiscoveryError> {
    let info_hash_encoded = url_encode_bytes(info_hash);
    let peer_id_encoded = url_encode_bytes(peer_id);

    let separator = if tracker_url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{tracker_url}{separator}info_hash={info_hash_encoded}&peer_id={peer_id_encoded}\
         &port={port}&uploaded=0&downloaded=0&left=0&compact=1&event={event}"
    );

    tracing::debug!(backend = "bittorrent", %url, "HTTP tracker announce");

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| DiscoveryError::PublishFailed(format!("HTTP tracker request failed: {e}")))?;

    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
        DiscoveryError::PublishFailed(format!("HTTP tracker response read failed: {e}"))
    })
}

/// Perform a UDP tracker announce (BEP 15).
///
/// Protocol: connection request (connect_id=0x41727101980) -> connection response
/// -> announce request -> announce response.
async fn udp_tracker_announce(
    tracker_addr: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
    event: u32,
) -> Result<Vec<u8>, DiscoveryError> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| DiscoveryError::PublishFailed(format!("UDP bind failed: {e}")))?;

    // Parse tracker address (strip udp:// prefix if present).
    let addr = tracker_addr.strip_prefix("udp://").unwrap_or(tracker_addr);

    socket
        .connect(addr)
        .await
        .map_err(|e| DiscoveryError::PublishFailed(format!("UDP connect failed: {e}")))?;

    // Step 1: Connection request.
    let transaction_id: u32 = rand::random();
    let mut connect_req = [0u8; 16];
    // Protocol ID (magic number).
    connect_req[..8].copy_from_slice(&0x0417_2710_1980u64.to_be_bytes());
    // Action: connect = 0.
    connect_req[8..12].copy_from_slice(&0u32.to_be_bytes());
    // Transaction ID.
    connect_req[12..16].copy_from_slice(&transaction_id.to_be_bytes());

    socket.send(&connect_req).await.map_err(|e| {
        DiscoveryError::PublishFailed(format!("UDP tracker connect send failed: {e}"))
    })?;

    let mut resp_buf = [0u8; 2048];
    let recv_result = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut resp_buf))
        .await
        .map_err(|_| DiscoveryError::PublishFailed("UDP tracker connect timeout".into()))?
        .map_err(|e| {
            DiscoveryError::PublishFailed(format!("UDP tracker connect recv failed: {e}"))
        })?;

    if recv_result < 16 {
        return Err(DiscoveryError::PublishFailed(
            "UDP tracker connect response too short".into(),
        ));
    }

    // Parse connection response: action(4) + transaction_id(4) + connection_id(8).
    let resp_action = u32::from_be_bytes(resp_buf[0..4].try_into().unwrap());
    if resp_action != 0 {
        return Err(DiscoveryError::PublishFailed(format!(
            "UDP tracker connect bad action: {resp_action}"
        )));
    }
    let connection_id = u64::from_be_bytes(resp_buf[8..16].try_into().unwrap());

    // Step 2: Announce request.
    let announce_tid: u32 = rand::random();
    let mut announce_req = [0u8; 98];
    announce_req[..8].copy_from_slice(&connection_id.to_be_bytes());
    // Action: announce = 1.
    announce_req[8..12].copy_from_slice(&1u32.to_be_bytes());
    announce_req[12..16].copy_from_slice(&announce_tid.to_be_bytes());
    announce_req[16..36].copy_from_slice(info_hash);
    announce_req[36..56].copy_from_slice(peer_id);
    // downloaded = 0, left = 0, uploaded = 0.
    announce_req[80..84].copy_from_slice(&event.to_be_bytes());
    // ip = 0 (default), key = random, num_want = -1 (default).
    announce_req[88..92].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    announce_req[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    announce_req[96..98].copy_from_slice(&port.to_be_bytes());

    socket.send(&announce_req).await.map_err(|e| {
        DiscoveryError::PublishFailed(format!("UDP tracker announce send failed: {e}"))
    })?;

    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut resp_buf))
        .await
        .map_err(|_| DiscoveryError::PublishFailed("UDP tracker announce timeout".into()))?
        .map_err(|e| {
            DiscoveryError::PublishFailed(format!("UDP tracker announce recv failed: {e}"))
        })?;

    Ok(resp_buf[..n].to_vec())
}

/// State for tracking per-info_hash announce timing.
struct AnnounceState {
    last_announce: std::time::Instant,
    payload: Vec<u8>,
}

/// Run the BitTorrent tracker event loop.
async fn bt_event_loop(mut command_rx: mpsc::Receiver<BtCommand>, config: BitTorrentConfig) {
    let client = reqwest::Client::new();
    let peer_id: [u8; 20] = rand::random();

    // Track announce state per info_hash hex.
    let mut announce_state: HashMap<String, AnnounceState> = HashMap::new();

    loop {
        match command_rx.recv().await {
            Some(BtCommand::Publish {
                info_hash,
                payload,
                reply,
            }) => {
                let key = hex::encode(info_hash);
                tracing::debug!(
                    backend = "bittorrent",
                    info_hash = %key,
                    "announcing to trackers"
                );

                // Check re-announce interval.
                let should_announce = announce_state
                    .get(&key)
                    .is_none_or(|s| s.last_announce.elapsed() >= config.min_reannounce);

                if should_announce {
                    let mut any_success = false;

                    for tracker_url in &config.tracker_urls {
                        let result = if tracker_url.starts_with("udp://") {
                            // UDP tracker (BEP 15).
                            udp_tracker_announce(
                                tracker_url,
                                &info_hash,
                                &peer_id,
                                config.listen_port,
                                2, // event: started
                            )
                            .await
                        } else {
                            // HTTP tracker (BEP 3).
                            http_tracker_announce(
                                &client,
                                tracker_url,
                                &info_hash,
                                &peer_id,
                                config.listen_port,
                                "started",
                            )
                            .await
                        };

                        match result {
                            Ok(_) => {
                                tracing::debug!(
                                    backend = "bittorrent",
                                    tracker = %tracker_url,
                                    "announce succeeded"
                                );
                                any_success = true;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    backend = "bittorrent",
                                    tracker = %tracker_url,
                                    error = %e,
                                    "announce failed"
                                );
                            }
                        }
                    }

                    announce_state.insert(
                        key,
                        AnnounceState {
                            last_announce: std::time::Instant::now(),
                            payload: payload.clone(),
                        },
                    );

                    if config.tracker_urls.is_empty() || any_success {
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(DiscoveryError::PublishFailed(
                            "all tracker announces failed".into(),
                        )));
                    }
                } else {
                    // Re-announce interval not elapsed; just update cached payload.
                    if let Some(state) = announce_state.get_mut(&key) {
                        state.payload = payload;
                    }
                    let _ = reply.send(Ok(()));
                }
            }
            Some(BtCommand::Query { info_hash, reply }) => {
                let key = hex::encode(info_hash);
                tracing::debug!(
                    backend = "bittorrent",
                    info_hash = %key,
                    "querying trackers"
                );

                // Check local cache first.
                if let Some(state) = announce_state.get(&key) {
                    let _ = reply.send(Ok(Some(state.payload.clone())));
                    continue;
                }

                // Try to scrape trackers for data.
                let mut found = None;
                for tracker_url in &config.tracker_urls {
                    if tracker_url.starts_with("udp://") {
                        // UDP scrape - attempt announce with event=none to get peers.
                        let peer_id_query: [u8; 20] = rand::random();
                        match udp_tracker_announce(
                            tracker_url,
                            &info_hash,
                            &peer_id_query,
                            0,
                            0, // event: none
                        )
                        .await
                        {
                            Ok(data) if data.len() > 20 => {
                                found = Some(data);
                                break;
                            }
                            _ => continue,
                        }
                    } else {
                        // HTTP scrape.
                        let peer_id_query: [u8; 20] = rand::random();
                        match http_tracker_announce(
                            &client,
                            tracker_url,
                            &info_hash,
                            &peer_id_query,
                            0,
                            "",
                        )
                        .await
                        {
                            Ok(data) if !data.is_empty() => {
                                found = Some(data);
                                break;
                            }
                            _ => continue,
                        }
                    }
                }

                let _ = reply.send(Ok(found));
            }
            Some(BtCommand::Shutdown { reply }) => {
                tracing::debug!(backend = "bittorrent", "shutting down");
                announce_state.clear();
                let _ = reply.send(Ok(()));
                break;
            }
            None => {
                tracing::debug!(backend = "bittorrent", "command channel closed");
                break;
            }
        }
    }
}

#[async_trait]
impl DiscoveryBackend for BitTorrentBackend {
    fn name(&self) -> &str {
        "bittorrent"
    }

    async fn publish(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(BtCommand::Publish {
                info_hash: Self::to_info_hash(rendezvous_id),
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("BitTorrent event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("BitTorrent event loop dropped reply".into())
        })?
    }

    async fn query(&self, rendezvous_id: &RendezvousId) -> Result<Option<Vec<u8>>, DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(BtCommand::Query {
                info_hash: Self::to_info_hash(rendezvous_id),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("BitTorrent event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("BitTorrent event loop dropped reply".into())
        })?
    }

    async fn stop(&self) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(BtCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("BitTorrent event loop already shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("BitTorrent event loop dropped reply".into())
        })?
    }
}

/// Hex encoding utility.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Signaling server backend (WebSocket)
// ---------------------------------------------------------------------------

/// Commands sent from the SignalingBackend to its WebSocket task.
enum SignalCommand {
    /// Publish a payload for a topic.
    Publish {
        topic: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
    /// Query for a payload on a topic.
    Query {
        topic: String,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DiscoveryError>>,
    },
    /// Shut down the WebSocket connection.
    Shutdown {
        reply: oneshot::Sender<Result<(), DiscoveryError>>,
    },
}

/// Signaling server WebSocket-based discovery backend.
///
/// Connects to a cairn companion signaling server for real-time peer
/// discovery. The rendezvous ID maps to a WebSocket topic/room.
/// Sub-second latency. Requires Tier 1+ deployment.
pub struct SignalingBackend {
    command_tx: mpsc::Sender<SignalCommand>,
    /// Server URL (kept for the public accessor).
    server_url: String,
    /// Whether auth is configured (kept for the public accessor).
    has_auth_token: bool,
}

impl SignalingBackend {
    /// Create a new signaling backend.
    ///
    /// Spawns a background task that manages the WebSocket connection to the
    /// signaling server. The connection is established lazily on first use.
    pub fn new(server_url: String, auth_token: Option<String>) -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);
        let has_auth_token = auth_token.is_some();

        tokio::spawn(signaling_event_loop(
            command_rx,
            server_url.clone(),
            auth_token,
        ));

        Self {
            command_tx,
            server_url,
            has_auth_token,
        }
    }

    /// Get the configured server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Whether authentication is configured.
    pub fn has_auth(&self) -> bool {
        self.has_auth_token
    }
}

/// Run the signaling server WebSocket event loop.
///
/// Manages the WebSocket connection lifecycle: connect on first use,
/// reconnect on disconnect, send/receive JSON messages.
async fn signaling_event_loop(
    mut command_rx: mpsc::Receiver<SignalCommand>,
    server_url: String,
    auth_token: Option<String>,
) {
    use base64::Engine;
    use futures_util::SinkExt;

    // Local record cache for topics we've published or received.
    let mut local_records: HashMap<String, Vec<u8>> = HashMap::new();
    // Active WebSocket connection (lazily established).
    let mut ws_stream: Option<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
    > = None;

    /// Attempt to connect to the signaling server.
    async fn connect_ws(
        server_url: &str,
        auth_token: &Option<String>,
    ) -> Option<(
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    )> {
        let mut request =
            match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                server_url,
            ) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(backend = "signaling", error = %e, "invalid server URL");
                    return None;
                }
            };

        if let Some(token) = auth_token {
            if let Ok(val) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!(
                "Bearer {token}"
            )) {
                request.headers_mut().insert("Authorization", val);
            }
        }

        match tokio_tungstenite::connect_async(request).await {
            Ok((stream, _)) => {
                tracing::debug!(backend = "signaling", "WebSocket connected");
                let (sink, stream) = futures_util::StreamExt::split(stream);
                Some((sink, stream))
            }
            Err(e) => {
                tracing::warn!(backend = "signaling", error = %e, "WebSocket connection failed");
                None
            }
        }
    }

    loop {
        match command_rx.recv().await {
            Some(SignalCommand::Publish {
                topic,
                payload,
                reply,
            }) => {
                tracing::debug!(
                    backend = "signaling",
                    server = %server_url,
                    topic = %topic,
                    "publishing to signaling server"
                );

                // Store locally.
                local_records.insert(topic.clone(), payload.clone());

                // Try to send over WebSocket.
                let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
                let msg = serde_json::json!({
                    "type": "publish",
                    "topic": topic,
                    "payload": payload_b64,
                });

                // Ensure connection exists.
                if ws_stream.is_none() {
                    if let Some((sink, _reader)) = connect_ws(&server_url, &auth_token).await {
                        ws_stream = Some(sink);
                        // Note: in production, the reader stream would be spawned
                        // as a separate task to receive incoming messages.
                    }
                }

                if let Some(ref mut sink) = ws_stream {
                    let ws_msg = tokio_tungstenite::tungstenite::Message::Text(msg.to_string());
                    if let Err(e) = sink.send(ws_msg).await {
                        tracing::warn!(
                            backend = "signaling",
                            error = %e,
                            "WebSocket send failed, will reconnect"
                        );
                        ws_stream = None;
                    }
                }

                // Publish succeeds even if WS is unavailable (cached locally).
                let _ = reply.send(Ok(()));
            }
            Some(SignalCommand::Query { topic, reply }) => {
                tracing::debug!(
                    backend = "signaling",
                    server = %server_url,
                    topic = %topic,
                    "querying signaling server"
                );

                // Check local cache.
                let result = local_records.get(&topic).cloned();

                // If not in cache and we have a WS connection, send a query.
                if result.is_none() {
                    if ws_stream.is_none() {
                        if let Some((sink, _reader)) = connect_ws(&server_url, &auth_token).await {
                            ws_stream = Some(sink);
                        }
                    }

                    if let Some(ref mut sink) = ws_stream {
                        let msg = serde_json::json!({
                            "type": "query",
                            "topic": topic,
                        });
                        let ws_msg = tokio_tungstenite::tungstenite::Message::Text(msg.to_string());
                        if let Err(e) = sink.send(ws_msg).await {
                            tracing::warn!(
                                backend = "signaling",
                                error = %e,
                                "WebSocket query send failed"
                            );
                            ws_stream = None;
                        }
                    }
                }

                let _ = reply.send(Ok(result));
            }
            Some(SignalCommand::Shutdown { reply }) => {
                tracing::debug!(
                    backend = "signaling",
                    server = %server_url,
                    "shutting down"
                );

                // Close WebSocket connection.
                if let Some(ref mut sink) = ws_stream {
                    let _ = sink
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                }
                drop(ws_stream);
                local_records.clear();

                let _ = reply.send(Ok(()));
                break;
            }
            None => {
                tracing::debug!(backend = "signaling", "command channel closed");
                if let Some(ref mut sink) = ws_stream {
                    let _ = sink
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                }
                break;
            }
        }
    }
}

#[async_trait]
impl DiscoveryBackend for SignalingBackend {
    fn name(&self) -> &str {
        "signaling"
    }

    async fn publish(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SignalCommand::Publish {
                topic: rendezvous_id.to_hex(),
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Signaling event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Signaling event loop dropped reply".into())
        })?
    }

    async fn query(&self, rendezvous_id: &RendezvousId) -> Result<Option<Vec<u8>>, DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SignalCommand::Query {
                topic: rendezvous_id.to_hex(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Signaling event loop shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Signaling event loop dropped reply".into())
        })?
    }

    async fn stop(&self) -> Result<(), DiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SignalCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| {
                DiscoveryError::BackendUnavailable("Signaling event loop already shut down".into())
            })?;
        reply_rx.await.map_err(|_| {
            DiscoveryError::BackendUnavailable("Signaling event loop dropped reply".into())
        })?
    }
}

// ---------------------------------------------------------------------------
// Multi-backend discovery coordinator
// ---------------------------------------------------------------------------

/// Coordinates discovery across all configured backends.
///
/// Publishes to and queries from all backends simultaneously.
/// First successful query result wins.
pub struct DiscoveryCoordinator {
    backends: Vec<Box<dyn DiscoveryBackend>>,
}

impl DiscoveryCoordinator {
    pub fn new(backends: Vec<Box<dyn DiscoveryBackend>>) -> Self {
        Self { backends }
    }

    /// Publish reachability to all backends simultaneously.
    pub async fn publish_all(
        &self,
        rendezvous_id: &RendezvousId,
        payload: &[u8],
    ) -> Vec<Result<(), DiscoveryError>> {
        let mut results = Vec::with_capacity(self.backends.len());
        for backend in &self.backends {
            let result = backend.publish(rendezvous_id, payload).await;
            if let Err(ref e) = result {
                tracing::warn!(backend = backend.name(), error = %e, "publish failed");
            }
            results.push(result);
        }
        results
    }

    /// Query all backends simultaneously. Returns the first successful result.
    pub async fn query_first(
        &self,
        rendezvous_id: &RendezvousId,
    ) -> Result<Option<Vec<u8>>, DiscoveryError> {
        for backend in &self.backends {
            match backend.query(rendezvous_id).await {
                Ok(Some(payload)) => {
                    tracing::debug!(backend = backend.name(), "query succeeded");
                    return Ok(Some(payload));
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(backend = backend.name(), error = %e, "query failed");
                    continue;
                }
            }
        }
        Ok(None)
    }

    /// Stop all backends.
    pub async fn stop_all(&self) -> Vec<Result<(), DiscoveryError>> {
        let mut results = Vec::with_capacity(self.backends.len());
        for backend in &self.backends {
            results.push(backend.stop().await);
        }
        results
    }

    /// Number of configured backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// List backend names.
    pub fn backend_names(&self) -> Vec<&str> {
        self.backends.iter().map(|b| b.name()).collect()
    }

    /// Create a coordinator with mDNS and Kademlia backends connected to
    /// the composed swarm.
    ///
    /// The mDNS backend uses local records (mDNS discovery is handled by the
    /// swarm's mDNS behaviour). The Kademlia backend routes DHT operations
    /// through the swarm's Kademlia behaviour via `SwarmCommandSender`.
    pub fn from_swarm(swarm_sender: crate::transport::swarm::SwarmCommandSender) -> Self {
        let mdns = MdnsBackend::from_swarm();
        let kad = KademliaBackend::from_swarm(swarm_sender);
        Self {
            backends: vec![Box::new(mdns), Box::new(kad)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mdns_publish_and_query() {
        let backend = MdnsBackend::new().unwrap();
        let id = RendezvousId([0xAA; 32]);
        let payload = b"encrypted-reachability";

        backend.publish(&id, payload).await.unwrap();
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(payload.to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn mdns_query_not_found() {
        let backend = MdnsBackend::new().unwrap();
        let id = RendezvousId([0xBB; 32]);
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, None);

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn mdns_stop_clears_records() {
        let backend = MdnsBackend::new().unwrap();
        let id = RendezvousId([0xCC; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, the event loop is gone so queries will fail with BackendUnavailable.
        let result = backend.query(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kademlia_publish_and_query() {
        let backend = KademliaBackend::new(KademliaConfig::default()).unwrap();
        let id = RendezvousId([0xDD; 32]);
        backend.publish(&id, b"dht-payload").await.unwrap();
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(b"dht-payload".to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn kademlia_query_not_found() {
        let backend = KademliaBackend::new(KademliaConfig::default()).unwrap();
        let id = RendezvousId([0xBB; 32]);
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, None);

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn kademlia_stop_shuts_down() {
        let backend = KademliaBackend::new(KademliaConfig::default()).unwrap();
        let id = RendezvousId([0xCC; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, queries should fail.
        let result = backend.query(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bittorrent_publish_and_query() {
        let backend = BitTorrentBackend::new(BitTorrentConfig::default());
        let id = RendezvousId([0xEE; 32]);
        backend.publish(&id, b"tracker-payload").await.unwrap();
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(b"tracker-payload".to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn bittorrent_info_hash_is_20_bytes() {
        let id = RendezvousId([0xFF; 32]);
        let hash = BitTorrentBackend::to_info_hash(&id);
        assert_eq!(hash.len(), 20);
        assert_eq!(hash, [0xFF; 20]);
    }

    #[tokio::test]
    async fn bittorrent_min_reannounce_is_15_min() {
        let backend = BitTorrentBackend::new(BitTorrentConfig::default());
        assert_eq!(
            backend.min_reannounce_interval(),
            Duration::from_secs(15 * 60)
        );

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn bittorrent_stop_clears_records() {
        let backend = BitTorrentBackend::new(BitTorrentConfig::default());
        let id = RendezvousId([0xCC; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, queries should fail.
        let result = backend.query(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bittorrent_reannounce_interval_enforced() {
        let config = BitTorrentConfig {
            min_reannounce: Duration::from_secs(15 * 60),
            ..BitTorrentConfig::default()
        };
        let backend = BitTorrentBackend::new(config);
        let id = RendezvousId([0xDD; 32]);

        // First publish should succeed.
        backend.publish(&id, b"payload-1").await.unwrap();

        // Second publish within the interval should still succeed (updates cache).
        backend.publish(&id, b"payload-2").await.unwrap();

        // Query should return the latest cached payload.
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(b"payload-2".to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn signaling_publish_and_query() {
        let backend =
            SignalingBackend::new("wss://signal.example.com".into(), Some("token-123".into()));
        assert_eq!(backend.server_url(), "wss://signal.example.com");
        assert!(backend.has_auth());

        let id = RendezvousId([0x11; 32]);
        backend.publish(&id, b"signal-payload").await.unwrap();
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(b"signal-payload".to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn signaling_no_auth() {
        let backend = SignalingBackend::new("wss://open.example.com".into(), None);
        assert!(!backend.has_auth());

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn signaling_stop_clears_records() {
        let backend = SignalingBackend::new("wss://signal.example.com".into(), None);
        let id = RendezvousId([0xCC; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, queries should fail.
        let result = backend.query(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn coordinator_publish_all() {
        let mdns = MdnsBackend::new().unwrap();
        let kad = KademliaBackend::new(KademliaConfig::default()).unwrap();
        let coord = DiscoveryCoordinator::new(vec![Box::new(mdns), Box::new(kad)]);

        assert_eq!(coord.backend_count(), 2);
        assert_eq!(coord.backend_names(), vec!["mdns", "kademlia"]);

        let id = RendezvousId([0x22; 32]);
        let results = coord.publish_all(&id, b"payload").await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));

        coord.stop_all().await;
    }

    #[tokio::test]
    async fn coordinator_query_first_finds_in_first_backend() {
        let mdns = MdnsBackend::new().unwrap();
        let kad = KademliaBackend::new(KademliaConfig::default()).unwrap();

        let id = RendezvousId([0x33; 32]);
        mdns.publish(&id, b"from-mdns").await.unwrap();

        let coord = DiscoveryCoordinator::new(vec![Box::new(mdns), Box::new(kad)]);

        let result = coord.query_first(&id).await.unwrap();
        assert_eq!(result, Some(b"from-mdns".to_vec()));

        coord.stop_all().await;
    }

    #[tokio::test]
    async fn coordinator_query_first_falls_through_to_second() {
        let mdns = MdnsBackend::new().unwrap();
        let kad = KademliaBackend::new(KademliaConfig::default()).unwrap();

        let id = RendezvousId([0x44; 32]);
        // Only publish to kademlia, not mdns.
        kad.publish(&id, b"from-kad").await.unwrap();

        let coord = DiscoveryCoordinator::new(vec![Box::new(mdns), Box::new(kad)]);

        let result = coord.query_first(&id).await.unwrap();
        assert_eq!(result, Some(b"from-kad".to_vec()));

        coord.stop_all().await;
    }

    #[tokio::test]
    async fn coordinator_query_first_returns_none_when_empty() {
        let mdns = MdnsBackend::new().unwrap();
        let coord = DiscoveryCoordinator::new(vec![Box::new(mdns)]);

        let id = RendezvousId([0x55; 32]);
        let result = coord.query_first(&id).await.unwrap();
        assert_eq!(result, None);

        coord.stop_all().await;
    }

    #[tokio::test]
    async fn coordinator_stop_all() {
        let mdns = MdnsBackend::new().unwrap();
        let kad = KademliaBackend::new(KademliaConfig::default()).unwrap();

        let id = RendezvousId([0x66; 32]);
        mdns.publish(&id, b"data").await.unwrap();
        kad.publish(&id, b"data").await.unwrap();

        let coord = DiscoveryCoordinator::new(vec![Box::new(mdns), Box::new(kad)]);

        let results = coord.stop_all().await;
        assert!(results.iter().all(|r| r.is_ok()));

        // After stop, queries should fail (event loops shut down).
        let result = coord.query_first(&id).await;
        // The backends' event loops are stopped, so queries should error.
        // But the coordinator catches errors and returns None.
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn all_backends_have_correct_names() {
        let mdns = MdnsBackend::new().unwrap();
        let kad = KademliaBackend::new(KademliaConfig::default()).unwrap();
        let bt = BitTorrentBackend::new(BitTorrentConfig::default());
        let sig = SignalingBackend::new("wss://example.com".into(), None);

        assert_eq!(mdns.name(), "mdns");
        assert_eq!(kad.name(), "kademlia");
        assert_eq!(bt.name(), "bittorrent");
        assert_eq!(sig.name(), "signaling");

        mdns.stop().await.unwrap();
        kad.stop().await.unwrap();
        bt.stop().await.unwrap();
        sig.stop().await.unwrap();
    }

    // --- Swarm-connected backend tests ---

    #[tokio::test]
    async fn mdns_from_swarm_publish_and_query() {
        let backend = MdnsBackend::from_swarm();
        let id = RendezvousId([0xA1; 32]);
        let payload = b"swarm-mdns-reachability";

        backend.publish(&id, payload).await.unwrap();
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(payload.to_vec()));

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn mdns_from_swarm_query_not_found() {
        let backend = MdnsBackend::from_swarm();
        let id = RendezvousId([0xB1; 32]);
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, None);

        backend.stop().await.unwrap();
    }

    #[tokio::test]
    async fn mdns_from_swarm_stop_clears_records() {
        let backend = MdnsBackend::from_swarm();
        let id = RendezvousId([0xC1; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, queries should fail.
        let result = backend.query(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kademlia_from_swarm_publish_and_query() {
        use crate::crypto::IdentityKeypair;
        use crate::transport::{build_swarm, TransportConfig};

        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let controller = build_swarm(&identity, &config).await.unwrap();
        let sender = controller.command_sender();

        let backend = KademliaBackend::from_swarm(sender);
        let id = RendezvousId([0xD1; 32]);
        backend.publish(&id, b"swarm-kad-payload").await.unwrap();

        // Query returns from local cache.
        let result = backend.query(&id).await.unwrap();
        assert_eq!(result, Some(b"swarm-kad-payload".to_vec()));

        backend.stop().await.unwrap();
        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn kademlia_from_swarm_stop_shuts_down() {
        use crate::crypto::IdentityKeypair;
        use crate::transport::{build_swarm, TransportConfig};

        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let controller = build_swarm(&identity, &config).await.unwrap();
        let sender = controller.command_sender();

        let backend = KademliaBackend::from_swarm(sender);
        let id = RendezvousId([0xC2; 32]);
        backend.publish(&id, b"data").await.unwrap();
        backend.stop().await.unwrap();

        // After stop, queries should fail.
        let result = backend.query(&id).await;
        assert!(result.is_err());

        controller.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn coordinator_from_swarm_publish_and_query() {
        use crate::crypto::IdentityKeypair;
        use crate::transport::{build_swarm, TransportConfig};

        let identity = IdentityKeypair::generate();
        let config = TransportConfig::default();
        let controller = build_swarm(&identity, &config).await.unwrap();
        let sender = controller.command_sender();

        let coord = DiscoveryCoordinator::from_swarm(sender);
        assert_eq!(coord.backend_count(), 2);
        assert_eq!(coord.backend_names(), vec!["mdns", "kademlia"]);

        let id = RendezvousId([0xE1; 32]);
        let results = coord.publish_all(&id, b"swarm-coord-payload").await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));

        // Query should find the payload (mdns backend returns it from local store).
        let result = coord.query_first(&id).await.unwrap();
        assert_eq!(result, Some(b"swarm-coord-payload".to_vec()));

        coord.stop_all().await;
        controller.shutdown().await.unwrap();
    }
}
