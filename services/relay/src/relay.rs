//! TURN relay allocation state machine per RFC 8656.
//!
//! Manages allocations, permissions, channel bindings, and data forwarding.

use crate::credentials::CredentialStore;
use crate::stun::{self, Message};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Default allocation lifetime in seconds (10 minutes per RFC 8656).
const DEFAULT_LIFETIME: u32 = 600;
/// Maximum allocation lifetime in seconds (1 hour).
const MAX_LIFETIME: u32 = 3600;
/// Permission lifetime in seconds (5 minutes per RFC 8656).
const PERMISSION_LIFETIME_SECS: u64 = 300;
/// Channel binding lifetime in seconds (10 minutes per RFC 8656).
const CHANNEL_BINDING_LIFETIME_SECS: u64 = 600;

/// A TURN allocation.
#[derive(Debug)]
#[allow(dead_code)] // Fields kept for allocation state per RFC 8656.
pub struct Allocation {
    /// The allocated relay address (the UDP socket the server listens on for this client).
    pub relay_addr: SocketAddr,
    /// The client's 5-tuple source address.
    pub client_addr: SocketAddr,
    /// Peer IP -> permission expiry.
    pub permissions: HashMap<IpAddr, Instant>,
    /// Channel number (0x4000-0x7FFF) -> peer address.
    pub channels: HashMap<u16, SocketAddr>,
    /// Reverse lookup: peer address -> channel number.
    pub channel_reverse: HashMap<SocketAddr, u16>,
    /// When this allocation expires.
    pub expires_at: Instant,
    /// The authenticated username.
    pub username: String,
    /// The relay socket for this allocation.
    pub relay_socket: Arc<UdpSocket>,
}

/// State shared across the relay server.
pub struct RelayState {
    /// Client address -> allocation.
    pub allocations: RwLock<HashMap<SocketAddr, Allocation>>,
    /// Credential store.
    pub credentials: CredentialStore,
    /// Relay address range: bind address prefix and port range.
    pub relay_bind_addr: IpAddr,
    pub port_range: (u16, u16),
    /// Next port to try (simple round-robin).
    next_port: RwLock<u16>,
    /// The main server socket (for sending responses and Data indications back to clients).
    pub server_socket: Arc<UdpSocket>,
}

impl RelayState {
    pub fn new(
        credentials: CredentialStore,
        relay_bind_addr: IpAddr,
        port_range: (u16, u16),
        server_socket: Arc<UdpSocket>,
    ) -> Self {
        Self {
            allocations: RwLock::new(HashMap::new()),
            credentials,
            relay_bind_addr,
            port_range,
            next_port: RwLock::new(port_range.0),
            server_socket,
        }
    }

    /// Allocate a relay UDP socket on an available port.
    async fn allocate_relay_socket(&self) -> Result<(Arc<UdpSocket>, SocketAddr), RelayError> {
        let mut next = self.next_port.write().await;
        let start = *next;
        let (lo, hi) = self.port_range;

        loop {
            let addr = SocketAddr::new(self.relay_bind_addr, *next);
            match UdpSocket::bind(addr).await {
                Ok(sock) => {
                    let local = sock
                        .local_addr()
                        .map_err(|e| RelayError::Io(e.to_string()))?;
                    *next = if *next >= hi { lo } else { *next + 1 };
                    return Ok((Arc::new(sock), local));
                }
                Err(_) => {
                    *next = if *next >= hi { lo } else { *next + 1 };
                    if *next == start {
                        return Err(RelayError::InsufficientCapacity);
                    }
                }
            }
        }
    }

    /// Process an incoming STUN message and return a response (if any).
    pub async fn handle_stun_message(
        self: &Arc<Self>,
        msg: &Message,
        raw: &[u8],
        client_addr: SocketAddr,
    ) -> Option<Vec<u8>> {
        match (msg.msg_type.class, msg.msg_type.method) {
            (stun::CLASS_REQUEST, stun::METHOD_BINDING) => {
                Some(self.handle_binding(msg, client_addr))
            }
            (stun::CLASS_REQUEST, stun::METHOD_ALLOCATE) => {
                Some(self.handle_allocate(msg, raw, client_addr).await)
            }
            (stun::CLASS_REQUEST, stun::METHOD_REFRESH) => {
                Some(self.handle_refresh(msg, raw, client_addr).await)
            }
            (stun::CLASS_REQUEST, stun::METHOD_CREATE_PERMISSION) => {
                Some(self.handle_create_permission(msg, raw, client_addr).await)
            }
            (stun::CLASS_REQUEST, stun::METHOD_CHANNEL_BIND) => {
                Some(self.handle_channel_bind(msg, raw, client_addr).await)
            }
            (stun::CLASS_INDICATION, stun::METHOD_SEND) => {
                self.handle_send_indication(msg, client_addr).await;
                None // Indications get no response
            }
            _ => {
                debug!(
                    method = msg.msg_type.method,
                    class = msg.msg_type.class,
                    "unsupported STUN method/class"
                );
                let resp = self.error_response(msg, stun::ERR_BAD_REQUEST, "unsupported method");
                Some(resp.encode())
            }
        }
    }

    /// Handle a STUN Binding request (simple STUN, returns reflexive address).
    fn handle_binding(&self, msg: &Message, client_addr: SocketAddr) -> Vec<u8> {
        let mut resp = Message::new(
            stun::CLASS_SUCCESS,
            stun::METHOD_BINDING,
            msg.transaction_id,
        );
        resp.add_xor_address(stun::ATTR_XOR_MAPPED_ADDRESS, client_addr);
        resp.add_software("cairn-relay");
        resp.encode()
    }

    /// Authenticate a STUN request using long-term credentials.
    /// Returns the key on success, or an error response on failure.
    fn authenticate(&self, msg: &Message, raw: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
        let username = match msg.parse_username() {
            Some(u) => u,
            None => {
                // No credentials: send 401 with realm and nonce
                let mut resp =
                    self.error_response(msg, stun::ERR_UNAUTHORIZED, "missing credentials");
                resp.add_realm(self.credentials.realm());
                resp.add_nonce(&crate::credentials::generate_nonce());
                return Err(resp.encode());
            }
        };

        let key = match self.credentials.lookup_key(&username) {
            Some(k) => k,
            None => {
                let mut resp = self.error_response(msg, stun::ERR_UNAUTHORIZED, "unknown user");
                resp.add_realm(self.credentials.realm());
                resp.add_nonce(&crate::credentials::generate_nonce());
                return Err(resp.encode());
            }
        };

        if !msg.verify_message_integrity(&key, raw) {
            let mut resp =
                self.error_response(msg, stun::ERR_UNAUTHORIZED, "bad message integrity");
            resp.add_realm(self.credentials.realm());
            resp.add_nonce(&crate::credentials::generate_nonce());
            return Err(resp.encode());
        }

        Ok(key)
    }

    /// Handle an Allocate request.
    async fn handle_allocate(
        self: &Arc<Self>,
        msg: &Message,
        raw: &[u8],
        client_addr: SocketAddr,
    ) -> Vec<u8> {
        let key = match self.authenticate(msg, raw) {
            Ok(k) => k,
            Err(err_resp) => return err_resp,
        };

        // Check requested transport (must be UDP = 17)
        match msg.parse_requested_transport() {
            Some(stun::TRANSPORT_UDP) => {}
            Some(_) => {
                return self
                    .error_response(msg, stun::ERR_BAD_REQUEST, "unsupported transport")
                    .encode();
            }
            None => {
                return self
                    .error_response(msg, stun::ERR_BAD_REQUEST, "missing REQUESTED-TRANSPORT")
                    .encode();
            }
        }

        // Check for existing allocation
        {
            let allocs = self.allocations.read().await;
            if allocs.contains_key(&client_addr) {
                return self
                    .error_response(msg, stun::ERR_ALLOCATION_MISMATCH, "allocation exists")
                    .encode();
            }
        }

        // Allocate a relay socket
        let (relay_socket, relay_addr) = match self.allocate_relay_socket().await {
            Ok(r) => r,
            Err(_) => {
                return self
                    .error_response(msg, stun::ERR_INSUFFICIENT_CAPACITY, "no ports available")
                    .encode();
            }
        };

        let lifetime = msg
            .parse_lifetime()
            .unwrap_or(DEFAULT_LIFETIME)
            .min(MAX_LIFETIME);
        let username = msg.parse_username().unwrap_or_default();

        let allocation = Allocation {
            relay_addr,
            client_addr,
            permissions: HashMap::new(),
            channels: HashMap::new(),
            channel_reverse: HashMap::new(),
            expires_at: Instant::now() + std::time::Duration::from_secs(lifetime as u64),
            username,
            relay_socket: relay_socket.clone(),
        };

        info!(
            client = %client_addr,
            relay = %relay_addr,
            lifetime = lifetime,
            "allocation created"
        );

        {
            let mut allocs = self.allocations.write().await;
            allocs.insert(client_addr, allocation);
        }

        // Start relay task for this allocation
        let state = Arc::clone(self);
        let client = client_addr;
        tokio::spawn(async move {
            state.relay_peer_to_client(relay_socket, client).await;
        });

        // Build success response
        let mut resp = Message::new(
            stun::CLASS_SUCCESS,
            stun::METHOD_ALLOCATE,
            msg.transaction_id,
        );
        resp.add_xor_address(stun::ATTR_XOR_RELAYED_ADDRESS, relay_addr);
        resp.add_xor_address(stun::ATTR_XOR_MAPPED_ADDRESS, client_addr);
        resp.add_lifetime(lifetime);
        resp.add_software("cairn-relay");
        resp.add_message_integrity(&key);
        resp.encode()
    }

    /// Handle a Refresh request.
    async fn handle_refresh(&self, msg: &Message, raw: &[u8], client_addr: SocketAddr) -> Vec<u8> {
        let key = match self.authenticate(msg, raw) {
            Ok(k) => k,
            Err(err_resp) => return err_resp,
        };

        let lifetime = msg.parse_lifetime().unwrap_or(DEFAULT_LIFETIME);

        let mut allocs = self.allocations.write().await;
        let alloc = match allocs.get_mut(&client_addr) {
            Some(a) => a,
            None => {
                return self
                    .error_response(msg, stun::ERR_ALLOCATION_MISMATCH, "no allocation")
                    .encode();
            }
        };

        if lifetime == 0 {
            // Delete the allocation
            info!(client = %client_addr, "allocation deleted by client");
            allocs.remove(&client_addr);
        } else {
            let clamped = lifetime.min(MAX_LIFETIME);
            alloc.expires_at = Instant::now() + std::time::Duration::from_secs(clamped as u64);
            debug!(client = %client_addr, lifetime = clamped, "allocation refreshed");
        }

        let granted = if lifetime == 0 {
            0
        } else {
            lifetime.min(MAX_LIFETIME)
        };
        let mut resp = Message::new(
            stun::CLASS_SUCCESS,
            stun::METHOD_REFRESH,
            msg.transaction_id,
        );
        resp.add_lifetime(granted);
        resp.add_message_integrity(&key);
        resp.encode()
    }

    /// Handle a CreatePermission request.
    async fn handle_create_permission(
        &self,
        msg: &Message,
        raw: &[u8],
        client_addr: SocketAddr,
    ) -> Vec<u8> {
        let key = match self.authenticate(msg, raw) {
            Ok(k) => k,
            Err(err_resp) => return err_resp,
        };

        // Extract all XOR-PEER-ADDRESS attributes
        let peer_addrs: Vec<SocketAddr> = msg
            .attributes
            .iter()
            .filter(|a| a.typ == stun::ATTR_XOR_PEER_ADDRESS)
            .filter_map(|a| {
                stun::Message::new(
                    stun::CLASS_REQUEST,
                    stun::METHOD_CREATE_PERMISSION,
                    msg.transaction_id,
                )
                .parse_xor_address_from_value(&a.value, &msg.transaction_id)
            })
            .collect();

        if peer_addrs.is_empty() {
            // Try parsing directly from the message
            if let Some(addr) = msg.parse_xor_address(stun::ATTR_XOR_PEER_ADDRESS) {
                let mut allocs = self.allocations.write().await;
                if let Some(alloc) = allocs.get_mut(&client_addr) {
                    let expiry =
                        Instant::now() + std::time::Duration::from_secs(PERMISSION_LIFETIME_SECS);
                    alloc.permissions.insert(addr.ip(), expiry);
                    debug!(client = %client_addr, peer = %addr.ip(), "permission created");
                } else {
                    return self
                        .error_response(msg, stun::ERR_ALLOCATION_MISMATCH, "no allocation")
                        .encode();
                }
            } else {
                return self
                    .error_response(msg, stun::ERR_BAD_REQUEST, "missing XOR-PEER-ADDRESS")
                    .encode();
            }
        } else {
            let mut allocs = self.allocations.write().await;
            if let Some(alloc) = allocs.get_mut(&client_addr) {
                let expiry =
                    Instant::now() + std::time::Duration::from_secs(PERMISSION_LIFETIME_SECS);
                for addr in &peer_addrs {
                    alloc.permissions.insert(addr.ip(), expiry);
                    debug!(client = %client_addr, peer = %addr.ip(), "permission created");
                }
            } else {
                return self
                    .error_response(msg, stun::ERR_ALLOCATION_MISMATCH, "no allocation")
                    .encode();
            }
        }

        let mut resp = Message::new(
            stun::CLASS_SUCCESS,
            stun::METHOD_CREATE_PERMISSION,
            msg.transaction_id,
        );
        resp.add_message_integrity(&key);
        resp.encode()
    }

    /// Handle a ChannelBind request.
    async fn handle_channel_bind(
        &self,
        msg: &Message,
        raw: &[u8],
        client_addr: SocketAddr,
    ) -> Vec<u8> {
        let key = match self.authenticate(msg, raw) {
            Ok(k) => k,
            Err(err_resp) => return err_resp,
        };

        let channel = match msg.parse_channel_number() {
            Some(c) if (0x4000..=0x7FFF).contains(&c) => c,
            _ => {
                return self
                    .error_response(msg, stun::ERR_BAD_REQUEST, "invalid channel number")
                    .encode();
            }
        };

        let peer_addr = match msg.parse_xor_address(stun::ATTR_XOR_PEER_ADDRESS) {
            Some(a) => a,
            None => {
                return self
                    .error_response(msg, stun::ERR_BAD_REQUEST, "missing XOR-PEER-ADDRESS")
                    .encode();
            }
        };

        let mut allocs = self.allocations.write().await;
        let alloc = match allocs.get_mut(&client_addr) {
            Some(a) => a,
            None => {
                return self
                    .error_response(msg, stun::ERR_ALLOCATION_MISMATCH, "no allocation")
                    .encode();
            }
        };

        // Check if channel is already bound to a different peer
        if let Some(existing) = alloc.channels.get(&channel) {
            if *existing != peer_addr {
                return self
                    .error_response(
                        msg,
                        stun::ERR_BAD_REQUEST,
                        "channel bound to different peer",
                    )
                    .encode();
            }
        }

        // Check if peer is already bound to a different channel
        if let Some(existing) = alloc.channel_reverse.get(&peer_addr) {
            if *existing != channel {
                return self
                    .error_response(
                        msg,
                        stun::ERR_BAD_REQUEST,
                        "peer bound to different channel",
                    )
                    .encode();
            }
        }

        alloc.channels.insert(channel, peer_addr);
        alloc.channel_reverse.insert(peer_addr, channel);

        // Channel binding also installs/refreshes a permission
        let expiry = Instant::now() + std::time::Duration::from_secs(CHANNEL_BINDING_LIFETIME_SECS);
        alloc.permissions.insert(peer_addr.ip(), expiry);

        debug!(
            client = %client_addr,
            channel = channel,
            peer = %peer_addr,
            "channel binding created"
        );

        let mut resp = Message::new(
            stun::CLASS_SUCCESS,
            stun::METHOD_CHANNEL_BIND,
            msg.transaction_id,
        );
        resp.add_message_integrity(&key);
        resp.encode()
    }

    /// Handle a Send indication (client -> peer via relay).
    async fn handle_send_indication(&self, msg: &Message, client_addr: SocketAddr) {
        let peer_addr = match msg.parse_xor_address(stun::ATTR_XOR_PEER_ADDRESS) {
            Some(a) => a,
            None => return,
        };

        let data = match msg.parse_data() {
            Some(d) => d,
            None => return,
        };

        let allocs = self.allocations.read().await;
        let alloc = match allocs.get(&client_addr) {
            Some(a) => a,
            None => return,
        };

        // Check permission
        if !Self::has_permission(alloc, peer_addr.ip()) {
            warn!(
                client = %client_addr,
                peer = %peer_addr,
                "send indication rejected: no permission"
            );
            return;
        }

        // Forward data from relay socket to peer
        if let Err(e) = alloc.relay_socket.send_to(data, peer_addr).await {
            warn!(peer = %peer_addr, error = %e, "failed to forward data to peer");
        }
    }

    /// Handle ChannelData from client: forward to peer via the relay socket.
    pub async fn handle_channel_data(&self, channel: u16, data: &[u8], client_addr: SocketAddr) {
        let allocs = self.allocations.read().await;
        let alloc = match allocs.get(&client_addr) {
            Some(a) => a,
            None => return,
        };

        let peer_addr = match alloc.channels.get(&channel) {
            Some(a) => *a,
            None => return,
        };

        if !Self::has_permission(alloc, peer_addr.ip()) {
            return;
        }

        if let Err(e) = alloc.relay_socket.send_to(data, peer_addr).await {
            warn!(peer = %peer_addr, error = %e, "failed to forward channel data to peer");
        }
    }

    /// Relay task: forward data from peer -> client via the relay socket.
    /// Runs as a background task for each allocation.
    async fn relay_peer_to_client(
        self: Arc<Self>,
        relay_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
    ) {
        let mut buf = vec![0u8; 65536];

        loop {
            let (len, peer_addr) = match relay_socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    debug!(error = %e, "relay socket recv error, stopping relay task");
                    break;
                }
            };

            // Check that the allocation still exists and has permission for this peer
            let allocs = self.allocations.read().await;
            let alloc = match allocs.get(&client_addr) {
                Some(a) => a,
                None => break, // Allocation removed
            };

            if !Self::has_permission(alloc, peer_addr.ip()) {
                continue;
            }

            // Check if there's a channel binding for this peer
            if let Some(&channel) = alloc.channel_reverse.get(&peer_addr) {
                // Send as ChannelData
                let channel_data = stun::encode_channel_data(channel, &buf[..len]);
                if let Err(e) = self.server_socket.send_to(&channel_data, client_addr).await {
                    warn!(client = %client_addr, error = %e, "failed to send channel data to client");
                }
            } else {
                // Send as Data indication
                let mut indication =
                    Message::new(stun::CLASS_INDICATION, stun::METHOD_DATA, rand::random());
                indication.add_xor_address(stun::ATTR_XOR_PEER_ADDRESS, peer_addr);
                indication.add_attribute(stun::ATTR_DATA, buf[..len].to_vec());
                if let Err(e) = self
                    .server_socket
                    .send_to(&indication.encode(), client_addr)
                    .await
                {
                    warn!(client = %client_addr, error = %e, "failed to send data indication to client");
                }
            }
        }
    }

    /// Check if an allocation has a valid (non-expired) permission for a peer IP.
    fn has_permission(alloc: &Allocation, peer_ip: IpAddr) -> bool {
        match alloc.permissions.get(&peer_ip) {
            Some(expiry) => Instant::now() < *expiry,
            None => false,
        }
    }

    /// Expire stale allocations. Called periodically.
    pub async fn expire_allocations(&self) {
        let now = Instant::now();
        let mut allocs = self.allocations.write().await;
        let before = allocs.len();
        allocs.retain(|addr, alloc| {
            if now >= alloc.expires_at {
                info!(client = %addr, relay = %alloc.relay_addr, "allocation expired");
                false
            } else {
                true
            }
        });
        let expired = before - allocs.len();
        if expired > 0 {
            debug!(
                expired = expired,
                remaining = allocs.len(),
                "expired allocations"
            );
        }
    }

    /// Build an error response for a given request.
    fn error_response(&self, request: &Message, code: u16, reason: &str) -> Message {
        let mut resp = Message::new(
            stun::CLASS_ERROR,
            request.msg_type.method,
            request.transaction_id,
        );
        resp.add_error_code(code, reason);
        resp.add_software("cairn-relay");
        resp
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("insufficient capacity: no relay ports available")]
    InsufficientCapacity,
}

// Helper to parse XOR address from raw attribute value (for multiple XOR-PEER-ADDRESS attrs)
impl Message {
    pub fn parse_xor_address_from_value(
        &self,
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> Option<SocketAddr> {
        if value.len() < 8 {
            return None;
        }
        let family = value[1];
        let xport = u16::from_be_bytes([value[2], value[3]]);
        let port = xport ^ (stun::MAGIC_COOKIE >> 16) as u16;
        let cookie_bytes = stun::MAGIC_COOKIE.to_be_bytes();

        match family {
            0x01 => {
                if value.len() < 8 {
                    return None;
                }
                let ip = std::net::Ipv4Addr::new(
                    value[4] ^ cookie_bytes[0],
                    value[5] ^ cookie_bytes[1],
                    value[6] ^ cookie_bytes[2],
                    value[7] ^ cookie_bytes[3],
                );
                Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            }
            0x02 => {
                if value.len() < 20 {
                    return None;
                }
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&cookie_bytes);
                xor_key[4..16].copy_from_slice(transaction_id);
                let mut octets = [0u8; 16];
                for i in 0..16 {
                    octets[i] = value[4 + i] ^ xor_key[i];
                }
                let ip = std::net::Ipv6Addr::from(octets);
                Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            }
            _ => None,
        }
    }
}
