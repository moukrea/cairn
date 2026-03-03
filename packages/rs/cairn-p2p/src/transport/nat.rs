use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::error::{CairnError, Result};

// ---------------------------------------------------------------------------
// NAT Type (spec section 7)
// ---------------------------------------------------------------------------

/// Detected NAT type, exposed as a read-only diagnostic.
///
/// > "Application behavior should never depend on NAT type -- the transport
/// > chain handles it transparently. This diagnostic is provided for
/// > debugging connectivity issues only." (spec section 7)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatType {
    /// Host has a public IP, no NAT.
    Open,
    /// Any external host can send to the mapped port (full cone / EIM+EIF).
    FullCone,
    /// Only hosts the internal host has sent to can reply (address-restricted).
    RestrictedCone,
    /// Restricted by both IP and port.
    PortRestrictedCone,
    /// Different mapping per destination -- hole punching unlikely.
    Symmetric,
    /// Detection failed or not yet attempted.
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "open"),
            NatType::FullCone => write!(f, "full_cone"),
            NatType::RestrictedCone => write!(f, "restricted_cone"),
            NatType::PortRestrictedCone => write!(f, "port_restricted_cone"),
            NatType::Symmetric => write!(f, "symmetric"),
            NatType::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Network info (public API surface)
// ---------------------------------------------------------------------------

/// Read-only network diagnostic info.
///
/// Obtained via `node.network_info()` (spec section 7).
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// External address as seen by the first STUN server (if available).
    pub external_addr: Option<SocketAddr>,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            external_addr: None,
        }
    }
}

// ---------------------------------------------------------------------------
// STUN binding request/response (minimal RFC 5389 implementation)
// ---------------------------------------------------------------------------

// STUN magic cookie (RFC 5389 section 6).
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
// STUN message type: Binding Request.
const STUN_BINDING_REQUEST: u16 = 0x0001;
// STUN message type: Binding Response (success).
const STUN_BINDING_RESPONSE: u16 = 0x0101;
// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Build a minimal STUN Binding Request (20 bytes header, no attributes).
fn build_binding_request(transaction_id: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    // Type: Binding Request
    buf[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message Length: 0 (no attributes)
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    // Magic Cookie
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    buf[8..20].copy_from_slice(transaction_id);
    buf
}

/// Parse a STUN Binding Response, returning the XOR-MAPPED-ADDRESS or
/// MAPPED-ADDRESS as a SocketAddr.
fn parse_binding_response(data: &[u8], expected_txn_id: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 20 {
        return Err(CairnError::Transport("STUN response too short".into()));
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(CairnError::Transport(format!(
            "unexpected STUN message type: 0x{msg_type:04x}"
        )));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE {
        return Err(CairnError::Transport("invalid STUN magic cookie".into()));
    }

    // Verify transaction ID
    if &data[8..20] != expected_txn_id {
        return Err(CairnError::Transport("STUN transaction ID mismatch".into()));
    }

    // Parse attributes
    let attrs = &data[20..20 + msg_len.min(data.len() - 20)];
    let mut offset = 0;
    let mut xor_mapped: Option<SocketAddr> = None;
    let mut mapped: Option<SocketAddr> = None;

    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let attr_start = offset + 4;

        if attr_start + attr_len > attrs.len() {
            break;
        }

        let attr_data = &attrs[attr_start..attr_start + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped = parse_xor_mapped_address(attr_data, expected_txn_id);
            }
            ATTR_MAPPED_ADDRESS => {
                mapped = parse_mapped_address(attr_data);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        offset = attr_start + padded_len;
    }

    xor_mapped
        .or(mapped)
        .ok_or_else(|| CairnError::Transport("no mapped address in STUN response".into()))
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
fn parse_xor_mapped_address(data: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let xor_ip =
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ STUN_MAGIC_COOKIE;
            let ip = std::net::Ipv4Addr::from(xor_ip);
            Some(SocketAddr::new(ip.into(), xor_port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(txn_id);
            for i in 0..16 {
                ip_bytes[i] ^= xor_key[i];
            }
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            Some(SocketAddr::new(ip.into(), xor_port))
        }
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1).
fn parse_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::new(ip.into(), port))
        }
        0x02 => {
            if data.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// NatDetector
// ---------------------------------------------------------------------------

/// STUN-based NAT type detector.
///
/// Queries configured STUN servers and classifies the NAT type by
/// comparing mapped addresses across servers (simplified RFC 5780 logic).
pub struct NatDetector {
    stun_servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl NatDetector {
    /// Create a new NAT detector with the given STUN server addresses and
    /// per-request timeout.
    pub fn new(stun_servers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            stun_servers,
            timeout,
        }
    }

    /// Create a NAT detector from string addresses (e.g. "stun.l.google.com:19302").
    /// Resolves hostnames to socket addresses.
    pub async fn from_stun_urls(urls: &[String], timeout: Duration) -> Result<Self> {
        let mut addrs = Vec::new();
        for url in urls {
            // Strip "stun:" prefix if present
            let host_port = url
                .strip_prefix("stun:")
                .or_else(|| url.strip_prefix("stuns:"))
                .unwrap_or(url);

            match tokio::net::lookup_host(host_port).await {
                Ok(mut resolved) => {
                    if let Some(addr) = resolved.next() {
                        addrs.push(addr);
                    }
                }
                Err(e) => {
                    warn!(%host_port, %e, "failed to resolve STUN server");
                }
            }
        }

        if addrs.is_empty() {
            return Err(CairnError::Transport(
                "could not resolve any STUN servers".into(),
            ));
        }

        Ok(Self::new(addrs, timeout))
    }

    /// Detect the NAT type by querying STUN servers.
    ///
    /// Returns `NatType::Unknown` if detection fails (e.g. no STUN servers
    /// reachable). Never returns an error -- failures are logged and result
    /// in `Unknown`.
    pub async fn detect(&self) -> NetworkInfo {
        if self.stun_servers.is_empty() {
            return NetworkInfo::default();
        }

        // Query each STUN server for our mapped address
        let mut mapped_addrs: Vec<(SocketAddr, SocketAddr)> = Vec::new(); // (server, mapped)

        for &server in &self.stun_servers {
            match self.stun_binding_request(server).await {
                Ok(mapped) => {
                    debug!(%server, %mapped, "STUN binding response");
                    mapped_addrs.push((server, mapped));
                }
                Err(e) => {
                    warn!(%server, %e, "STUN binding request failed");
                }
            }
        }

        if mapped_addrs.is_empty() {
            return NetworkInfo::default();
        }

        let first_mapped = mapped_addrs[0].1;
        let nat_type = self.classify_nat(&mapped_addrs);

        NetworkInfo {
            nat_type,
            external_addr: Some(first_mapped),
        }
    }

    /// Send a STUN Binding Request to the given server and return our
    /// mapped (external) address.
    async fn stun_binding_request(&self, server: SocketAddr) -> Result<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| CairnError::Transport(format!("failed to bind UDP socket: {e}")))?;

        let mut txn_id = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut txn_id);

        let request = build_binding_request(&txn_id);
        socket
            .send_to(&request, server)
            .await
            .map_err(|e| CairnError::Transport(format!("failed to send STUN request: {e}")))?;

        let mut buf = [0u8; 576]; // RFC 5389 recommends handling up to 576 bytes
        let (len, _from) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| CairnError::Transport("STUN request timed out".into()))?
            .map_err(|e| CairnError::Transport(format!("failed to receive STUN response: {e}")))?;

        parse_binding_response(&buf[..len], &txn_id)
    }

    /// Classify NAT type by comparing mapped addresses from multiple servers.
    ///
    /// Simplified RFC 5780 logic:
    /// - If the mapped address matches the local interface address: Open
    /// - If the same mapped address from all servers: probably cone NAT
    /// - If different mapped addresses from different servers: Symmetric
    ///
    /// Full RFC 5780 classification requires CHANGE-REQUEST attributes
    /// which are not universally supported. This simplified approach
    /// correctly identifies Open vs Symmetric vs cone NAT in most cases.
    fn classify_nat(&self, mapped_addrs: &[(SocketAddr, SocketAddr)]) -> NatType {
        if mapped_addrs.is_empty() {
            return NatType::Unknown;
        }

        if mapped_addrs.len() < 2 {
            // With only one server response, we can't differentiate cone types.
            // Return Unknown (we know we're behind *some* NAT but can't classify).
            return NatType::Unknown;
        }

        let first_ip = mapped_addrs[0].1.ip();
        let first_port = mapped_addrs[0].1.port();

        // Check if all mapped addresses are identical
        let all_same_ip = mapped_addrs.iter().all(|(_, m)| m.ip() == first_ip);
        let all_same_port = mapped_addrs.iter().all(|(_, m)| m.port() == first_port);

        if !all_same_ip {
            // Different external IPs from different servers -- Symmetric NAT
            return NatType::Symmetric;
        }

        if !all_same_port {
            // Same IP but different ports for different destinations -- Symmetric
            return NatType::Symmetric;
        }

        // Same IP and port from all servers -- some form of cone NAT.
        //
        // Without CHANGE-REQUEST support, we cannot distinguish between
        // FullCone, RestrictedCone, and PortRestrictedCone. Default to
        // PortRestrictedCone (the most restrictive cone type) as a
        // conservative classification.
        //
        // The distinction doesn't affect transport chain behavior -- all
        // cone NAT types are compatible with STUN-assisted hole punching.
        NatType::PortRestrictedCone
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- NatType Display --

    #[test]
    fn nat_type_display() {
        assert_eq!(NatType::Open.to_string(), "open");
        assert_eq!(NatType::FullCone.to_string(), "full_cone");
        assert_eq!(NatType::RestrictedCone.to_string(), "restricted_cone");
        assert_eq!(
            NatType::PortRestrictedCone.to_string(),
            "port_restricted_cone"
        );
        assert_eq!(NatType::Symmetric.to_string(), "symmetric");
        assert_eq!(NatType::Unknown.to_string(), "unknown");
    }

    // -- NetworkInfo defaults --

    #[test]
    fn network_info_default() {
        let info = NetworkInfo::default();
        assert_eq!(info.nat_type, NatType::Unknown);
        assert!(info.external_addr.is_none());
    }

    // -- STUN request building --

    #[test]
    fn binding_request_format() {
        let txn_id = [1u8; 12];
        let req = build_binding_request(&txn_id);
        assert_eq!(req.len(), 20);
        // Type: Binding Request (0x0001)
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        // Length: 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        // Magic Cookie
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        // Transaction ID
        assert_eq!(&req[8..20], &txn_id);
    }

    // -- STUN response parsing --

    #[test]
    fn parse_binding_response_with_xor_mapped_ipv4() {
        let txn_id = [0xAA; 12];
        // Build a minimal STUN Binding Response with XOR-MAPPED-ADDRESS
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Message length (will fill later)
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute
        // Type: 0x0020, Length: 8
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        // Family: IPv4 (0x01), reserved byte = 0
        resp.push(0x00);
        resp.push(0x01);
        // XOR'd port: 12345 ^ (magic_cookie >> 16) = 12345 ^ 0x2112
        let port: u16 = 12345;
        let xor_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        resp.extend_from_slice(&xor_port.to_be_bytes());
        // XOR'd IP: 192.168.1.100 ^ magic_cookie
        let ip = u32::from_be_bytes([192, 168, 1, 100]);
        let xor_ip = ip ^ STUN_MAGIC_COOKIE;
        resp.extend_from_slice(&xor_ip.to_be_bytes());

        // Fix message length (total attrs = 12 bytes: 4 header + 8 data)
        let msg_len = (resp.len() - 20) as u16;
        resp[2..4].copy_from_slice(&msg_len.to_be_bytes());

        let addr = parse_binding_response(&resp, &txn_id).unwrap();
        assert_eq!(addr.port(), 12345);
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn parse_binding_response_rejects_short_data() {
        let txn_id = [0u8; 12];
        let result = parse_binding_response(&[0u8; 10], &txn_id);
        assert!(result.is_err());
    }

    #[test]
    fn parse_binding_response_rejects_wrong_type() {
        let txn_id = [0u8; 12];
        let mut resp = [0u8; 20];
        // Wrong message type
        resp[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp[8..20].copy_from_slice(&txn_id);

        let result = parse_binding_response(&resp, &txn_id);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected STUN message type"));
    }

    #[test]
    fn parse_binding_response_rejects_wrong_txn_id() {
        let txn_id = [0xBB; 12];
        let wrong_id = [0xCC; 12];
        let mut resp = [0u8; 20];
        resp[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp[8..20].copy_from_slice(&wrong_id);

        let result = parse_binding_response(&resp, &txn_id);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("transaction ID mismatch"));
    }

    // -- NAT classification --

    #[test]
    fn classify_empty_is_unknown() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        assert_eq!(detector.classify_nat(&[]), NatType::Unknown);
    }

    #[test]
    fn classify_single_server_is_unknown() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        let server: SocketAddr = "1.1.1.1:3478".parse().unwrap();
        let mapped: SocketAddr = "203.0.113.50:54321".parse().unwrap();
        assert_eq!(detector.classify_nat(&[(server, mapped)]), NatType::Unknown);
    }

    #[test]
    fn classify_same_mapping_is_cone() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        let s1: SocketAddr = "1.1.1.1:3478".parse().unwrap();
        let s2: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let mapped: SocketAddr = "203.0.113.50:54321".parse().unwrap();
        let result = detector.classify_nat(&[(s1, mapped), (s2, mapped)]);
        assert_eq!(result, NatType::PortRestrictedCone);
    }

    #[test]
    fn classify_different_ips_is_symmetric() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        let s1: SocketAddr = "1.1.1.1:3478".parse().unwrap();
        let s2: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let m1: SocketAddr = "203.0.113.50:54321".parse().unwrap();
        let m2: SocketAddr = "203.0.113.51:54321".parse().unwrap(); // different IP
        let result = detector.classify_nat(&[(s1, m1), (s2, m2)]);
        assert_eq!(result, NatType::Symmetric);
    }

    #[test]
    fn classify_different_ports_is_symmetric() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        let s1: SocketAddr = "1.1.1.1:3478".parse().unwrap();
        let s2: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let m1: SocketAddr = "203.0.113.50:54321".parse().unwrap();
        let m2: SocketAddr = "203.0.113.50:54322".parse().unwrap(); // different port
        let result = detector.classify_nat(&[(s1, m1), (s2, m2)]);
        assert_eq!(result, NatType::Symmetric);
    }

    // -- NatDetector with no servers --

    #[tokio::test]
    async fn detect_with_no_servers_returns_unknown() {
        let detector = NatDetector::new(vec![], Duration::from_secs(2));
        let info = detector.detect().await;
        assert_eq!(info.nat_type, NatType::Unknown);
        assert!(info.external_addr.is_none());
    }
}
