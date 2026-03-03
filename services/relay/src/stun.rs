//! STUN message parsing and serialization per RFC 8489.
//!
//! A STUN message has a 20-byte header:
//!   - 2 bytes: message type (class + method)
//!   - 2 bytes: message length (excluding 20-byte header)
//!   - 4 bytes: magic cookie (0x2112A442)
//!   - 12 bytes: transaction ID

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_SIZE: usize = 20;
pub const FINGERPRINT_XOR: u32 = 0x5354_554E;

// STUN message classes
pub const CLASS_REQUEST: u16 = 0x0000;
pub const CLASS_INDICATION: u16 = 0x0010;
pub const CLASS_SUCCESS: u16 = 0x0100;
pub const CLASS_ERROR: u16 = 0x0110;

// STUN/TURN methods
pub const METHOD_BINDING: u16 = 0x0001;
pub const METHOD_ALLOCATE: u16 = 0x0003;
pub const METHOD_REFRESH: u16 = 0x0004;
pub const METHOD_SEND: u16 = 0x0006;
pub const METHOD_DATA: u16 = 0x0007;
pub const METHOD_CREATE_PERMISSION: u16 = 0x0008;
pub const METHOD_CHANNEL_BIND: u16 = 0x0009;

// STUN attribute types
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

// TURN-specific attribute types
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;

// Error codes
pub const ERR_BAD_REQUEST: u16 = 400;
pub const ERR_UNAUTHORIZED: u16 = 401;
pub const ERR_FORBIDDEN: u16 = 403;
pub const ERR_UNKNOWN_ATTRIBUTE: u16 = 420;
pub const ERR_ALLOCATION_MISMATCH: u16 = 437;
pub const ERR_STALE_NONCE: u16 = 438;
pub const ERR_INSUFFICIENT_CAPACITY: u16 = 508;

/// Transport protocol identifiers for REQUESTED-TRANSPORT attribute.
pub const TRANSPORT_UDP: u8 = 17;

/// STUN message type encodes both class and method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageType {
    pub class: u16,
    pub method: u16,
}

impl MessageType {
    pub fn new(class: u16, method: u16) -> Self {
        Self { class, method }
    }

    /// Encode class and method into the 14-bit STUN message type field.
    /// Bits: M11-M7 | C1 | M6-M4 | C0 | M3-M0
    pub fn to_raw(self) -> u16 {
        let m = self.method;
        let c = self.class;
        let m0_3 = m & 0x000F;
        let m4_6 = (m & 0x0070) >> 4;
        let m7_11 = (m & 0x0F80) >> 7;
        let c0 = (c & 0x0010) >> 4;
        let c1 = (c & 0x0100) >> 8;
        m0_3 | (c0 << 4) | (m4_6 << 5) | (c1 << 8) | (m7_11 << 9)
    }

    /// Decode the 14-bit STUN message type field into class and method.
    pub fn from_raw(raw: u16) -> Self {
        let m0_3 = raw & 0x000F;
        let c0 = (raw >> 4) & 0x0001;
        let m4_6 = (raw >> 5) & 0x0007;
        let c1 = (raw >> 8) & 0x0001;
        let m7_11 = (raw >> 9) & 0x001F;
        let method = m0_3 | (m4_6 << 4) | (m7_11 << 7);
        let class = (c0 << 4) | (c1 << 8);
        Self { class, method }
    }
}

/// A STUN attribute (type-length-value).
#[derive(Debug, Clone)]
pub struct Attribute {
    pub typ: u16,
    pub value: Vec<u8>,
}

/// A parsed STUN message.
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<Attribute>,
}

impl Message {
    pub fn new(class: u16, method: u16, transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type: MessageType::new(class, method),
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Parse a STUN message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < HEADER_SIZE {
            return Err(StunError::TooShort);
        }

        // First two bits must be 0 (STUN messages)
        if data[0] & 0xC0 != 0 {
            return Err(StunError::NotStun);
        }

        let raw_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_type = MessageType::from_raw(raw_type);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadMagicCookie);
        }

        if !msg_len.is_multiple_of(4) {
            return Err(StunError::BadAlignment);
        }

        if data.len() < HEADER_SIZE + msg_len {
            return Err(StunError::TooShort);
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        let mut attributes = Vec::new();
        let mut pos = HEADER_SIZE;
        let end = HEADER_SIZE + msg_len;

        while pos + 4 <= end {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + attr_len > end {
                return Err(StunError::TooShort);
            }

            let value = data[pos..pos + attr_len].to_vec();
            attributes.push(Attribute {
                typ: attr_type,
                value,
            });

            // Pad to 4-byte boundary
            pos += (attr_len + 3) & !3;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Encode the message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut attrs_buf = Vec::new();
        for attr in &self.attributes {
            attrs_buf.extend_from_slice(&attr.typ.to_be_bytes());
            attrs_buf.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            attrs_buf.extend_from_slice(&attr.value);
            // Pad to 4-byte boundary
            let pad = (4 - (attr.value.len() % 4)) % 4;
            attrs_buf.extend(std::iter::repeat_n(0u8, pad));
        }

        let mut buf = Vec::with_capacity(HEADER_SIZE + attrs_buf.len());
        buf.extend_from_slice(&self.msg_type.to_raw().to_be_bytes());
        buf.extend_from_slice(&(attrs_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.transaction_id);
        buf.extend(attrs_buf);

        buf
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, typ: u16, value: Vec<u8>) {
        self.attributes.push(Attribute { typ, value });
    }

    /// Find the first attribute of a given type.
    pub fn get_attribute(&self, typ: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.typ == typ)
    }

    /// Add XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS attribute.
    pub fn add_xor_address(&mut self, attr_type: u16, addr: SocketAddr) {
        let value = encode_xor_address(addr, &self.transaction_id);
        self.add_attribute(attr_type, value);
    }

    /// Parse an XOR address attribute (XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS).
    pub fn parse_xor_address(&self, attr_type: u16) -> Option<SocketAddr> {
        let attr = self.get_attribute(attr_type)?;
        decode_xor_address(&attr.value, &self.transaction_id)
    }

    /// Add a LIFETIME attribute.
    pub fn add_lifetime(&mut self, seconds: u32) {
        self.add_attribute(ATTR_LIFETIME, seconds.to_be_bytes().to_vec());
    }

    /// Parse LIFETIME attribute.
    pub fn parse_lifetime(&self) -> Option<u32> {
        let attr = self.get_attribute(ATTR_LIFETIME)?;
        if attr.value.len() >= 4 {
            Some(u32::from_be_bytes([
                attr.value[0],
                attr.value[1],
                attr.value[2],
                attr.value[3],
            ]))
        } else {
            None
        }
    }

    /// Add an ERROR-CODE attribute.
    pub fn add_error_code(&mut self, code: u16, reason: &str) {
        let class = (code / 100) as u8;
        let number = (code % 100) as u8;
        let mut value = vec![0u8, 0u8, class, number];
        value.extend_from_slice(reason.as_bytes());
        self.add_attribute(ATTR_ERROR_CODE, value);
    }

    /// Add USERNAME attribute.
    pub fn add_username(&mut self, username: &str) {
        self.add_attribute(ATTR_USERNAME, username.as_bytes().to_vec());
    }

    /// Parse USERNAME attribute.
    pub fn parse_username(&self) -> Option<String> {
        let attr = self.get_attribute(ATTR_USERNAME)?;
        String::from_utf8(attr.value.clone()).ok()
    }

    /// Add REALM attribute.
    pub fn add_realm(&mut self, realm: &str) {
        self.add_attribute(ATTR_REALM, realm.as_bytes().to_vec());
    }

    /// Parse REALM attribute.
    pub fn parse_realm(&self) -> Option<String> {
        let attr = self.get_attribute(ATTR_REALM)?;
        String::from_utf8(attr.value.clone()).ok()
    }

    /// Add NONCE attribute.
    pub fn add_nonce(&mut self, nonce: &str) {
        self.add_attribute(ATTR_NONCE, nonce.as_bytes().to_vec());
    }

    /// Parse NONCE attribute.
    pub fn parse_nonce(&self) -> Option<String> {
        let attr = self.get_attribute(ATTR_NONCE)?;
        String::from_utf8(attr.value.clone()).ok()
    }

    /// Parse REQUESTED-TRANSPORT attribute.
    pub fn parse_requested_transport(&self) -> Option<u8> {
        let attr = self.get_attribute(ATTR_REQUESTED_TRANSPORT)?;
        if attr.value.len() >= 4 {
            Some(attr.value[0])
        } else {
            None
        }
    }

    /// Parse CHANNEL-NUMBER attribute.
    pub fn parse_channel_number(&self) -> Option<u16> {
        let attr = self.get_attribute(ATTR_CHANNEL_NUMBER)?;
        if attr.value.len() >= 4 {
            Some(u16::from_be_bytes([attr.value[0], attr.value[1]]))
        } else {
            None
        }
    }

    /// Parse DATA attribute.
    pub fn parse_data(&self) -> Option<&[u8]> {
        let attr = self.get_attribute(ATTR_DATA)?;
        Some(&attr.value)
    }

    /// Add MESSAGE-INTEGRITY attribute using HMAC-SHA1.
    pub fn add_message_integrity(&mut self, key: &[u8]) {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        // Encode the message so far, adjusting the length to include MESSAGE-INTEGRITY (24 bytes).
        let mut buf = self.encode();
        let new_len = buf.len() - HEADER_SIZE + 24; // +4 attr header + 20 HMAC
        buf[2..4].copy_from_slice(&(new_len as u16).to_be_bytes());

        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
        mac.update(&buf);
        let result = mac.finalize().into_bytes();

        self.add_attribute(ATTR_MESSAGE_INTEGRITY, result.to_vec());
    }

    /// Verify MESSAGE-INTEGRITY attribute.
    pub fn verify_message_integrity(&self, key: &[u8], raw: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let integrity_attr = match self.get_attribute(ATTR_MESSAGE_INTEGRITY) {
            Some(a) => a,
            None => return false,
        };

        if integrity_attr.value.len() != 20 {
            return false;
        }

        // Find the position of MESSAGE-INTEGRITY attribute in the raw data.
        // We need to compute HMAC over everything up to (but not including) MESSAGE-INTEGRITY,
        // with the message length adjusted to include MESSAGE-INTEGRITY.
        let mut pos = HEADER_SIZE;
        let mut integrity_offset = None;
        while pos + 4 <= raw.len() {
            let attr_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            let attr_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
            if attr_type == ATTR_MESSAGE_INTEGRITY {
                integrity_offset = Some(pos);
                break;
            }
            pos += 4 + ((attr_len + 3) & !3);
        }

        let integrity_offset = match integrity_offset {
            Some(o) => o,
            None => return false,
        };

        // Build the data to HMAC: header (with adjusted length) + attributes before MESSAGE-INTEGRITY
        let adjusted_len = (integrity_offset - HEADER_SIZE + 24) as u16; // +24 for MI attr itself
        let mut buf = raw[..integrity_offset].to_vec();
        buf[2..4].copy_from_slice(&adjusted_len.to_be_bytes());

        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
        mac.update(&buf);

        mac.verify_slice(&integrity_attr.value).is_ok()
    }

    /// Add SOFTWARE attribute.
    pub fn add_software(&mut self, software: &str) {
        self.add_attribute(ATTR_SOFTWARE, software.as_bytes().to_vec());
    }
}

/// Encode a socket address as XOR-MAPPED-ADDRESS value.
fn encode_xor_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0); // reserved

    let xport = (addr.port()) ^ (MAGIC_COOKIE >> 16) as u16;

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.push(0x01); // family: IPv4
            buf.extend_from_slice(&xport.to_be_bytes());
            let octets = ipv4.octets();
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            buf.push(octets[0] ^ cookie_bytes[0]);
            buf.push(octets[1] ^ cookie_bytes[1]);
            buf.push(octets[2] ^ cookie_bytes[2]);
            buf.push(octets[3] ^ cookie_bytes[3]);
        }
        IpAddr::V6(ipv6) => {
            buf.push(0x02); // family: IPv6
            buf.extend_from_slice(&xport.to_be_bytes());
            let octets = ipv6.octets();
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..16].copy_from_slice(transaction_id);
            for i in 0..16 {
                buf.push(octets[i] ^ xor_key[i]);
            }
        }
    }

    buf
}

/// Decode an XOR-MAPPED-ADDRESS value to a socket address.
fn decode_xor_address(data: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let ip = Ipv4Addr::new(
                data[4] ^ cookie_bytes[0],
                data[5] ^ cookie_bytes[1],
                data[6] ^ cookie_bytes[2],
                data[7] ^ cookie_bytes[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..16].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = data[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("message too short")]
    TooShort,
    #[error("not a STUN message")]
    NotStun,
    #[error("bad magic cookie")]
    BadMagicCookie,
    #[error("bad alignment")]
    BadAlignment,
}

/// Check if a buffer starts with a ChannelData message (first two bits are 01).
/// ChannelData: 2-byte channel number (0x4000-0x7FFF), 2-byte length, then data.
pub fn is_channel_data(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    (0x4000..=0x7FFF).contains(&channel)
}

/// Parse a ChannelData message. Returns (channel_number, payload).
pub fn parse_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return None;
    }
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + length {
        return None;
    }
    Some((channel, &data[4..4 + length]))
}

/// Encode a ChannelData message.
pub fn encode_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&channel.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    // Pad to 4-byte boundary for UDP
    let pad = (4 - (payload.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        let mt = MessageType::new(CLASS_REQUEST, METHOD_ALLOCATE);
        let raw = mt.to_raw();
        let decoded = MessageType::from_raw(raw);
        assert_eq!(decoded.class, CLASS_REQUEST);
        assert_eq!(decoded.method, METHOD_ALLOCATE);
    }

    #[test]
    fn test_message_encode_decode() {
        let tid = [1u8; 12];
        let mut msg = Message::new(CLASS_REQUEST, METHOD_BINDING, tid);
        msg.add_lifetime(600);
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type.method, METHOD_BINDING);
        assert_eq!(decoded.msg_type.class, CLASS_REQUEST);
        assert_eq!(decoded.transaction_id, tid);
        assert_eq!(decoded.parse_lifetime(), Some(600));
    }

    #[test]
    fn test_xor_address_roundtrip() {
        let tid = [0xAB; 12];
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let mut msg = Message::new(CLASS_SUCCESS, METHOD_BINDING, tid);
        msg.add_xor_address(ATTR_XOR_MAPPED_ADDRESS, addr);
        let parsed = msg.parse_xor_address(ATTR_XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_channel_data_roundtrip() {
        let channel = 0x4001u16;
        let payload = b"hello world";
        let encoded = encode_channel_data(channel, payload);
        assert!(is_channel_data(&encoded));
        let (ch, data) = parse_channel_data(&encoded).unwrap();
        assert_eq!(ch, channel);
        assert_eq!(data, payload);
    }
}
