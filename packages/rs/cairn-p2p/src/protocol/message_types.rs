// Pairing (0x01xx)
pub const PAIR_REQUEST: u16 = 0x0100;
pub const PAIR_CHALLENGE: u16 = 0x0101;
pub const PAIR_RESPONSE: u16 = 0x0102;
pub const PAIR_CONFIRM: u16 = 0x0103;
pub const PAIR_REJECT: u16 = 0x0104;
pub const PAIR_REVOKE: u16 = 0x0105;

// Handshake (0x01Ex) — Noise XX over transport
pub const HANDSHAKE_INIT: u16 = 0x01E0;
pub const HANDSHAKE_RESPONSE: u16 = 0x01E1;
pub const HANDSHAKE_FINISH: u16 = 0x01E2;
pub const HANDSHAKE_ACK: u16 = 0x01E3;

// Session (0x02xx)
pub const SESSION_RESUME: u16 = 0x0200;
pub const SESSION_RESUME_ACK: u16 = 0x0201;
pub const SESSION_EXPIRED: u16 = 0x0202;
pub const SESSION_CLOSE: u16 = 0x0203;

// Data (0x03xx)
pub const DATA_MESSAGE: u16 = 0x0300;
pub const DATA_ACK: u16 = 0x0301;
pub const DATA_NACK: u16 = 0x0302;

// Control (0x04xx)
pub const HEARTBEAT: u16 = 0x0400;
pub const HEARTBEAT_ACK: u16 = 0x0401;
pub const TRANSPORT_MIGRATE: u16 = 0x0402;
pub const TRANSPORT_MIGRATE_ACK: u16 = 0x0403;

// Mesh (0x05xx)
pub const ROUTE_REQUEST: u16 = 0x0500;
pub const ROUTE_RESPONSE: u16 = 0x0501;
pub const RELAY_DATA: u16 = 0x0502;
pub const RELAY_ACK: u16 = 0x0503;

// Rendezvous (0x06xx)
pub const RENDEZVOUS_PUBLISH: u16 = 0x0600;
pub const RENDEZVOUS_QUERY: u16 = 0x0601;
pub const RENDEZVOUS_RESPONSE: u16 = 0x0602;

// Forward (0x07xx)
pub const FORWARD_REQUEST: u16 = 0x0700;
pub const FORWARD_ACK: u16 = 0x0701;
pub const FORWARD_DELIVER: u16 = 0x0702;
pub const FORWARD_PURGE: u16 = 0x0703;

// Version negotiation
pub const VERSION_NEGOTIATE: u16 = 0x0001;

// Reserved ranges
pub const CAIRN_RESERVED_START: u16 = 0x0100;
pub const CAIRN_RESERVED_END: u16 = 0xEFFF;
pub const APP_EXTENSION_START: u16 = 0xF000;
pub const APP_EXTENSION_END: u16 = 0xFFFF;

/// Returns the category name for a given message type code.
pub fn message_category(msg_type: u16) -> &'static str {
    match msg_type {
        0x0001 => "version",
        0x0100..=0x01FF => "pairing",
        0x0200..=0x02FF => "session",
        0x0300..=0x03FF => "data",
        0x0400..=0x04FF => "control",
        0x0500..=0x05FF => "mesh",
        0x0600..=0x06FF => "rendezvous",
        0x0700..=0x07FF => "forward",
        0x0800..=0xEFFF => "reserved",
        APP_EXTENSION_START..=APP_EXTENSION_END => "application",
        _ => "reserved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_category() {
        assert_eq!(message_category(VERSION_NEGOTIATE), "version");
        assert_eq!(message_category(PAIR_REQUEST), "pairing");
        assert_eq!(message_category(PAIR_REVOKE), "pairing");
        assert_eq!(message_category(SESSION_RESUME), "session");
        assert_eq!(message_category(SESSION_CLOSE), "session");
        assert_eq!(message_category(DATA_MESSAGE), "data");
        assert_eq!(message_category(DATA_NACK), "data");
        assert_eq!(message_category(HEARTBEAT), "control");
        assert_eq!(message_category(TRANSPORT_MIGRATE_ACK), "control");
        assert_eq!(message_category(ROUTE_REQUEST), "mesh");
        assert_eq!(message_category(RELAY_ACK), "mesh");
        assert_eq!(message_category(RENDEZVOUS_PUBLISH), "rendezvous");
        assert_eq!(message_category(RENDEZVOUS_RESPONSE), "rendezvous");
        assert_eq!(message_category(FORWARD_REQUEST), "forward");
        assert_eq!(message_category(FORWARD_PURGE), "forward");
        assert_eq!(message_category(0xF000), "application");
        assert_eq!(message_category(0xFFFF), "application");
        assert_eq!(message_category(0x0800), "reserved");
    }
}
