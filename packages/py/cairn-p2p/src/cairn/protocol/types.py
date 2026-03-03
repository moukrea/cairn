"""Message type constants matching the cairn wire protocol registry."""

# Version negotiation
VERSION_NEGOTIATE: int = 0x0001

# Pairing (0x01xx)
PAIR_REQUEST: int = 0x0100
PAIR_CHALLENGE: int = 0x0101
PAIR_RESPONSE: int = 0x0102
PAIR_CONFIRM: int = 0x0103
PAIR_REJECT: int = 0x0104
PAIR_REVOKE: int = 0x0105

# Session (0x02xx)
SESSION_RESUME: int = 0x0200
SESSION_RESUME_ACK: int = 0x0201
SESSION_EXPIRED: int = 0x0202
SESSION_CLOSE: int = 0x0203

# Data (0x03xx)
DATA_MESSAGE: int = 0x0300
DATA_ACK: int = 0x0301
DATA_NACK: int = 0x0302

# Control (0x04xx)
HEARTBEAT: int = 0x0400
HEARTBEAT_ACK: int = 0x0401
TRANSPORT_MIGRATE: int = 0x0402
TRANSPORT_MIGRATE_ACK: int = 0x0403

# Mesh (0x05xx)
ROUTE_REQUEST: int = 0x0500
ROUTE_RESPONSE: int = 0x0501
RELAY_DATA: int = 0x0502
RELAY_ACK: int = 0x0503

# Rendezvous (0x06xx)
RENDEZVOUS_PUBLISH: int = 0x0600
RENDEZVOUS_QUERY: int = 0x0601
RENDEZVOUS_RESPONSE: int = 0x0602

# Forward (0x07xx)
FORWARD_REQUEST: int = 0x0700
FORWARD_ACK: int = 0x0701
FORWARD_DELIVER: int = 0x0702
FORWARD_PURGE: int = 0x0703

# Reserved ranges
CAIRN_RESERVED_START: int = 0x0100
CAIRN_RESERVED_END: int = 0xEFFF
APP_EXTENSION_START: int = 0xF000
APP_EXTENSION_END: int = 0xFFFF


def message_category(msg_type: int) -> str:
    """Return the category name for a given message type code."""
    if msg_type == 0x0001:
        return "version"
    if 0x0100 <= msg_type <= 0x01FF:
        return "pairing"
    if 0x0200 <= msg_type <= 0x02FF:
        return "session"
    if 0x0300 <= msg_type <= 0x03FF:
        return "data"
    if 0x0400 <= msg_type <= 0x04FF:
        return "control"
    if 0x0500 <= msg_type <= 0x05FF:
        return "mesh"
    if 0x0600 <= msg_type <= 0x06FF:
        return "rendezvous"
    if 0x0700 <= msg_type <= 0x07FF:
        return "forward"
    if 0xF000 <= msg_type <= 0xFFFF:
        return "application"
    return "reserved"
