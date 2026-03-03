<?php

declare(strict_types=1);

namespace Cairn\Protocol;

/**
 * Message type constants for the cairn wire protocol.
 *
 * All constants match the Rust reference implementation in
 * packages/rs/cairn-p2p/src/protocol/message_types.rs.
 */
final class MessageType
{
    // Version negotiation
    public const VERSION_NEGOTIATE = 0x0001;

    // Hello / handshake (0x01xx)
    public const HELLO = 0x0100;
    public const HELLO_ACK = 0x0101;

    // Pairing (0x01xx)
    public const PAKE_INIT = 0x0102;
    public const PAIR_REQUEST = 0x0103;
    public const PAIR_CONFIRM = 0x0104;
    public const PAIR_REJECT = 0x0105;
    public const PAIR_REVOKE = 0x0106;

    // Session (0x02xx)
    public const SESSION_RESUME = 0x0200;
    public const SESSION_RESUME_ACK = 0x0201;
    public const SESSION_EXPIRED = 0x0202;
    public const SESSION_CLOSE = 0x0203;

    // Data (0x03xx)
    public const DATA_MESSAGE = 0x0300;
    public const DATA_ACK = 0x0301;
    public const DATA_NACK = 0x0302;

    // Control (0x04xx)
    public const HEARTBEAT = 0x0400;
    public const HEARTBEAT_ACK = 0x0401;
    public const TRANSPORT_MIGRATE = 0x0402;
    public const TRANSPORT_MIGRATE_ACK = 0x0403;

    // Mesh (0x05xx)
    public const ROUTE_REQUEST = 0x0500;
    public const ROUTE_RESPONSE = 0x0501;
    public const RELAY_DATA = 0x0502;
    public const RELAY_ACK = 0x0503;

    // Rendezvous (0x06xx)
    public const RENDEZVOUS_PUBLISH = 0x0600;
    public const RENDEZVOUS_QUERY = 0x0601;
    public const RENDEZVOUS_RESPONSE = 0x0602;

    // Forward (0x07xx)
    public const FORWARD_REQUEST = 0x0700;
    public const FORWARD_ACK = 0x0701;
    public const FORWARD_DELIVER = 0x0702;
    public const FORWARD_PURGE = 0x0703;

    // Reserved ranges
    public const CAIRN_RESERVED_END = 0xEFFF;
    public const APP_EXTENSION_START = 0xF000;
    public const APP_EXTENSION_END = 0xFFFF;

    private function __construct()
    {
    }

    /**
     * Returns the category name for a given message type code.
     *
     * Matches the Rust message_category() function exactly.
     */
    public static function category(int $msgType): string
    {
        if ($msgType === 0x0001) {
            return 'version';
        }

        return match (true) {
            $msgType >= 0x0100 && $msgType <= 0x01FF => 'pairing',
            $msgType >= 0x0200 && $msgType <= 0x02FF => 'session',
            $msgType >= 0x0300 && $msgType <= 0x03FF => 'data',
            $msgType >= 0x0400 && $msgType <= 0x04FF => 'control',
            $msgType >= 0x0500 && $msgType <= 0x05FF => 'mesh',
            $msgType >= 0x0600 && $msgType <= 0x06FF => 'rendezvous',
            $msgType >= 0x0700 && $msgType <= 0x07FF => 'forward',
            $msgType >= 0xF000 && $msgType <= 0xFFFF => 'application',
            default => 'reserved',
        };
    }
}
