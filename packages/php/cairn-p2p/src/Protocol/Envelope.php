<?php

declare(strict_types=1);

namespace Cairn\Protocol;

use Cairn\Error\CairnException;
use Ramsey\Uuid\Uuid;

/**
 * Wire-level message envelope for all cairn protocol messages.
 *
 * Serialized as a CBOR map with integer keys (0-5) for compactness.
 * Matches the Rust MessageEnvelope in packages/rs/cairn-p2p/src/protocol/envelope.rs.
 */
final class Envelope
{
    /**
     * @param int $version Protocol version identifier (uint8). Initial version is 1.
     * @param int $messageType Message type code (uint16) from the message type registry.
     * @param string $msgId UUID v7 message ID (16 bytes), timestamp-ordered.
     * @param string|null $sessionId Session ID (32 bytes). Null before session establishment.
     * @param string $payload Type-specific CBOR-encoded payload.
     * @param string|null $authTag HMAC or AEAD authentication tag. Null before key establishment.
     */
    public function __construct(
        public readonly int $version,
        public readonly int $messageType,
        public readonly string $msgId,
        public readonly ?string $sessionId,
        public readonly string $payload,
        public readonly ?string $authTag,
    ) {
    }

    /**
     * Generate a new UUID v7 message ID as a 16-byte binary string.
     */
    public static function newMsgId(): string
    {
        return Uuid::uuid7()->getBytes();
    }

    /**
     * Encode this envelope to CBOR bytes.
     *
     * @throws CairnException
     */
    public function encode(): string
    {
        return $this->encodeToCbor();
    }

    /**
     * Encode this envelope to deterministic CBOR (RFC 8949 section 4.2).
     *
     * Keys are sorted by integer value and all values use their shortest
     * encoding. Used when the output will be input to a signature or HMAC.
     *
     * Our custom CBOR encoder always produces deterministic output, so this
     * is identical to encode().
     *
     * @throws CairnException
     */
    public function encodeDeterministic(): string
    {
        return $this->encodeToCbor();
    }

    /**
     * Decode an Envelope from CBOR bytes.
     *
     * @throws CairnException
     */
    public static function decode(string $bytes): self
    {
        try {
            $map = Cbor::decode($bytes);
        } catch (CairnException $e) {
            throw new CairnException('CBOR decode error: ' . $e->getMessage(), 0, $e);
        }

        if (!is_array($map)) {
            throw new CairnException('CBOR decode error: expected map, got ' . get_debug_type($map));
        }

        /** @var array<int|string, mixed> $map */

        if (!array_key_exists(0, $map)) {
            throw new CairnException('CBOR decode error: missing field version (key 0)');
        }
        if (!is_int($map[0])) {
            throw new CairnException('CBOR decode error: version must be an integer');
        }

        if (!array_key_exists(1, $map)) {
            throw new CairnException('CBOR decode error: missing field msg_type (key 1)');
        }
        if (!is_int($map[1])) {
            throw new CairnException('CBOR decode error: msg_type must be an integer');
        }

        if (!array_key_exists(2, $map)) {
            throw new CairnException('CBOR decode error: missing field msg_id (key 2)');
        }
        if (!is_string($map[2]) || strlen($map[2]) !== 16) {
            throw new CairnException('CBOR decode error: msg_id must be 16 bytes');
        }

        $sessionId = null;
        if (array_key_exists(3, $map)) {
            if (!is_string($map[3]) || strlen($map[3]) !== 32) {
                throw new CairnException('CBOR decode error: session_id must be 32 bytes');
            }
            $sessionId = $map[3];
        }

        if (!array_key_exists(4, $map)) {
            throw new CairnException('CBOR decode error: missing field payload (key 4)');
        }
        if (!is_string($map[4])) {
            throw new CairnException('CBOR decode error: payload must be a byte string');
        }

        $authTag = null;
        if (array_key_exists(5, $map)) {
            if (!is_string($map[5])) {
                throw new CairnException('CBOR decode error: auth_tag must be a byte string');
            }
            $authTag = $map[5];
        }

        return new self(
            version: $map[0],
            messageType: $map[1],
            msgId: $map[2],
            sessionId: $sessionId,
            payload: $map[4],
            authTag: $authTag,
        );
    }

    /**
     * Encode the envelope as a CBOR map with integer keys 0-5.
     *
     * Keys are emitted in ascending order. Optional fields (sessionId, authTag)
     * are omitted when null. Our Cbor encoder handles deterministic key sorting.
     */
    private function encodeToCbor(): string
    {
        $map = [
            0 => $this->version,
            1 => $this->messageType,
            2 => $this->msgId,
        ];

        if ($this->sessionId !== null) {
            $map[3] = $this->sessionId;
        }

        $map[4] = $this->payload;

        if ($this->authTag !== null) {
            $map[5] = $this->authTag;
        }

        return Cbor::encode($map);
    }
}
