<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Protocol\Cbor;

/**
 * A connection hint for peer discovery (e.g., rendezvous server address, direct IP).
 */
final class ConnectionHint
{
    public function __construct(
        public readonly string $hintType,
        public readonly string $value,
    ) {
    }
}

/**
 * The data exchanged during pairing initiation.
 *
 * Contains everything a peer needs to bootstrap a connection and PAKE handshake.
 * Serialized as CBOR with compact integer keys matching the Rust implementation.
 *
 * Key mapping: 0=peer_id, 1=nonce, 2=pake_credential, 3=hints, 4=created_at, 5=expires_at
 */
final class PairingPayload
{
    /**
     * @param PeerId $peerId Peer identity
     * @param string $nonce 16-byte one-time nonce
     * @param string $pakeCredential PAKE credential bytes
     * @param list<ConnectionHint>|null $connectionHints Optional connection hints
     * @param int $createdAt Unix timestamp of creation
     * @param int $expiresAt Unix timestamp of expiry
     */
    public function __construct(
        public readonly PeerId $peerId,
        public readonly string $nonce,
        public readonly string $pakeCredential,
        public readonly ?array $connectionHints,
        public readonly int $createdAt,
        public readonly int $expiresAt,
    ) {
    }

    /**
     * Create a new PairingPayload with auto-generated nonce, timestamps, and no hints.
     *
     * @param PeerId $peerId Peer identity
     * @param string $pakeCredential PAKE credential bytes
     * @param int $ttlSeconds Time-to-live in seconds (default: 300)
     * @return self
     */
    public static function create(
        PeerId $peerId,
        string $pakeCredential,
        int $ttlSeconds = 300,
    ): self {
        $now = time();
        return new self(
            peerId: $peerId,
            nonce: random_bytes(16),
            pakeCredential: $pakeCredential,
            connectionHints: null,
            createdAt: $now,
            expiresAt: $now + $ttlSeconds,
        );
    }

    /**
     * Check whether this payload has expired.
     */
    public function isExpired(?int $nowUnix = null): bool
    {
        $now = $nowUnix ?? time();
        return $now > $this->expiresAt;
    }

    /**
     * Serialize to CBOR using compact integer keys.
     */
    public function toCbor(): string
    {
        // Build the CBOR-encoded entries in key order (0-5)
        $entries = '';
        $count = 0;

        // 0: peer_id (bytes)
        $entries .= Cbor::encode(0) . Cbor::encode($this->peerId->asBytes());
        $count++;

        // 1: nonce (bytes)
        $entries .= Cbor::encode(1) . Cbor::encode($this->nonce);
        $count++;

        // 2: pake_credential (bytes)
        $entries .= Cbor::encode(2) . Cbor::encode($this->pakeCredential);
        $count++;

        // 3: hints (optional array of [text, text])
        if ($this->connectionHints !== null) {
            $hints = [];
            foreach ($this->connectionHints as $hint) {
                $hints[] = [$hint->hintType, $hint->value];
            }
            $entries .= Cbor::encode(3) . self::encodeHintsArray($hints);
            $count++;
        }

        // 4: created_at (unsigned int)
        $entries .= Cbor::encode(4) . Cbor::encode($this->createdAt);
        $count++;

        // 5: expires_at (unsigned int)
        $entries .= Cbor::encode(5) . Cbor::encode($this->expiresAt);
        $count++;

        return self::encodeCborMapHeader($count) . $entries;
    }

    /**
     * Deserialize from CBOR with compact integer keys.
     *
     * @throws CairnException
     */
    public static function fromCbor(string $data): self
    {
        /** @var array<int|string, mixed> $map */
        $map = Cbor::decode($data);

        if (!is_array($map)) {
            throw new CairnException('pairing payload: expected CBOR map');
        }

        if (!isset($map[0]) || !is_string($map[0])) {
            throw new CairnException('pairing payload: missing or invalid peer_id');
        }
        $peerId = PeerId::fromBytes($map[0]);

        if (!isset($map[1]) || !is_string($map[1])) {
            throw new CairnException('pairing payload: missing or invalid nonce');
        }
        $nonce = $map[1];
        if (strlen($nonce) !== 16) {
            throw new CairnException('pairing payload: nonce must be 16 bytes');
        }

        if (!isset($map[2]) || !is_string($map[2])) {
            throw new CairnException('pairing payload: missing or invalid pake_credential');
        }
        $pakeCredential = $map[2];

        $connectionHints = null;
        if (isset($map[3]) && is_array($map[3])) {
            $connectionHints = [];
            /** @var list<mixed> $hintsArray */
            $hintsArray = $map[3];
            foreach ($hintsArray as $hint) {
                if (!is_array($hint) || count($hint) !== 2) {
                    throw new CairnException('pairing payload: hint must be [type, value]');
                }
                /** @var list<mixed> $hint */
                if (!is_string($hint[0]) || !is_string($hint[1])) {
                    throw new CairnException('pairing payload: hint type and value must be strings');
                }
                $connectionHints[] = new ConnectionHint($hint[0], $hint[1]);
            }
        }

        $createdAt = 0;
        if (isset($map[4]) && is_int($map[4])) {
            $createdAt = $map[4];
        }

        $expiresAt = 0;
        if (isset($map[5]) && is_int($map[5])) {
            $expiresAt = $map[5];
        }

        return new self(
            peerId: $peerId,
            nonce: $nonce,
            pakeCredential: $pakeCredential,
            connectionHints: $connectionHints,
            createdAt: $createdAt,
            expiresAt: $expiresAt,
        );
    }

    /**
     * Encode a CBOR map header for N entries.
     */
    private static function encodeCborMapHeader(int $count): string
    {
        // Major type 5 (map) = 0xA0 | count
        if ($count <= 23) {
            return chr(0xA0 | $count);
        }
        if ($count <= 0xFF) {
            return "\xB8" . chr($count);
        }
        return "\xB9" . pack('n', $count);
    }

    /**
     * Encode an array of [hintType, value] pairs as CBOR.
     *
     * Each hint is a 2-element array of text strings.
     *
     * @param list<array{0: string, 1: string}> $hints
     */
    private static function encodeHintsArray(array $hints): string
    {
        $count = count($hints);

        // CBOR array header (major type 4)
        if ($count <= 23) {
            $result = chr(0x80 | $count);
        } elseif ($count <= 0xFF) {
            $result = "\x98" . chr($count);
        } else {
            $result = "\x99" . pack('n', $count);
        }

        foreach ($hints as [$hintType, $value]) {
            // Each hint is a 2-element array of text strings
            $result .= "\x82"; // 2-element array
            $result .= Cbor::encodeText($hintType);
            $result .= Cbor::encodeText($value);
        }

        return $result;
    }
}
