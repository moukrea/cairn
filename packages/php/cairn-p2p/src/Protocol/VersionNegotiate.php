<?php

declare(strict_types=1);

namespace Cairn\Protocol;

use Cairn\Error\CairnException;

/**
 * Version negotiation for the cairn wire protocol.
 *
 * Matches the Rust implementation in packages/rs/cairn-p2p/src/protocol/version.rs.
 */
final class VersionNegotiate
{
    /** Current protocol version. */
    public const CURRENT_VERSION = 1;

    /** All protocol versions this implementation supports, highest first. */
    public const SUPPORTED_VERSIONS = [1];

    private function __construct()
    {
    }

    /**
     * Select the highest mutually supported version.
     *
     * @param list<int> $ourVersions Our supported versions (highest first)
     * @param list<int> $peerVersions Peer's supported versions (highest first)
     * @throws CairnException When no common version exists
     */
    public static function selectVersion(array $ourVersions, array $peerVersions): int
    {
        foreach ($ourVersions as $v) {
            if (in_array($v, $peerVersions, true)) {
                return $v;
            }
        }

        throw new CairnException(sprintf(
            'version mismatch: local supports %s, remote supports %s; '
            . 'update the peer with the older protocol version',
            self::formatVersions($ourVersions),
            self::formatVersions($peerVersions),
        ));
    }

    /**
     * Create a VersionNegotiate message envelope advertising our supported versions.
     *
     * @throws CairnException
     */
    public static function createNegotiate(): Envelope
    {
        return new Envelope(
            version: self::CURRENT_VERSION,
            messageType: MessageType::VERSION_NEGOTIATE,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: self::encodePayload(self::SUPPORTED_VERSIONS),
            authTag: null,
        );
    }

    /**
     * Parse a received VersionNegotiate envelope and extract the version list.
     *
     * @return list<int>
     * @throws CairnException
     */
    public static function parseNegotiate(Envelope $envelope): array
    {
        if ($envelope->messageType !== MessageType::VERSION_NEGOTIATE) {
            throw new CairnException(sprintf(
                'expected VERSION_NEGOTIATE (0x%04X), got 0x%04X',
                MessageType::VERSION_NEGOTIATE,
                $envelope->messageType,
            ));
        }

        return self::decodePayload($envelope->payload);
    }

    /**
     * Process a received VersionNegotiate and produce a response.
     *
     * @return array{0: int, 1: Envelope} Tuple of (selected version, response envelope)
     * @throws CairnException
     */
    public static function handleNegotiate(Envelope $received): array
    {
        $peerVersions = self::parseNegotiate($received);
        $selected = self::selectVersion(self::SUPPORTED_VERSIONS, $peerVersions);

        $response = new Envelope(
            version: self::CURRENT_VERSION,
            messageType: MessageType::VERSION_NEGOTIATE,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: self::encodePayload([$selected]),
            authTag: null,
        );

        return [$selected, $response];
    }

    /**
     * Encode a VersionNegotiatePayload to CBOR.
     *
     * The Rust serde/ciborium encodes this as a CBOR map with text key "versions"
     * pointing to an array of unsigned integers. We replicate that format exactly.
     *
     * @param list<int> $versions
     */
    private static function encodePayload(array $versions): string
    {
        // CBOR map with 1 entry
        $result = "\xA1";
        // Key: text string "versions"
        $result .= Cbor::encodeText('versions');
        // Value: array of unsigned ints
        $result .= Cbor::encode($versions);
        return $result;
    }

    /**
     * Decode a VersionNegotiatePayload from CBOR.
     *
     * @return list<int>
     * @throws CairnException
     */
    private static function decodePayload(string $data): array
    {
        $decoded = Cbor::decode($data);

        if (!is_array($decoded)) {
            throw new CairnException('CBOR decode error: expected map for VersionNegotiatePayload');
        }

        if (!array_key_exists('versions', $decoded)) {
            throw new CairnException('CBOR decode error: missing "versions" field');
        }

        $versions = $decoded['versions'];
        if (!is_array($versions)) {
            throw new CairnException('CBOR decode error: "versions" must be an array');
        }

        /** @var list<int> */
        return $versions;
    }

    /**
     * @param list<int> $versions
     */
    private static function formatVersions(array $versions): string
    {
        return '[' . implode(', ', $versions) . ']';
    }
}
