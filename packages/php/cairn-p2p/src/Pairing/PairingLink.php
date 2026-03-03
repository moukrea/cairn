<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Protocol\Cbor;

/**
 * Pairing link/URI mechanism.
 *
 * Generates and parses `cairn://pair?pid=...&nonce=...&pake=...&hints=...` URIs.
 * Binary fields use hex encoding. Hints use base64url-encoded CBOR.
 *
 * Matches packages/rs/cairn-p2p/src/pairing/mechanisms/link.rs.
 */
final class PairingLink
{
    /** Default URI scheme. */
    public const DEFAULT_SCHEME = 'cairn';

    /** Default TTL in seconds (5 minutes). */
    public const DEFAULT_TTL = 300;

    private function __construct()
    {
    }

    /**
     * Alias for generate().
     *
     * @param PairingPayload $payload The payload to encode
     * @param string $scheme URI scheme (default: "cairn")
     * @return string The complete URI
     */
    public static function toUri(PairingPayload $payload, string $scheme = self::DEFAULT_SCHEME): string
    {
        return self::generate($payload, $scheme);
    }

    /**
     * Alias for parse().
     *
     * @param string $uri The URI to parse
     * @param string $scheme Expected URI scheme (default: "cairn")
     * @throws CairnException
     */
    public static function fromUri(string $uri, string $scheme = self::DEFAULT_SCHEME): PairingPayload
    {
        return self::parse($uri, $scheme);
    }

    /**
     * Generate a pairing link URI from a PairingPayload.
     *
     * @param PairingPayload $payload The payload to encode
     * @param string $scheme URI scheme (default: "cairn")
     * @return string The complete URI
     */
    public static function generate(PairingPayload $payload, string $scheme = self::DEFAULT_SCHEME): string
    {
        $pid = self::base58Encode($payload->peerId->asBytes());
        $nonce = bin2hex($payload->nonce);
        $pake = bin2hex($payload->pakeCredential);

        $uri = sprintf(
            '%s://pair?pid=%s&nonce=%s&pake=%s',
            $scheme,
            $pid,
            $nonce,
            $pake,
        );

        if ($payload->connectionHints !== null && count($payload->connectionHints) > 0) {
            $encodedHints = self::encodeHints($payload->connectionHints);
            $uri .= '&hints=' . $encodedHints;
        }

        $uri .= sprintf('&t=%d&x=%d', $payload->createdAt, $payload->expiresAt);

        return $uri;
    }

    /**
     * Parse a pairing link URI into a PairingPayload.
     *
     * @param string $uri The URI to parse
     * @param string $scheme Expected URI scheme (default: "cairn")
     * @throws CairnException
     */
    public static function parse(string $uri, string $scheme = self::DEFAULT_SCHEME): PairingPayload
    {
        $parts = parse_url($uri);
        if ($parts === false) {
            throw new CairnException('invalid pairing link URI');
        }

        // Validate scheme
        $actualScheme = $parts['scheme'] ?? '';
        if ($actualScheme !== $scheme) {
            throw new CairnException(sprintf(
                "expected scheme '%s', got '%s'",
                $scheme,
                $actualScheme,
            ));
        }

        // Validate host (should be "pair")
        $host = $parts['host'] ?? '';
        if ($host !== 'pair') {
            throw new CairnException("expected host 'pair' in URI");
        }

        // Parse query parameters
        $queryString = $parts['query'] ?? '';
        parse_str($queryString, $params);

        // Check presence of all required parameters first
        if (!isset($params['pid']) || !is_string($params['pid'])) {
            throw new CairnException("missing 'pid' parameter");
        }
        if (!isset($params['nonce']) || !is_string($params['nonce'])) {
            throw new CairnException("missing 'nonce' parameter");
        }
        if (!isset($params['pake']) || !is_string($params['pake'])) {
            throw new CairnException("missing 'pake' parameter");
        }

        // pid (base58 PeerId)
        $pidBytes = self::base58Decode($params['pid']);
        $peerId = PeerId::fromBytes($pidBytes);

        // nonce (hex)
        $nonce = hex2bin($params['nonce']);
        if ($nonce === false || strlen($nonce) !== 16) {
            throw new CairnException('invalid or wrong-length nonce');
        }

        // pake (hex)
        $pakeCredential = hex2bin($params['pake']);
        if ($pakeCredential === false) {
            throw new CairnException('invalid hex pake credential');
        }

        // hints (optional, base64url-encoded CBOR)
        $connectionHints = null;
        if (isset($params['hints']) && is_string($params['hints'])) {
            $connectionHints = self::decodeHints($params['hints']);
        }

        // timestamps
        $createdAt = isset($params['t']) && is_string($params['t']) ? (int) $params['t'] : 0;
        $expiresAt = isset($params['x']) && is_string($params['x']) ? (int) $params['x'] : 0;

        $payload = new PairingPayload(
            peerId: $peerId,
            nonce: $nonce,
            pakeCredential: $pakeCredential,
            connectionHints: $connectionHints,
            createdAt: $createdAt,
            expiresAt: $expiresAt,
        );

        if ($payload->isExpired()) {
            throw new CairnException('pairing link has expired');
        }

        return $payload;
    }

    /**
     * Encode connection hints as base64url-encoded CBOR.
     *
     * @param list<ConnectionHint> $hints
     */
    private static function encodeHints(array $hints): string
    {
        // Build CBOR array of [text, text] pairs
        $count = count($hints);
        if ($count <= 23) {
            $cbor = chr(0x80 | $count);
        } else {
            $cbor = "\x98" . chr($count);
        }

        foreach ($hints as $hint) {
            $cbor .= "\x82"; // 2-element array
            $cbor .= Cbor::encodeText($hint->hintType);
            $cbor .= Cbor::encodeText($hint->value);
        }

        return self::base64urlEncode($cbor);
    }

    /**
     * Decode connection hints from base64url-encoded CBOR.
     *
     * @return list<ConnectionHint>
     * @throws CairnException
     */
    private static function decodeHints(string $encoded): array
    {
        $cbor = self::base64urlDecode($encoded);

        /** @var list<mixed> $arr */
        $arr = Cbor::decode($cbor);
        if (!is_array($arr)) {
            throw new CairnException('hints must be CBOR array');
        }

        $hints = [];
        foreach ($arr as $item) {
            if (!is_array($item) || count($item) !== 2) {
                throw new CairnException('each hint must be [type, value]');
            }
            /** @var list<mixed> $item */
            if (!is_string($item[0]) || !is_string($item[1])) {
                throw new CairnException('hint type and value must be strings');
            }
            $hints[] = new ConnectionHint($item[0], $item[1]);
        }

        return $hints;
    }

    /**
     * Base64url encode (no padding).
     */
    private static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64url decode (no padding).
     *
     * @throws CairnException
     */
    private static function base64urlDecode(string $data): string
    {
        $result = base64_decode(strtr($data, '-_', '+/'), true);
        if ($result === false) {
            throw new CairnException('invalid base64url encoding');
        }
        return $result;
    }

    /**
     * Base58 encode using Bitcoin alphabet (for PeerId in URIs).
     */
    private static function base58Encode(string $data): string
    {
        // Use PeerId's __toString which does base58 encoding
        // But we need a standalone encoder here for arbitrary bytes
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        $leadingZeros = 0;
        $len = strlen($data);
        while ($leadingZeros < $len && ord($data[$leadingZeros]) === 0) {
            $leadingZeros++;
        }

        $num = gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        if ($num === false) {
            $num = gmp_init(0);
        }

        $result = '';
        $zero = gmp_init(0);
        $base = gmp_init(58);

        while (gmp_cmp($num, $zero) > 0) {
            [$num, $rem] = gmp_div_qr($num, $base);
            $result = $alphabet[gmp_intval($rem)] . $result;
        }

        return str_repeat('1', $leadingZeros) . $result;
    }

    /**
     * Base58 decode using Bitcoin alphabet.
     *
     * @throws CairnException
     */
    private static function base58Decode(string $encoded): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        if ($encoded === '') {
            return '';
        }

        $leadingOnes = 0;
        $len = strlen($encoded);
        while ($leadingOnes < $len && $encoded[$leadingOnes] === '1') {
            $leadingOnes++;
        }

        $num = gmp_init(0);
        $base = gmp_init(58);

        for ($i = $leadingOnes; $i < $len; $i++) {
            $pos = strpos($alphabet, $encoded[$i]);
            if ($pos === false) {
                throw new CairnException("invalid base58 character: '{$encoded[$i]}'");
            }
            $num = gmp_add(gmp_mul($num, $base), gmp_init($pos));
        }

        $bytes = '';
        if (gmp_cmp($num, gmp_init(0)) > 0) {
            $exported = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            if ($exported !== false) {
                $bytes = $exported;
            }
        }

        return str_repeat("\x00", $leadingOnes) . $bytes;
    }
}
