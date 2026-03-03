<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * HKDF-SHA256 key derivation with domain separation constants.
 *
 * Uses PHP's native hash_hkdf() (available since PHP 7.1.2).
 * Matches the Rust implementation in packages/rs/cairn-p2p/src/crypto/exchange.rs.
 */
final class Kdf
{
    // Domain separation info strings for HKDF derivations.
    // These MUST match the Rust constants exactly.
    public const HKDF_INFO_SESSION_KEY = 'cairn-session-key-v1';
    public const HKDF_INFO_RENDEZVOUS = 'cairn-rendezvous-id-v1';
    public const HKDF_INFO_SAS = 'cairn-sas-derivation-v1';
    public const HKDF_INFO_CHAIN_KEY = 'cairn-chain-key-v1';
    public const HKDF_INFO_MESSAGE_KEY = 'cairn-message-key-v1';

    // Additional constants used by Double Ratchet (from spec/19)
    public const HKDF_INFO_ROOT_CHAIN = 'cairn-root-chain-v1';
    public const HKDF_INFO_CHAIN_ADVANCE = 'cairn-chain-advance-v1';
    public const HKDF_INFO_MSG_ENCRYPT = 'cairn-msg-encrypt-v1';

    private function __construct()
    {
    }

    /**
     * Derive key material using HKDF-SHA256 (RFC 5869).
     *
     * @param string $ikm Input keying material (e.g., DH shared secret)
     * @param string $info Context-specific info string for domain separation
     * @param int $length Desired output length in bytes (max 255 * 32 = 8160)
     * @param string $salt Optional salt (empty string uses zero-filled salt)
     * @return string Derived key material
     * @throws CairnException
     */
    public static function hkdfSha256(
        string $ikm,
        string $info,
        int $length = 32,
        string $salt = '',
    ): string {
        $result = hash_hkdf('sha256', $ikm, $length, $info, $salt);

        if ($result === false) {
            throw new CairnException('HKDF-SHA256 derivation failed');
        }

        return $result;
    }
}
