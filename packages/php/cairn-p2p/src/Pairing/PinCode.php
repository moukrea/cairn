<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\Kdf;
use Cairn\Error\CairnException;

/**
 * Pin code pairing mechanism using Crockford Base32.
 *
 * Generates 8-character codes formatted as XXXX-XXXX (40 bits entropy).
 * The code serves as both SPAKE2 password and rendezvous ID source.
 *
 * Matches packages/rs/cairn-p2p/src/pairing/mechanisms/pin.rs.
 */
final class PinCode
{
    /** Crockford Base32 alphabet (excludes I, L, O, U). */
    private const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /** Pin code length in characters (before formatting). */
    private const PIN_LENGTH = 8;

    /** HKDF info string for deriving rendezvous ID from pin code. */
    private const HKDF_INFO_PIN_RENDEZVOUS = 'cairn-pin-rendezvous-v1';

    private function __construct()
    {
    }

    /**
     * Generate a random 8-character Crockford Base32 pin code.
     *
     * @return string 8-character raw Crockford Base32 string
     */
    public static function generate(): string
    {
        $bytes = random_bytes(5); // 40 bits
        return self::encodeCrockford($bytes);
    }

    /**
     * Format a pin code as XXXX-XXXX.
     */
    public static function format(string $pin): string
    {
        if (strlen($pin) === self::PIN_LENGTH) {
            return substr($pin, 0, 4) . '-' . substr($pin, 4, 4);
        }
        return $pin;
    }

    /**
     * Normalize pin code input: uppercase, strip separators, apply Crockford substitutions.
     *
     * - Case-insensitive (uppercased)
     * - I/L -> 1
     * - O -> 0
     * - U removed (Crockford excludes U)
     * - Hyphens and spaces stripped
     */
    public static function normalize(string $input): string
    {
        $result = '';
        $upper = strtoupper($input);
        $len = strlen($upper);

        for ($i = 0; $i < $len; $i++) {
            $ch = $upper[$i];

            // Strip separators
            if ($ch === '-' || $ch === ' ') {
                continue;
            }

            // Remove U (Crockford excludes it)
            if ($ch === 'U') {
                continue;
            }

            // Apply substitutions
            if ($ch === 'I' || $ch === 'L') {
                $result .= '1';
                continue;
            }

            if ($ch === 'O') {
                $result .= '0';
                continue;
            }

            $result .= $ch;
        }

        return $result;
    }

    /**
     * Alias for normalize().
     */
    public static function normalizeCrockford(string $input): string
    {
        return self::normalize($input);
    }

    /**
     * Validate a normalized pin code (8 characters, all in Crockford alphabet).
     *
     * @throws CairnException
     */
    public static function validate(string $normalized): void
    {
        if (strlen($normalized) !== self::PIN_LENGTH) {
            throw new CairnException(sprintf(
                'invalid pin code: expected %d characters, got %d',
                self::PIN_LENGTH,
                strlen($normalized),
            ));
        }

        for ($i = 0; $i < self::PIN_LENGTH; $i++) {
            if (strpos(self::CROCKFORD_ALPHABET, $normalized[$i]) === false) {
                throw new CairnException(sprintf(
                    "invalid pin code: character '%s' not in Crockford alphabet",
                    $normalized[$i],
                ));
            }
        }
    }

    /**
     * Derive a 32-byte rendezvous ID from a pin code.
     *
     * Uses HKDF-SHA256 with info="cairn-pin-rendezvous-v1".
     */
    public static function deriveRendezvousId(string $pinBytes): string
    {
        return Kdf::hkdfSha256($pinBytes, self::HKDF_INFO_PIN_RENDEZVOUS, 32, '');
    }

    /**
     * Encode 5 bytes (40 bits) to 8 Crockford Base32 characters.
     */
    public static function encodeCrockford(string $bytes): string
    {
        if (strlen($bytes) !== 5) {
            throw new CairnException('encodeCrockford requires exactly 5 bytes');
        }

        // Convert 5 bytes to a 40-bit integer
        $bits = 0;
        for ($i = 0; $i < 5; $i++) {
            $bits = ($bits << 8) | ord($bytes[$i]);
        }

        // Extract 8 x 5-bit chunks from the top
        $result = '';
        for ($i = 7; $i >= 0; $i--) {
            $index = ($bits >> ($i * 5)) & 0x1F;
            $result .= self::CROCKFORD_ALPHABET[$index];
        }

        return $result;
    }

    /**
     * Decode a Crockford Base32 string (8 chars, normalized) to 5 bytes.
     *
     * @throws CairnException
     */
    public static function decodeCrockford(string $input): string
    {
        if (strlen($input) !== self::PIN_LENGTH) {
            throw new CairnException(sprintf(
                'decodeCrockford: expected %d characters, got %d',
                self::PIN_LENGTH,
                strlen($input),
            ));
        }

        $bits = 0;
        for ($i = 0; $i < self::PIN_LENGTH; $i++) {
            $pos = strpos(self::CROCKFORD_ALPHABET, $input[$i]);
            if ($pos === false) {
                throw new CairnException(sprintf(
                    "decodeCrockford: invalid character '%s'",
                    $input[$i],
                ));
            }
            $bits = ($bits << 5) | $pos;
        }

        // Extract 5 bytes from the 40-bit value
        $result = '';
        for ($i = 4; $i >= 0; $i--) {
            $result .= chr(($bits >> ($i * 8)) & 0xFF);
        }

        return $result;
    }
}
