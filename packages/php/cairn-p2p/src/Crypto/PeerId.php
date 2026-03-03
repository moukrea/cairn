<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;
use Stringable;

/**
 * A peer identifier derived from the SHA-256 multihash of an Ed25519 public key.
 *
 * Internal representation: [0x12, 0x20, <32-byte SHA-256 digest>] (34 bytes total).
 * Display uses base58 (Bitcoin alphabet) encoding, matching libp2p convention.
 *
 * Matches the Rust PeerId in packages/rs/cairn-p2p/src/identity/peer_id.rs.
 */
final class PeerId implements Stringable
{
    /** Multihash code for SHA2-256. */
    private const MULTIHASH_CODE = 0x12;

    /** Multihash digest length for SHA2-256 (32 bytes). */
    private const MULTIHASH_LEN = 0x20;

    /** Total length: 2-byte prefix + 32-byte digest. */
    public const PEER_ID_LEN = 34;

    /** Base58 Bitcoin alphabet. */
    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    public readonly string $bytes;

    private function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    /**
     * Derive a PeerId from an Ed25519 public key.
     *
     * @param string $publicKey 32-byte Ed25519 public key
     */
    public static function fromPublicKey(string $publicKey): self
    {
        $digest = hash('sha256', $publicKey, true);
        $bytes = chr(self::MULTIHASH_CODE) . chr(self::MULTIHASH_LEN) . $digest;
        return new self($bytes);
    }

    /**
     * Construct from raw 34-byte multihash bytes. Validates the prefix.
     *
     * @throws CairnException
     */
    public static function fromBytes(string $bytes): self
    {
        if (strlen($bytes) !== self::PEER_ID_LEN) {
            throw new CairnException(sprintf(
                'invalid peer ID: expected %d bytes, got %d',
                self::PEER_ID_LEN,
                strlen($bytes),
            ));
        }

        if (ord($bytes[0]) !== self::MULTIHASH_CODE || ord($bytes[1]) !== self::MULTIHASH_LEN) {
            throw new CairnException('invalid peer ID: wrong multihash prefix');
        }

        return new self($bytes);
    }

    /**
     * Parse a PeerId from a base58 string.
     *
     * @throws CairnException
     */
    public static function fromString(string $base58): self
    {
        $bytes = self::base58Decode($base58);
        return self::fromBytes($bytes);
    }

    /**
     * Returns the raw 34-byte multihash representation.
     */
    public function asBytes(): string
    {
        return $this->bytes;
    }

    /**
     * Returns the base58 (Bitcoin alphabet) string representation.
     */
    public function __toString(): string
    {
        return self::base58Encode($this->bytes);
    }

    public function equals(self $other): bool
    {
        return $this->bytes === $other->bytes;
    }

    /**
     * Encode binary data to base58 (Bitcoin alphabet).
     */
    private static function base58Encode(string $data): string
    {
        $alphabet = self::BASE58_ALPHABET;

        // Count leading zero bytes
        $leadingZeros = 0;
        $len = strlen($data);
        while ($leadingZeros < $len && ord($data[$leadingZeros]) === 0) {
            $leadingZeros++;
        }

        // Convert to big integer using GMP
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

        // Add leading '1's for leading zero bytes
        return str_repeat('1', $leadingZeros) . $result;
    }

    /**
     * Decode a base58 (Bitcoin alphabet) string to binary data.
     *
     * @throws CairnException
     */
    private static function base58Decode(string $encoded): string
    {
        $alphabet = self::BASE58_ALPHABET;

        if ($encoded === '') {
            return '';
        }

        // Count leading '1's (representing leading zero bytes)
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
