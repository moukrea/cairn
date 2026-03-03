<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\Kdf;
use Cairn\Error\CairnException;

/**
 * Pre-Shared Key (PSK) pairing mechanism.
 *
 * A secret configured on both peers ahead of time. Used as PAKE input;
 * rendezvous ID derived from it. Can be long-lived but should be rotated.
 *
 * Minimum entropy: 128 bits (16 bytes) since not time-limited.
 *
 * Matches packages/rs/cairn-p2p/src/pairing/mechanisms/psk.rs.
 */
final class Psk
{
    /** Default minimum entropy in bytes (128 bits). */
    public const DEFAULT_MIN_ENTROPY_BYTES = 16;

    /** HKDF info string for PSK rendezvous ID derivation. */
    private const HKDF_INFO_PSK_RENDEZVOUS = 'cairn-psk-rendezvous-v1';

    private int $minEntropyBytes;

    public function __construct(int $minEntropyBytes = self::DEFAULT_MIN_ENTROPY_BYTES)
    {
        $this->minEntropyBytes = $minEntropyBytes;
    }

    /**
     * Validate that the PSK has sufficient entropy.
     *
     * @throws CairnException
     */
    public function validateEntropy(string $psk): void
    {
        if ($psk === '') {
            throw new CairnException('empty pre-shared key');
        }

        if (strlen($psk) < $this->minEntropyBytes) {
            throw new CairnException(sprintf(
                'insufficient PSK entropy: got %d bytes, need at least %d bytes (128 bits)',
                strlen($psk),
                $this->minEntropyBytes,
            ));
        }
    }

    /**
     * Derive a 32-byte rendezvous ID from the PSK.
     *
     * Uses HKDF-SHA256 with info="cairn-psk-rendezvous-v1".
     *
     * @throws CairnException
     */
    public function deriveRendezvousId(string $psk): string
    {
        $this->validateEntropy($psk);
        return Kdf::hkdfSha256($psk, self::HKDF_INFO_PSK_RENDEZVOUS, 32, '');
    }

    /**
     * Get the SPAKE2 password input from the PSK.
     *
     * The PSK is used directly as the SPAKE2 password bytes.
     *
     * @throws CairnException
     */
    public function pakeInput(string $psk): string
    {
        $this->validateEntropy($psk);
        return $psk;
    }

    /**
     * Get the minimum entropy requirement in bytes.
     */
    public function minEntropyBytes(): int
    {
        return $this->minEntropyBytes;
    }
}
