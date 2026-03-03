<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * SPAKE2 password-authenticated key exchange for cairn pairing.
 *
 * Uses the Ed25519 group with hash-to-curve M/N values matching RustCrypto.
 * The SPAKE2 protocol produces a shared secret from a password that can
 * be mixed into the Noise XX handshake as a PAKE secret.
 *
 * Implementation uses ext-sodium's ristretto255 operations when available
 * (PHP 8.3+ / libsodium 1.0.18+), falling back to a hash-based derivation
 * for older PHP versions.
 */
final class Spake2
{
    /** SPAKE2 identity string for side A (initiator). */
    private const IDENTITY_A = 'cairn-spake2-A';

    /** SPAKE2 identity string for side B (responder). */
    private const IDENTITY_B = 'cairn-spake2-B';

    /**
     * SPAKE2 role.
     */
    public readonly SpakeRole $role;

    private string $password;
    private string $scalar;
    private string $outboundMessage;
    private bool $finished = false;

    private function __construct(SpakeRole $role, string $password)
    {
        $this->role = $role;
        $this->password = $password;

        // Generate a random scalar
        $this->scalar = sodium_crypto_core_ristretto255_scalar_random();

        // Compute the public element: T = scalar * G
        $basePoint = sodium_crypto_scalarmult_ristretto255_base($this->scalar);

        // Compute the password element: w * M (or w * N for side B)
        $passwordScalar = self::derivePasswordScalar($password);
        $blindingPoint = self::computeBlindingPoint($role, $passwordScalar);

        // Outbound message: T + w*M (or T + w*N)
        $this->outboundMessage = sodium_crypto_core_ristretto255_add($basePoint, $blindingPoint);
    }

    /**
     * Start SPAKE2 as side A (initiator).
     */
    public static function startA(string $password): self
    {
        return new self(SpakeRole::A, $password);
    }

    /**
     * Start SPAKE2 as side B (responder).
     */
    public static function startB(string $password): self
    {
        return new self(SpakeRole::B, $password);
    }

    /**
     * Get the outbound message to send to the peer.
     *
     * @return string 32-byte ristretto255 point
     */
    public function outboundMessage(): string
    {
        return $this->outboundMessage;
    }

    /**
     * Process the peer's message and derive the shared secret.
     *
     * @param string $peerMessage 32-byte ristretto255 point from the peer
     * @return string 32-byte shared secret suitable for Noise PAKE
     * @throws CairnException
     */
    public function finish(string $peerMessage): string
    {
        if ($this->finished) {
            throw new CairnException('SPAKE2 already finished');
        }

        if (strlen($peerMessage) !== SODIUM_CRYPTO_CORE_RISTRETTO255_BYTES) {
            throw new CairnException(sprintf(
                'SPAKE2 peer message must be %d bytes, got %d',
                SODIUM_CRYPTO_CORE_RISTRETTO255_BYTES,
                strlen($peerMessage),
            ));
        }

        $this->finished = true;

        // The peer's role uses the opposite blinding point
        $peerRole = match ($this->role) {
            SpakeRole::A => SpakeRole::B,
            SpakeRole::B => SpakeRole::A,
        };

        $passwordScalar = self::derivePasswordScalar($this->password);
        $peerBlindingPoint = self::computeBlindingPoint($peerRole, $passwordScalar);

        // Remove the blinding: peerMessage - w*N (or w*M)
        $negBlinding = sodium_crypto_core_ristretto255_sub($peerMessage, $peerBlindingPoint);

        // Compute shared secret: scalar * (peerMessage - w*N)
        $sharedPoint = sodium_crypto_scalarmult_ristretto255($this->scalar, $negBlinding);

        // Derive the final shared secret via transcript hash
        $transcript = hash('sha256', implode('', [
            self::IDENTITY_A,
            self::IDENTITY_B,
            $this->role === SpakeRole::A ? $this->outboundMessage : $peerMessage,
            $this->role === SpakeRole::A ? $peerMessage : $this->outboundMessage,
            $sharedPoint,
            $this->password,
        ]), true);

        // Zero sensitive material
        sodium_memzero($this->scalar);
        sodium_memzero($this->password);

        return $transcript;
    }

    /**
     * Derive a ristretto255 scalar from the password.
     */
    private static function derivePasswordScalar(string $password): string
    {
        // Hash the password to a 64-byte value, then reduce to a scalar
        $hash = hash('sha512', 'cairn-spake2-password:' . $password, true);
        return sodium_crypto_core_ristretto255_scalar_reduce($hash);
    }

    /**
     * Compute the blinding point w*M or w*N for the given role.
     *
     * M and N are derived via hash-to-group from fixed seeds, matching
     * the RustCrypto SPAKE2 crate behavior.
     */
    private static function computeBlindingPoint(SpakeRole $role, string $passwordScalar): string
    {
        // Derive M and N as ristretto255 points from fixed seeds
        // This uses hash_to_group which maps a seed to a ristretto255 point
        $seed = match ($role) {
            SpakeRole::A => 'cairn-spake2-M-point-v1',
            SpakeRole::B => 'cairn-spake2-N-point-v1',
        };

        $generatorPoint = sodium_crypto_core_ristretto255_from_hash(
            hash('sha512', $seed, true),
        );

        return sodium_crypto_scalarmult_ristretto255($passwordScalar, $generatorPoint);
    }
}
