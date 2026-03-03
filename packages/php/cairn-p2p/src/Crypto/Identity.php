<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * Ed25519 identity keypair for signing and peer identification.
 *
 * Uses ext-sodium (sodium_crypto_sign_*). Matches the Rust IdentityKeypair
 * in packages/rs/cairn-p2p/src/crypto/identity.rs.
 */
final class Identity
{
    /** Ed25519 secret key size in bytes. */
    public const SECRET_KEY_SIZE = SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;

    /** Ed25519 public key size in bytes. */
    public const PUBLIC_KEY_SIZE = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

    /** Ed25519 signature size in bytes. */
    public const SIGNATURE_SIZE = SODIUM_CRYPTO_SIGN_BYTES;

    private string $secretKey;
    private string $publicKey;

    /**
     * @param string $secretKey 64-byte Ed25519 secret key (seed + public key)
     * @param string $publicKey 32-byte Ed25519 public key
     */
    private function __construct(string $secretKey, string $publicKey)
    {
        $this->secretKey = $secretKey;
        $this->publicKey = $publicKey;
    }

    public function __destruct()
    {
        sodium_memzero($this->secretKey);
    }

    /**
     * Generate a new random Ed25519 identity keypair.
     */
    public static function generate(): self
    {
        $keypair = sodium_crypto_sign_keypair();
        return new self(
            sodium_crypto_sign_secretkey($keypair),
            sodium_crypto_sign_publickey($keypair),
        );
    }

    /**
     * Restore from a 32-byte secret key seed.
     *
     * @param string $seed 32-byte Ed25519 seed
     * @throws CairnException
     */
    public static function fromSeed(string $seed): self
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new CairnException(sprintf(
                'Ed25519 seed must be %d bytes, got %d',
                SODIUM_CRYPTO_SIGN_SEEDBYTES,
                strlen($seed),
            ));
        }

        $keypair = sodium_crypto_sign_seed_keypair($seed);
        return new self(
            sodium_crypto_sign_secretkey($keypair),
            sodium_crypto_sign_publickey($keypair),
        );
    }

    /**
     * Export the 32-byte secret key seed.
     */
    public function seedBytes(): string
    {
        // The first 32 bytes of the 64-byte secret key is the seed
        return substr($this->secretKey, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES);
    }

    /**
     * Get the 32-byte Ed25519 public key.
     */
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Derive the PeerId from this identity's public key.
     */
    public function peerId(): PeerId
    {
        return PeerId::fromPublicKey($this->publicKey);
    }

    /**
     * Sign a message. Deterministic (Ed25519).
     *
     * @return string 64-byte signature
     */
    public function sign(string $message): string
    {
        return sodium_crypto_sign_detached($message, $this->secretKey);
    }

    /**
     * Magic instance method handler.
     *
     * Handles verify(message, signature) as an instance call that uses
     * this keypair's public key. Throws CairnException on failure.
     *
     * @throws CairnException
     * @throws \BadMethodCallException
     */
    public function __call(string $name, array $arguments): mixed
    {
        if ($name === 'verify' && count($arguments) === 2) {
            self::verifySignature($this->publicKey, $arguments[0], $arguments[1]);
            return null;
        }
        throw new \BadMethodCallException("Call to undefined method Identity::{$name}()");
    }

    /**
     * Magic static method handler.
     *
     * Handles Identity::verify(publicKey, message, signature) as a static call
     * that returns bool.
     *
     * @throws \BadMethodCallException
     */
    public static function __callStatic(string $name, array $arguments): mixed
    {
        if ($name === 'verify' && count($arguments) === 3) {
            return sodium_crypto_sign_verify_detached($arguments[2], $arguments[1], $arguments[0]);
        }
        throw new \BadMethodCallException("Call to undefined static method Identity::{$name}()");
    }

    /**
     * Verify a signature against an arbitrary public key. Throws on failure.
     *
     * @param string $publicKey 32-byte Ed25519 public key
     * @param string $message The original message
     * @param string $signature 64-byte signature
     * @throws CairnException If verification fails
     */
    public static function verifySignature(string $publicKey, string $message, string $signature): void
    {
        if (!sodium_crypto_sign_verify_detached($signature, $message, $publicKey)) {
            throw new CairnException('Ed25519 signature verification failed');
        }
    }

    /**
     * Convert Ed25519 secret key to X25519 secret key for Noise handshakes.
     *
     * @return string 32-byte X25519 secret key
     */
    public function toX25519SecretKey(): string
    {
        return sodium_crypto_sign_ed25519_sk_to_curve25519($this->secretKey);
    }

    /**
     * Convert Ed25519 public key to X25519 public key for Noise handshakes.
     *
     * @return string 32-byte X25519 public key
     */
    public function toX25519PublicKey(): string
    {
        return sodium_crypto_sign_ed25519_pk_to_curve25519($this->publicKey);
    }
}

/**
 * Derive a PeerId from a public key without needing the full Identity.
 *
 * @param string $publicKey 32-byte Ed25519 public key
 * @return string 32-byte SHA-256 hash
 */
function peerIdFromPublicKey(string $publicKey): string
{
    return hash('sha256', $publicKey, true);
}
