<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * X25519 keypair for Diffie-Hellman key exchange.
 *
 * Uses ext-sodium (sodium_crypto_scalarmult). Matches the Rust X25519Keypair
 * in packages/rs/cairn-p2p/src/crypto/exchange.rs.
 */
final class X25519Keypair
{
    /** X25519 key size: 32 bytes. */
    public const KEY_SIZE = SODIUM_CRYPTO_SCALARMULT_BYTES;

    private string $secretKey;
    private string $pubKey;

    private function __construct(string $secretKey, string $publicKey)
    {
        $this->secretKey = $secretKey;
        $this->pubKey = $publicKey;
    }

    public function __destruct()
    {
        sodium_memzero($this->secretKey);
    }

    /**
     * Generate a new random X25519 keypair.
     */
    public static function generate(): self
    {
        $secretKey = sodium_crypto_box_keypair();
        $sk = sodium_crypto_box_secretkey($secretKey);
        $pk = sodium_crypto_box_publickey($secretKey);
        return new self($sk, $pk);
    }

    /**
     * Restore from a 32-byte secret key.
     *
     * @throws CairnException
     */
    public static function fromSecretKey(string $secretKey): self
    {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SCALARMULT_SCALARBYTES) {
            throw new CairnException(sprintf(
                'X25519 secret key must be %d bytes, got %d',
                SODIUM_CRYPTO_SCALARMULT_SCALARBYTES,
                strlen($secretKey),
            ));
        }

        $publicKey = sodium_crypto_scalarmult_base($secretKey);
        return new self($secretKey, $publicKey);
    }

    /**
     * Get the 32-byte public key.
     */
    public function publicKey(): string
    {
        return $this->pubKey;
    }

    /**
     * Get the 32-byte public key (alias).
     */
    public function publicKeyBytes(): string
    {
        return $this->pubKey;
    }

    /**
     * Export the 32-byte secret key.
     */
    public function secretKeyBytes(): string
    {
        return $this->secretKey;
    }

    /**
     * Perform Diffie-Hellman key exchange with a peer's public key.
     *
     * @param string $peerPublicKey 32-byte X25519 public key
     * @return string 32-byte shared secret
     * @throws CairnException
     */
    public function computeSharedSecret(string $peerPublicKey): string
    {
        return $this->diffieHellman($peerPublicKey);
    }

    /**
     * Perform Diffie-Hellman key exchange with a peer's public key.
     *
     * @param string $peerPublicKey 32-byte X25519 public key
     * @return string 32-byte shared secret
     * @throws CairnException
     */
    public function diffieHellman(string $peerPublicKey): string
    {
        if (strlen($peerPublicKey) !== SODIUM_CRYPTO_SCALARMULT_BYTES) {
            throw new CairnException(sprintf(
                'X25519 public key must be %d bytes, got %d',
                SODIUM_CRYPTO_SCALARMULT_BYTES,
                strlen($peerPublicKey),
            ));
        }

        return sodium_crypto_scalarmult($this->secretKey, $peerPublicKey);
    }
}
