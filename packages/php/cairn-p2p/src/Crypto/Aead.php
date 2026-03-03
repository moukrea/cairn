<?php

declare(strict_types=1);

namespace Cairn\Crypto;

use Cairn\Error\CairnException;

/**
 * AEAD encryption/decryption for cairn.
 *
 * ChaCha20-Poly1305 via ext-sodium (preferred, constant-time).
 * AES-256-GCM via ext-openssl (when AES-NI available).
 *
 * Both use 32-byte key, 12-byte nonce, 16-byte tag.
 * Matches the Rust implementation in packages/rs/cairn-p2p/src/crypto/aead.rs.
 */
final class Aead
{
    /** Nonce size for both ciphers: 12 bytes. */
    public const NONCE_SIZE = 12;

    /** Key size for both ciphers: 32 bytes. */
    public const KEY_SIZE = 32;

    /** Authentication tag size: 16 bytes for both ciphers. */
    public const TAG_SIZE = 16;

    private function __construct()
    {
    }

    /**
     * Encrypt plaintext with associated data using the specified cipher.
     *
     * @param CipherSuite $cipher Which AEAD to use
     * @param string $key 32-byte encryption key
     * @param string $nonce 12-byte nonce (must be unique per key)
     * @param string $plaintext Data to encrypt
     * @param string $aad Associated data to authenticate but not encrypt
     * @return string Ciphertext with appended authentication tag
     * @throws CairnException
     */
    public static function encrypt(
        CipherSuite $cipher,
        string $key,
        string $nonce,
        string $plaintext,
        string $aad = '',
    ): string {
        self::validateKeyAndNonce($key, $nonce);

        return match ($cipher) {
            CipherSuite::ChaCha20Poly1305 => self::chachaEncrypt($key, $nonce, $plaintext, $aad),
            CipherSuite::Aes256Gcm => self::aesGcmEncrypt($key, $nonce, $plaintext, $aad),
        };
    }

    /**
     * Decrypt ciphertext with associated data using the specified cipher.
     *
     * @param CipherSuite $cipher Which AEAD to use
     * @param string $key 32-byte encryption key
     * @param string $nonce 12-byte nonce
     * @param string $ciphertext Ciphertext with appended authentication tag
     * @param string $aad Associated data
     * @return string Decrypted plaintext
     * @throws CairnException If authentication fails
     */
    public static function decrypt(
        CipherSuite $cipher,
        string $key,
        string $nonce,
        string $ciphertext,
        string $aad = '',
    ): string {
        self::validateKeyAndNonce($key, $nonce);

        return match ($cipher) {
            CipherSuite::ChaCha20Poly1305 => self::chachaDecrypt($key, $nonce, $ciphertext, $aad),
            CipherSuite::Aes256Gcm => self::aesGcmDecrypt($key, $nonce, $ciphertext, $aad),
        };
    }

    /**
     * ChaCha20-Poly1305 encrypt via ext-sodium.
     */
    private static function chachaEncrypt(string $key, string $nonce, string $plaintext, string $aad): string
    {
        $result = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            $aad,
            $nonce,
            $key,
        );

        // sodium returns ciphertext || tag
        return $result;
    }

    /**
     * ChaCha20-Poly1305 decrypt via ext-sodium.
     *
     * @throws CairnException
     */
    private static function chachaDecrypt(string $key, string $nonce, string $ciphertext, string $aad): string
    {
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            $aad,
            $nonce,
            $key,
        );

        if ($result === false) {
            throw new CairnException('ChaCha20-Poly1305 decryption failed: authentication error');
        }

        return $result;
    }

    /**
     * AES-256-GCM encrypt via ext-openssl.
     *
     * @throws CairnException
     */
    private static function aesGcmEncrypt(string $key, string $nonce, string $plaintext, string $aad): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            self::TAG_SIZE,
        );

        if ($ciphertext === false) {
            throw new CairnException('AES-256-GCM encryption failed');
        }

        // Return ciphertext || tag to match Rust behavior
        return $ciphertext . $tag;
    }

    /**
     * AES-256-GCM decrypt via ext-openssl.
     *
     * @throws CairnException
     */
    private static function aesGcmDecrypt(string $key, string $nonce, string $ciphertext, string $aad): string
    {
        if (strlen($ciphertext) < self::TAG_SIZE) {
            throw new CairnException('AES-256-GCM decryption failed: ciphertext too short');
        }

        // Split ciphertext and tag
        $ct = substr($ciphertext, 0, -self::TAG_SIZE);
        $tag = substr($ciphertext, -self::TAG_SIZE);

        $plaintext = openssl_decrypt(
            $ct,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
        );

        if ($plaintext === false) {
            throw new CairnException('AES-256-GCM decryption failed: authentication error');
        }

        return $plaintext;
    }

    /**
     * @throws CairnException
     */
    private static function validateKeyAndNonce(string $key, string $nonce): void
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new CairnException(sprintf(
                'AEAD key must be %d bytes, got %d',
                self::KEY_SIZE,
                strlen($key),
            ));
        }

        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new CairnException(sprintf(
                'AEAD nonce must be %d bytes, got %d',
                self::NONCE_SIZE,
                strlen($nonce),
            ));
        }
    }
}
