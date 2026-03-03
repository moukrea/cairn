<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\Aead;
use Cairn\Crypto\CipherSuite;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Aead::class)]
final class AeadTest extends TestCase
{
    private function testKey(): string
    {
        $key = str_repeat("\x00", 32);
        $key[0] = "\x42";
        $key[31] = "\xFF";
        return $key;
    }

    private function testNonce(): string
    {
        $nonce = str_repeat("\x00", 12);
        $nonce[0] = "\x01";
        return $nonce;
    }

    public function testChaCha20EncryptDecryptRoundtrip(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $plaintext = 'hello cairn chacha20';
        $aad = 'associated-data';

        $ciphertext = Aead::encrypt(CipherSuite::ChaCha20Poly1305, $key, $nonce, $plaintext, $aad);
        $decrypted = Aead::decrypt(CipherSuite::ChaCha20Poly1305, $key, $nonce, $ciphertext, $aad);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testAesGcmEncryptDecryptRoundtrip(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $plaintext = 'hello cairn aes-gcm';
        $aad = 'associated-data';

        $ciphertext = Aead::encrypt(CipherSuite::Aes256Gcm, $key, $nonce, $plaintext, $aad);
        $decrypted = Aead::decrypt(CipherSuite::Aes256Gcm, $key, $nonce, $ciphertext, $aad);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testChaCha20TamperedCiphertextRejected(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $ciphertext = Aead::encrypt(CipherSuite::ChaCha20Poly1305, $key, $nonce, 'sensitive data', 'aad');

        // Tamper with ciphertext
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 0xFF);

        $this->expectException(CairnException::class);
        Aead::decrypt(CipherSuite::ChaCha20Poly1305, $key, $nonce, $ciphertext, 'aad');
    }

    public function testAesGcmTamperedCiphertextRejected(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $ciphertext = Aead::encrypt(CipherSuite::Aes256Gcm, $key, $nonce, 'sensitive data', 'aad');

        // Tamper with ciphertext
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 0xFF);

        $this->expectException(CairnException::class);
        Aead::decrypt(CipherSuite::Aes256Gcm, $key, $nonce, $ciphertext, 'aad');
    }

    public function testWrongAadRejected(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $ciphertext = Aead::encrypt(CipherSuite::Aes256Gcm, $key, $nonce, 'data', 'correct-aad');

        $this->expectException(CairnException::class);
        Aead::decrypt(CipherSuite::Aes256Gcm, $key, $nonce, $ciphertext, 'wrong-aad');
    }

    public function testWrongKeyRejected(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $ciphertext = Aead::encrypt(CipherSuite::Aes256Gcm, $key, $nonce, 'data', 'aad');

        $wrongKey = $key;
        $wrongKey[0] = chr(ord($wrongKey[0]) ^ 0x01);

        $this->expectException(CairnException::class);
        Aead::decrypt(CipherSuite::Aes256Gcm, $wrongKey, $nonce, $ciphertext, 'aad');
    }

    public function testCiphertextIncludesTag(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $plaintext = 'hello';

        $ctAes = Aead::encrypt(CipherSuite::Aes256Gcm, $key, $nonce, $plaintext);
        $this->assertSame(strlen($plaintext) + Aead::TAG_SIZE, strlen($ctAes));

        $ctChacha = Aead::encrypt(CipherSuite::ChaCha20Poly1305, $key, $nonce, $plaintext);
        $this->assertSame(strlen($plaintext) + Aead::TAG_SIZE, strlen($ctChacha));
    }

    public function testEmptyPlaintextRoundtrip(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $aad = 'some-context';

        foreach ([CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] as $suite) {
            $ciphertext = Aead::encrypt($suite, $key, $nonce, '', $aad);
            $decrypted = Aead::decrypt($suite, $key, $nonce, $ciphertext, $aad);
            $this->assertSame('', $decrypted);
        }
    }

    public function testEmptyAadRoundtrip(): void
    {
        $key = $this->testKey();
        $nonce = $this->testNonce();
        $plaintext = 'data with no aad';

        foreach ([CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] as $suite) {
            $ciphertext = Aead::encrypt($suite, $key, $nonce, $plaintext);
            $decrypted = Aead::decrypt($suite, $key, $nonce, $ciphertext);
            $this->assertSame($plaintext, $decrypted);
        }
    }
}
