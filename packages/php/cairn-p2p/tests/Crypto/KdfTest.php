<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\Kdf;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Kdf::class)]
final class KdfTest extends TestCase
{
    public function testHkdfProducesDeterministicOutput(): void
    {
        $ikm = 'shared-secret-material';
        $out1 = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY);
        $out2 = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY);
        $this->assertSame($out1, $out2);
    }

    public function testDomainSeparationProducesDifferentKeys(): void
    {
        $ikm = 'same-input-keying-material';
        $sessionKey = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY);
        $rendezvousKey = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_RENDEZVOUS);
        $this->assertNotSame($sessionKey, $rendezvousKey);
    }

    public function testWithSaltDiffersFromWithout(): void
    {
        $ikm = 'input-keying-material';
        $salt = 'some-salt-value';
        $withSalt = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY, 32, $salt);
        $withoutSalt = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY);
        $this->assertNotSame($withSalt, $withoutSalt);
    }

    public function testVariousOutputLengths(): void
    {
        $ikm = 'key-material';
        $short = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY, 16);
        $this->assertSame(16, strlen($short));

        $long = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY, 64);
        $this->assertSame(64, strlen($long));
    }

    public function testDefaultOutputIs32Bytes(): void
    {
        $ikm = 'key-material';
        $result = Kdf::hkdfSha256($ikm, Kdf::HKDF_INFO_SESSION_KEY);
        $this->assertSame(32, strlen($result));
    }

    public function testAllDomainConstantsAreUnique(): void
    {
        $constants = [
            Kdf::HKDF_INFO_SESSION_KEY,
            Kdf::HKDF_INFO_RENDEZVOUS,
            Kdf::HKDF_INFO_SAS,
            Kdf::HKDF_INFO_CHAIN_KEY,
            Kdf::HKDF_INFO_MESSAGE_KEY,
            Kdf::HKDF_INFO_ROOT_CHAIN,
            Kdf::HKDF_INFO_CHAIN_ADVANCE,
            Kdf::HKDF_INFO_MSG_ENCRYPT,
        ];

        $unique = array_unique($constants);
        $this->assertCount(count($constants), $unique, 'Domain separation constants must be unique');
    }
}
