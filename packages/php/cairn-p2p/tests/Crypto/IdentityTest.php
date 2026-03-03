<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\Identity;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Identity::class)]
final class IdentityTest extends TestCase
{
    public function testGenerateAndRoundtripKeypair(): void
    {
        $kp = Identity::generate();
        $seed = $kp->seedBytes();
        $restored = Identity::fromSeed($seed);
        $this->assertSame($kp->publicKey(), $restored->publicKey());
    }

    public function testSignAndVerify(): void
    {
        $kp = Identity::generate();
        $message = 'hello cairn';
        $sig = $kp->sign($message);
        $kp->verify($message, $sig);
        $this->assertTrue(true); // No exception means success
    }

    public function testVerifyWrongMessageFails(): void
    {
        $kp = Identity::generate();
        $sig = $kp->sign('correct message');
        $this->expectException(CairnException::class);
        $kp->verify('wrong message', $sig);
    }

    public function testVerifyWrongKeyFails(): void
    {
        $kp1 = Identity::generate();
        $kp2 = Identity::generate();
        $sig = $kp1->sign('hello');
        $this->expectException(CairnException::class);
        $kp2->verify('hello', $sig);
    }

    public function testVerifySignatureStandalone(): void
    {
        $kp = Identity::generate();
        $message = 'standalone verify';
        $sig = $kp->sign($message);

        Identity::verifySignature($kp->publicKey(), $message, $sig);
        $this->assertTrue(true);
    }

    public function testPeerIdIsDeterministic(): void
    {
        $kp = Identity::generate();
        $id1 = $kp->peerId();
        $id2 = $kp->peerId();
        $this->assertTrue($id1->equals($id2));
    }

    public function testDifferentKeysProduceDifferentPeerIds(): void
    {
        $kp1 = Identity::generate();
        $kp2 = Identity::generate();
        $this->assertFalse($kp1->peerId()->equals($kp2->peerId()));
    }

    public function testSignatureIsDeterministic(): void
    {
        $kp = Identity::generate();
        $message = 'deterministic';
        $sig1 = $kp->sign($message);
        $sig2 = $kp->sign($message);
        $this->assertSame($sig1, $sig2);
    }

    public function testSignatureIs64Bytes(): void
    {
        $kp = Identity::generate();
        $sig = $kp->sign('test');
        $this->assertSame(64, strlen($sig));
    }

    public function testPublicKeyIs32Bytes(): void
    {
        $kp = Identity::generate();
        $this->assertSame(32, strlen($kp->publicKey()));
    }

    public function testFromSeedRejectsWrongSize(): void
    {
        $this->expectException(CairnException::class);
        Identity::fromSeed('too short');
    }
}
