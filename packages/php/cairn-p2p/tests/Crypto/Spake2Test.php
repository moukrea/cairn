<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\Spake2;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Spake2::class)]
final class Spake2Test extends TestCase
{
    protected function setUp(): void
    {
        if (!function_exists('sodium_crypto_core_ed25519_scalar_random')) {
            $this->markTestSkipped('Ed25519 sodium functions not available');
        }
    }

    public function testMatchingPasswordsProduceMatchingSecrets(): void
    {
        $password = '123456';
        $sideA = Spake2::startA($password);
        $sideB = Spake2::startB($password);

        $msgA = $sideA->outboundMessage();
        $msgB = $sideB->outboundMessage();

        $secretA = $sideA->finish($msgB);
        $secretB = $sideB->finish($msgA);

        $this->assertSame($secretA, $secretB);
    }

    public function testDifferentPasswordsProduceDifferentSecrets(): void
    {
        $sideA = Spake2::startA('password1');
        $sideB = Spake2::startB('password2');

        $msgA = $sideA->outboundMessage();
        $msgB = $sideB->outboundMessage();

        $secretA = $sideA->finish($msgB);
        $secretB = $sideB->finish($msgA);

        $this->assertNotSame($secretA, $secretB);
    }

    public function testSharedSecretIs32Bytes(): void
    {
        $password = 'test';
        $sideA = Spake2::startA($password);
        $sideB = Spake2::startB($password);

        $secret = $sideA->finish($sideB->outboundMessage());
        $this->assertSame(32, strlen($secret));
    }

    public function testOutboundMessageIs33Bytes(): void
    {
        $sideA = Spake2::startA('password');
        $this->assertSame(33, strlen($sideA->outboundMessage()));
    }

    public function testFinishTwiceThrows(): void
    {
        $sideA = Spake2::startA('password');
        $sideB = Spake2::startB('password');

        $sideA->finish($sideB->outboundMessage());

        $this->expectException(CairnException::class);
        $sideA->finish($sideB->outboundMessage());
    }

    public function testDifferentSessionsProduceDifferentMessages(): void
    {
        $session1 = Spake2::startA('password');
        $session2 = Spake2::startA('password');

        // Messages should differ due to random scalars
        $this->assertNotSame($session1->outboundMessage(), $session2->outboundMessage());
    }
}
