<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PeerId::class)]
final class PeerIdTest extends TestCase
{
    public function testFromPublicKeyProduces34Bytes(): void
    {
        $kp = Identity::generate();
        $pid = PeerId::fromPublicKey($kp->publicKey());
        $this->assertSame(34, strlen($pid->asBytes()));
        $this->assertSame(0x12, ord($pid->asBytes()[0]));
        $this->assertSame(0x20, ord($pid->asBytes()[1]));
    }

    public function testFromPublicKeyIsDeterministic(): void
    {
        $kp = Identity::generate();
        $pid1 = PeerId::fromPublicKey($kp->publicKey());
        $pid2 = PeerId::fromPublicKey($kp->publicKey());
        $this->assertTrue($pid1->equals($pid2));
    }

    public function testDifferentKeysProduceDifferentPeerIds(): void
    {
        $kp1 = Identity::generate();
        $kp2 = Identity::generate();
        $pid1 = PeerId::fromPublicKey($kp1->publicKey());
        $pid2 = PeerId::fromPublicKey($kp2->publicKey());
        $this->assertFalse($pid1->equals($pid2));
    }

    public function testDisplayAndFromStringRoundtrip(): void
    {
        $kp = Identity::generate();
        $pid = PeerId::fromPublicKey($kp->publicKey());
        $display = (string) $pid;
        $parsed = PeerId::fromString($display);
        $this->assertTrue($pid->equals($parsed));
    }

    public function testFromStringRejectsInvalidBase58(): void
    {
        $this->expectException(CairnException::class);
        PeerId::fromString('0OOinvalid!!!');
    }

    public function testFromBytesRejectsWrongPrefix(): void
    {
        $bytes = str_repeat("\x00", 34);
        $bytes[0] = "\xFF"; // wrong code
        $bytes[1] = "\x20";
        $this->expectException(CairnException::class);
        PeerId::fromBytes($bytes);
    }

    public function testFromBytesRejectsWrongLength(): void
    {
        $this->expectException(CairnException::class);
        PeerId::fromBytes('too short');
    }

    public function testFromBytesRoundtrip(): void
    {
        $kp = Identity::generate();
        $pid = PeerId::fromPublicKey($kp->publicKey());
        $restored = PeerId::fromBytes($pid->asBytes());
        $this->assertTrue($pid->equals($restored));
    }
}
