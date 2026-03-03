<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\X25519Keypair;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(X25519Keypair::class)]
final class X25519KeypairTest extends TestCase
{
    public function testSharedSecretMatchesBothSides(): void
    {
        $alice = X25519Keypair::generate();
        $bob = X25519Keypair::generate();

        $aliceShared = $alice->diffieHellman($bob->publicKeyBytes());
        $bobShared = $bob->diffieHellman($alice->publicKeyBytes());

        $this->assertSame($aliceShared, $bobShared);
    }

    public function testDifferentPeersProduceDifferentSharedSecrets(): void
    {
        $alice = X25519Keypair::generate();
        $bob = X25519Keypair::generate();
        $charlie = X25519Keypair::generate();

        $ab = $alice->diffieHellman($bob->publicKeyBytes());
        $ac = $alice->diffieHellman($charlie->publicKeyBytes());

        $this->assertNotSame($ab, $ac);
    }

    public function testFromSecretKeyRoundtrip(): void
    {
        $original = X25519Keypair::generate();
        $secret = $original->secretKeyBytes();
        $restored = X25519Keypair::fromSecretKey($secret);

        $this->assertSame($original->publicKeyBytes(), $restored->publicKeyBytes());
    }

    public function testPublicKeyIs32Bytes(): void
    {
        $kp = X25519Keypair::generate();
        $this->assertSame(32, strlen($kp->publicKeyBytes()));
    }

    public function testSharedSecretIs32Bytes(): void
    {
        $alice = X25519Keypair::generate();
        $bob = X25519Keypair::generate();
        $shared = $alice->diffieHellman($bob->publicKeyBytes());
        $this->assertSame(32, strlen($shared));
    }
}
