<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Pairing\ConnectionHint;
use Cairn\Pairing\PairingPayload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PairingPayload::class)]
final class PairingPayloadTest extends TestCase
{
    private function makePayload(int $expiresAt = PHP_INT_MAX): PairingPayload
    {
        $identity = Identity::generate();
        $peerId = PeerId::fromPublicKey($identity->publicKey());

        return new PairingPayload(
            peerId: $peerId,
            nonce: str_repeat("\x42", 16),
            pakeCredential: str_repeat("\xAB", 32),
            connectionHints: [new ConnectionHint('rendezvous', 'relay.example.com:9090')],
            createdAt: 1700000000,
            expiresAt: $expiresAt,
        );
    }

    public function testCborRoundtrip(): void
    {
        $payload = $this->makePayload();
        $cbor = $payload->toCbor();
        $restored = PairingPayload::fromCbor($cbor);

        $this->assertTrue($payload->peerId->equals($restored->peerId));
        $this->assertSame($payload->nonce, $restored->nonce);
        $this->assertSame($payload->pakeCredential, $restored->pakeCredential);
        $this->assertSame($payload->createdAt, $restored->createdAt);
        $this->assertSame($payload->expiresAt, $restored->expiresAt);
        $this->assertNotNull($restored->connectionHints);
        $this->assertCount(1, $restored->connectionHints);
        $this->assertSame('rendezvous', $restored->connectionHints[0]->hintType);
        $this->assertSame('relay.example.com:9090', $restored->connectionHints[0]->value);
    }

    public function testCborRoundtripWithoutHints(): void
    {
        $identity = Identity::generate();
        $peerId = PeerId::fromPublicKey($identity->publicKey());

        $payload = new PairingPayload(
            peerId: $peerId,
            nonce: str_repeat("\xFF", 16),
            pakeCredential: str_repeat("\x00", 32),
            connectionHints: null,
            createdAt: 100,
            expiresAt: 400,
        );

        $cbor = $payload->toCbor();
        $restored = PairingPayload::fromCbor($cbor);

        $this->assertNull($restored->connectionHints);
        $this->assertSame($payload->nonce, $restored->nonce);
    }

    public function testExpiryCheck(): void
    {
        $payload = $this->makePayload(1700000300);

        $this->assertFalse($payload->isExpired(1700000100));
        $this->assertTrue($payload->isExpired(1700000301));
        $this->assertFalse($payload->isExpired(1700000300));
    }

    public function testCborRejectsInvalidData(): void
    {
        $this->expectException(CairnException::class);
        PairingPayload::fromCbor("\xFF\xFF");
    }

    public function testTypicalPayloadUnder256Bytes(): void
    {
        $payload = $this->makePayload();
        $cbor = $payload->toCbor();
        $this->assertLessThanOrEqual(256, strlen($cbor), 'payload was ' . strlen($cbor) . ' bytes');
    }
}
