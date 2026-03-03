<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Pairing\ConnectionHint;
use Cairn\Pairing\PairingPayload;
use Cairn\Pairing\QrCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(QrCode::class)]
final class QrCodeTest extends TestCase
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

    public function testGeneratePayloadRoundtrip(): void
    {
        $payload = $this->makePayload();
        $raw = QrCode::generatePayload($payload);
        $this->assertLessThanOrEqual(256, strlen($raw));

        $restored = QrCode::consumePayload($raw);
        $this->assertTrue($payload->peerId->equals($restored->peerId));
        $this->assertSame($payload->nonce, $restored->nonce);
        $this->assertSame($payload->pakeCredential, $restored->pakeCredential);
    }

    public function testRejectsOversizedPayload(): void
    {
        $identity = Identity::generate();
        $peerId = PeerId::fromPublicKey($identity->publicKey());

        $payload = new PairingPayload(
            peerId: $peerId,
            nonce: str_repeat("\x42", 16),
            pakeCredential: str_repeat("\xAB", 32),
            connectionHints: array_map(
                fn(int $i) => new ConnectionHint("type-{$i}", "very-long-value-{$i}-padding-data-here"),
                range(0, 19),
            ),
            createdAt: 1700000000,
            expiresAt: PHP_INT_MAX,
        );

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/maximum size/');
        QrCode::generatePayload($payload);
    }

    public function testRejectsExpiredPayload(): void
    {
        $payload = $this->makePayload(1000); // expired long ago
        $raw = $payload->toCbor();

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/expired/');
        QrCode::consumePayload($raw);
    }

    public function testTypicalPayloadFits(): void
    {
        $payload = $this->makePayload();
        $raw = QrCode::generatePayload($payload);
        $this->assertLessThanOrEqual(200, strlen($raw), 'payload was ' . strlen($raw) . ' bytes');
    }
}
