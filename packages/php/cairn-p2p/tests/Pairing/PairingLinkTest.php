<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Pairing\ConnectionHint;
use Cairn\Pairing\PairingLink;
use Cairn\Pairing\PairingPayload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PairingLink::class)]
final class PairingLinkTest extends TestCase
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

    public function testGenerateAndParseRoundtrip(): void
    {
        $payload = $this->makePayload();
        $uri = PairingLink::generate($payload);

        $this->assertStringStartsWith('cairn://pair?', $uri);

        $restored = PairingLink::parse($uri);
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

    public function testRoundtripWithoutHints(): void
    {
        $identity = Identity::generate();
        $peerId = PeerId::fromPublicKey($identity->publicKey());

        $payload = new PairingPayload(
            peerId: $peerId,
            nonce: str_repeat("\xFF", 16),
            pakeCredential: str_repeat("\x00", 32),
            connectionHints: null,
            createdAt: 1700000000,
            expiresAt: PHP_INT_MAX,
        );

        $uri = PairingLink::generate($payload);
        $restored = PairingLink::parse($uri);

        $this->assertNull($restored->connectionHints);
        $this->assertSame($payload->nonce, $restored->nonce);
    }

    public function testRejectsExpiredLink(): void
    {
        $payload = $this->makePayload(1000);
        $uri = PairingLink::generate($payload);

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/expired/');
        PairingLink::parse($uri);
    }

    public function testRejectsWrongScheme(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches("/expected scheme 'cairn'/");
        PairingLink::parse('https://pair?pid=abc&nonce=abc&pake=abc');
    }

    public function testRejectsMissingPid(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches("/missing 'pid'/");
        PairingLink::parse('cairn://pair?nonce=aa&pake=bb');
    }

    public function testRejectsMissingNonce(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches("/missing 'nonce'/");
        PairingLink::parse('cairn://pair?pid=abc&pake=bb');
    }

    public function testRejectsMissingPake(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches("/missing 'pake'/");
        PairingLink::parse('cairn://pair?pid=abc&nonce=aa');
    }

    public function testCustomScheme(): void
    {
        $payload = $this->makePayload();
        $uri = PairingLink::generate($payload, 'myapp');

        $this->assertStringStartsWith('myapp://pair?', $uri);

        $restored = PairingLink::parse($uri, 'myapp');
        $this->assertTrue($payload->peerId->equals($restored->peerId));
    }

    public function testCustomSchemeRejectsDefault(): void
    {
        $payload = $this->makePayload();
        $uri = PairingLink::generate($payload); // cairn:// scheme

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches("/expected scheme 'myapp'/");
        PairingLink::parse($uri, 'myapp');
    }

    public function testMultipleHintsRoundtrip(): void
    {
        $identity = Identity::generate();
        $peerId = PeerId::fromPublicKey($identity->publicKey());

        $payload = new PairingPayload(
            peerId: $peerId,
            nonce: str_repeat("\x42", 16),
            pakeCredential: str_repeat("\xAB", 32),
            connectionHints: [
                new ConnectionHint('rendezvous', 'relay.example.com:9090'),
                new ConnectionHint('address', '192.168.1.100:4433'),
            ],
            createdAt: 1700000000,
            expiresAt: PHP_INT_MAX,
        );

        $uri = PairingLink::generate($payload);
        $restored = PairingLink::parse($uri);

        $this->assertNotNull($restored->connectionHints);
        $this->assertCount(2, $restored->connectionHints);
        $this->assertSame('rendezvous', $restored->connectionHints[0]->hintType);
        $this->assertSame('address', $restored->connectionHints[1]->hintType);
    }
}
