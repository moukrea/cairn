<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\Crypto\Identity;
use Cairn\Crypto\Kdf;
use Cairn\Pairing\PairingPayload;
use Cairn\Pairing\PinCode;
use Cairn\Pairing\PairingLink;
use Cairn\Pairing\RateLimiter;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Pairing mechanism tests: QR round-trip, PIN normalization,
 * link URI parsing, rate limiter behavior.
 */
#[CoversClass(PairingPayload::class)]
#[CoversClass(PinCode::class)]
#[CoversClass(PairingLink::class)]
#[CoversClass(RateLimiter::class)]
final class PairingTest extends TestCase
{
    // =========================================================================
    // PairingPayload round-trip
    // =========================================================================

    /**
     * PairingPayload CBOR encode/decode round-trip.
     */
    public function testPayloadCborRoundTrip(): void
    {
        $identity = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );

        $encoded = $payload->toCbor();
        $this->assertIsString($encoded);
        $this->assertNotEmpty($encoded);

        $decoded = PairingPayload::fromCbor($encoded);
        $this->assertTrue($decoded->peerId->equals($payload->peerId));
        $this->assertSame($payload->nonce, $decoded->nonce);
        $this->assertSame($payload->pakeCredential, $decoded->pakeCredential);
    }

    /**
     * PairingPayload has 16-byte nonce.
     */
    public function testPayloadNonceIs16Bytes(): void
    {
        $identity = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );
        $this->assertSame(16, strlen($payload->nonce));
    }

    /**
     * PairingPayload has expiry in the future.
     */
    public function testPayloadExpiresInFuture(): void
    {
        $identity = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );
        $now = time();
        $this->assertGreaterThan($now, $payload->expiresAt);
    }

    /**
     * PairingPayload expiry detection.
     */
    public function testPayloadExpiryDetection(): void
    {
        $identity = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );
        $this->assertFalse($payload->isExpired());

        // Create an already-expired payload
        $expired = new PairingPayload(
            peerId: $identity->peerId(),
            nonce: random_bytes(16),
            pakeCredential: random_bytes(32),
            connectionHints: [],
            createdAt: 1000,
            expiresAt: 1001,
        );
        $this->assertTrue($expired->isExpired());
    }

    // =========================================================================
    // PIN code (Crockford Base32)
    // =========================================================================

    /**
     * PIN code generation returns formatted XXXX-XXXX.
     */
    public function testPinCodeFormat(): void
    {
        $pin = PinCode::format(PinCode::generate());
        $this->assertSame(9, strlen($pin));
        $this->assertSame('-', $pin[4]);
    }

    /**
     * PIN code normalization handles Crockford confusables.
     */
    public function testPinCodeNormalization(): void
    {
        // Crockford Base32 normalization:
        // O/o -> 0, I/i/L/l -> 1
        $this->assertSame('0', PinCode::normalizeCrockford('O'));
        $this->assertSame('0', PinCode::normalizeCrockford('o'));
        $this->assertSame('1', PinCode::normalizeCrockford('I'));
        $this->assertSame('1', PinCode::normalizeCrockford('i'));
        $this->assertSame('1', PinCode::normalizeCrockford('L'));
        $this->assertSame('1', PinCode::normalizeCrockford('l'));
    }

    /**
     * PIN code normalization is idempotent.
     */
    public function testPinCodeNormalizationIdempotent(): void
    {
        $pin = PinCode::generate();
        $n1 = PinCode::normalizeCrockford($pin);
        $n2 = PinCode::normalizeCrockford($n1);
        $this->assertSame($n1, $n2);
    }

    /**
     * PIN code normalization strips whitespace/dashes.
     */
    public function testPinCodeNormalizationStripsFormatting(): void
    {
        $raw = '1234-5678';
        $normalized = PinCode::normalizeCrockford($raw);
        $this->assertStringNotContainsString('-', $normalized);
    }

    // =========================================================================
    // Pairing link URI
    // =========================================================================

    /**
     * Pairing link generation produces valid cairn:// URI.
     */
    public function testPairingLinkUriFormat(): void
    {
        $identity = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );
        $uri = PairingLink::toUri($payload);
        $this->assertStringStartsWith('cairn://pair?', $uri);
        $this->assertStringContainsString('pid=', $uri);
        $this->assertStringContainsString('nonce=', $uri);
        $this->assertStringContainsString('pake=', $uri);
    }

    /**
     * Pairing link round-trip: encode -> decode -> same payload.
     */
    public function testPairingLinkRoundTrip(): void
    {
        $identity = Identity::generate();
        $original = PairingPayload::create(
            peerId: $identity->peerId(),
            pakeCredential: random_bytes(32),
        );
        $uri = PairingLink::toUri($original);
        $restored = PairingLink::fromUri($uri);

        $this->assertTrue($restored->peerId->equals($original->peerId));
        $this->assertSame($original->nonce, $restored->nonce);
        $this->assertSame($original->pakeCredential, $restored->pakeCredential);
    }

    /**
     * Invalid pairing link URI is rejected.
     */
    public function testInvalidPairingLinkRejected(): void
    {
        $this->expectException(CairnException::class);
        PairingLink::fromUri('https://example.com/not-a-pairing-link');
    }

    // =========================================================================
    // Rate limiter
    // =========================================================================

    /**
     * Rate limiter allows requests within limit.
     */
    public function testRateLimiterAllowsWithinLimit(): void
    {
        $limiter = new RateLimiter(maxAttempts: 3, windowSeconds: 60);
        $this->assertTrue($limiter->attempt('peer-1'));
        $this->assertTrue($limiter->attempt('peer-1'));
        $this->assertTrue($limiter->attempt('peer-1'));
    }

    /**
     * Rate limiter blocks after max attempts.
     */
    public function testRateLimiterBlocksAfterMax(): void
    {
        $limiter = new RateLimiter(maxAttempts: 2, windowSeconds: 60);
        $this->assertTrue($limiter->attempt('peer-1'));
        $this->assertTrue($limiter->attempt('peer-1'));
        $this->assertFalse($limiter->attempt('peer-1'));
    }

    /**
     * Rate limiter tracks peers independently.
     */
    public function testRateLimiterIndependentPeers(): void
    {
        $limiter = new RateLimiter(maxAttempts: 1, windowSeconds: 60);
        $this->assertTrue($limiter->attempt('peer-1'));
        $this->assertTrue($limiter->attempt('peer-2'));
        $this->assertFalse($limiter->attempt('peer-1'));
    }

    /**
     * Rate limiter reset clears all state.
     */
    public function testRateLimiterReset(): void
    {
        $limiter = new RateLimiter(maxAttempts: 1, windowSeconds: 60);
        $limiter->attempt('peer-1');
        $this->assertFalse($limiter->attempt('peer-1'));

        $limiter->reset('peer-1');
        $this->assertTrue($limiter->attempt('peer-1'));
    }
}
