<?php

declare(strict_types=1);

namespace Cairn\Tests\Protocol;

use Cairn\Error\CairnException;
use Cairn\Protocol\Envelope;
use Cairn\Protocol\MessageType;
use Cairn\Protocol\VersionNegotiate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(VersionNegotiate::class)]
final class VersionNegotiateTest extends TestCase
{
    public function testCurrentVersionIs1(): void
    {
        $this->assertSame(1, VersionNegotiate::CURRENT_VERSION);
    }

    public function testSupportedVersionsContainsCurrent(): void
    {
        $this->assertContains(
            VersionNegotiate::CURRENT_VERSION,
            VersionNegotiate::SUPPORTED_VERSIONS,
        );
    }

    public function testSelectVersionCommon(): void
    {
        $this->assertSame(2, VersionNegotiate::selectVersion([3, 2, 1], [2, 1]));
    }

    public function testSelectVersionExactMatch(): void
    {
        $this->assertSame(1, VersionNegotiate::selectVersion([1], [1]));
    }

    public function testSelectVersionPicksHighestMutual(): void
    {
        $this->assertSame(3, VersionNegotiate::selectVersion([5, 3, 1], [4, 3, 2, 1]));
    }

    public function testSelectVersionNoCommon(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/version mismatch/');
        VersionNegotiate::selectVersion([3, 2], [5, 4]);
    }

    public function testSelectVersionEmptyOurs(): void
    {
        $this->expectException(CairnException::class);
        VersionNegotiate::selectVersion([], [1]);
    }

    public function testSelectVersionEmptyPeer(): void
    {
        $this->expectException(CairnException::class);
        VersionNegotiate::selectVersion([1], []);
    }

    public function testCreateNegotiateEnvelope(): void
    {
        $envelope = VersionNegotiate::createNegotiate();

        $this->assertSame(VersionNegotiate::CURRENT_VERSION, $envelope->version);
        $this->assertSame(MessageType::VERSION_NEGOTIATE, $envelope->messageType);
        $this->assertNull($envelope->sessionId);
        $this->assertNull($envelope->authTag);

        $versions = VersionNegotiate::parseNegotiate($envelope);
        $this->assertSame(VersionNegotiate::SUPPORTED_VERSIONS, $versions);
    }

    public function testParseNegotiateWrongType(): void
    {
        $envelope = new Envelope(
            version: 1,
            messageType: MessageType::PAIR_REQUEST,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: '',
            authTag: null,
        );

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/VERSION_NEGOTIATE/');
        VersionNegotiate::parseNegotiate($envelope);
    }

    public function testHandleNegotiateCompatible(): void
    {
        $initiator = VersionNegotiate::createNegotiate();
        [$selected, $response] = VersionNegotiate::handleNegotiate($initiator);

        $this->assertSame(1, $selected);
        $this->assertSame(MessageType::VERSION_NEGOTIATE, $response->messageType);

        $respVersions = VersionNegotiate::parseNegotiate($response);
        $this->assertSame([1], $respVersions);
    }

    public function testFullNegotiationRoundtrip(): void
    {
        // Alice initiates
        $aliceOffer = VersionNegotiate::createNegotiate();
        $aliceWire = $aliceOffer->encode();

        // Bob receives and responds
        $bobReceived = Envelope::decode($aliceWire);
        [$selected, $bobResponse] = VersionNegotiate::handleNegotiate($bobReceived);
        $this->assertSame(1, $selected);
        $bobWire = $bobResponse->encode();

        // Alice processes the response
        $aliceReceived = Envelope::decode($bobWire);
        $respVersions = VersionNegotiate::parseNegotiate($aliceReceived);
        $this->assertSame([1], $respVersions);
    }
}
