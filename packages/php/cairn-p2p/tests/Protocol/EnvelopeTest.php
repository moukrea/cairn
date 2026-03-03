<?php

declare(strict_types=1);

namespace Cairn\Tests\Protocol;

use Cairn\Error\CairnException;
use Cairn\Protocol\Envelope;
use Cairn\Protocol\MessageType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Envelope::class)]
final class EnvelopeTest extends TestCase
{
    public function testNewMsgIdIs16Bytes(): void
    {
        $id = Envelope::newMsgId();
        $this->assertSame(16, strlen($id));
    }

    public function testNewMsgIdIsUnique(): void
    {
        $id1 = Envelope::newMsgId();
        $id2 = Envelope::newMsgId();
        $this->assertNotSame($id1, $id2);
    }

    public function testRoundtripMinimalEnvelope(): void
    {
        $envelope = new Envelope(
            version: 1,
            messageType: MessageType::HEARTBEAT,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: '',
            authTag: null,
        );

        $encoded = $envelope->encode();
        $decoded = Envelope::decode($encoded);

        $this->assertSame($envelope->version, $decoded->version);
        $this->assertSame($envelope->messageType, $decoded->messageType);
        $this->assertSame($envelope->msgId, $decoded->msgId);
        $this->assertNull($decoded->sessionId);
        $this->assertSame($envelope->payload, $decoded->payload);
        $this->assertNull($decoded->authTag);
    }

    public function testRoundtripFullEnvelope(): void
    {
        $sessionId = str_repeat("\xAB", 32);
        $envelope = new Envelope(
            version: 1,
            messageType: MessageType::DATA_MESSAGE,
            msgId: Envelope::newMsgId(),
            sessionId: $sessionId,
            payload: "\xCA\xFE\xBA\xBE",
            authTag: "\xDE\xAD",
        );

        $encoded = $envelope->encode();
        $decoded = Envelope::decode($encoded);

        $this->assertSame($envelope->version, $decoded->version);
        $this->assertSame($envelope->messageType, $decoded->messageType);
        $this->assertSame($envelope->msgId, $decoded->msgId);
        $this->assertSame($sessionId, $decoded->sessionId);
        $this->assertSame($envelope->payload, $decoded->payload);
        $this->assertSame("\xDE\xAD", $decoded->authTag);
    }

    public function testOptionalFieldsAbsent(): void
    {
        $envelope = new Envelope(
            version: 1,
            messageType: MessageType::PAIR_REQUEST,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: "\x01",
            authTag: null,
        );

        $encoded = $envelope->encode();
        $decoded = Envelope::decode($encoded);

        $this->assertNull($decoded->sessionId);
        $this->assertNull($decoded->authTag);
    }

    public function testDeterministicEncodingIsStable(): void
    {
        $envelope = new Envelope(
            version: 1,
            messageType: MessageType::HEARTBEAT,
            msgId: str_repeat("\x01", 16),
            sessionId: str_repeat("\x02", 32),
            payload: "\xFF",
            authTag: "\x00\x01",
        );

        $enc1 = $envelope->encodeDeterministic();
        $enc2 = $envelope->encodeDeterministic();
        $this->assertSame($enc1, $enc2);
    }

    public function testDecodeInvalidCbor(): void
    {
        $this->expectException(CairnException::class);
        Envelope::decode("\xFF\xFF\xFF");
    }

    public function testVersionFieldPreserved(): void
    {
        foreach ([0, 1, 255] as $v) {
            $envelope = new Envelope(
                version: $v,
                messageType: MessageType::HEARTBEAT,
                msgId: str_repeat("\x00", 16),
                sessionId: null,
                payload: '',
                authTag: null,
            );

            $decoded = Envelope::decode($envelope->encode());
            $this->assertSame($v, $decoded->version);
        }
    }
}
