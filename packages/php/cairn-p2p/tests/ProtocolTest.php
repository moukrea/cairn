<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\Protocol\Cbor;
use Cairn\Protocol\Envelope;
use Cairn\Protocol\MessageType;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Wire protocol and CBOR interoperability tests.
 *
 * Includes golden vectors for deterministic encoding verification
 * and cross-language compatibility.
 */
#[CoversClass(Cbor::class)]
#[CoversClass(Envelope::class)]
final class ProtocolTest extends TestCase
{
    // =========================================================================
    // CBOR deterministic encoding golden vectors
    // =========================================================================

    /**
     * Unsigned integers use shortest encoding.
     */
    public function testCborUnsignedIntegerEncoding(): void
    {
        // 0 -> 0x00
        $this->assertSame("\x00", Cbor::encode(0));
        // 1 -> 0x01
        $this->assertSame("\x01", Cbor::encode(1));
        // 23 -> 0x17
        $this->assertSame("\x17", Cbor::encode(23));
        // 24 -> 0x1818
        $this->assertSame("\x18\x18", Cbor::encode(24));
        // 255 -> 0x18ff
        $this->assertSame("\x18\xff", Cbor::encode(255));
        // 256 -> 0x190100
        $this->assertSame("\x19\x01\x00", Cbor::encode(256));
        // 65535 -> 0x19ffff
        $this->assertSame("\x19\xff\xff", Cbor::encode(65535));
        // 65536 -> 0x1a00010000
        $this->assertSame("\x1a\x00\x01\x00\x00", Cbor::encode(65536));
    }

    /**
     * Negative integer encoding.
     */
    public function testCborNegativeIntegerEncoding(): void
    {
        // -1 -> 0x20
        $this->assertSame("\x20", Cbor::encode(-1));
        // -10 -> 0x29
        $this->assertSame("\x29", Cbor::encode(-10));
        // -24 -> 0x37
        $this->assertSame("\x37", Cbor::encode(-24));
        // -25 -> 0x3818
        $this->assertSame("\x38\x18", Cbor::encode(-25));
    }

    /**
     * Byte string encoding.
     */
    public function testCborByteStringEncoding(): void
    {
        // Empty byte string -> 0x40
        $this->assertSame("\x40", Cbor::encode(''));
        // 4 bytes -> 0x44 + data
        $this->assertSame("\x44\x01\x02\x03\x04", Cbor::encode("\x01\x02\x03\x04"));
    }

    /**
     * Array encoding.
     */
    public function testCborArrayEncoding(): void
    {
        // Empty array -> 0x80
        $this->assertSame("\x80", Cbor::encode([]));
        // [1, 2, 3] -> 0x83 0x01 0x02 0x03
        $this->assertSame("\x83\x01\x02\x03", Cbor::encode([1, 2, 3]));
    }

    /**
     * Map encoding with deterministic key ordering.
     */
    public function testCborMapDeterministicKeyOrder(): void
    {
        // Map {1: "a", 0: "b"} should encode keys in ascending order: {0: "b", 1: "a"}
        $map = [1 => 'a', 0 => 'b'];
        $encoded = Cbor::encode($map);
        // Map of 2 entries, key 0 first, key 1 second
        $expected = "\xa2" . "\x00\x41b" . "\x01\x41a";
        $this->assertSame($expected, $encoded);
    }

    /**
     * Null and boolean encoding.
     */
    public function testCborNullAndBoolEncoding(): void
    {
        $this->assertSame("\xf6", Cbor::encode(null));
        $this->assertSame("\xf5", Cbor::encode(true));
        $this->assertSame("\xf4", Cbor::encode(false));
    }

    /**
     * CBOR encode/decode round-trip for various types.
     */
    public function testCborRoundTripTypes(): void
    {
        $values = [0, 1, 255, 65535, -1, -100, '', 'hello', true, false, null];
        foreach ($values as $value) {
            $encoded = Cbor::encode($value);
            $decoded = Cbor::decode($encoded);
            $this->assertSame($value, $decoded, "Round-trip failed for: " . var_export($value, true));
        }
    }

    /**
     * CBOR encode/decode round-trip for nested structures.
     */
    public function testCborRoundTripNestedStructure(): void
    {
        $data = [0 => 42, 1 => 'hello', 2 => [1, 2, 3]];
        $encoded = Cbor::encode($data);
        $decoded = Cbor::decode($encoded);
        $this->assertSame($data, $decoded);
    }

    // =========================================================================
    // Deterministic encoding stability
    // =========================================================================

    /**
     * Same input always produces identical bytes.
     */
    public function testDeterministicEncodingIsStable(): void
    {
        $data = [0 => 1, 1 => 0x0100, 4 => 'payload', 5 => "\xDE\xAD"];
        $e1 = Cbor::encode($data);
        $e2 = Cbor::encode($data);
        $this->assertSame($e1, $e2);
    }

    /**
     * Key insertion order does not affect output.
     */
    public function testDeterministicEncodingIgnoresInsertionOrder(): void
    {
        // Use non-sequential keys so both are treated as CBOR maps
        $a = [10 => 'x', 20 => 'y', 30 => 'z'];
        $b = [30 => 'z', 10 => 'x', 20 => 'y'];
        $this->assertSame(Cbor::encode($a), Cbor::encode($b));
    }

    // =========================================================================
    // Envelope encode/decode round-trip
    // =========================================================================

    /**
     * Full envelope round-trip with all fields.
     */
    public function testEnvelopeRoundTripAllFields(): void
    {
        $env = new Envelope(
            version: 1,
            messageType: MessageType::HELLO,
            msgId: Envelope::newMsgId(),
            sessionId: random_bytes(32),
            payload: 'test-payload',
            authTag: random_bytes(16),
        );

        $bytes = $env->encode();
        $restored = Envelope::decode($bytes);

        $this->assertSame($env->version, $restored->version);
        $this->assertSame($env->messageType, $restored->messageType);
        $this->assertSame($env->msgId, $restored->msgId);
        $this->assertSame($env->sessionId, $restored->sessionId);
        $this->assertSame($env->payload, $restored->payload);
        $this->assertSame($env->authTag, $restored->authTag);
    }

    /**
     * Envelope round-trip with optional fields null.
     */
    public function testEnvelopeRoundTripOptionalFieldsNull(): void
    {
        $env = new Envelope(
            version: 1,
            messageType: MessageType::PAKE_INIT,
            msgId: Envelope::newMsgId(),
            sessionId: null,
            payload: '',
            authTag: null,
        );

        $bytes = $env->encode();
        $restored = Envelope::decode($bytes);

        $this->assertNull($restored->sessionId);
        $this->assertNull($restored->authTag);
        $this->assertSame('', $restored->payload);
    }

    /**
     * Deterministic encoding produces stable output for envelopes.
     */
    public function testEnvelopeDeterministicEncoding(): void
    {
        $msgId = str_repeat("\xAB", 16);
        $env = new Envelope(
            version: 1,
            messageType: 0x0100,
            msgId: $msgId,
            sessionId: null,
            payload: 'test',
            authTag: null,
        );

        $e1 = $env->encode();
        $e2 = $env->encodeDeterministic();
        $this->assertSame($e1, $e2);

        // Decode and re-encode should produce identical bytes
        $restored = Envelope::decode($e1);
        $e3 = $restored->encode();
        $this->assertSame($e1, $e3);
    }

    /**
     * UUID v7 message IDs are 16 bytes.
     */
    public function testMsgIdIs16Bytes(): void
    {
        $id = Envelope::newMsgId();
        $this->assertSame(16, strlen($id));
    }

    /**
     * UUID v7 message IDs are timestamp-ordered.
     */
    public function testMsgIdsAreOrdered(): void
    {
        $id1 = Envelope::newMsgId();
        usleep(1000); // 1ms
        $id2 = Envelope::newMsgId();
        // UUID v7 bytes should be ordered (first 6 bytes are timestamp)
        $this->assertTrue($id1 < $id2 || $id1 === $id2);
    }

    // =========================================================================
    // Error handling
    // =========================================================================

    /**
     * Invalid CBOR data is rejected.
     */
    public function testInvalidCborDataRejected(): void
    {
        $this->expectException(CairnException::class);
        Cbor::decode("\xff\xff\xff");
    }

    /**
     * Envelope with missing required fields is rejected.
     */
    public function testEnvelopeMissingVersionRejected(): void
    {
        // Map without key 0 (version)
        $cbor = Cbor::encode([1 => 0x0100, 2 => str_repeat("\x00", 16), 4 => '']);
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/missing field version/');
        Envelope::decode($cbor);
    }

    /**
     * Envelope with wrong msg_id length is rejected.
     */
    public function testEnvelopeWrongMsgIdLengthRejected(): void
    {
        $cbor = Cbor::encode([0 => 1, 1 => 0x0100, 2 => 'too-short', 4 => '']);
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/msg_id/');
        Envelope::decode($cbor);
    }

    // =========================================================================
    // Message type registry coverage
    // =========================================================================

    /**
     * All message type constants are distinct.
     */
    public function testMessageTypeConstantsDistinct(): void
    {
        $ref = new \ReflectionClass(MessageType::class);
        $constants = $ref->getConstants();
        $values = array_values($constants);
        $unique = array_unique($values);
        $this->assertCount(count($values), $unique, 'Message type constants must be unique');
    }

    /**
     * Core message types have expected values from spec.
     */
    public function testCoreMessageTypeValues(): void
    {
        $this->assertSame(0x0100, MessageType::HELLO);
        $this->assertSame(0x0101, MessageType::HELLO_ACK);
    }
}
