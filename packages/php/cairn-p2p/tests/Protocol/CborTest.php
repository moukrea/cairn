<?php

declare(strict_types=1);

namespace Cairn\Tests\Protocol;

use Cairn\Error\CairnException;
use Cairn\Protocol\Cbor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Cbor::class)]
final class CborTest extends TestCase
{
    public function testEncodeDecodeSmallUnsigned(): void
    {
        // 0 encodes as single byte 0x00
        $this->assertSame("\x00", Cbor::encode(0));
        $this->assertSame(0, Cbor::decode("\x00"));

        // 23 encodes as single byte 0x17
        $this->assertSame("\x17", Cbor::encode(23));
        $this->assertSame(23, Cbor::decode("\x17"));
    }

    public function testEncodeDecodeOneByte(): void
    {
        // 24 encodes as 0x18 0x18
        $this->assertSame("\x18\x18", Cbor::encode(24));
        $this->assertSame(24, Cbor::decode("\x18\x18"));

        // 255 encodes as 0x18 0xFF
        $this->assertSame("\x18\xFF", Cbor::encode(255));
        $this->assertSame(255, Cbor::decode("\x18\xFF"));
    }

    public function testEncodeDecodeTwoBytes(): void
    {
        // 256 encodes as 0x19 0x01 0x00
        $this->assertSame("\x19\x01\x00", Cbor::encode(256));
        $this->assertSame(256, Cbor::decode("\x19\x01\x00"));

        // 0x0400 (HEARTBEAT) encodes as 0x19 0x04 0x00
        $this->assertSame("\x19\x04\x00", Cbor::encode(0x0400));
        $this->assertSame(0x0400, Cbor::decode("\x19\x04\x00"));
    }

    public function testEncodeDecodeByteString(): void
    {
        $data = "\xCA\xFE\xBA\xBE";
        $encoded = Cbor::encode($data);
        $this->assertSame($data, Cbor::decode($encoded));
    }

    public function testEncodeDecodeEmptyByteString(): void
    {
        $encoded = Cbor::encode('');
        $this->assertSame("\x40", $encoded); // empty byte string
        $this->assertSame('', Cbor::decode($encoded));
    }

    public function testEncodeDecodeArray(): void
    {
        $arr = [1, 2, 3];
        $encoded = Cbor::encode($arr);
        $this->assertSame($arr, Cbor::decode($encoded));
    }

    public function testEncodeDecodeEmptyArray(): void
    {
        $encoded = Cbor::encode([]);
        $this->assertSame("\x80", $encoded); // empty array
        $this->assertSame([], Cbor::decode($encoded));
    }

    public function testEncodeDecodeMapWithIntKeys(): void
    {
        $map = [0 => 1, 1 => 256];
        $encoded = Cbor::encode($map);
        $decoded = Cbor::decode($encoded);
        $this->assertSame($map, $decoded);
    }

    public function testMapKeysSortedDeterministically(): void
    {
        // Even if we provide keys out of order, CBOR should sort them
        $map = [4 => 'payload', 0 => 1, 2 => 'msgid'];
        $enc1 = Cbor::encode($map);
        // Re-encode with keys in different order
        $map2 = [0 => 1, 2 => 'msgid', 4 => 'payload'];
        $enc2 = Cbor::encode($map2);
        $this->assertSame($enc1, $enc2);
    }

    public function testEncodeDecodeTextString(): void
    {
        $text = 'versions';
        $encoded = Cbor::encodeText($text);
        // Major type 3 (text string), length 8: 0x68
        $this->assertSame("\x68versions", $encoded);
        $decoded = Cbor::decode($encoded);
        $this->assertSame($text, $decoded);
    }

    public function testDecodeInvalidData(): void
    {
        $this->expectException(CairnException::class);
        Cbor::decode('');
    }

    public function testEncodeDecodeNull(): void
    {
        $encoded = Cbor::encode(null);
        $this->assertSame("\xF6", $encoded);
        $this->assertNull(Cbor::decode($encoded));
    }

    public function testEncodeDecodeBool(): void
    {
        $this->assertSame("\xF5", Cbor::encode(true));
        $this->assertSame("\xF4", Cbor::encode(false));
        $this->assertTrue(Cbor::decode("\xF5"));
        $this->assertFalse(Cbor::decode("\xF4"));
    }
}
