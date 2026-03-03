<?php

declare(strict_types=1);

namespace Cairn\Protocol;

use Cairn\Error\CairnException;

/**
 * Minimal CBOR encoder/decoder for the cairn wire protocol.
 *
 * Implements RFC 8949 encoding/decoding for the subset of CBOR types used
 * in the message envelope: unsigned integers, byte strings, text strings,
 * arrays, and maps with integer keys. Always produces deterministic output
 * (shortest encoding, sorted keys) per RFC 8949 section 4.2.
 */
final class Cbor
{
    // CBOR major types
    private const MAJOR_UNSIGNED = 0;
    private const MAJOR_NEGATIVE = 1;
    private const MAJOR_BYTES = 2;
    private const MAJOR_TEXT = 3;
    private const MAJOR_ARRAY = 4;
    private const MAJOR_MAP = 5;

    private function __construct()
    {
    }

    /**
     * Encode a PHP value to CBOR bytes.
     *
     * Supports: int (non-negative), string (as byte string), array (indexed or associative).
     *
     * @throws CairnException
     */
    public static function encode(mixed $value): string
    {
        if (is_int($value)) {
            if ($value < 0) {
                return self::encodeHead(self::MAJOR_NEGATIVE, -1 - $value);
            }
            return self::encodeHead(self::MAJOR_UNSIGNED, $value);
        }

        if (is_string($value)) {
            return self::encodeHead(self::MAJOR_BYTES, strlen($value)) . $value;
        }

        if (is_array($value)) {
            if (array_is_list($value)) {
                return self::encodeArray($value);
            }
            return self::encodeMap($value);
        }

        if (is_null($value)) {
            // CBOR null (major 7, additional 22)
            return "\xF6";
        }

        if (is_bool($value)) {
            return $value ? "\xF5" : "\xF4";
        }

        throw new CairnException('CBOR encode: unsupported type ' . get_debug_type($value));
    }

    /**
     * Encode a string as a CBOR text string (major type 3) instead of byte string.
     */
    public static function encodeText(string $value): string
    {
        return self::encodeHead(self::MAJOR_TEXT, strlen($value)) . $value;
    }

    /**
     * Decode CBOR bytes to a PHP value.
     *
     * @return array{0: mixed, 1: int} Tuple of (decoded value, bytes consumed)
     * @throws CairnException
     */
    public static function decodeValue(string $data, int $offset = 0): array
    {
        if ($offset >= strlen($data)) {
            throw new CairnException('CBOR decode: unexpected end of data');
        }

        $initial = ord($data[$offset]);
        $major = $initial >> 5;
        $additional = $initial & 0x1F;

        return match ($major) {
            self::MAJOR_UNSIGNED => self::decodeUnsigned($data, $offset, $additional),
            self::MAJOR_NEGATIVE => self::decodeNegative($data, $offset, $additional),
            self::MAJOR_BYTES => self::decodeBytes($data, $offset, $additional),
            self::MAJOR_TEXT => self::decodeText($data, $offset, $additional),
            self::MAJOR_ARRAY => self::decodeArray($data, $offset, $additional),
            self::MAJOR_MAP => self::decodeMap($data, $offset, $additional),
            7 => self::decodeSimple($data, $offset, $additional),
            default => throw new CairnException("CBOR decode: unsupported major type {$major}"),
        };
    }

    /**
     * Decode a full CBOR item from bytes.
     *
     * @throws CairnException
     */
    public static function decode(string $data): mixed
    {
        [$value] = self::decodeValue($data);
        return $value;
    }

    /**
     * Encode a CBOR head (major type + argument).
     */
    private static function encodeHead(int $major, int $value): string
    {
        $majorShifted = $major << 5;

        if ($value <= 23) {
            return chr($majorShifted | $value);
        }
        if ($value <= 0xFF) {
            return chr($majorShifted | 24) . chr($value);
        }
        if ($value <= 0xFFFF) {
            return chr($majorShifted | 25) . pack('n', $value);
        }
        if ($value <= 0xFFFFFFFF) {
            return chr($majorShifted | 26) . pack('N', $value);
        }
        return chr($majorShifted | 27) . pack('J', $value);
    }

    /**
     * @param list<mixed> $items
     */
    private static function encodeArray(array $items): string
    {
        $result = self::encodeHead(self::MAJOR_ARRAY, count($items));
        foreach ($items as $item) {
            $result .= self::encode($item);
        }
        return $result;
    }

    /**
     * Encode an associative array as a CBOR map with deterministic key ordering.
     *
     * Keys are sorted by their CBOR encoding (per RFC 8949 section 4.2.1).
     *
     * @param array<int|string, mixed> $map
     */
    private static function encodeMap(array $map): string
    {
        // For deterministic encoding, sort by CBOR-encoded key bytes
        $entries = [];
        foreach ($map as $key => $value) {
            $encodedKey = self::encode($key);
            $entries[] = [$encodedKey, self::encode($value)];
        }

        usort($entries, static function (array $a, array $b): int {
            return strcmp($a[0], $b[0]);
        });

        $result = self::encodeHead(self::MAJOR_MAP, count($entries));
        foreach ($entries as [$encodedKey, $encodedValue]) {
            $result .= $encodedKey . $encodedValue;
        }
        return $result;
    }

    /**
     * Read the argument value from additional info.
     *
     * @return array{0: int, 1: int} Tuple of (value, total bytes consumed including initial byte)
     * @throws CairnException
     */
    private static function readArgument(string $data, int $offset, int $additional): array
    {
        if ($additional <= 23) {
            return [$additional, 1];
        }

        if ($additional === 24) {
            return [ord($data[$offset + 1]), 2];
        }

        if ($additional === 25) {
            /** @var array{1: int} $unpacked */
            $unpacked = unpack('n', substr($data, $offset + 1, 2));
            return [$unpacked[1], 3];
        }

        if ($additional === 26) {
            /** @var array{1: int} $unpacked */
            $unpacked = unpack('N', substr($data, $offset + 1, 4));
            return [$unpacked[1], 5];
        }

        if ($additional === 27) {
            /** @var array{1: int} $unpacked */
            $unpacked = unpack('J', substr($data, $offset + 1, 8));
            return [$unpacked[1], 9];
        }

        throw new CairnException("CBOR decode: unsupported additional info {$additional}");
    }

    /**
     * @return array{0: int, 1: int}
     */
    private static function decodeUnsigned(string $data, int $offset, int $additional): array
    {
        [$value, $headLen] = self::readArgument($data, $offset, $additional);
        return [$value, $offset + $headLen];
    }

    /**
     * @return array{0: int, 1: int}
     */
    private static function decodeNegative(string $data, int $offset, int $additional): array
    {
        [$value, $headLen] = self::readArgument($data, $offset, $additional);
        return [-1 - $value, $offset + $headLen];
    }

    /**
     * @return array{0: string, 1: int}
     */
    private static function decodeBytes(string $data, int $offset, int $additional): array
    {
        [$len, $headLen] = self::readArgument($data, $offset, $additional);
        $start = $offset + $headLen;
        return [substr($data, $start, $len), $start + $len];
    }

    /**
     * @return array{0: string, 1: int}
     */
    private static function decodeText(string $data, int $offset, int $additional): array
    {
        // Text strings have the same encoding as byte strings, just different major type
        return self::decodeBytes($data, $offset, $additional);
    }

    /**
     * @return array{0: list<mixed>, 1: int}
     */
    private static function decodeArray(string $data, int $offset, int $additional): array
    {
        [$count, $headLen] = self::readArgument($data, $offset, $additional);
        $pos = $offset + $headLen;
        $items = [];
        for ($i = 0; $i < $count; $i++) {
            [$item, $pos] = self::decodeValue($data, $pos);
            $items[] = $item;
        }
        return [$items, $pos];
    }

    /**
     * @return array{0: array<int|string, mixed>, 1: int}
     */
    private static function decodeMap(string $data, int $offset, int $additional): array
    {
        [$count, $headLen] = self::readArgument($data, $offset, $additional);
        $pos = $offset + $headLen;
        $map = [];
        for ($i = 0; $i < $count; $i++) {
            [$key, $pos] = self::decodeValue($data, $pos);
            [$value, $pos] = self::decodeValue($data, $pos);
            if (!is_int($key) && !is_string($key)) {
                throw new CairnException('CBOR decode: map key must be int or string');
            }
            $map[$key] = $value;
        }
        return [$map, $pos];
    }

    /**
     * @return array{0: mixed, 1: int}
     */
    private static function decodeSimple(string $data, int $offset, int $additional): array
    {
        return match ($additional) {
            20 => [false, $offset + 1],
            21 => [true, $offset + 1],
            22 => [null, $offset + 1],
            default => throw new CairnException("CBOR decode: unsupported simple value {$additional}"),
        };
    }
}
