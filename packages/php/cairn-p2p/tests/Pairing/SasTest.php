<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Pairing\Sas;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Sas::class)]
final class SasTest extends TestCase
{
    public function testNumericSasProduces6Digits(): void
    {
        $transcript = str_repeat("\xAB", 32);
        $sas = Sas::deriveNumeric($transcript);
        $this->assertSame(6, strlen($sas));
        $this->assertMatchesRegularExpression('/^\d{6}$/', $sas);
    }

    public function testNumericSasIsDeterministic(): void
    {
        $transcript = str_repeat("\x42", 32);
        $sas1 = Sas::deriveNumeric($transcript);
        $sas2 = Sas::deriveNumeric($transcript);
        $this->assertSame($sas1, $sas2);
    }

    public function testNumericSasDiffersForDifferentTranscripts(): void
    {
        $sas1 = Sas::deriveNumeric(str_repeat("\x01", 32));
        $sas2 = Sas::deriveNumeric(str_repeat("\x02", 32));
        $this->assertNotSame($sas1, $sas2);
    }

    public function testEmojiSasProduces4Emojis(): void
    {
        $transcript = str_repeat("\xAB", 32);
        $emojis = Sas::deriveEmoji($transcript);
        $this->assertCount(4, $emojis);
        foreach ($emojis as $emoji) {
            $this->assertNotEmpty($emoji);
        }
    }

    public function testEmojiSasIsDeterministic(): void
    {
        $transcript = str_repeat("\x42", 32);
        $e1 = Sas::deriveEmoji($transcript);
        $e2 = Sas::deriveEmoji($transcript);
        $this->assertSame($e1, $e2);
    }

    public function testEmojiSasDiffersForDifferentTranscripts(): void
    {
        $e1 = Sas::deriveEmoji(str_repeat("\x01", 32));
        $e2 = Sas::deriveEmoji(str_repeat("\x02", 32));
        $this->assertNotSame($e1, $e2);
    }

    public function testEmojiTableHas64Entries(): void
    {
        $this->assertCount(64, Sas::EMOJI_TABLE);
    }

    public function testEmojiTableEntriesAreNonEmpty(): void
    {
        foreach (Sas::EMOJI_TABLE as $emoji) {
            $this->assertNotEmpty($emoji);
        }
    }

    public function testEmojisAreFromTable(): void
    {
        $transcript = str_repeat("\x42", 32);
        $emojis = Sas::deriveEmoji($transcript);
        foreach ($emojis as $emoji) {
            $this->assertContains($emoji, Sas::EMOJI_TABLE);
        }
    }
}
