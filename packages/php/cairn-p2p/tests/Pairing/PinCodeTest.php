<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Error\CairnException;
use Cairn\Pairing\PinCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PinCode::class)]
final class PinCodeTest extends TestCase
{
    public function testGenerateReturns8Characters(): void
    {
        $pin = PinCode::generate();
        $this->assertSame(8, strlen($pin));
    }

    public function testGenerateOnlyCrockfordCharacters(): void
    {
        $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
        for ($i = 0; $i < 50; $i++) {
            $pin = PinCode::generate();
            for ($j = 0; $j < strlen($pin); $j++) {
                $this->assertNotFalse(
                    strpos($alphabet, $pin[$j]),
                    "unexpected character: '{$pin[$j]}'",
                );
            }
        }
    }

    public function testFormatAddsHyphen(): void
    {
        $pin = PinCode::generate();
        $formatted = PinCode::format($pin);
        $this->assertSame(9, strlen($formatted));
        $this->assertSame('-', $formatted[4]);
    }

    public function testFormatLeavesNon8CharUnchanged(): void
    {
        $this->assertSame('ABC', PinCode::format('ABC'));
    }

    public function testNormalizeCaseInsensitive(): void
    {
        $this->assertSame('ABCDEFGH', PinCode::normalize('abcd-efgh'));
    }

    public function testNormalizeStripsSeparators(): void
    {
        $this->assertSame('ABCDEFGH', PinCode::normalize('AB CD-EF GH'));
    }

    public function testNormalizeSubstitutions(): void
    {
        $this->assertSame('1100AAAA', PinCode::normalize('ILOO-AAAA'));
    }

    public function testNormalizeRemovesU(): void
    {
        $this->assertSame('ABCD', PinCode::normalize('AUBU-CUDU'));
    }

    public function testValidateAcceptsGoodPin(): void
    {
        $pin = PinCode::generate();
        PinCode::validate($pin);
        $this->assertTrue(true); // no exception
    }

    public function testValidateRejectsWrongLength(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/expected 8 characters/');
        PinCode::validate('ABC');
    }

    public function testValidateRejectsInvalidChars(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/not in Crockford/');
        PinCode::validate('!!!!!!!!');
    }

    public function testCrockfordEncodeDecodeRoundtrip(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $bytes = random_bytes(5);
            $encoded = PinCode::encodeCrockford($bytes);
            $decoded = PinCode::decodeCrockford($encoded);
            $this->assertSame($bytes, $decoded);
        }
    }

    public function testCrockfordKnownValues(): void
    {
        $this->assertSame('00000000', PinCode::encodeCrockford(str_repeat("\x00", 5)));
        $this->assertSame('ZZZZZZZZ', PinCode::encodeCrockford(str_repeat("\xFF", 5)));
    }

    public function testRendezvousIdDerivation(): void
    {
        $id1 = PinCode::deriveRendezvousId('98AFXZ2A');
        $id2 = PinCode::deriveRendezvousId('98AFXZ2A');
        $this->assertSame($id1, $id2);
        $this->assertSame(32, strlen($id1));

        // Different pins give different IDs
        $id3 = PinCode::deriveRendezvousId('ABCDEFGH');
        $this->assertNotSame($id1, $id3);
    }

    public function testPin40BitsEntropy(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $pin = PinCode::generate();
            $decoded = PinCode::decodeCrockford($pin);
            $this->assertSame(5, strlen($decoded));
        }
    }
}
