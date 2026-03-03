<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Error\CairnException;
use Cairn\Pairing\Psk;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Psk::class)]
final class PskTest extends TestCase
{
    public function testDefaultMinEntropy(): void
    {
        $psk = new Psk();
        $this->assertSame(16, $psk->minEntropyBytes());
    }

    public function testValidateEntropyAcceptsSufficientKey(): void
    {
        $psk = new Psk();
        $psk->validateEntropy(str_repeat("\xAB", 16)); // exactly 128 bits
        $this->assertTrue(true);
    }

    public function testValidateEntropyAcceptsLongerKey(): void
    {
        $psk = new Psk();
        $psk->validateEntropy(str_repeat("\xAB", 32)); // 256 bits
        $this->assertTrue(true);
    }

    public function testValidateEntropyRejectsShortKey(): void
    {
        $psk = new Psk();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/insufficient/i');
        $psk->validateEntropy(str_repeat("\xAB", 15));
    }

    public function testValidateEntropyRejectsEmptyKey(): void
    {
        $psk = new Psk();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/empty/');
        $psk->validateEntropy('');
    }

    public function testCustomMinEntropy(): void
    {
        $psk = new Psk(32);
        $this->assertSame(32, $psk->minEntropyBytes());

        $this->expectException(CairnException::class);
        $psk->validateEntropy(str_repeat("\xAB", 16));
    }

    public function testDeriveRendezvousIdIsDeterministic(): void
    {
        $psk = new Psk();
        $key = str_repeat("\x42", 16);
        $id1 = $psk->deriveRendezvousId($key);
        $id2 = $psk->deriveRendezvousId($key);
        $this->assertSame($id1, $id2);
        $this->assertSame(32, strlen($id1));
    }

    public function testDeriveRendezvousIdDiffersForDifferentKeys(): void
    {
        $psk = new Psk();
        $id1 = $psk->deriveRendezvousId(str_repeat("\x01", 16));
        $id2 = $psk->deriveRendezvousId(str_repeat("\x02", 16));
        $this->assertNotSame($id1, $id2);
    }

    public function testDeriveRendezvousIdRejectsInsufficientEntropy(): void
    {
        $psk = new Psk();
        $this->expectException(CairnException::class);
        $psk->deriveRendezvousId(str_repeat("\xAB", 8));
    }

    public function testPakeInputReturnsRawPsk(): void
    {
        $psk = new Psk();
        $key = str_repeat("\xDE", 16);
        $this->assertSame($key, $psk->pakeInput($key));
    }

    public function testPakeInputRejectsShortKey(): void
    {
        $psk = new Psk();
        $this->expectException(CairnException::class);
        $psk->pakeInput(str_repeat("\xAB", 4));
    }

    public function testCrockfordBase3226CharsPassValidation(): void
    {
        $psk = new Psk();
        $key = 'ABCDEFGHJKMNPQRSTVWXYZ0123';
        $this->assertSame(26, strlen($key));
        $psk->validateEntropy($key);
        $this->assertTrue(true);
    }
}
