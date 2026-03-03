<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\CipherSuite;
use Cairn\Crypto\DoubleRatchet;
use Cairn\Crypto\RatchetConfig;
use Cairn\Crypto\X25519Keypair;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DoubleRatchet::class)]
final class RatchetTest extends TestCase
{
    /**
     * @return array{0: DoubleRatchet, 1: DoubleRatchet}
     */
    private function setupPair(?RatchetConfig $config = null): array
    {
        $config ??= new RatchetConfig();
        $sharedSecret = str_repeat("\x42", 32);
        $bobKp = X25519Keypair::generate();

        $alice = DoubleRatchet::initInitiator($sharedSecret, $bobKp->publicKeyBytes(), $config);
        $bob = DoubleRatchet::initResponder($sharedSecret, $bobKp, $config);

        return [$alice, $bob];
    }

    public function testAliceSendsBobReceives(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$header, $ciphertext] = $alice->encrypt('hello bob');
        $decrypted = $bob->decrypt($header, $ciphertext);
        $this->assertSame('hello bob', $decrypted);
    }

    public function testMultipleMessagesOneDirection(): void
    {
        [$alice, $bob] = $this->setupPair();

        for ($i = 0; $i < 10; $i++) {
            $msg = "message {$i}";
            [$header, $ct] = $alice->encrypt($msg);
            $pt = $bob->decrypt($header, $ct);
            $this->assertSame($msg, $pt);
        }
    }

    public function testBidirectionalMessages(): void
    {
        [$alice, $bob] = $this->setupPair();

        // Alice -> Bob
        [$h1, $ct1] = $alice->encrypt('hello bob');
        $this->assertSame('hello bob', $bob->decrypt($h1, $ct1));

        // Bob -> Alice
        [$h2, $ct2] = $bob->encrypt('hello alice');
        $this->assertSame('hello alice', $alice->decrypt($h2, $ct2));

        // Alice -> Bob again
        [$h3, $ct3] = $alice->encrypt('how are you?');
        $this->assertSame('how are you?', $bob->decrypt($h3, $ct3));
    }

    public function testOutOfOrderMessages(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$h1, $ct1] = $alice->encrypt('msg 0');
        [$h2, $ct2] = $alice->encrypt('msg 1');
        [$h3, $ct3] = $alice->encrypt('msg 2');

        // Deliver out of order: 2, 0, 1
        $this->assertSame('msg 2', $bob->decrypt($h3, $ct3));
        $this->assertSame('msg 0', $bob->decrypt($h1, $ct1));
        $this->assertSame('msg 1', $bob->decrypt($h2, $ct2));
    }

    public function testMaxSkipThresholdRespected(): void
    {
        $config = new RatchetConfig(maxSkip: 2);
        [$alice, $bob] = $this->setupPair($config);

        $alice->encrypt('skip 0');
        $alice->encrypt('skip 1');
        $alice->encrypt('skip 2');
        [$h4, $ct4] = $alice->encrypt('msg 3');

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/max skip/');
        $bob->decrypt($h4, $ct4);
    }

    public function testStateExportImportRoundtrip(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$h1, $ct1] = $alice->encrypt('before persist');
        $this->assertSame('before persist', $bob->decrypt($h1, $ct1));

        // Export and reimport Alice's state
        $exported = $alice->exportState();
        $alice2 = DoubleRatchet::importState($exported);

        [$h2, $ct2] = $alice2->encrypt('after persist');
        $this->assertSame('after persist', $bob->decrypt($h2, $ct2));
    }

    public function testMultipleRatchetTurns(): void
    {
        [$alice, $bob] = $this->setupPair();

        for ($round = 0; $round < 5; $round++) {
            $msgAb = "alice round {$round}";
            [$h, $ct] = $alice->encrypt($msgAb);
            $this->assertSame($msgAb, $bob->decrypt($h, $ct));

            $msgBa = "bob round {$round}";
            [$h, $ct] = $bob->encrypt($msgBa);
            $this->assertSame($msgBa, $alice->decrypt($h, $ct));
        }
    }

    public function testTamperedCiphertextRejected(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$header, $ciphertext] = $alice->encrypt('tamper test');
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 0xFF);

        $this->expectException(CairnException::class);
        $bob->decrypt($header, $ciphertext);
    }

    public function testChaCha20CipherSuite(): void
    {
        $config = new RatchetConfig(cipher: CipherSuite::ChaCha20Poly1305);
        [$alice, $bob] = $this->setupPair($config);

        [$h, $ct] = $alice->encrypt('chacha20 test');
        $this->assertSame('chacha20 test', $bob->decrypt($h, $ct));
    }

    public function testEmptyPlaintext(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$h, $ct] = $alice->encrypt('');
        $this->assertSame('', $bob->decrypt($h, $ct));
    }

    public function testMessageNumbersIncrement(): void
    {
        [$alice] = $this->setupPair();

        [$h1] = $alice->encrypt('msg0');
        [$h2] = $alice->encrypt('msg1');
        [$h3] = $alice->encrypt('msg2');

        $this->assertSame(0, $h1->msgNum);
        $this->assertSame(1, $h2->msgNum);
        $this->assertSame(2, $h3->msgNum);
    }

    public function testDhPublicKeyChangesOnRatchet(): void
    {
        [$alice, $bob] = $this->setupPair();

        [$h1, $ct1] = $alice->encrypt('from alice');
        $alicePk1 = $h1->dhPublic;
        $bob->decrypt($h1, $ct1);

        [$h2, $ct2] = $bob->encrypt('from bob');
        $alice->decrypt($h2, $ct2);

        [$h3] = $alice->encrypt('from alice again');
        $alicePk2 = $h3->dhPublic;

        $this->assertNotSame($alicePk1, $alicePk2);
    }

    public function testImportStateInvalidData(): void
    {
        $this->expectException(CairnException::class);
        DoubleRatchet::importState('not valid json');
    }
}
