<?php

declare(strict_types=1);

namespace Cairn\Tests\Crypto;

use Cairn\Crypto\HandshakeResult;
use Cairn\Crypto\Identity;
use Cairn\Crypto\NoiseXXHandshake;
use Cairn\Crypto\Role;
use Cairn\Crypto\StepOutput;
use Cairn\Crypto\StepOutputType;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(NoiseXXHandshake::class)]
final class NoiseTest extends TestCase
{
    /**
     * Run a complete Noise XX handshake between two peers.
     *
     * @return array{0: HandshakeResult, 1: HandshakeResult}
     */
    private function runHandshake(
        ?Identity $alice = null,
        ?Identity $bob = null,
        ?string $pakeSecret = null,
    ): array {
        $alice ??= Identity::generate();
        $bob ??= Identity::generate();

        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $responder = new NoiseXXHandshake(Role::Responder, $bob);

        if ($pakeSecret !== null) {
            $initiator->withPakeSecret($pakeSecret);
            $responder->withPakeSecret($pakeSecret);
        }

        // Initiator sends msg1
        $out1 = $initiator->step();
        $this->assertSame(StepOutputType::SendMessage, $out1->type);
        $msg1 = $out1->message;
        $this->assertNotNull($msg1);

        // Responder receives msg1, sends msg2
        $out2 = $responder->step($msg1);
        $this->assertSame(StepOutputType::SendMessage, $out2->type);
        $msg2 = $out2->message;
        $this->assertNotNull($msg2);

        // Initiator receives msg2, sends msg3
        $out3 = $initiator->step($msg2);
        $this->assertSame(StepOutputType::SendMessage, $out3->type);
        $msg3 = $out3->message;
        $this->assertNotNull($msg3);

        // Get initiator result
        $initResult = $initiator->result();

        // Responder receives msg3, completes
        $out4 = $responder->step($msg3);
        $this->assertSame(StepOutputType::Complete, $out4->type);
        $respResult = $out4->result;
        $this->assertNotNull($respResult);

        /** @var HandshakeResult $respResult */
        return [$initResult, $respResult];
    }

    public function testFullHandshakeProducesMatchingSessionKeys(): void
    {
        [$initResult, $respResult] = $this->runHandshake();
        $this->assertSame($initResult->sessionKey, $respResult->sessionKey);
    }

    public function testHandshakeRevealsRemoteStaticKeys(): void
    {
        $alice = Identity::generate();
        $bob = Identity::generate();
        $alicePub = $alice->publicKey();
        $bobPub = $bob->publicKey();

        [$initResult, $respResult] = $this->runHandshake($alice, $bob);

        $this->assertSame($bobPub, $initResult->remoteStatic);
        $this->assertSame($alicePub, $respResult->remoteStatic);
    }

    public function testHandshakeTranscriptHashesMatch(): void
    {
        [$initResult, $respResult] = $this->runHandshake();
        $this->assertSame($initResult->transcriptHash, $respResult->transcriptHash);
    }

    public function testDifferentHandshakesProduceDifferentSessionKeys(): void
    {
        [$result1] = $this->runHandshake();
        [$result2] = $this->runHandshake();
        $this->assertNotSame($result1->sessionKey, $result2->sessionKey);
    }

    public function testHandshakeWithPakeSecret(): void
    {
        $pake = str_repeat("\x2A", 32);
        [$initResult, $respResult] = $this->runHandshake(pakeSecret: $pake);
        $this->assertSame($initResult->sessionKey, $respResult->sessionKey);
    }

    public function testMismatchedPakeSecretsFail(): void
    {
        $alice = Identity::generate();
        $bob = Identity::generate();

        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $initiator->withPakeSecret(str_repeat("\x01", 32));
        $responder = new NoiseXXHandshake(Role::Responder, $bob);
        $responder->withPakeSecret(str_repeat("\x02", 32));

        $out1 = $initiator->step();
        $out2 = $responder->step($out1->message);
        $out3 = $initiator->step($out2->message);

        $this->expectException(CairnException::class);
        $responder->step($out3->message);
    }

    public function testMsg1WrongLengthRejected(): void
    {
        $bob = Identity::generate();
        $responder = new NoiseXXHandshake(Role::Responder, $bob);

        $this->expectException(CairnException::class);
        $responder->step(str_repeat("\x00", 16));
    }

    public function testMsg2TooShortRejected(): void
    {
        $alice = Identity::generate();
        $bob = Identity::generate();

        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $responder = new NoiseXXHandshake(Role::Responder, $bob);

        $out1 = $initiator->step();
        $out2 = $responder->step($out1->message);

        $this->expectException(CairnException::class);
        $initiator->step(substr($out2->message ?? '', 0, 10));
    }

    public function testTamperedMsg2Rejected(): void
    {
        $alice = Identity::generate();
        $bob = Identity::generate();

        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $responder = new NoiseXXHandshake(Role::Responder, $bob);

        $out1 = $initiator->step();
        $out2 = $responder->step($out1->message);
        $msg2 = $out2->message ?? '';

        // Tamper with encrypted portion
        if (strlen($msg2) > 40) {
            $msg2[40] = chr(ord($msg2[40]) ^ 0xFF);
        }

        $this->expectException(CairnException::class);
        $initiator->step($msg2);
    }

    public function testOutOfOrderStepRejected(): void
    {
        $alice = Identity::generate();
        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);

        $this->expectException(CairnException::class);
        $initiator->step(str_repeat("\x00", 32));
    }

    public function testStepAfterCompleteRejected(): void
    {
        $alice = Identity::generate();
        $bob = Identity::generate();

        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $responder = new NoiseXXHandshake(Role::Responder, $bob);

        $out1 = $initiator->step();
        $out2 = $responder->step($out1->message);
        $out3 = $initiator->step($out2->message);
        $responder->step($out3->message);

        $this->expectException(CairnException::class);
        $responder->step();
    }

    // --- SAS tests ---

    public function testSasDerivableFromHandshake(): void
    {
        [$initResult, $respResult] = $this->runHandshake();

        $initSas = NoiseXXHandshake::deriveNumericSas($initResult->transcriptHash);
        $respSas = NoiseXXHandshake::deriveNumericSas($respResult->transcriptHash);

        $this->assertSame($initSas, $respSas);
    }

    public function testEmojiSasMatchesBetweenPeers(): void
    {
        [$initResult, $respResult] = $this->runHandshake();

        $initEmoji = NoiseXXHandshake::deriveEmojiSas($initResult->transcriptHash);
        $respEmoji = NoiseXXHandshake::deriveEmojiSas($respResult->transcriptHash);

        $this->assertSame($initEmoji, $respEmoji);
    }

    public function testNumericSasFormat(): void
    {
        $hash = str_repeat("\x2A", 32);
        $sas = NoiseXXHandshake::deriveNumericSas($hash);
        $this->assertSame(6, strlen($sas));
        $this->assertMatchesRegularExpression('/^\d{6}$/', $sas);
    }

    public function testNumericSasIsDeterministic(): void
    {
        $hash = str_repeat("\x63", 32);
        $sas1 = NoiseXXHandshake::deriveNumericSas($hash);
        $sas2 = NoiseXXHandshake::deriveNumericSas($hash);
        $this->assertSame($sas1, $sas2);
    }

    public function testDifferentTranscriptsProduceDifferentSas(): void
    {
        $hash1 = str_repeat("\x01", 32);
        $hash2 = str_repeat("\x02", 32);
        $sas1 = NoiseXXHandshake::deriveNumericSas($hash1);
        $sas2 = NoiseXXHandshake::deriveNumericSas($hash2);
        $this->assertNotSame($sas1, $sas2);
    }

    public function testEmojiSasReturns4Entries(): void
    {
        $hash = str_repeat("\x2A", 32);
        $emojis = NoiseXXHandshake::deriveEmojiSas($hash);
        $this->assertCount(4, $emojis);
    }

    public function testEmojiSasEntriesAreFromTable(): void
    {
        $hash = str_repeat("\x4D", 32);
        $emojis = NoiseXXHandshake::deriveEmojiSas($hash);
        foreach ($emojis as $emoji) {
            $this->assertContains($emoji, NoiseXXHandshake::EMOJI_TABLE);
        }
    }

    public function testMsg1Is32Bytes(): void
    {
        $alice = Identity::generate();
        $initiator = new NoiseXXHandshake(Role::Initiator, $alice);
        $out = $initiator->step();
        $this->assertNotNull($out->message);
        $this->assertSame(32, strlen($out->message));
    }
}
