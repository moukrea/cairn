<?php

declare(strict_types=1);

namespace Cairn\Tests\Pairing;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Pairing\PairRejectReason;
use Cairn\Pairing\PairingFlowType;
use Cairn\Pairing\PairingRole;
use Cairn\Pairing\PairingSession;
use Cairn\Pairing\PairingState;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PairingSession::class)]
final class StateMachineTest extends TestCase
{
    protected function setUp(): void
    {
        if (!function_exists('sodium_crypto_core_ed25519_scalar_random')) {
            $this->markTestSkipped('Ed25519 sodium functions not available');
        }
    }

    private function makePeerId(): PeerId
    {
        $identity = Identity::generate();
        return PeerId::fromPublicKey($identity->publicKey());
    }

    public function testInitiatorCreatesRequest(): void
    {
        $peerId = $this->makePeerId();
        [$session, $request] = PairingSession::newInitiator($peerId, 'test-password');

        $this->assertSame(PairingState::AwaitingPakeExchange, $session->state());
        $this->assertSame(PairingRole::Initiator, $session->role());
        $this->assertSame(PairingFlowType::Initiation, $session->flowType());
        $this->assertSame('pair_request', $request['type']);
        $this->assertNotNull($request['pake_msg']);
        $this->assertSame(16, strlen($request['nonce']));
    }

    public function testInitiationFlowFullExchange(): void
    {
        $alicePeerId = $this->makePeerId();
        $bobPeerId = $this->makePeerId();
        $password = 'test-pairing-password-42';

        // Alice creates initiator session
        [$alice, $aliceReqMsg] = PairingSession::newInitiator($alicePeerId, $password);
        $this->assertSame(PairingState::AwaitingPakeExchange, $alice->state());

        // Bob creates responder session
        $bob = PairingSession::newResponder($password);
        $this->assertSame(PairingState::Idle, $bob->state());

        // Bob handles Alice's PairRequest -> returns PairChallenge
        $challenge = $bob->handleRequest(
            $aliceReqMsg['peer_id'],
            $aliceReqMsg['nonce'],
            $aliceReqMsg['pake_msg'],
            $bobPeerId,
        );
        $this->assertNotNull($challenge);
        $this->assertSame('pair_challenge', $challenge['type']);
        $this->assertSame(PairingState::AwaitingVerification, $bob->state());

        // Alice handles Bob's PairChallenge -> returns PairResponse (key confirmation)
        $response = $alice->handleChallenge(
            $challenge['peer_id'],
            $challenge['nonce'],
            $challenge['pake_msg'],
        );
        $this->assertSame('pair_response', $response['type']);
        $this->assertSame(PairingState::AwaitingConfirmation, $alice->state());

        // Bob handles Alice's PairResponse -> verifies, returns PairConfirm
        $bobConfirm = $bob->handleResponse($response['key_confirmation']);
        $this->assertSame('pair_confirm', $bobConfirm['type']);
        $this->assertSame(PairingState::AwaitingConfirmation, $bob->state());

        // Alice handles Bob's PairConfirm -> completes
        $aliceConfirmBack = $alice->handleConfirm($bobConfirm['key_confirmation']);
        $this->assertSame(PairingState::Completed, $alice->state());
        $this->assertNotNull($alice->sharedKey());

        // If Alice sent a confirm back, Bob processes it
        if ($aliceConfirmBack !== null) {
            $bob->handleConfirm($aliceConfirmBack['key_confirmation']);
            $this->assertSame(PairingState::Completed, $bob->state());
            $this->assertNotNull($bob->sharedKey());
        }

        // Both derived the same shared key
        $this->assertSame($alice->sharedKey(), $bob->sharedKey());
    }

    public function testStandardFlowInitiatorCreatesRequest(): void
    {
        $peerId = $this->makePeerId();
        [$session, $request] = PairingSession::newStandardInitiator($peerId);

        $this->assertSame(PairingState::AwaitingVerification, $session->state());
        $this->assertSame(PairingRole::Initiator, $session->role());
        $this->assertSame(PairingFlowType::Standard, $session->flowType());
        $this->assertSame('pair_request', $request['type']);
        $this->assertNull($request['pake_msg']);
    }

    public function testStandardFlowResponderHandlesRequest(): void
    {
        $bobPeerId = $this->makePeerId();
        $alicePeerId = $this->makePeerId();
        $bob = PairingSession::newStandardResponder();

        $result = $bob->handleRequest($alicePeerId, str_repeat("\x00", 16), null, $bobPeerId);
        $this->assertNull($result);
        $this->assertSame(PairingState::AwaitingVerification, $bob->state());
    }

    public function testStandardFlowKeyConfirmationExchange(): void
    {
        $alicePeerId = $this->makePeerId();
        $bobPeerId = $this->makePeerId();

        [$alice, $aliceReqMsg] = PairingSession::newStandardInitiator($alicePeerId);
        $bob = PairingSession::newStandardResponder();

        $bob->handleRequest($aliceReqMsg['peer_id'], $aliceReqMsg['nonce'], null, $bobPeerId);

        // Both set the same shared key (simulated from Noise XX)
        $shared = str_repeat("\xAB", 32);
        $alice->setSharedKey($shared);
        $bob->setSharedKey($shared);

        // Set nonces so both sides derive the same confirmation
        $bob->setRemoteNonce($alice->localNonce());
        $alice->setRemoteNonce($bob->localNonce());

        // Alice sends key confirmation (PairResponse)
        $aliceResponse = $alice->sendKeyConfirmation();
        $this->assertSame(PairingState::AwaitingConfirmation, $alice->state());
        $this->assertSame('pair_response', $aliceResponse['type']);

        // Bob handles Alice's PairResponse -> sends PairConfirm
        $bobReply = $bob->handleResponse($aliceResponse['key_confirmation']);
        $this->assertSame('pair_confirm', $bobReply['type']);
        $this->assertSame(PairingState::AwaitingConfirmation, $bob->state());

        // Alice handles Bob's PairConfirm
        $aliceReply = $alice->handleConfirm($bobReply['key_confirmation']);
        $this->assertSame(PairingState::Completed, $alice->state());
        $this->assertNotNull($alice->sharedKey());

        if ($aliceReply !== null) {
            $bob->handleConfirm($aliceReply['key_confirmation']);
            $this->assertSame(PairingState::Completed, $bob->state());
        }
    }

    public function testWrongKeyConfirmationFails(): void
    {
        $alicePeerId = $this->makePeerId();
        $bobPeerId = $this->makePeerId();

        [$alice, $aliceReqMsg] = PairingSession::newStandardInitiator($alicePeerId);
        $bob = PairingSession::newStandardResponder();

        $bob->handleRequest($aliceReqMsg['peer_id'], $aliceReqMsg['nonce'], null, $bobPeerId);

        // Set different keys to simulate MITM
        $alice->setSharedKey(str_repeat("\xAA", 32));
        $bob->setSharedKey(str_repeat("\xBB", 32));

        $bob->setRemoteNonce($alice->localNonce());
        $alice->setRemoteNonce($bob->localNonce());

        $aliceResponse = $alice->sendKeyConfirmation();

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/PAKE authentication/');
        $bob->handleResponse($aliceResponse['key_confirmation']);
    }

    public function testRejectTransitionsToFailed(): void
    {
        $peerId = $this->makePeerId();
        [$session] = PairingSession::newStandardInitiator($peerId);

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/rejected/');
        $session->handleReject(PairRejectReason::UserRejected);
    }

    public function testInitiatorRejectsPairRequest(): void
    {
        $peerId = $this->makePeerId();
        $otherPeerId = $this->makePeerId();
        [$session] = PairingSession::newStandardInitiator($peerId);

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/only responder/');
        $session->handleRequest($otherPeerId, str_repeat("\x00", 16), null, $peerId);
    }

    public function testResponderRejectsChallenge(): void
    {
        $otherPeerId = $this->makePeerId();
        $session = PairingSession::newStandardResponder();

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/only initiator/');
        $session->handleChallenge($otherPeerId, str_repeat("\x00", 16), str_repeat("\x00", 32));
    }

    public function testSharedKeyNotAvailableBeforeCompletion(): void
    {
        $peerId = $this->makePeerId();
        [$session] = PairingSession::newStandardInitiator($peerId);
        $session->setSharedKey(str_repeat("\x42", 32));

        $this->assertNull($session->sharedKey());
    }

    public function testSessionNotExpiredWithDefaultTimeout(): void
    {
        $peerId = $this->makePeerId();
        [$session] = PairingSession::newStandardInitiator($peerId);
        $this->assertFalse($session->isExpired());
    }

    public function testRemotePeerIdInitiallyNull(): void
    {
        $peerId = $this->makePeerId();
        [$session] = PairingSession::newStandardInitiator($peerId);
        $this->assertNull($session->remotePeerId());
    }
}
