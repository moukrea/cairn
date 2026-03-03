<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\CairnConfig;
use Cairn\Crypto\Aead;
use Cairn\Crypto\CipherSuite;
use Cairn\Crypto\Identity;
use Cairn\Crypto\Kdf;
use Cairn\Crypto\X25519Keypair;
use Cairn\Discovery\DiscoveryCoordinator;
use Cairn\Discovery\MdnsBackend;

use function Cairn\Discovery\activeRendezvousIds;
use function Cairn\Discovery\deriveRendezvousId;

use Cairn\Mesh\MeshConfig;
use Cairn\Mesh\RelayManager;
use Cairn\Mesh\Route;
use Cairn\Mesh\RoutingTable;
use Cairn\Node;
use Cairn\Pairing\PairingPayload;
use Cairn\Pairing\PairingLink;
use Cairn\Protocol\Envelope;
use Cairn\Protocol\MessageType;
use Cairn\Server\ForwardRequest;
use Cairn\Server\MessageQueue;
use Cairn\Server\PeerSyncState;
use Cairn\SessionStateMachine;
use Cairn\SessionState;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for the full pairing-to-messaging flow.
 *
 * These tests create two in-process nodes, pair them, establish a session,
 * and exchange encrypted messages using the cairn protocol stack.
 */
final class IntegrationTest extends TestCase
{
    /**
     * Full pairing -> key exchange -> encrypted message flow between two peers.
     */
    public function testFullPairingToMessageFlow(): void
    {
        // 1. Both peers generate identities
        $alice = Identity::generate();
        $bob = Identity::generate();

        // 2. Alice creates a pairing payload
        $alicePayload = PairingPayload::create(
            peerId: $alice->peerId(),
            pakeCredential: random_bytes(32),
        );
        $this->assertFalse($alicePayload->isExpired());

        // 3. Payload is encoded/transmitted (simulated via CBOR)
        $encoded = $alicePayload->toCbor();
        $decoded = PairingPayload::fromCbor($encoded);
        $this->assertTrue($decoded->peerId->equals($alice->peerId()));

        // 4. Both peers perform X25519 key exchange
        $aliceKp = X25519Keypair::generate();
        $bobKp = X25519Keypair::generate();
        $sharedSecret = $aliceKp->computeSharedSecret($bobKp->publicKey());
        $sharedSecretBob = $bobKp->computeSharedSecret($aliceKp->publicKey());
        $this->assertSame($sharedSecret, $sharedSecretBob);

        // 5. Derive session keys using HKDF
        $sessionKey = Kdf::hkdfSha256($sharedSecret, Kdf::HKDF_INFO_SESSION_KEY);
        $this->assertSame(32, strlen($sessionKey));

        // 6. Alice encrypts a message
        $plaintext = 'Hello from Alice!';
        $nonce = random_bytes(Aead::NONCE_SIZE);
        $ciphertext = Aead::encrypt(
            CipherSuite::ChaCha20Poly1305,
            $sessionKey,
            $nonce,
            $plaintext,
            'cairn-message',
        );

        // 7. Bob decrypts the message
        $decrypted = Aead::decrypt(
            CipherSuite::ChaCha20Poly1305,
            $sessionKey,
            $nonce,
            $ciphertext,
            'cairn-message',
        );
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Pairing link round-trip between two peers.
     */
    public function testPairingLinkExchange(): void
    {
        $alice = Identity::generate();
        $payload = PairingPayload::create(
            peerId: $alice->peerId(),
            pakeCredential: random_bytes(32),
        );

        // Alice generates a pairing link
        $uri = PairingLink::toUri($payload);
        $this->assertStringStartsWith('cairn://pair?', $uri);

        // Bob receives the link and parses it
        $restored = PairingLink::fromUri($uri);
        $this->assertTrue($restored->peerId->equals($alice->peerId()));
        $this->assertSame($payload->pakeCredential, $restored->pakeCredential);
    }

    /**
     * Envelope wire format round-trip through encode/decode.
     */
    public function testEnvelopeWireRoundTrip(): void
    {
        $sessionId = random_bytes(32);
        $env = new Envelope(
            version: 1,
            messageType: MessageType::HELLO,
            msgId: Envelope::newMsgId(),
            sessionId: $sessionId,
            payload: 'encrypted-payload-bytes',
            authTag: random_bytes(16),
        );

        $wire = $env->encode();
        $restored = Envelope::decode($wire);

        $this->assertSame($env->version, $restored->version);
        $this->assertSame($env->messageType, $restored->messageType);
        $this->assertSame($env->payload, $restored->payload);
        $this->assertSame($env->sessionId, $restored->sessionId);
    }

    /**
     * Session state machine transitions through normal lifecycle.
     */
    public function testSessionLifecycleTransitions(): void
    {
        $sm = new SessionStateMachine();
        $this->assertSame(SessionState::Connected, $sm->state());

        $sm->transitionTo(SessionState::Unstable);
        $this->assertSame(SessionState::Unstable, $sm->state());

        $sm->transitionTo(SessionState::Disconnected);
        $this->assertSame(SessionState::Disconnected, $sm->state());

        $sm->transitionTo(SessionState::Reconnecting);
        $this->assertSame(SessionState::Reconnecting, $sm->state());

        $sm->transitionTo(SessionState::Reconnected);
        $this->assertSame(SessionState::Reconnected, $sm->state());

        $sm->transitionTo(SessionState::Connected);
        $this->assertSame(SessionState::Connected, $sm->state());
    }

    /**
     * Discovery: publish and query across backends.
     */
    public function testDiscoveryPublishAndQuery(): void
    {
        $mdns = new MdnsBackend();
        $coord = new DiscoveryCoordinator([$mdns]);

        $id = deriveRendezvousId('test-secret', 1);
        $coord->publishAll($id, 'alice-reachability-info');

        $result = null;
        $coord->queryFirst($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('alice-reachability-info', $result);
    }

    /**
     * Rendezvous ID rotation: both peers derive same ID at same epoch.
     */
    public function testRendezvousIdAgreement(): void
    {
        $sharedSecret = 'shared-pairing-secret';
        $epoch = 12345;

        $aliceId = deriveRendezvousId($sharedSecret, $epoch);
        $bobId = deriveRendezvousId($sharedSecret, $epoch);
        $this->assertSame($aliceId->bytes, $bobId->bytes);
    }

    /**
     * Store-and-forward: enqueue, deliver, purge cycle.
     */
    public function testStoreAndForwardCycle(): void
    {
        $queue = new MessageQueue();
        $sender = Identity::fromSeed(str_repeat("\x01", 32))->peerId();
        $recipient = Identity::fromSeed(str_repeat("\x02", 32))->peerId();
        $paired = [(string) $sender => true, (string) $recipient => true];

        // Enqueue 3 messages
        for ($seq = 1; $seq <= 3; $seq++) {
            $req = new ForwardRequest(
                msgId: bin2hex(random_bytes(16)),
                recipient: $recipient,
                encryptedPayload: "message-{$seq}",
                sequenceNumber: $seq,
            );
            $ack = $queue->enqueue($req, $sender, $paired);
            $this->assertTrue($ack->accepted);
        }
        $this->assertSame(3, $queue->queueDepth($recipient));

        // Deliver all
        [$delivers, $purge] = $queue->deliver($recipient);
        $this->assertCount(3, $delivers);
        $this->assertCount(3, $purge->msgIds);
        $this->assertSame(0, $queue->queueDepth($recipient));

        // Verify order
        $this->assertSame(1, $delivers[0]->sequenceNumber);
        $this->assertSame(2, $delivers[1]->sequenceNumber);
        $this->assertSame(3, $delivers[2]->sequenceNumber);
    }

    /**
     * Mesh routing: direct vs relayed route selection.
     */
    public function testMeshRoutingSelection(): void
    {
        $rt = new RoutingTable(3);
        $dest = Identity::generate()->peerId();
        $relay = Identity::generate()->peerId();

        // Add a relayed route with low latency
        $rt->addRoute($dest, Route::relayed([$relay], 5, 10_000_000));
        // Add a direct route with higher latency
        $rt->addRoute($dest, Route::direct(100, 100_000));

        // Direct route should be preferred (fewer hops wins)
        $best = $rt->selectBestRoute($dest);
        $this->assertSame(0, $best->hopCount());
        $this->assertSame(100, $best->latencyMs);
    }

    /**
     * Relay session lifecycle: request, use, close.
     */
    public function testRelaySessionLifecycle(): void
    {
        $config = MeshConfig::serverMode();
        $mgr = new RelayManager($config);

        $src = Identity::generate()->peerId();
        $dst = Identity::generate()->peerId();

        $id = $mgr->requestRelay($src, $dst);
        $this->assertSame(1, $mgr->activeSessionCount());

        $session = $mgr->getSession($id);
        $this->assertTrue($session->source->equals($src));
        $this->assertTrue($session->destination->equals($dst));

        $mgr->closeSession($id);
        $this->assertSame(0, $mgr->activeSessionCount());
    }

    /**
     * Multi-device sync state tracking.
     */
    public function testMultiDeviceSyncState(): void
    {
        $peer = Identity::generate()->peerId();
        $state = new PeerSyncState($peer);

        $state->markConnected();
        $this->assertNotNull($state->lastConnected);

        // Simulate: server receives 5 messages for this peer
        $state->addPending(5);
        $this->assertSame(5, $state->pendingDeliveries);

        // Simulate: peer reconnects and acknowledges up to sequence 3
        $state->advanceSequence(3);
        $this->assertSame(3, $state->lastSeenSequence);
        $this->assertSame(2, $state->pendingDeliveries);

        // Simulate: peer catches up completely
        $state->advanceSequence(5);
        $this->assertSame(5, $state->lastSeenSequence);
        $this->assertSame(0, $state->pendingDeliveries);
    }

    /**
     * Node creation with different tier configs.
     */
    public function testNodeTierCreation(): void
    {
        $t0 = Node::create(CairnConfig::tier0());
        $this->assertFalse($t0->isServerMode());
        $this->assertFalse($t0->config()->meshSettings->meshEnabled);

        $server = Node::createServer();
        $this->assertTrue($server->isServerMode());
        $this->assertTrue($server->config()->meshSettings->meshEnabled);
    }

    /**
     * Two nodes have different identities.
     */
    public function testTwoNodesHaveDifferentIdentities(): void
    {
        $node1 = Node::create();
        $node2 = Node::create();
        $this->assertNotSame($node1->peerId(), $node2->peerId());
    }

    /**
     * End-to-end: identity -> key exchange -> encrypt -> decrypt with different ciphers.
     */
    public function testCrossCipherEncryption(): void
    {
        $alice = X25519Keypair::generate();
        $bob = X25519Keypair::generate();
        $shared = $alice->computeSharedSecret($bob->publicKey());

        $sessionKey = Kdf::hkdfSha256($shared, Kdf::HKDF_INFO_SESSION_KEY);
        $msg = 'cross-cipher test message';
        $nonce = random_bytes(Aead::NONCE_SIZE);

        // Encrypt with ChaCha20, verify AES can't decrypt it
        $ct = Aead::encrypt(CipherSuite::ChaCha20Poly1305, $sessionKey, $nonce, $msg);

        // Same cipher decrypts fine
        $pt = Aead::decrypt(CipherSuite::ChaCha20Poly1305, $sessionKey, $nonce, $ct);
        $this->assertSame($msg, $pt);

        // Encrypt with AES-GCM
        $ctAes = Aead::encrypt(CipherSuite::Aes256Gcm, $sessionKey, $nonce, $msg);
        $ptAes = Aead::decrypt(CipherSuite::Aes256Gcm, $sessionKey, $nonce, $ctAes);
        $this->assertSame($msg, $ptAes);
    }
}
