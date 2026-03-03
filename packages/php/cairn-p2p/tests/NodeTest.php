<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\CairnConfig;
use Cairn\Channel;
use Cairn\MeshSettings;
use Cairn\Node;
use Cairn\ReconnectionPolicy;
use Cairn\Session;
use Cairn\SessionState;
use Cairn\Error\CairnException;
use Evenement\EventEmitterInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Node::class)]
final class NodeTest extends TestCase
{
    public function testCreateReturnsNode(): void
    {
        $node = Node::create();
        $this->assertInstanceOf(Node::class, $node);
        $this->assertFalse($node->isServerMode());
    }

    public function testCreateWithConfig(): void
    {
        $config = new CairnConfig(
            meshSettings: new MeshSettings(meshEnabled: true, maxHops: 5),
        );
        $node = Node::create($config);
        $this->assertTrue($node->config()->meshSettings->meshEnabled);
        $this->assertSame(5, $node->config()->meshSettings->maxHops);
    }

    public function testCreateValidatesConfig(): void
    {
        $bad = new CairnConfig(stunServers: []);
        $this->expectException(CairnException::class);
        Node::create($bad);
    }

    public function testCreateServerReturnsServerNode(): void
    {
        $node = Node::createServer();
        $this->assertTrue($node->isServerMode());
    }

    public function testCreateServerWithConfig(): void
    {
        $config = CairnConfig::defaultServer();
        $node = Node::createServer($config);
        $this->assertTrue($node->isServerMode());
        $this->assertTrue($node->config()->meshSettings->relayWilling);
    }

    public function testPeerId(): void
    {
        $node = Node::create();
        $peerId = $node->peerId();
        $this->assertNotEmpty($peerId);
        $this->assertIsString($peerId);
    }

    public function testIdentityAccessible(): void
    {
        $node = Node::create();
        $identity = $node->identity();
        $this->assertSame(32, strlen($identity->publicKey()));
    }

    public function testConfigAccessible(): void
    {
        $node = Node::create();
        $config = $node->config();
        $this->assertInstanceOf(CairnConfig::class, $config);
    }

    public function testNodeIsEventEmitter(): void
    {
        $node = Node::create();
        $this->assertInstanceOf(EventEmitterInterface::class, $node);
    }

    public function testNodeEmitsEvents(): void
    {
        $node = Node::create();
        $received = null;
        $node->on('test', function (string $data) use (&$received): void {
            $received = $data;
        });
        $node->emit('test', ['hello']);
        $this->assertSame('hello', $received);
    }

    public function testServerModeDefaults(): void
    {
        $node = Node::createServer();
        $cfg = $node->config();
        $this->assertSame(604800.0, $cfg->reconnectionPolicy->sessionExpiry);
        $this->assertSame(PHP_FLOAT_MAX, $cfg->reconnectionPolicy->reconnectMaxDuration);
        $this->assertTrue($cfg->meshSettings->meshEnabled);
        $this->assertTrue($cfg->meshSettings->relayWilling);
        $this->assertSame(100, $cfg->meshSettings->relayCapacity);
    }

    // --- Connection tests ---

    public function testConnectReturnsSession(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-1');
        $this->assertInstanceOf(Session::class, $session);
        $this->assertSame('test-peer-1', $session->peerId);
        $this->assertSame(SessionState::Connected, $session->state());
    }

    public function testConnectHasRatchet(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-2');
        $this->assertNotNull($session->ratchet());
    }

    public function testConnectEmitsPeerConnected(): void
    {
        $node = Node::create();
        $emittedPeerId = null;
        $node->on('peer_connected', function (string $peerId) use (&$emittedPeerId): void {
            $emittedPeerId = $peerId;
        });

        $node->connect('test-peer-3');
        $this->assertSame('test-peer-3', $emittedPeerId);
    }

    public function testConnectReusesExistingSession(): void
    {
        $node = Node::create();
        $session1 = $node->connect('test-peer-4');
        $session2 = $node->connect('test-peer-4');
        $this->assertSame($session1->id, $session2->id);
    }

    public function testConnectRejectsWhenClosed(): void
    {
        $node = Node::create();
        $node->close();
        $this->expectException(CairnException::class);
        $this->expectExceptionMessage('node is closed');
        $node->connect('test-peer-5');
    }

    // --- Close tests ---

    public function testCloseMarksNodeClosed(): void
    {
        $node = Node::create();
        $this->assertFalse($node->isClosed());
        $node->close();
        $this->assertTrue($node->isClosed());
    }

    public function testCloseTerminatesSessions(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-6');
        $this->assertSame(SessionState::Connected, $session->state());

        $node->close();
        $this->assertSame(SessionState::Failed, $session->state());
    }

    // --- Unpair tests ---

    public function testUnpairEmitsEvent(): void
    {
        $node = Node::create();
        $emittedPeerId = null;
        $node->on('peer_unpaired', function (string $peerId) use (&$emittedPeerId): void {
            $emittedPeerId = $peerId;
        });

        $node->unpair('test-peer-7');
        $this->assertSame('test-peer-7', $emittedPeerId);
    }

    public function testUnpairClosesSession(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-8');
        $this->assertSame(SessionState::Connected, $session->state());

        $node->unpair('test-peer-8');
        $this->assertSame(SessionState::Failed, $session->state());
    }

    // --- Network info tests ---

    public function testNetworkInfoReturnsDefaults(): void
    {
        $node = Node::create();
        $info = $node->networkInfo();
        $this->assertSame('unknown', $info['natType']);
        $this->assertNull($info['externalAddr']);
    }

    // --- Pairing tests ---

    public function testPairGenerateQrReturnsPayload(): void
    {
        $node = Node::create();
        $result = $node->pairGenerateQr();
        $this->assertArrayHasKey('payload', $result);
        $this->assertArrayHasKey('expiresIn', $result);
        $this->assertNotEmpty($result['payload']);
        $this->assertGreaterThan(0, $result['expiresIn']);
    }

    public function testPairScanQrRoundtrip(): void
    {
        $node = Node::create();
        $result = $node->pairGenerateQr();

        $emittedPeerId = null;
        $node->on('pairing_complete', function (string $peerId) use (&$emittedPeerId): void {
            $emittedPeerId = $peerId;
        });

        $peerId = $node->pairScanQr($result['payload']);
        $this->assertNotEmpty($peerId);
        $this->assertSame($peerId, $emittedPeerId);
    }

    public function testPairGeneratePinReturnsFormattedPin(): void
    {
        $node = Node::create();
        $result = $node->pairGeneratePin();
        $this->assertArrayHasKey('pin', $result);
        $this->assertArrayHasKey('expiresIn', $result);
        // Pin format: XXXX-XXXX (9 chars with dash)
        $this->assertSame(9, strlen($result['pin']));
        $this->assertSame('-', $result['pin'][4]);
    }

    public function testPairEnterPinReturnspeerId(): void
    {
        $node = Node::create();

        $emittedPeerId = null;
        $node->on('pairing_complete', function (string $peerId) use (&$emittedPeerId): void {
            $emittedPeerId = $peerId;
        });

        $peerId = $node->pairEnterPin('ABCD-EFGH');
        $this->assertNotEmpty($peerId);
        $this->assertSame($peerId, $emittedPeerId);
    }

    public function testPairEnterPinRejectsInvalid(): void
    {
        $node = Node::create();
        $this->expectException(CairnException::class);
        $node->pairEnterPin('!!!');
    }

    public function testPairGenerateLinkReturnsUri(): void
    {
        $node = Node::create();
        $result = $node->pairGenerateLink();
        $this->assertArrayHasKey('uri', $result);
        $this->assertArrayHasKey('expiresIn', $result);
        $this->assertStringContainsString('cairn://pair?', $result['uri']);
        $this->assertStringContainsString('pid=', $result['uri']);
    }

    public function testPairFromLinkRoundtrip(): void
    {
        $node = Node::create();
        $result = $node->pairGenerateLink();

        $emittedPeerId = null;
        $node->on('pairing_complete', function (string $peerId) use (&$emittedPeerId): void {
            $emittedPeerId = $peerId;
        });

        $peerId = $node->pairFromLink($result['uri']);
        $this->assertNotEmpty($peerId);
        $this->assertSame($peerId, $emittedPeerId);
    }

    public function testPairFromLinkRejectsInvalidUri(): void
    {
        $node = Node::create();
        $this->expectException(CairnException::class);
        $node->pairFromLink('https://example.com');
    }

    // --- Session channel and send tests ---

    public function testOpenChannelOnSession(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-9');
        $channel = $session->openChannel('data');
        $this->assertInstanceOf(Channel::class, $channel);
        $this->assertSame('data', $channel->name);
        $this->assertTrue($channel->isOpen());
    }

    public function testOpenChannelProducesOutboxEnvelope(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-10');
        $session->openChannel('chat');

        // Should have a ChannelInit envelope in the outbox
        $outbox = $session->outbox();
        $this->assertCount(1, $outbox);
        $this->assertNotEmpty($outbox[0]);
    }

    public function testSendProducesOutboxEnvelope(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-11');
        $channel = $session->openChannel('data');

        // Clear the ChannelInit envelope
        $session->outbox();

        $session->send($channel, 'hello world');

        $outbox = $session->outbox();
        $this->assertCount(1, $outbox);
        $this->assertNotEmpty($outbox[0]);
    }

    public function testSendQueuesWhenDisconnected(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-12');
        $channel = $session->openChannel('data');

        // Clear outbox
        $session->outbox();

        // Transition to disconnected
        $session->transition(SessionState::Disconnected);

        $session->send($channel, 'queued message');

        // Outbox should be empty (message was queued)
        $this->assertEmpty($session->outbox());

        // Queue should have the message
        $queued = $session->drainQueue();
        $this->assertCount(1, $queued);
        $this->assertSame('queued message', $queued[0]->payload);
    }

    public function testSendRejectsOnFailedSession(): void
    {
        $node = Node::create();
        $session = $node->connect('test-peer-13');
        $channel = $session->openChannel('data');

        $session->close();
        $this->assertSame(SessionState::Failed, $session->state());

        // Channel is closed during session close, so send() rejects with channel error
        $this->expectException(CairnException::class);
        $session->send($channel, 'should fail');
    }

    // --- Session state event forwarding ---

    public function testSessionStateEventForwardedToNode(): void
    {
        $node = Node::create();
        $emittedState = null;
        $emittedPeer = null;
        $node->on('session_state', function (string $peerId, string $state) use (&$emittedPeer, &$emittedState): void {
            $emittedPeer = $peerId;
            $emittedState = $state;
        });

        $session = $node->connect('test-peer-14');
        $session->transition(SessionState::Disconnected);

        $this->assertSame('test-peer-14', $emittedPeer);
        $this->assertSame('disconnected', $emittedState);
    }
}
