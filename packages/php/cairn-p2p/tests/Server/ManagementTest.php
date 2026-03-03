<?php

declare(strict_types=1);

namespace Cairn\Tests\Server;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;
use Cairn\Server\HeadlessPairing;
use Cairn\Server\HeadlessPairingMethod;
use Cairn\Server\HeadlessPairingMethodType;
use Cairn\Server\ManagementConfig;
use Cairn\Server\ManagementServer;
use Cairn\Server\ManagementState;
use Cairn\Server\MgmtPeerInfo;
use Cairn\Server\PeerMetrics;
use Cairn\Server\PeerQuota;
use Cairn\Server\PeerRelayStats;
use Cairn\Server\PeerSyncState;
use Cairn\Server\PersonalRelayConfig;
use Cairn\Server\QueueInfo;
use Cairn\Server\RelayStats;
use Cairn\Server\RetentionPolicy;
use Cairn\Server\ServerConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ServerConfig::class)]
#[CoversClass(HeadlessPairing::class)]
#[CoversClass(HeadlessPairingMethod::class)]
#[CoversClass(PersonalRelayConfig::class)]
#[CoversClass(PeerSyncState::class)]
#[CoversClass(PeerMetrics::class)]
#[CoversClass(PeerQuota::class)]
#[CoversClass(ManagementConfig::class)]
#[CoversClass(ManagementServer::class)]
#[CoversClass(ManagementState::class)]
#[CoversClass(MgmtPeerInfo::class)]
#[CoversClass(QueueInfo::class)]
#[CoversClass(PeerRelayStats::class)]
#[CoversClass(RelayStats::class)]
final class ManagementTest extends TestCase
{
    private function makePeer(int $seed): PeerId
    {
        return Identity::fromSeed(str_repeat(chr($seed), 32))->peerId();
    }

    // --- ServerConfig ---

    public function testServerConfigDefaults(): void
    {
        $cfg = new ServerConfig();
        $this->assertTrue($cfg->meshEnabled);
        $this->assertTrue($cfg->relayWilling);
        $this->assertSame(100, $cfg->relayCapacity);
        $this->assertTrue($cfg->storeForwardEnabled);
        $this->assertSame(1000, $cfg->storeForwardMaxPerPeer);
        $this->assertSame(604800, $cfg->storeForwardMaxAge); // 7 days
        $this->assertSame(1_073_741_824, $cfg->storeForwardMaxTotalSize);
        $this->assertSame(604800, $cfg->sessionExpiry);
        $this->assertSame(60, $cfg->heartbeatInterval);
        $this->assertNull($cfg->reconnectMaxDuration);
        $this->assertTrue($cfg->headless);
    }

    public function testServerConfigCustom(): void
    {
        $cfg = new ServerConfig(
            relayCapacity: 500,
            storeForwardMaxPerPeer: 10000,
            headless: false,
        );
        $this->assertSame(500, $cfg->relayCapacity);
        $this->assertSame(10000, $cfg->storeForwardMaxPerPeer);
        $this->assertFalse($cfg->headless);
    }

    public function testRetentionPolicyFromServerConfig(): void
    {
        $cfg = new ServerConfig();
        $policy = $cfg->retentionPolicy();
        $this->assertSame($cfg->storeForwardMaxAge, $policy->maxAge);
        $this->assertSame($cfg->storeForwardMaxPerPeer, $policy->maxMessages);
    }

    // --- HeadlessPairing ---

    public function testHeadlessPairingDefaultValidity(): void
    {
        $hp = new HeadlessPairing();
        $this->assertSame(300, $hp->validityWindow);
    }

    public function testCustomValidityWindow(): void
    {
        $hp = new HeadlessPairing(validityWindow: 60);
        $this->assertSame(60, $hp->validityWindow);
    }

    public function testSasNotAvailableInHeadlessMode(): void
    {
        $hp = new HeadlessPairing();
        $this->assertFalse($hp->sasAvailable());
    }

    public function testSupportedMechanismsList(): void
    {
        $hp = new HeadlessPairing();
        $mechs = $hp->supportedMechanisms();
        $this->assertCount(4, $mechs);
        $this->assertContains('psk', $mechs);
        $this->assertContains('pin', $mechs);
        $this->assertContains('link', $mechs);
        $this->assertContains('qr', $mechs);
        // SAS should NOT be in the list
        $this->assertNotContains('sas', $mechs);
    }

    // --- PSK ---

    public function testGeneratePskWithValidKey(): void
    {
        $hp = new HeadlessPairing();
        $key = str_repeat("\xAB", 16); // 128 bits
        $method = $hp->generatePsk($key);
        $this->assertSame(HeadlessPairingMethodType::PreSharedKey, $method->type);
        $this->assertSame($key, $method->value);
    }

    public function testGeneratePskRejectsShortKey(): void
    {
        $hp = new HeadlessPairing();
        $key = str_repeat("\xAB", 8); // 64 bits < 128 bits

        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/too short/');
        $hp->generatePsk($key);
    }

    public function testPskNeverExpires(): void
    {
        $hp = new HeadlessPairing();
        $method = $hp->generatePsk(str_repeat("\x00", 32));
        $this->assertFalse($method->isExpired());
    }

    // --- Pin code ---

    public function testGeneratePinReturnsFormattedPin(): void
    {
        $hp = new HeadlessPairing();
        $method = $hp->generatePin();
        $this->assertSame(HeadlessPairingMethodType::PinCode, $method->type);
        $this->assertSame(9, strlen($method->value)); // XXXX-XXXX
        $this->assertSame('-', $method->value[4]);
    }

    public function testPinNotExpiredImmediately(): void
    {
        $hp = new HeadlessPairing();
        $method = $hp->generatePin();
        $this->assertFalse($method->isExpired());
    }

    // --- Pairing link ---

    public function testGenerateLinkReturnsCairnUri(): void
    {
        $hp = new HeadlessPairing();
        $method = $hp->generateLink('test-peer-id', 'test-nonce', 'test-pake');
        $this->assertSame(HeadlessPairingMethodType::PairingLink, $method->type);
        $this->assertStringStartsWith('cairn://pair?', $method->value);
        $this->assertStringContainsString('pid=', $method->value);
        $this->assertStringContainsString('nonce=', $method->value);
        $this->assertStringContainsString('pake=', $method->value);
    }

    public function testLinkNotExpiredImmediately(): void
    {
        $hp = new HeadlessPairing();
        $method = $hp->generateLink('peer', 'nonce', 'pake');
        $this->assertFalse($method->isExpired());
    }

    // --- HeadlessPairingMethod ---

    public function testMethodExpiryForTimedMethods(): void
    {
        // Method with expiry in the far past
        $expired = new HeadlessPairingMethod(
            type: HeadlessPairingMethodType::PinCode,
            value: '1234-5678',
            expiresAt: microtime(true) - 1000,
        );
        $this->assertTrue($expired->isExpired());

        // Method with expiry in the future
        $valid = new HeadlessPairingMethod(
            type: HeadlessPairingMethodType::PinCode,
            value: '1234-5678',
            expiresAt: microtime(true) + 1000,
        );
        $this->assertFalse($valid->isExpired());
    }

    // --- PersonalRelayConfig ---

    public function testRelayConfigDefaults(): void
    {
        $cfg = new PersonalRelayConfig();
        $this->assertTrue($cfg->relayWilling);
        $this->assertSame(100, $cfg->relayCapacity);
        $this->assertSame([], $cfg->allowedPeers);
    }

    public function testRelayAllowsAllPeersWhenListEmpty(): void
    {
        $cfg = new PersonalRelayConfig();
        $peer = $this->makePeer(1);
        $this->assertTrue($cfg->isPeerAllowed($peer));
    }

    public function testRelayRestrictsToAllowedPeers(): void
    {
        $peerA = $this->makePeer(1);
        $peerB = $this->makePeer(2);
        $peerC = $this->makePeer(3);
        $cfg = new PersonalRelayConfig(
            relayWilling: true,
            relayCapacity: 10,
            allowedPeers: [$peerA, $peerB],
        );
        $this->assertTrue($cfg->isPeerAllowed($peerA));
        $this->assertTrue($cfg->isPeerAllowed($peerB));
        $this->assertFalse($cfg->isPeerAllowed($peerC));
    }

    // --- PeerSyncState ---

    public function testPeerSyncStateNewIsZeroed(): void
    {
        $peer = $this->makePeer(1);
        $state = new PeerSyncState($peer);
        $this->assertTrue($state->peerId->equals($peer));
        $this->assertSame(0, $state->lastSeenSequence);
        $this->assertSame(0, $state->pendingDeliveries);
        $this->assertNull($state->lastConnected);
    }

    public function testPeerSyncStateLifecycle(): void
    {
        $state = new PeerSyncState($this->makePeer(1));
        $this->assertSame(0, $state->pendingDeliveries);
        $this->assertNull($state->lastConnected);

        $state->markConnected();
        $this->assertNotNull($state->lastConnected);

        $state->enqueueDelivery();
        $state->enqueueDelivery();
        $state->enqueueDelivery();
        $this->assertSame(3, $state->pendingDeliveries);

        $state->advanceSequence(2);
        $this->assertSame(2, $state->lastSeenSequence);
        $this->assertSame(1, $state->pendingDeliveries);
    }

    public function testPeerSyncStateAdvanceDoesNotGoBackwards(): void
    {
        $state = new PeerSyncState($this->makePeer(1));
        $state->advanceSequence(42);
        $this->assertSame(42, $state->lastSeenSequence);
        // Should not go backwards
        $state->advanceSequence(10);
        $this->assertSame(42, $state->lastSeenSequence);
    }

    public function testPeerSyncStateAddPendingAndAcknowledge(): void
    {
        $state = new PeerSyncState($this->makePeer(1));
        $state->addPending(5);
        $this->assertSame(5, $state->pendingDeliveries);
        $state->acknowledgeDelivery(3);
        $this->assertSame(2, $state->pendingDeliveries);
        // Cannot go below zero
        $state->acknowledgeDelivery(10);
        $this->assertSame(0, $state->pendingDeliveries);
    }

    // --- PeerMetrics ---

    public function testPeerMetricsNewIsZeroed(): void
    {
        $peer = $this->makePeer(1);
        $metrics = new PeerMetrics($peer);
        $this->assertTrue($metrics->peerId->equals($peer));
        $this->assertSame(0, $metrics->bytesRelayed);
        $this->assertSame(0, $metrics->bytesStored);
    }

    public function testPeerMetricsAccounting(): void
    {
        $m = new PeerMetrics($this->makePeer(1));
        $m->recordRelay(1024);
        $m->recordStore(512);
        $this->assertSame(1024, $m->bytesRelayed);
        $this->assertSame(512, $m->bytesStored);
    }

    public function testPeerMetricsReleaseStored(): void
    {
        $m = new PeerMetrics($this->makePeer(1));
        $m->recordStore(2048);
        $m->releaseStored(1024);
        $this->assertSame(1024, $m->bytesStored);
        // Cannot go below zero
        $m->releaseStored(5000);
        $this->assertSame(0, $m->bytesStored);
    }

    // --- PeerQuota ---

    public function testPeerQuotaDefaultDisabled(): void
    {
        $q = new PeerQuota();
        $this->assertNull($q->maxStoredMessages);
        $this->assertNull($q->maxRelayBandwidthBps);
    }

    public function testQuotaCheckStoreUnlimited(): void
    {
        $quota = new PeerQuota();
        $this->assertTrue($quota->checkStoreQuota(1_000_000));
    }

    public function testQuotaCheckStoreWithinLimit(): void
    {
        $quota = new PeerQuota(maxStoredMessages: 100);
        $this->assertTrue($quota->checkStoreQuota(99));
        $this->assertFalse($quota->checkStoreQuota(100));
        $this->assertFalse($quota->checkStoreQuota(101));
    }

    public function testQuotaCheckRelayUnlimited(): void
    {
        $quota = new PeerQuota();
        $this->assertTrue($quota->checkRelayQuota(PHP_INT_MAX));
    }

    public function testQuotaCheckRelayWithinLimit(): void
    {
        $quota = new PeerQuota(maxRelayBandwidthBps: 1_000_000);
        $this->assertTrue($quota->checkRelayQuota(999_999));
        $this->assertTrue($quota->checkRelayQuota(1_000_000));
        $this->assertFalse($quota->checkRelayQuota(1_000_001));
    }

    // --- ManagementConfig ---

    public function testManagementConfigDefaults(): void
    {
        $cfg = new ManagementConfig();
        $this->assertFalse($cfg->enabled);
        $this->assertSame('127.0.0.1', $cfg->bindAddress);
        $this->assertSame(9090, $cfg->port);
        $this->assertSame('', $cfg->authToken);
    }

    public function testManagementConfigIsLoopback(): void
    {
        $this->assertTrue((new ManagementConfig(bindAddress: '127.0.0.1'))->isLoopback());
        $this->assertTrue((new ManagementConfig(bindAddress: '::1'))->isLoopback());
        $this->assertTrue((new ManagementConfig(bindAddress: 'localhost'))->isLoopback());
        $this->assertFalse((new ManagementConfig(bindAddress: '0.0.0.0'))->isLoopback());
    }

    // --- ManagementState ---

    public function testManagementStateDefaults(): void
    {
        $state = new ManagementState(authToken: 'test-token');
        $this->assertSame('test-token', $state->authToken);
        $this->assertSame([], $state->peers);
        $this->assertSame([], $state->queues);
        $this->assertSame(0, $state->relayStats->activeConnections);
        $this->assertSame([], $state->relayStats->perPeer);
    }

    // --- ManagementServer construction ---

    public function testManagementServerRejectsEmptyToken(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('auth token is empty');
        new ManagementServer(
            new ManagementConfig(enabled: true, authToken: ''),
            new ManagementState(authToken: ''),
        );
    }

    // --- ManagementServer HTTP ---

    private const AUTH_TOKEN = 'test-secret-token-1234';

    private function makeServer(
        array $peers = [],
        array $queues = [],
        ?RelayStats $relay = null,
    ): ManagementServer {
        $cfg = new ManagementConfig(enabled: true, port: 0, authToken: self::AUTH_TOKEN);
        $state = new ManagementState(authToken: self::AUTH_TOKEN);
        $state->peers = $peers;
        $state->queues = $queues;
        if ($relay !== null) {
            $state->relayStats = $relay;
        }
        $srv = new ManagementServer($cfg, $state);
        $srv->start();
        return $srv;
    }

    /**
     * Send a raw HTTP request to the management server.
     *
     * @return array{int, array<string, mixed>}
     */
    private function sendRequest(
        ManagementServer $srv,
        string $path,
        ?string $token = self::AUTH_TOKEN,
        string $method = 'GET',
    ): array {
        $port = $srv->port();
        $fp = fsockopen('127.0.0.1', $port, $errno, $errstr, 5.0);
        $this->assertNotFalse($fp, "Failed to connect: $errstr ($errno)");

        $request = "$method $path HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n";
        if ($token !== null) {
            $request .= "Authorization: Bearer $token\r\n";
        }
        $request .= "\r\n";
        fwrite($fp, $request);

        // Trigger server to handle this connection
        $srv->handleOne(1.0);

        // Read response
        $response = '';
        stream_set_timeout($fp, 5);
        while (!feof($fp)) {
            $chunk = fread($fp, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $response .= $chunk;
        }
        fclose($fp);

        // Parse status code and body
        $headerEnd = strpos($response, "\r\n\r\n");
        $this->assertNotFalse($headerEnd, 'Invalid HTTP response');
        $statusLine = substr($response, 0, strpos($response, "\r\n"));
        $parts = explode(' ', $statusLine, 3);
        $statusCode = (int) $parts[1];
        $body = json_decode(substr($response, $headerEnd + 4), true);
        return [$statusCode, $body ?? []];
    }

    public function testAuthMissingHeader(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/health', token: null);
            $this->assertSame(401, $status);
            $this->assertSame('unauthorized', $body['error']);
        } finally {
            $srv->stop();
        }
    }

    public function testAuthWrongToken(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/health', token: 'wrong-token');
            $this->assertSame(401, $status);
            $this->assertSame('unauthorized', $body['error']);
        } finally {
            $srv->stop();
        }
    }

    public function testAuthCorrectToken(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/health');
            $this->assertSame(200, $status);
        } finally {
            $srv->stop();
        }
    }

    public function testMethodNotAllowed(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/health', method: 'POST');
            $this->assertSame(405, $status);
            $this->assertSame('method not allowed', $body['error']);
        } finally {
            $srv->stop();
        }
    }

    public function testNotFound(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/nonexistent');
            $this->assertSame(404, $status);
            $this->assertSame('not found', $body['error']);
        } finally {
            $srv->stop();
        }
    }

    public function testHealthDegradedNoPeers(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/health');
            $this->assertSame(200, $status);
            $this->assertSame('degraded', $body['status']);
            $this->assertSame(0, $body['connected_peers']);
            $this->assertSame(0, $body['total_peers']);
            $this->assertArrayHasKey('uptime_secs', $body);
        } finally {
            $srv->stop();
        }
    }

    public function testHealthHealthyWithConnectedPeer(): void
    {
        $peers = [
            new MgmtPeerInfo(peerId: 'aabb', name: 'phone', connected: true),
            new MgmtPeerInfo(peerId: 'ccdd', name: 'laptop', connected: false),
        ];
        $srv = $this->makeServer(peers: $peers);
        try {
            [$status, $body] = $this->sendRequest($srv, '/health');
            $this->assertSame(200, $status);
            $this->assertSame('healthy', $body['status']);
            $this->assertSame(1, $body['connected_peers']);
            $this->assertSame(2, $body['total_peers']);
        } finally {
            $srv->stop();
        }
    }

    public function testPeersEmpty(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/peers');
            $this->assertSame(200, $status);
            $this->assertSame([], $body['peers']);
        } finally {
            $srv->stop();
        }
    }

    public function testPeersWithData(): void
    {
        $peers = [
            new MgmtPeerInfo(
                peerId: 'aabb',
                name: 'phone',
                connected: true,
                lastSeen: '2026-01-01T00:00:00Z',
            ),
        ];
        $srv = $this->makeServer(peers: $peers);
        try {
            [$status, $body] = $this->sendRequest($srv, '/peers');
            $this->assertSame(200, $status);
            $this->assertCount(1, $body['peers']);
            $this->assertSame('aabb', $body['peers'][0]['peer_id']);
            $this->assertSame('phone', $body['peers'][0]['name']);
            $this->assertTrue($body['peers'][0]['connected']);
            $this->assertSame('2026-01-01T00:00:00Z', $body['peers'][0]['last_seen']);
        } finally {
            $srv->stop();
        }
    }

    public function testQueuesEmpty(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/queues');
            $this->assertSame(200, $status);
            $this->assertSame([], $body['queues']);
        } finally {
            $srv->stop();
        }
    }

    public function testQueuesWithData(): void
    {
        $queues = [
            new QueueInfo(
                peerId: 'aabb',
                pendingMessages: 5,
                oldestMessageAgeSecs: 120.5,
                totalBytes: 2048,
            ),
        ];
        $srv = $this->makeServer(queues: $queues);
        try {
            [$status, $body] = $this->sendRequest($srv, '/queues');
            $this->assertSame(200, $status);
            $this->assertCount(1, $body['queues']);
            $this->assertSame('aabb', $body['queues'][0]['peer_id']);
            $this->assertSame(5, $body['queues'][0]['pending_messages']);
            $this->assertSame(120.5, $body['queues'][0]['oldest_message_age_secs']);
            $this->assertSame(2048, $body['queues'][0]['total_bytes']);
        } finally {
            $srv->stop();
        }
    }

    public function testRelayStatsDefault(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/relay/stats');
            $this->assertSame(200, $status);
            $this->assertSame(0, $body['relay']['active_connections']);
            $this->assertSame([], $body['relay']['per_peer']);
        } finally {
            $srv->stop();
        }
    }

    public function testRelayStatsWithData(): void
    {
        $relay = new RelayStats(
            activeConnections: 3,
            perPeer: [
                new PeerRelayStats(peerId: 'aabb', bytesRelayed: 4096, activeStreams: 2),
            ],
        );
        $srv = $this->makeServer(relay: $relay);
        try {
            [$status, $body] = $this->sendRequest($srv, '/relay/stats');
            $this->assertSame(200, $status);
            $this->assertSame(3, $body['relay']['active_connections']);
            $this->assertCount(1, $body['relay']['per_peer']);
            $this->assertSame('aabb', $body['relay']['per_peer'][0]['peer_id']);
            $this->assertSame(4096, $body['relay']['per_peer'][0]['bytes_relayed']);
            $this->assertSame(2, $body['relay']['per_peer'][0]['active_streams']);
        } finally {
            $srv->stop();
        }
    }

    public function testPairingQrPlaceholder(): void
    {
        $srv = $this->makeServer();
        try {
            [$status, $body] = $this->sendRequest($srv, '/pairing/qr');
            $this->assertSame(503, $status);
            $this->assertStringContainsString('not yet available', $body['error']);
        } finally {
            $srv->stop();
        }
    }
}
