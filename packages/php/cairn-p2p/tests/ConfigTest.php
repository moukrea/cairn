<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\CairnConfig;
use Cairn\MeshSettings;
use Cairn\ReconnectionPolicy;
use Cairn\StorageBackendType;
use Cairn\TransportType;
use Cairn\TurnServer;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CairnConfig::class)]
#[CoversClass(ReconnectionPolicy::class)]
#[CoversClass(MeshSettings::class)]
#[CoversClass(TurnServer::class)]
final class ConfigTest extends TestCase
{
    // --- Defaults ---

    public function testDefaultConfigHasStunServers(): void
    {
        $cfg = new CairnConfig();
        $this->assertCount(3, $cfg->stunServers);
        $this->assertStringContainsString('google.com', $cfg->stunServers[0]);
        $this->assertStringContainsString('cloudflare.com', $cfg->stunServers[2]);
    }

    public function testDefaultConfigHasTransportOrder(): void
    {
        $cfg = new CairnConfig();
        $this->assertSame([
            TransportType::Tcp,
            TransportType::WsTls,
            TransportType::CircuitRelayV2,
        ], $cfg->transportPreferences);
    }

    public function testDefaultReconnectionPolicyValues(): void
    {
        $p = new ReconnectionPolicy();
        $this->assertSame(30.0, $p->connectTimeout);
        $this->assertSame(10.0, $p->transportTimeout);
        $this->assertSame(3600.0, $p->reconnectMaxDuration);
        $this->assertSame(1.0, $p->reconnectBackoffInitial);
        $this->assertSame(60.0, $p->reconnectBackoffMax);
        $this->assertSame(2.0, $p->reconnectBackoffFactor);
        $this->assertSame(30.0, $p->rendezvousPollInterval);
        $this->assertSame(86400.0, $p->sessionExpiry);
        $this->assertSame(300.0, $p->pairingPayloadExpiry);
    }

    public function testDefaultMeshSettings(): void
    {
        $m = new MeshSettings();
        $this->assertFalse($m->meshEnabled);
        $this->assertSame(3, $m->maxHops);
        $this->assertFalse($m->relayWilling);
        $this->assertSame(10, $m->relayCapacity);
    }

    public function testDefaultConfigIsNotServerMode(): void
    {
        $cfg = new CairnConfig();
        $this->assertFalse($cfg->serverMode);
    }

    public function testDefaultConfigValidates(): void
    {
        $cfg = new CairnConfig();
        $cfg->validate();
        $this->addToAssertionCount(1); // no exception thrown
    }

    // --- Tier presets ---

    public function testTier0IsDefault(): void
    {
        $t0 = CairnConfig::tier0();
        $def = new CairnConfig();
        $this->assertSame($t0->stunServers, $def->stunServers);
        $this->assertSame([], $t0->signalingServers);
        $this->assertSame([], $t0->turnServers);
    }

    public function testTier1HasSignalingAndTurn(): void
    {
        $t1 = CairnConfig::tier1(
            signalingServers: ['wss://signal.example.com'],
            turnServers: [new TurnServer('turn:relay.example.com:3478', 'user', 'pass')],
        );
        $this->assertCount(1, $t1->signalingServers);
        $this->assertCount(1, $t1->turnServers);
        $t1->validate();
        $this->addToAssertionCount(1);
    }

    public function testTier2HasTrackersAndBootstrap(): void
    {
        $t2 = CairnConfig::tier2(
            signalingServers: ['wss://signal.example.com'],
            trackerUrls: ['udp://tracker.example.com:6969'],
            bootstrapNodes: ['/ip4/1.2.3.4/tcp/4001'],
        );
        $this->assertCount(1, $t2->trackerUrls);
        $this->assertCount(1, $t2->bootstrapNodes);
        $t2->validate();
        $this->addToAssertionCount(1);
    }

    public function testTier3HasMeshSettings(): void
    {
        $t3 = CairnConfig::tier3(
            signalingServers: ['wss://signal.example.com'],
            meshSettings: new MeshSettings(
                meshEnabled: true,
                maxHops: 5,
                relayWilling: true,
                relayCapacity: 20,
            ),
        );
        $this->assertTrue($t3->meshSettings->meshEnabled);
        $this->assertSame(5, $t3->meshSettings->maxHops);
        $t3->validate();
        $this->addToAssertionCount(1);
    }

    // --- Server mode ---

    public function testDefaultServerConfig(): void
    {
        $cfg = CairnConfig::defaultServer();
        $this->assertTrue($cfg->serverMode);
        $this->assertTrue($cfg->meshSettings->relayWilling);
        $this->assertSame(100, $cfg->meshSettings->relayCapacity);
        $this->assertSame(604800.0, $cfg->reconnectionPolicy->sessionExpiry);
        $this->assertSame(PHP_FLOAT_MAX, $cfg->reconnectionPolicy->reconnectMaxDuration);
        $cfg->validate();
        $this->addToAssertionCount(1);
    }

    // --- Validation ---

    public function testValidationEmptyStunNoTurnFails(): void
    {
        $cfg = new CairnConfig(stunServers: []);
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/stunServers/');
        $cfg->validate();
    }

    public function testValidationEmptyStunWithTurnOk(): void
    {
        $cfg = new CairnConfig(
            stunServers: [],
            turnServers: [new TurnServer('turn:relay.example.com:3478', 'u', 'p')],
        );
        $cfg->validate();
        $this->addToAssertionCount(1);
    }

    public function testValidationBackoffFactorLeOneFails(): void
    {
        $cfg = new CairnConfig(
            reconnectionPolicy: new ReconnectionPolicy(reconnectBackoffFactor: 1.0),
        );
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/reconnectBackoffFactor/');
        $cfg->validate();
    }

    public function testValidationMaxHopsZeroFails(): void
    {
        $cfg = new CairnConfig(
            meshSettings: new MeshSettings(maxHops: 0),
        );
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/maxHops/');
        $cfg->validate();
    }

    public function testValidationMaxHopsElevenFails(): void
    {
        $cfg = new CairnConfig(
            meshSettings: new MeshSettings(maxHops: 11),
        );
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/maxHops/');
        $cfg->validate();
    }

    // --- Transport types ---

    public function testTransportTypeValues(): void
    {
        $this->assertSame('tcp', TransportType::Tcp->value);
        $this->assertSame('ws_tls', TransportType::WsTls->value);
        $this->assertSame('circuit_relay_v2', TransportType::CircuitRelayV2->value);
    }

    // --- Storage backend ---

    public function testStorageBackendTypeValues(): void
    {
        $this->assertSame('filesystem', StorageBackendType::Filesystem->value);
        $this->assertSame('in_memory', StorageBackendType::InMemory->value);
    }

    // --- TurnServer ---

    public function testTurnServerFields(): void
    {
        $ts = new TurnServer('turn:example.com:3478', 'user', 'pass');
        $this->assertSame('turn:example.com:3478', $ts->url);
        $this->assertSame('user', $ts->username);
        $this->assertSame('pass', $ts->credential);
    }
}
