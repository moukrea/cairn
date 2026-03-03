<?php

declare(strict_types=1);

namespace Cairn\Tests\Mesh;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Mesh\MeshConfig;
use Cairn\Mesh\MeshException;
use Cairn\Mesh\MeshTopologyUpdate;
use Cairn\Mesh\ReachabilityEntry;
use Cairn\Mesh\Route;
use Cairn\Mesh\RoutingTable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MeshConfig::class)]
#[CoversClass(Route::class)]
#[CoversClass(RoutingTable::class)]
#[CoversClass(MeshTopologyUpdate::class)]
#[CoversClass(ReachabilityEntry::class)]
#[CoversClass(MeshException::class)]
final class RouterTest extends TestCase
{
    private function makePeer(): PeerId
    {
        return Identity::generate()->peerId();
    }

    // --- MeshConfig ---

    public function testDefaultConfig(): void
    {
        $config = new MeshConfig();
        $this->assertFalse($config->meshEnabled);
        $this->assertSame(3, $config->maxHops);
        $this->assertFalse($config->relayWilling);
        $this->assertSame(10, $config->relayCapacity);
    }

    public function testServerModeConfig(): void
    {
        $config = MeshConfig::serverMode();
        $this->assertTrue($config->meshEnabled);
        $this->assertTrue($config->relayWilling);
        $this->assertSame(100, $config->relayCapacity);
        $this->assertSame(3, $config->maxHops);
    }

    public function testCustomConfig(): void
    {
        $config = new MeshConfig(
            meshEnabled: true,
            maxHops: 5,
            relayWilling: true,
            relayCapacity: 50,
        );
        $this->assertTrue($config->meshEnabled);
        $this->assertSame(5, $config->maxHops);
        $this->assertTrue($config->relayWilling);
        $this->assertSame(50, $config->relayCapacity);
    }

    // --- Route ---

    public function testRouteDirect(): void
    {
        $route = Route::direct(10, 1_000_000);
        $this->assertSame(0, $route->hopCount());
        $this->assertSame(10, $route->latencyMs);
        $this->assertSame(1_000_000, $route->bandwidthBps);
        $this->assertSame([], $route->hops);
    }

    public function testRouteRelayed(): void
    {
        $relay = $this->makePeer();
        $route = Route::relayed([$relay], 50, 500_000);
        $this->assertSame(1, $route->hopCount());
        $this->assertSame(50, $route->latencyMs);
        $this->assertSame(500_000, $route->bandwidthBps);
    }

    public function testRouteMultiHop(): void
    {
        $r1 = $this->makePeer();
        $r2 = $this->makePeer();
        $route = Route::relayed([$r1, $r2], 100, 200_000);
        $this->assertSame(2, $route->hopCount());
    }

    public function testRouteSelectionKey(): void
    {
        $route = Route::direct(10, 1_000_000);
        $key = $route->selectionKey();
        $this->assertSame([0, 10, -1_000_000], $key);
    }

    // --- RoutingTable ---

    public function testAddAndSelectRoute(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        $rt->addRoute($dest, Route::direct(20, 1_000_000));

        $best = $rt->selectBestRoute($dest);
        $this->assertSame(0, $best->hopCount());
        $this->assertSame(20, $best->latencyMs);
    }

    public function testMaxHopsEnforced(): void
    {
        $rt = new RoutingTable(2);
        $dest = $this->makePeer();
        $hops = [$this->makePeer(), $this->makePeer(), $this->makePeer()]; // 3 hops

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/max hops exceeded: 3 > 2/');
        $rt->addRoute($dest, Route::relayed($hops, 100, 100_000));
    }

    public function testRouteSelectionPrefsFewerHops(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();
        $relay = $this->makePeer();

        // 1-hop route with better latency
        $rt->addRoute($dest, Route::relayed([$relay], 5, 10_000_000));
        // Direct route with worse latency
        $rt->addRoute($dest, Route::direct(100, 100_000));

        $best = $rt->selectBestRoute($dest);
        $this->assertSame(0, $best->hopCount()); // Direct wins despite higher latency
    }

    public function testRouteSelectionPrefersLowerLatencyAtSameHops(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        $rt->addRoute($dest, Route::direct(100, 1_000_000));
        $rt->addRoute($dest, Route::direct(10, 1_000_000));

        $best = $rt->selectBestRoute($dest);
        $this->assertSame(10, $best->latencyMs);
    }

    public function testRouteSelectionPrefersHigherBandwidthAtSameHopsAndLatency(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        $rt->addRoute($dest, Route::direct(10, 100_000));
        $rt->addRoute($dest, Route::direct(10, 10_000_000));

        $best = $rt->selectBestRoute($dest);
        $this->assertSame(10_000_000, $best->bandwidthBps);
    }

    public function testNoRouteError(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/no route to peer/');
        $rt->selectBestRoute($dest);
    }

    public function testRemoveRoutes(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();
        $rt->addRoute($dest, Route::direct(10, 1_000_000));
        $this->assertSame(1, $rt->peerCount());

        $rt->removeRoutes($dest);
        $this->assertSame(0, $rt->peerCount());
    }

    public function testPeerAndRouteCounts(): void
    {
        $rt = new RoutingTable(3);
        $dest1 = $this->makePeer();
        $dest2 = $this->makePeer();

        $rt->addRoute($dest1, Route::direct(10, 1_000_000));
        $rt->addRoute($dest1, Route::direct(20, 500_000));
        $rt->addRoute($dest2, Route::direct(15, 800_000));

        $this->assertSame(2, $rt->peerCount());
        $this->assertSame(3, $rt->routeCount());
    }

    public function testDestinations(): void
    {
        $rt = new RoutingTable(3);
        $dest1 = $this->makePeer();
        $dest2 = $this->makePeer();

        $rt->addRoute($dest1, Route::direct(10, 1_000_000));
        $rt->addRoute($dest2, Route::direct(20, 500_000));

        $dests = $rt->destinations();
        $this->assertCount(2, $dests);
        $this->assertContains((string) $dest1, $dests);
        $this->assertContains((string) $dest2, $dests);
    }

    public function testGetRoutes(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        $this->assertNull($rt->getRoutes($dest));

        $rt->addRoute($dest, Route::direct(10, 1_000_000));
        $routes = $rt->getRoutes($dest);
        $this->assertNotNull($routes);
        $this->assertCount(1, $routes);
    }

    public function testMaxHopsAccessor(): void
    {
        $rt = new RoutingTable(5);
        $this->assertSame(5, $rt->maxHops());
    }

    public function testExpireRoutes(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        // Add a route with a timestamp far in the past
        $staleRoute = new Route(
            hops: [],
            latencyMs: 10,
            bandwidthBps: 1_000_000,
            lastSeen: microtime(true) - 7200, // 2 hours ago
        );
        $rt->addRoute($dest, $staleRoute);
        $this->assertSame(1, $rt->peerCount());

        // Expire routes older than 1 hour
        $rt->expireRoutes(3600);
        $this->assertSame(0, $rt->peerCount());
    }

    public function testExpireRoutesKeepsFresh(): void
    {
        $rt = new RoutingTable(3);
        $dest = $this->makePeer();

        // Add a fresh route (just created)
        $rt->addRoute($dest, Route::direct(10, 1_000_000));

        // Expire routes older than 1 hour
        $rt->expireRoutes(3600);
        $this->assertSame(1, $rt->peerCount());
    }

    // --- Topology Updates ---

    public function testApplyTopologyUpdate(): void
    {
        $rt = new RoutingTable(3);
        $neighbor = $this->makePeer();
        $remotePeer = $this->makePeer();

        $update = new MeshTopologyUpdate([
            new ReachabilityEntry(
                peerId: $remotePeer,
                viaHops: [],
                latencyMs: 30,
                bandwidthBps: 500_000,
            ),
        ]);

        $added = $rt->applyTopologyUpdate($neighbor, $update);
        $this->assertSame(1, $added);

        $best = $rt->selectBestRoute($remotePeer);
        $this->assertSame(1, $best->hopCount()); // Through neighbor
        $this->assertSame(30, $best->latencyMs);
    }

    public function testApplyTopologyUpdateExceedingMaxHopsSkipped(): void
    {
        $rt = new RoutingTable(1); // max 1 hop
        $neighbor = $this->makePeer();
        $relay = $this->makePeer();
        $remotePeer = $this->makePeer();

        $update = new MeshTopologyUpdate([
            new ReachabilityEntry(
                peerId: $remotePeer,
                viaHops: [$relay], // neighbor + relay = 2 hops, exceeds max
                latencyMs: 30,
                bandwidthBps: 500_000,
            ),
        ]);

        $added = $rt->applyTopologyUpdate($neighbor, $update);
        $this->assertSame(0, $added);

        $this->expectException(MeshException::class);
        $rt->selectBestRoute($remotePeer);
    }

    public function testApplyTopologyUpdateMultipleEntries(): void
    {
        $rt = new RoutingTable(3);
        $neighbor = $this->makePeer();
        $peer1 = $this->makePeer();
        $peer2 = $this->makePeer();

        $update = new MeshTopologyUpdate([
            new ReachabilityEntry(
                peerId: $peer1,
                viaHops: [],
                latencyMs: 10,
                bandwidthBps: 1_000_000,
            ),
            new ReachabilityEntry(
                peerId: $peer2,
                viaHops: [],
                latencyMs: 20,
                bandwidthBps: 500_000,
            ),
        ]);

        $added = $rt->applyTopologyUpdate($neighbor, $update);
        $this->assertSame(2, $added);
        $this->assertSame(2, $rt->peerCount());
    }

    // --- MeshException ---

    public function testMeshExceptionMessages(): void
    {
        $this->assertSame('mesh routing disabled', MeshException::meshDisabled()->getMessage());
        $this->assertSame('no route to peer abc', MeshException::noRoute('abc')->getMessage());
        $this->assertSame('max hops exceeded: 4 > 3', MeshException::maxHopsExceeded(4, 3)->getMessage());
        $this->assertSame('relay capacity full (10/10)', MeshException::relayCapacityFull(10, 10)->getMessage());
        $this->assertSame('relay not willing', MeshException::relayNotWilling()->getMessage());
        $this->assertSame(
            'relay connection failed: timeout',
            MeshException::relayConnectionFailed('timeout')->getMessage(),
        );
    }
}
