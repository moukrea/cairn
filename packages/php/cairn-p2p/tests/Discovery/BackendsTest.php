<?php

declare(strict_types=1);

namespace Cairn\Tests\Discovery;

use Cairn\Discovery\DhtBackend;
use Cairn\Discovery\DiscoveryCoordinator;
use Cairn\Discovery\MdnsBackend;
use Cairn\Discovery\RendezvousId;
use Cairn\Discovery\SignalingBackend;
use Cairn\Discovery\TrackerBackend;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MdnsBackend::class)]
#[CoversClass(DhtBackend::class)]
#[CoversClass(TrackerBackend::class)]
#[CoversClass(SignalingBackend::class)]
#[CoversClass(DiscoveryCoordinator::class)]
final class BackendsTest extends TestCase
{
    private function makeId(int $byte): RendezvousId
    {
        return new RendezvousId(str_repeat(chr($byte), 32));
    }

    // --- mDNS ---

    public function testMdnsPublishAndQuery(): void
    {
        $backend = new MdnsBackend();
        $id = $this->makeId(0xAA);
        $payload = 'encrypted-reachability';

        $backend->publish($id, $payload);
        $result = null;
        $backend->query($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame($payload, $result);
    }

    public function testMdnsQueryNotFound(): void
    {
        $backend = new MdnsBackend();
        $result = 'not-null';
        $backend->query($this->makeId(0xBB))->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertNull($result);
    }

    public function testMdnsStopClearsRecords(): void
    {
        $backend = new MdnsBackend();
        $id = $this->makeId(0xCC);
        $backend->publish($id, 'data');
        $this->assertSame(1, $backend->recordCount());

        $backend->stop();

        $result = 'not-null';
        $backend->query($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertNull($result);
        $this->assertSame(0, $backend->recordCount());
    }

    public function testMdnsName(): void
    {
        $this->assertSame('mdns', (new MdnsBackend())->name());
    }

    // --- DHT ---

    public function testDhtPublishAndQuery(): void
    {
        $backend = new DhtBackend();
        $id = $this->makeId(0xDD);
        $backend->publish($id, 'dht-payload');

        $result = null;
        $backend->query($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('dht-payload', $result);
    }

    public function testDhtName(): void
    {
        $this->assertSame('kademlia', (new DhtBackend())->name());
    }

    public function testDhtBootstrapNodes(): void
    {
        $backend = new DhtBackend(['node1:4001', 'node2:4001']);
        $this->assertSame(['node1:4001', 'node2:4001'], $backend->bootstrapNodes());
    }

    // --- BitTorrent Tracker ---

    public function testTrackerPublishAndQuery(): void
    {
        $backend = new TrackerBackend();
        $id = $this->makeId(0xEE);
        $backend->publish($id, 'tracker-payload');

        $result = null;
        $backend->query($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('tracker-payload', $result);
    }

    public function testTrackerInfoHashIs20Bytes(): void
    {
        $id = $this->makeId(0xFF);
        $hash = TrackerBackend::toInfoHash($id);
        $this->assertSame(20, strlen($hash));
        $this->assertSame(str_repeat("\xFF", 20), $hash);
    }

    public function testTrackerMinReannounceIs15Min(): void
    {
        $backend = new TrackerBackend();
        $this->assertSame(900, $backend->minReannounceInterval());
    }

    public function testTrackerName(): void
    {
        $this->assertSame('bittorrent', (new TrackerBackend())->name());
    }

    public function testTrackerUrls(): void
    {
        $backend = new TrackerBackend(['http://tracker.example.com/announce']);
        $this->assertSame(['http://tracker.example.com/announce'], $backend->trackerUrls());
    }

    // --- Signaling ---

    public function testSignalingPublishAndQuery(): void
    {
        $backend = new SignalingBackend('wss://signal.example.com', 'token-123');
        $this->assertSame('wss://signal.example.com', $backend->serverUrl());
        $this->assertTrue($backend->hasAuth());

        $id = $this->makeId(0x11);
        $backend->publish($id, 'signal-payload');

        $result = null;
        $backend->query($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('signal-payload', $result);
    }

    public function testSignalingNoAuth(): void
    {
        $backend = new SignalingBackend('wss://open.example.com');
        $this->assertFalse($backend->hasAuth());
    }

    public function testSignalingName(): void
    {
        $this->assertSame('signaling', (new SignalingBackend('wss://example.com'))->name());
    }

    // --- DiscoveryCoordinator ---

    public function testCoordinatorPublishAll(): void
    {
        $mdns = new MdnsBackend();
        $dht = new DhtBackend();
        $coord = new DiscoveryCoordinator([$mdns, $dht]);

        $this->assertSame(2, $coord->backendCount());
        $this->assertSame(['mdns', 'kademlia'], $coord->backendNames());

        $id = $this->makeId(0x22);
        $results = $coord->publishAll($id, 'payload');
        $this->assertCount(2, $results);
    }

    public function testCoordinatorQueryFirstFindsInFirstBackend(): void
    {
        $mdns = new MdnsBackend();
        $dht = new DhtBackend();

        $id = $this->makeId(0x33);
        $mdns->publish($id, 'from-mdns');

        $coord = new DiscoveryCoordinator([$mdns, $dht]);
        $result = null;
        $coord->queryFirst($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('from-mdns', $result);
    }

    public function testCoordinatorQueryFirstFallsThroughToSecond(): void
    {
        $mdns = new MdnsBackend();
        $dht = new DhtBackend();

        $id = $this->makeId(0x44);
        $dht->publish($id, 'from-dht');

        $coord = new DiscoveryCoordinator([$mdns, $dht]);
        $result = null;
        $coord->queryFirst($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertSame('from-dht', $result);
    }

    public function testCoordinatorQueryFirstReturnsNullWhenEmpty(): void
    {
        $coord = new DiscoveryCoordinator([new MdnsBackend()]);
        $id = $this->makeId(0x55);
        $result = 'not-null';
        $coord->queryFirst($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertNull($result);
    }

    public function testCoordinatorStopAll(): void
    {
        $mdns = new MdnsBackend();
        $dht = new DhtBackend();

        $id = $this->makeId(0x66);
        $mdns->publish($id, 'data');
        $dht->publish($id, 'data');

        $coord = new DiscoveryCoordinator([$mdns, $dht]);
        $results = $coord->stopAll();
        $this->assertCount(2, $results);

        // After stop, queries return null
        $result = 'not-null';
        $coord->queryFirst($id)->then(function ($v) use (&$result): void {
            $result = $v;
        });
        $this->assertNull($result);
    }

    public function testAllBackendsHaveCorrectNames(): void
    {
        $this->assertSame('mdns', (new MdnsBackend())->name());
        $this->assertSame('kademlia', (new DhtBackend())->name());
        $this->assertSame('bittorrent', (new TrackerBackend())->name());
        $this->assertSame('signaling', (new SignalingBackend('wss://example.com'))->name());
    }
}
