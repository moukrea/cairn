<?php

declare(strict_types=1);

namespace Cairn\Tests\Mesh;

use Cairn\Crypto\Identity;
use Cairn\Crypto\PeerId;
use Cairn\Mesh\MeshConfig;
use Cairn\Mesh\MeshException;
use Cairn\Mesh\RelayManager;
use Cairn\Mesh\RelaySession;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RelayManager::class)]
#[CoversClass(RelaySession::class)]
final class RelayTest extends TestCase
{
    private function makePeer(): PeerId
    {
        return Identity::generate()->peerId();
    }

    private function willingConfig(): MeshConfig
    {
        return new MeshConfig(
            meshEnabled: true,
            maxHops: 3,
            relayWilling: true,
            relayCapacity: 10,
        );
    }

    public function testRelayRequestSuccess(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $src = $this->makePeer();
        $dst = $this->makePeer();

        $id = $mgr->requestRelay($src, $dst);
        $this->assertSame(1, $mgr->activeSessionCount());
        $this->assertNotNull($mgr->getSession($id));
    }

    public function testRelayRequestMeshDisabled(): void
    {
        $config = new MeshConfig(
            meshEnabled: false,
            relayWilling: true,
            relayCapacity: 10,
        );
        $mgr = new RelayManager($config);

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/mesh routing disabled/');
        $mgr->requestRelay($this->makePeer(), $this->makePeer());
    }

    public function testRelayRequestNotWilling(): void
    {
        $config = new MeshConfig(
            meshEnabled: true,
            relayWilling: false,
            relayCapacity: 10,
        );
        $mgr = new RelayManager($config);

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/relay not willing/');
        $mgr->requestRelay($this->makePeer(), $this->makePeer());
    }

    public function testRelayCapacityEnforced(): void
    {
        $config = new MeshConfig(
            meshEnabled: true,
            relayWilling: true,
            relayCapacity: 2,
        );
        $mgr = new RelayManager($config);

        $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $mgr->requestRelay($this->makePeer(), $this->makePeer());

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/relay capacity full \(2\/2\)/');
        $mgr->requestRelay($this->makePeer(), $this->makePeer());
    }

    public function testRelaySameSourceAndDestRejected(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $peer = $this->makePeer();

        $this->expectException(MeshException::class);
        $this->expectExceptionMessageMatches('/source and destination are the same peer/');
        $mgr->requestRelay($peer, $peer);
    }

    public function testCloseSession(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $id = $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $this->assertSame(1, $mgr->activeSessionCount());

        $this->assertTrue($mgr->closeSession($id));
        $this->assertSame(0, $mgr->activeSessionCount());
    }

    public function testCloseNonexistentSession(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $this->assertFalse($mgr->closeSession(999));
    }

    public function testRemainingCapacity(): void
    {
        $config = new MeshConfig(
            meshEnabled: true,
            relayWilling: true,
            relayCapacity: 5,
        );
        $mgr = new RelayManager($config);
        $this->assertSame(5, $mgr->remainingCapacity());

        $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $this->assertSame(4, $mgr->remainingCapacity());
    }

    public function testCapacityRestoredAfterClose(): void
    {
        $config = new MeshConfig(
            meshEnabled: true,
            relayWilling: true,
            relayCapacity: 2,
        );
        $mgr = new RelayManager($config);

        $id1 = $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $mgr->requestRelay($this->makePeer(), $this->makePeer());

        // At capacity
        $this->assertSame(0, $mgr->remainingCapacity());

        // Close one, now there's room
        $mgr->closeSession($id1);
        $this->assertSame(1, $mgr->remainingCapacity());

        // Can add another
        $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $this->assertSame(0, $mgr->remainingCapacity());
    }

    public function testUniqueSessionIds(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $id1 = $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $id2 = $mgr->requestRelay($this->makePeer(), $this->makePeer());
        $this->assertNotSame($id1, $id2);
    }

    public function testSessionDetails(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $src = $this->makePeer();
        $dst = $this->makePeer();
        $id = $mgr->requestRelay($src, $dst);

        $session = $mgr->getSession($id);
        $this->assertNotNull($session);
        $this->assertSame($id, $session->id);
        $this->assertTrue($session->source->equals($src));
        $this->assertTrue($session->destination->equals($dst));
    }

    public function testGetSessionNotFound(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $this->assertNull($mgr->getSession(999));
    }

    public function testIsWilling(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $this->assertTrue($mgr->isWilling());

        $config = new MeshConfig(
            meshEnabled: true,
            relayWilling: false,
        );
        $mgr2 = new RelayManager($config);
        $this->assertFalse($mgr2->isWilling());
    }

    public function testUpdateConfig(): void
    {
        $mgr = new RelayManager($this->willingConfig());
        $this->assertTrue($mgr->isWilling());

        $mgr->updateConfig(new MeshConfig(
            meshEnabled: true,
            relayWilling: false,
        ));
        $this->assertFalse($mgr->isWilling());
    }
}
