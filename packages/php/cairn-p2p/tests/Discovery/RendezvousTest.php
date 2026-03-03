<?php

declare(strict_types=1);

namespace Cairn\Tests\Discovery;

use Cairn\Discovery\RendezvousId;
use Cairn\Discovery\RotationConfig;
use Cairn\Error\CairnException;

use function Cairn\Discovery\activeRendezvousIdsAt;
use function Cairn\Discovery\computeEpoch;
use function Cairn\Discovery\deriveEpochOffset;
use function Cairn\Discovery\derivePairingRendezvousId;
use function Cairn\Discovery\deriveRendezvousId;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RendezvousId::class)]
#[CoversClass(RotationConfig::class)]
final class RendezvousTest extends TestCase
{
    public function testDeriveRendezvousIdDeterministic(): void
    {
        $secret = 'shared-pairing-secret';
        $id1 = deriveRendezvousId($secret, 42);
        $id2 = deriveRendezvousId($secret, 42);
        $this->assertSame($id1->bytes, $id2->bytes);
    }

    public function testDeriveRendezvousIdDifferentEpochsDiffer(): void
    {
        $secret = 'shared-pairing-secret';
        $id1 = deriveRendezvousId($secret, 1);
        $id2 = deriveRendezvousId($secret, 2);
        $this->assertNotSame($id1->bytes, $id2->bytes);
    }

    public function testDeriveRendezvousIdDifferentSecretsDiffer(): void
    {
        $id1 = deriveRendezvousId('secret-a', 1);
        $id2 = deriveRendezvousId('secret-b', 1);
        $this->assertNotSame($id1->bytes, $id2->bytes);
    }

    public function testDerivePairingRendezvousIdDeterministic(): void
    {
        $cred = 'pake-credential';
        $nonce = 'nonce-123';
        $id1 = derivePairingRendezvousId($cred, $nonce);
        $id2 = derivePairingRendezvousId($cred, $nonce);
        $this->assertSame($id1->bytes, $id2->bytes);
    }

    public function testDerivePairingRendezvousDifferentNoncesDiffer(): void
    {
        $cred = 'pake-credential';
        $id1 = derivePairingRendezvousId($cred, 'nonce-a');
        $id2 = derivePairingRendezvousId($cred, 'nonce-b');
        $this->assertNotSame($id1->bytes, $id2->bytes);
    }

    public function testDerivePairingRendezvousDiffersFromStandard(): void
    {
        $secret = 'same-input';
        $standard = deriveRendezvousId($secret, 1);
        $epochSalt = pack('J', 1);
        $pairing = derivePairingRendezvousId($secret, $epochSalt);
        $this->assertNotSame($standard->bytes, $pairing->bytes);
    }

    public function testComputeEpochConsistent(): void
    {
        $secret = 'test-secret';
        $ts = 1_700_000_000;
        $e1 = computeEpoch($secret, 3600, $ts);
        $e2 = computeEpoch($secret, 3600, $ts);
        $this->assertSame($e1, $e2);
    }

    public function testComputeEpochAdvancesWithTime(): void
    {
        $secret = 'test-secret';
        $e1 = computeEpoch($secret, 3600, 1_700_000_000);
        $e2 = computeEpoch($secret, 3600, 1_700_000_000 + 3600);
        $this->assertSame($e2, $e1 + 1);
    }

    public function testComputeEpochZeroIntervalRejected(): void
    {
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/rotation interval/');
        computeEpoch('secret', 0, 1_700_000_000);
    }

    public function testComputeEpochDifferentSecretsDifferentOffsets(): void
    {
        $ts = 1_700_000_000;
        $e1 = computeEpoch('secret-a', 3600, $ts);
        $e2 = computeEpoch('secret-b', 3600, $ts);
        $this->assertNotSame($e1, $e2);
    }

    public function testActiveIdsIncludesCurrentEpochId(): void
    {
        $secret = 'test-secret';
        $config = new RotationConfig();
        $ts = 1_700_000_000;

        $ids = activeRendezvousIdsAt($secret, $config, $ts);
        $epoch = computeEpoch($secret, $config->rotationInterval, $ts);
        $expectedId = deriveRendezvousId($secret, $epoch);

        $found = false;
        foreach ($ids as $id) {
            if ($id->bytes === $expectedId->bytes) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'active IDs must include current epoch ID');
    }

    public function testActiveIdsDualNearEpochBoundary(): void
    {
        $secret = 'test-secret';
        $config = new RotationConfig(
            rotationInterval: 86400,
            overlapWindow: 3600,
            clockTolerance: 300,
        );

        $offset = deriveEpochOffset($secret);
        $interval = 86400;

        // Find a timestamp right at the start of an epoch boundary
        $n = intdiv(1_700_000_000 + $offset, $interval) + 1;
        $boundaryAdjusted = $n * $interval;
        $boundaryTs = $boundaryAdjusted - $offset;

        // Just after the boundary
        $idsAfter = activeRendezvousIdsAt($secret, $config, $boundaryTs + 100);
        $this->assertCount(2, $idsAfter, 'should have 2 IDs near epoch boundary (just after)');

        // Just before the boundary
        $idsBefore = activeRendezvousIdsAt($secret, $config, $boundaryTs - 100);
        $this->assertCount(2, $idsBefore, 'should have 2 IDs near epoch boundary (just before)');
    }

    public function testRendezvousIdToHex(): void
    {
        $id = new RendezvousId(str_repeat("\xAB", 32));
        $hex = $id->toHex();
        $this->assertSame(64, strlen($hex));
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $hex);
    }

    public function testRendezvousIdToInfoHash(): void
    {
        $id = new RendezvousId(str_repeat("\xFF", 32));
        $hash = $id->toInfoHash();
        $this->assertSame(20, strlen($hash));
        $this->assertSame(str_repeat("\xFF", 20), $hash);
    }

    public function testRendezvousIdInvalidLength(): void
    {
        $this->expectException(CairnException::class);
        new RendezvousId('too-short');
    }

    public function testRotationConfigDefaults(): void
    {
        $config = new RotationConfig();
        $this->assertSame(86400, $config->rotationInterval);
        $this->assertSame(3600, $config->overlapWindow);
        $this->assertSame(300, $config->clockTolerance);
    }

    public function testBothPeersComputeSameRendezvousId(): void
    {
        $sharedSecret = 'shared-pairing-secret-between-alice-and-bob';
        $epoch = 12345;
        $aliceId = deriveRendezvousId($sharedSecret, $epoch);
        $bobId = deriveRendezvousId($sharedSecret, $epoch);
        $this->assertSame($aliceId->bytes, $bobId->bytes);
    }
}
