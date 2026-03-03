<?php

declare(strict_types=1);

namespace Cairn\Tests\Transport;

use Cairn\Transport\ConnectionQuality;
use Cairn\Transport\ConnectionQualityMonitor;
use Cairn\Transport\QualityThresholds;
use Cairn\Transport\TransportAttempt;
use Cairn\Transport\TransportAttemptResult;
use Cairn\Transport\TransportChain;
use Cairn\Transport\TransportConfig;
use Cairn\Transport\TransportType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TransportChain::class)]
#[CoversClass(TransportConfig::class)]
#[CoversClass(TransportType::class)]
#[CoversClass(ConnectionQualityMonitor::class)]
final class ChainTest extends TestCase
{
    public function testTransportTypePriorities(): void
    {
        $this->assertSame(2, TransportType::StunHolePunch->priority());
        $this->assertSame(3, TransportType::Tcp->priority());
        $this->assertSame(4, TransportType::TurnUdp->priority());
        $this->assertSame(5, TransportType::TurnTcp->priority());
        $this->assertSame(6, TransportType::WebSocketTls->priority());
        $this->assertSame(8, TransportType::CircuitRelayV2->priority());
        $this->assertSame(9, TransportType::HttpsLongPoll->priority());
    }

    public function testAllInOrderCount(): void
    {
        $all = TransportType::allInOrder();
        $this->assertCount(7, $all);
    }

    public function testAllInOrderIsSorted(): void
    {
        $all = TransportType::allInOrder();
        for ($i = 1; $i < count($all); $i++) {
            $this->assertLessThan(
                $all[$i]->priority(),
                $all[$i - 1]->priority(),
                sprintf('%s should be before %s', $all[$i - 1]->label(), $all[$i]->label()),
            );
        }
    }

    public function testTier0Availability(): void
    {
        $this->assertTrue(TransportType::StunHolePunch->tier0Available());
        $this->assertTrue(TransportType::Tcp->tier0Available());
        $this->assertFalse(TransportType::TurnUdp->tier0Available());
        $this->assertFalse(TransportType::TurnTcp->tier0Available());
        $this->assertFalse(TransportType::WebSocketTls->tier0Available());
        $this->assertTrue(TransportType::CircuitRelayV2->tier0Available());
        $this->assertFalse(TransportType::HttpsLongPoll->tier0Available());
    }

    public function testTransportTypeLabels(): void
    {
        $this->assertSame('Direct TCP', TransportType::Tcp->label());
        $this->assertSame('HTTPS long-polling (443)', TransportType::HttpsLongPoll->label());
    }

    public function testTier0Config(): void
    {
        $config = TransportConfig::tier0();
        $this->assertTrue($config->isEnabled(TransportType::StunHolePunch));
        $this->assertTrue($config->isEnabled(TransportType::Tcp));
        $this->assertFalse($config->isEnabled(TransportType::TurnUdp));
        $this->assertFalse($config->isEnabled(TransportType::TurnTcp));
        $this->assertFalse($config->isEnabled(TransportType::WebSocketTls));
        $this->assertTrue($config->isEnabled(TransportType::CircuitRelayV2));
        $this->assertFalse($config->isEnabled(TransportType::HttpsLongPoll));
    }

    public function testFullConfig(): void
    {
        $config = TransportConfig::full();
        foreach (TransportType::allInOrder() as $type) {
            $this->assertTrue($config->isEnabled($type), $type->label() . ' should be enabled');
        }
    }

    public function testChainTier0HasCorrectAvailability(): void
    {
        $chain = TransportChain::tier0();
        $transports = $chain->transports();
        $this->assertCount(7, $transports);

        // Check availability
        foreach ($transports as $attempt) {
            if ($attempt->type->tier0Available()) {
                $this->assertTrue($attempt->available, $attempt->type->label() . ' should be available');
            } else {
                $this->assertFalse($attempt->available, $attempt->type->label() . ' should not be available');
            }
        }
    }

    public function testTransportAttemptResultDisplay(): void
    {
        $skipped = new TransportAttemptResult(
            type: TransportType::TurnUdp,
            error: null,
            skipped: true,
            durationSeconds: 0.0,
        );
        $this->assertStringContainsString('skipped', (string) $skipped);

        $failed = new TransportAttemptResult(
            type: TransportType::Tcp,
            error: 'connection refused',
            skipped: false,
            durationSeconds: 1.5,
        );
        $this->assertStringContainsString('connection refused', (string) $failed);
        $this->assertStringContainsString('Direct TCP', (string) $failed);

        $success = new TransportAttemptResult(
            type: TransportType::Tcp,
            error: null,
            skipped: false,
            durationSeconds: 0.5,
        );
        $this->assertStringContainsString('success', (string) $success);
    }

    public function testConnectionQualityDefaults(): void
    {
        $q = new ConnectionQuality();
        $this->assertSame(0.0, $q->latency);
        $this->assertSame(0.0, $q->jitter);
        $this->assertSame(0.0, $q->packetLossRatio);
    }

    public function testQualityThresholdsDefaults(): void
    {
        $t = new QualityThresholds();
        $this->assertSame(0.5, $t->maxLatency);
        $this->assertSame(0.1, $t->maxJitter);
        $this->assertSame(0.05, $t->maxPacketLoss);
    }

    public function testMonitorDetectsHighLatency(): void
    {
        $monitor = new ConnectionQualityMonitor();
        $good = new ConnectionQuality(latency: 0.1);
        $this->assertFalse($monitor->isDegraded($good));

        $bad = new ConnectionQuality(latency: 0.6);
        $this->assertTrue($monitor->isDegraded($bad));
    }

    public function testMonitorDetectsHighJitter(): void
    {
        $monitor = new ConnectionQualityMonitor();
        $bad = new ConnectionQuality(jitter: 0.15);
        $this->assertTrue($monitor->isDegraded($bad));
    }

    public function testMonitorDetectsHighPacketLoss(): void
    {
        $monitor = new ConnectionQualityMonitor();
        $bad = new ConnectionQuality(packetLossRatio: 0.10);
        $this->assertTrue($monitor->isDegraded($bad));
    }

    public function testMonitorCustomThresholds(): void
    {
        $thresholds = new QualityThresholds(maxLatency: 1.0, maxJitter: 0.5, maxPacketLoss: 0.10);
        $monitor = new ConnectionQualityMonitor($thresholds);

        $ok = new ConnectionQuality(latency: 0.9, jitter: 0.4, packetLossRatio: 0.09);
        $this->assertFalse($monitor->isDegraded($ok));

        $bad = new ConnectionQuality(latency: 1.1);
        $this->assertTrue($monitor->isDegraded($bad));
    }

    public function testParallelModeDefault(): void
    {
        $chain = TransportChain::tier0();
        $this->assertFalse($chain->parallelMode());
    }

    public function testParallelModeEnabled(): void
    {
        $chain = new TransportChain(TransportConfig::tier0(), parallelMode: true);
        $this->assertTrue($chain->parallelMode());
    }
}
