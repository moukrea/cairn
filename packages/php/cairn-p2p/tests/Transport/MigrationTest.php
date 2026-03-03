<?php

declare(strict_types=1);

namespace Cairn\Tests\Transport;

use Cairn\Transport\BackoffConfig;
use Cairn\Transport\BackoffState;
use Cairn\Transport\ChallengeProof;
use Cairn\Transport\HeartbeatScheduler;
use Cairn\Transport\NetworkChange;
use Cairn\Transport\NetworkChangeType;
use Cairn\Transport\NetworkMonitor;
use Cairn\Transport\ResumptionRejectReason;
use Cairn\Transport\SessionResumptionRequest;
use Cairn\HeartbeatConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(BackoffConfig::class)]
#[CoversClass(BackoffState::class)]
#[CoversClass(NetworkMonitor::class)]
#[CoversClass(HeartbeatScheduler::class)]
final class MigrationTest extends TestCase
{
    // --- BackoffConfig ---

    public function testBackoffDefaults(): void
    {
        $config = new BackoffConfig();
        $this->assertSame(1.0, $config->initialDelay);
        $this->assertSame(60.0, $config->maxDelay);
        $this->assertSame(2.0, $config->factor);
    }

    // --- BackoffState ---

    public function testBackoffSequence(): void
    {
        $state = new BackoffState();
        // attempt 0: 1.0 * 2^0 = 1.0
        $this->assertSame(1.0, $state->nextDelay());
        // attempt 1: 1.0 * 2^1 = 2.0
        $this->assertSame(2.0, $state->nextDelay());
        // attempt 2: 1.0 * 2^2 = 4.0
        $this->assertSame(4.0, $state->nextDelay());
        // attempt 3: 1.0 * 2^3 = 8.0
        $this->assertSame(8.0, $state->nextDelay());
        $this->assertSame(4, $state->attempt());
    }

    public function testBackoffMaxDelayCap(): void
    {
        $state = new BackoffState();
        // Run through enough attempts to exceed 60s
        for ($i = 0; $i < 10; $i++) {
            $state->nextDelay();
        }
        // After many attempts, delay should be capped at maxDelay
        $delay = $state->nextDelay();
        $this->assertSame(60.0, $delay);
    }

    public function testBackoffReset(): void
    {
        $state = new BackoffState();
        $state->nextDelay();
        $state->nextDelay();
        $this->assertSame(2, $state->attempt());

        $state->reset();
        $this->assertSame(0, $state->attempt());
        $this->assertSame(1.0, $state->nextDelay());
    }

    public function testBackoffCustomConfig(): void
    {
        $config = new BackoffConfig(initialDelay: 0.1, maxDelay: 5.0, factor: 3.0);
        $state = new BackoffState($config);

        // 0.1 * 3^0 = 0.1
        $this->assertEqualsWithDelta(0.1, $state->nextDelay(), 0.001);
        // 0.1 * 3^1 = 0.3
        $this->assertEqualsWithDelta(0.3, $state->nextDelay(), 0.001);
        // 0.1 * 3^2 = 0.9
        $this->assertEqualsWithDelta(0.9, $state->nextDelay(), 0.001);
        // 0.1 * 3^3 = 2.7
        $this->assertEqualsWithDelta(2.7, $state->nextDelay(), 0.001);
        // 0.1 * 3^4 = 8.1 -> capped to 5.0
        $this->assertSame(5.0, $state->nextDelay());
    }

    public function testBackoffWithJitter(): void
    {
        $state = new BackoffState();
        $delay = $state->nextDelayWithJitter();
        // Base delay for attempt 0 is 1.0
        // With jitter: 1.0 + random(0, 0.5) -> [1.0, 1.5]
        $this->assertGreaterThanOrEqual(1.0, $delay);
        $this->assertLessThanOrEqual(1.5, $delay);
    }

    public function testBackoffWithJitterCappedAtMax(): void
    {
        $config = new BackoffConfig(initialDelay: 50.0, maxDelay: 60.0, factor: 2.0);
        $state = new BackoffState($config);
        // attempt 0: base = 50.0, jitter up to 25 -> max 75 -> capped to 60
        $delay = $state->nextDelayWithJitter();
        $this->assertLessThanOrEqual(60.0, $delay);
    }

    public function testBackoffConfigAccessible(): void
    {
        $config = new BackoffConfig(initialDelay: 2.0);
        $state = new BackoffState($config);
        $this->assertSame(2.0, $state->config()->initialDelay);
    }

    // --- ResumptionRejectReason ---

    public function testResumptionRejectReasonValues(): void
    {
        $this->assertSame('session_not_found', ResumptionRejectReason::SessionNotFound->value);
        $this->assertSame('session_expired', ResumptionRejectReason::SessionExpired->value);
        $this->assertSame('invalid_proof', ResumptionRejectReason::InvalidProof->value);
        $this->assertSame('replay_detected', ResumptionRejectReason::ReplayDetected->value);
    }

    public function testResumptionRejectReasonLabels(): void
    {
        $this->assertSame('session not found', ResumptionRejectReason::SessionNotFound->label());
        $this->assertSame('session expired', ResumptionRejectReason::SessionExpired->label());
        $this->assertSame('invalid proof', ResumptionRejectReason::InvalidProof->label());
        $this->assertSame('replay detected', ResumptionRejectReason::ReplayDetected->label());
    }

    // --- ChallengeProof ---

    public function testChallengeProofConstruction(): void
    {
        $proof = new ChallengeProof(
            signature: str_repeat("\x01", 64),
            publicKey: str_repeat("\x02", 32),
        );
        $this->assertSame(64, strlen($proof->signature));
        $this->assertSame(32, strlen($proof->publicKey));
    }

    // --- SessionResumptionRequest ---

    public function testSessionResumptionRequestConstruction(): void
    {
        $proof = new ChallengeProof(
            signature: str_repeat("\x00", 64),
            publicKey: str_repeat("\x00", 32),
        );
        $req = new SessionResumptionRequest(
            sessionId: 'test-session',
            proof: $proof,
            lastSeenSeq: 42,
            timestamp: 1_700_000_000,
            nonce: str_repeat("\x00", 32),
        );
        $this->assertSame('test-session', $req->sessionId);
        $this->assertSame(42, $req->lastSeenSeq);
        $this->assertSame(1_700_000_000, $req->timestamp);
    }

    // --- NetworkChange ---

    public function testNetworkChangeTypeValues(): void
    {
        $this->assertSame('interface_up', NetworkChangeType::InterfaceUp->value);
        $this->assertSame('interface_down', NetworkChangeType::InterfaceDown->value);
        $this->assertSame('address_changed', NetworkChangeType::AddressChanged->value);
    }

    public function testNetworkChangeToString(): void
    {
        $up = new NetworkChange(
            type: NetworkChangeType::InterfaceUp,
            interface: 'wlan0',
        );
        $this->assertSame('interface up: wlan0', (string) $up);

        $down = new NetworkChange(
            type: NetworkChangeType::InterfaceDown,
            interface: 'eth0',
        );
        $this->assertSame('interface down: eth0', (string) $down);

        $changed = new NetworkChange(
            type: NetworkChangeType::AddressChanged,
            interface: 'wlan0',
            oldAddress: '192.168.1.10',
            newAddress: '10.0.0.5',
        );
        $this->assertSame('address changed on wlan0: 10.0.0.5', (string) $changed);
    }

    // --- NetworkMonitor ---

    public function testNetworkMonitorPollInterval(): void
    {
        $monitor = new NetworkMonitor(pollInterval: 10.0);
        $this->assertSame(10.0, $monitor->pollInterval());
    }

    public function testNetworkMonitorReportChange(): void
    {
        $monitor = new NetworkMonitor();
        /** @var list<NetworkChange> $changes */
        $changes = [];
        $monitor->on('network_change', function (NetworkChange $c) use (&$changes): void {
            $changes[] = $c;
        });

        $change = new NetworkChange(
            type: NetworkChangeType::InterfaceUp,
            interface: 'wlan0',
        );
        $monitor->reportChange($change);

        $this->assertCount(1, $changes);
        $this->assertSame(NetworkChangeType::InterfaceUp, $changes[0]->type);
        $this->assertSame('wlan0', $changes[0]->interface);
    }

    // --- HeartbeatScheduler ---

    public function testHeartbeatSchedulerStartStop(): void
    {
        $scheduler = new HeartbeatScheduler();
        $this->assertFalse($scheduler->isRunning());

        $scheduler->start();
        $this->assertTrue($scheduler->isRunning());

        $scheduler->stop();
        $this->assertFalse($scheduler->isRunning());
    }

    public function testHeartbeatSchedulerTickWhenNotRunning(): void
    {
        $scheduler = new HeartbeatScheduler();
        $emitted = false;
        $scheduler->on('send_heartbeat', function () use (&$emitted): void {
            $emitted = true;
        });

        $scheduler->tick();
        $this->assertFalse($emitted);
    }

    public function testHeartbeatSchedulerEmitsTimeout(): void
    {
        $scheduler = new HeartbeatScheduler(new HeartbeatConfig(timeout: 0.0));
        $timedOut = false;
        $scheduler->on('timeout', function () use (&$timedOut): void {
            $timedOut = true;
        });

        $scheduler->start();
        $scheduler->tick();
        $this->assertTrue($timedOut);
    }

    public function testHeartbeatSchedulerEmitsSendHeartbeat(): void
    {
        $scheduler = new HeartbeatScheduler(new HeartbeatConfig(interval: 0.0, timeout: 60.0));
        $sent = false;
        $scheduler->on('send_heartbeat', function () use (&$sent): void {
            $sent = true;
        });

        $scheduler->start();
        $scheduler->tick();
        $this->assertTrue($sent);
    }

    public function testHeartbeatSchedulerRecordActivity(): void
    {
        $scheduler = new HeartbeatScheduler(new HeartbeatConfig(timeout: 0.0));

        // Normally would be timed out, but if we change config to a non-zero timeout...
        // This test validates recordActivity() doesn't throw
        $scheduler->recordActivity();
        $this->assertGreaterThan(0.0, $scheduler->monitor()->lastActivity());
    }

    public function testHeartbeatSchedulerTimeUntilMethods(): void
    {
        $scheduler = new HeartbeatScheduler();
        $this->assertGreaterThanOrEqual(0.0, $scheduler->timeUntilNextHeartbeat());
        $this->assertGreaterThanOrEqual(0.0, $scheduler->timeUntilTimeout());
    }
}
