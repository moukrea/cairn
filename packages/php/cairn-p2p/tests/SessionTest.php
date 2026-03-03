<?php

declare(strict_types=1);

namespace Cairn\Tests;

use Cairn\EnqueueResult;
use Cairn\HeartbeatConfig;
use Cairn\HeartbeatMonitor;
use Cairn\MessageQueue;
use Cairn\QueueConfig;
use Cairn\QueueStrategy;
use Cairn\Session;
use Cairn\SessionEvent;
use Cairn\SessionState;
use Cairn\SessionStateMachine;
use Cairn\Error\CairnException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SessionStateMachine::class)]
#[CoversClass(Session::class)]
#[CoversClass(MessageQueue::class)]
#[CoversClass(HeartbeatMonitor::class)]
final class SessionTest extends TestCase
{
    // --- SessionState ---

    public function testSessionStateValues(): void
    {
        $this->assertSame('connected', SessionState::Connected->value);
        $this->assertSame('unstable', SessionState::Unstable->value);
        $this->assertSame('disconnected', SessionState::Disconnected->value);
        $this->assertSame('reconnecting', SessionState::Reconnecting->value);
        $this->assertSame('suspended', SessionState::Suspended->value);
        $this->assertSame('reconnected', SessionState::Reconnected->value);
        $this->assertSame('failed', SessionState::Failed->value);
    }

    public function testSessionStateLabels(): void
    {
        $this->assertSame('Connected', SessionState::Connected->label());
        $this->assertSame('Failed', SessionState::Failed->label());
    }

    // --- SessionStateMachine ---

    public function testInitialState(): void
    {
        $sm = new SessionStateMachine('test-session-id');
        $this->assertSame(SessionState::Connected, $sm->state());
        $this->assertSame('test-session-id', $sm->sessionId());
    }

    public function testValidTransitionConnectedToUnstable(): void
    {
        $sm = new SessionStateMachine('sid');
        $sm->transition(SessionState::Unstable);
        $this->assertSame(SessionState::Unstable, $sm->state());
    }

    public function testValidTransitionConnectedToDisconnected(): void
    {
        $sm = new SessionStateMachine('sid');
        $sm->transition(SessionState::Disconnected, 'abrupt loss');
        $this->assertSame(SessionState::Disconnected, $sm->state());
    }

    public function testValidTransitionUnstableToConnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Unstable);
        $sm->transition(SessionState::Connected);
        $this->assertSame(SessionState::Connected, $sm->state());
    }

    public function testValidTransitionUnstableToDisconnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Unstable);
        $sm->transition(SessionState::Disconnected);
        $this->assertSame(SessionState::Disconnected, $sm->state());
    }

    public function testValidTransitionDisconnectedToReconnecting(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Disconnected);
        $sm->transition(SessionState::Reconnecting);
        $this->assertSame(SessionState::Reconnecting, $sm->state());
    }

    public function testValidTransitionReconnectingToReconnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Reconnecting);
        $sm->transition(SessionState::Reconnected);
        $this->assertSame(SessionState::Reconnected, $sm->state());
    }

    public function testValidTransitionReconnectingToSuspended(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Reconnecting);
        $sm->transition(SessionState::Suspended);
        $this->assertSame(SessionState::Suspended, $sm->state());
    }

    public function testValidTransitionSuspendedToReconnecting(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Suspended);
        $sm->transition(SessionState::Reconnecting);
        $this->assertSame(SessionState::Reconnecting, $sm->state());
    }

    public function testValidTransitionSuspendedToFailed(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Suspended);
        $sm->transition(SessionState::Failed, 'max retries');
        $this->assertSame(SessionState::Failed, $sm->state());
    }

    public function testValidTransitionReconnectedToConnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Reconnected);
        $sm->transition(SessionState::Connected);
        $this->assertSame(SessionState::Connected, $sm->state());
    }

    public function testInvalidTransitionConnectedToFailed(): void
    {
        $sm = new SessionStateMachine('sid');
        $this->expectException(CairnException::class);
        $this->expectExceptionMessageMatches('/invalid session state transition/');
        $sm->transition(SessionState::Failed);
    }

    public function testInvalidTransitionDisconnectedToConnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Disconnected);
        $this->expectException(CairnException::class);
        $sm->transition(SessionState::Connected);
    }

    public function testInvalidTransitionFailedToConnected(): void
    {
        $sm = new SessionStateMachine('sid', SessionState::Failed);
        $this->expectException(CairnException::class);
        $sm->transition(SessionState::Connected);
    }

    public function testInvalidTransitionConnectedToReconnecting(): void
    {
        $sm = new SessionStateMachine('sid');
        $this->expectException(CairnException::class);
        $sm->transition(SessionState::Reconnecting);
    }

    public function testSelfTransitionRejected(): void
    {
        $sm = new SessionStateMachine('sid');
        $this->expectException(CairnException::class);
        $sm->transition(SessionState::Connected);
    }

    public function testStateChangeEventEmitted(): void
    {
        $sm = new SessionStateMachine('sid');
        /** @var list<SessionEvent> $events */
        $events = [];
        $sm->on('state_change', function (SessionEvent $e) use (&$events): void {
            $events[] = $e;
        });

        $sm->transition(SessionState::Unstable, 'high latency');

        $this->assertCount(1, $events);
        $this->assertSame(SessionState::Connected, $events[0]->fromState);
        $this->assertSame(SessionState::Unstable, $events[0]->toState);
        $this->assertSame('high latency', $events[0]->reason);
        $this->assertSame('sid', $events[0]->sessionId);
    }

    public function testMultipleEventsEmitted(): void
    {
        $sm = new SessionStateMachine('sid');
        /** @var list<SessionEvent> $events */
        $events = [];
        $sm->on('state_change', function (SessionEvent $e) use (&$events): void {
            $events[] = $e;
        });

        $sm->transition(SessionState::Unstable);
        $sm->transition(SessionState::Disconnected);
        $sm->transition(SessionState::Reconnecting);

        $this->assertCount(3, $events);
        $this->assertSame(SessionState::Unstable, $events[0]->toState);
        $this->assertSame(SessionState::Disconnected, $events[1]->toState);
        $this->assertSame(SessionState::Reconnecting, $events[2]->toState);
    }

    public function testFullReconnectionCycle(): void
    {
        $sm = new SessionStateMachine('sid');
        $sm->transition(SessionState::Unstable);
        $sm->transition(SessionState::Disconnected);
        $sm->transition(SessionState::Reconnecting);
        $sm->transition(SessionState::Reconnected);
        $sm->transition(SessionState::Connected);
        $this->assertSame(SessionState::Connected, $sm->state());
    }

    public function testSuspendedRetryCycle(): void
    {
        $sm = new SessionStateMachine('sid');
        $sm->transition(SessionState::Disconnected);
        $sm->transition(SessionState::Reconnecting);
        $sm->transition(SessionState::Suspended);
        $sm->transition(SessionState::Reconnecting);
        $sm->transition(SessionState::Suspended);
        $sm->transition(SessionState::Failed, 'max retries');
        $this->assertSame(SessionState::Failed, $sm->state());
    }

    public function testIsValidTransitionExhaustive(): void
    {
        $valid = [
            [SessionState::Connected, SessionState::Unstable],
            [SessionState::Connected, SessionState::Disconnected],
            [SessionState::Unstable, SessionState::Disconnected],
            [SessionState::Unstable, SessionState::Connected],
            [SessionState::Disconnected, SessionState::Reconnecting],
            [SessionState::Reconnecting, SessionState::Reconnected],
            [SessionState::Reconnecting, SessionState::Suspended],
            [SessionState::Suspended, SessionState::Reconnecting],
            [SessionState::Suspended, SessionState::Failed],
            [SessionState::Reconnected, SessionState::Connected],
        ];
        foreach ($valid as [$from, $to]) {
            $this->assertTrue(
                SessionStateMachine::isValidTransition($from, $to),
                sprintf('expected valid: %s -> %s', $from->label(), $to->label()),
            );
        }

        $invalid = [
            [SessionState::Connected, SessionState::Failed],
            [SessionState::Connected, SessionState::Reconnecting],
            [SessionState::Connected, SessionState::Reconnected],
            [SessionState::Connected, SessionState::Suspended],
            [SessionState::Disconnected, SessionState::Connected],
            [SessionState::Disconnected, SessionState::Failed],
            [SessionState::Reconnecting, SessionState::Connected],
            [SessionState::Reconnecting, SessionState::Failed],
            [SessionState::Reconnected, SessionState::Failed],
            [SessionState::Reconnected, SessionState::Disconnected],
            [SessionState::Failed, SessionState::Connected],
            [SessionState::Failed, SessionState::Reconnecting],
        ];
        foreach ($invalid as [$from, $to]) {
            $this->assertFalse(
                SessionStateMachine::isValidTransition($from, $to),
                sprintf('expected invalid: %s -> %s', $from->label(), $to->label()),
            );
        }
    }

    public function testInvalidTransitionDoesNotChangeState(): void
    {
        $sm = new SessionStateMachine('sid');
        try {
            $sm->transition(SessionState::Failed);
        } catch (CairnException) {
        }
        $this->assertSame(SessionState::Connected, $sm->state());
    }

    // --- Session ---

    public function testSessionCreate(): void
    {
        $session = Session::create('peer-abc');
        $this->assertSame('peer-abc', $session->peerId);
        $this->assertSame(SessionState::Connected, $session->state());
        $this->assertNotEmpty($session->id);
        $this->assertSame(0, $session->sequenceTx());
        $this->assertSame(0, $session->sequenceRx());
        $this->assertSame(0, $session->ratchetEpoch());
        $this->assertSame(86400.0, $session->expiryDuration());
    }

    public function testSessionCustomExpiry(): void
    {
        $session = Session::create('peer-abc', expiryDuration: 3600.0);
        $this->assertSame(3600.0, $session->expiryDuration());
    }

    public function testSessionNotExpiredImmediately(): void
    {
        $session = Session::create('peer-abc');
        $this->assertFalse($session->isExpired());
    }

    public function testSessionExpiredWithZeroDuration(): void
    {
        $session = Session::create('peer-abc', expiryDuration: 0.0);
        $this->assertTrue($session->isExpired());
    }

    public function testSessionIsConnected(): void
    {
        $session = Session::create('peer-abc');
        $this->assertTrue($session->isConnected());

        $session->transition(SessionState::Unstable);
        $this->assertTrue($session->isConnected());

        $session->transition(SessionState::Disconnected);
        $this->assertFalse($session->isConnected());
    }

    public function testSessionTransition(): void
    {
        $session = Session::create('peer-abc');
        $session->transition(SessionState::Unstable);
        $this->assertSame(SessionState::Unstable, $session->state());
    }

    public function testSessionInvalidTransition(): void
    {
        $session = Session::create('peer-abc');
        $this->expectException(CairnException::class);
        $session->transition(SessionState::Failed);
    }

    public function testSessionNextSequenceTx(): void
    {
        $session = Session::create('peer-abc');
        $this->assertSame(0, $session->nextSequenceTx());
        $this->assertSame(1, $session->nextSequenceTx());
        $this->assertSame(2, $session->nextSequenceTx());
        $this->assertSame(3, $session->sequenceTx());
    }

    public function testSessionAdvanceRatchetEpoch(): void
    {
        $session = Session::create('peer-abc');
        $this->assertSame(0, $session->ratchetEpoch());
        $session->advanceRatchetEpoch();
        $this->assertSame(1, $session->ratchetEpoch());
        $session->advanceRatchetEpoch();
        $this->assertSame(2, $session->ratchetEpoch());
    }

    public function testSessionEventForwarded(): void
    {
        $session = Session::create('peer-abc');
        /** @var list<SessionEvent> $events */
        $events = [];
        $session->on('state_change', function (SessionEvent $e) use (&$events): void {
            $events[] = $e;
        });

        $session->transition(SessionState::Unstable, 'latency spike');

        $this->assertCount(1, $events);
        $this->assertSame(SessionState::Connected, $events[0]->fromState);
        $this->assertSame(SessionState::Unstable, $events[0]->toState);
        $this->assertSame('latency spike', $events[0]->reason);
    }

    public function testSessionFullLifecycle(): void
    {
        $session = Session::create('peer-abc');
        /** @var list<SessionEvent> $events */
        $events = [];
        $session->on('state_change', function (SessionEvent $e) use (&$events): void {
            $events[] = $e;
        });

        $session->transition(SessionState::Unstable);
        $session->transition(SessionState::Disconnected);
        $session->transition(SessionState::Reconnecting);
        $session->advanceRatchetEpoch();
        $session->transition(SessionState::Reconnected);
        $session->transition(SessionState::Connected);

        $this->assertSame(SessionState::Connected, $session->state());
        $this->assertSame(1, $session->ratchetEpoch());
        $this->assertCount(5, $events);
    }

    public function testSessionEnqueueMessage(): void
    {
        $session = Session::create('peer-abc');
        $result = $session->enqueueMessage('hello');
        $this->assertSame(EnqueueResult::Enqueued, $result);
        $this->assertSame(1, $session->queue()->len());
        $this->assertSame(1, $session->sequenceTx());
    }

    public function testSessionDrainQueue(): void
    {
        $session = Session::create('peer-abc');
        $session->enqueueMessage('msg1');
        $session->enqueueMessage('msg2');

        $msgs = $session->drainQueue();
        $this->assertCount(2, $msgs);
        $this->assertSame('msg1', $msgs[0]->payload);
        $this->assertSame('msg2', $msgs[1]->payload);
        $this->assertTrue($session->queue()->isEmpty());
    }

    // --- MessageQueue ---

    public function testQueueStartsEmpty(): void
    {
        $queue = new MessageQueue();
        $this->assertTrue($queue->isEmpty());
        $this->assertSame(0, $queue->len());
        $this->assertSame(1000, $queue->remainingCapacity());
    }

    public function testEnqueueSuccess(): void
    {
        $queue = new MessageQueue();
        $result = $queue->enqueue(1, 'data');
        $this->assertSame(EnqueueResult::Enqueued, $result);
        $this->assertSame(1, $queue->len());
    }

    public function testEnqueueMultiple(): void
    {
        $queue = new MessageQueue();
        $queue->enqueue(1, 'a');
        $queue->enqueue(2, 'b');
        $queue->enqueue(3, 'c');
        $this->assertSame(3, $queue->len());
        $this->assertSame(997, $queue->remainingCapacity());
    }

    public function testPeek(): void
    {
        $queue = new MessageQueue();
        $this->assertNull($queue->peek());

        $queue->enqueue(1, 'data');
        $msg = $queue->peek();
        $this->assertNotNull($msg);
        $this->assertSame(1, $msg->sequence);
        $this->assertSame('data', $msg->payload);
        $this->assertSame(1, $queue->len());
    }

    public function testEnqueueDisabled(): void
    {
        $queue = new MessageQueue(new QueueConfig(enabled: false));
        $result = $queue->enqueue(1, 'data');
        $this->assertSame(EnqueueResult::Disabled, $result);
        $this->assertTrue($queue->isEmpty());
    }

    public function testFifoRejectsWhenFull(): void
    {
        $queue = new MessageQueue(new QueueConfig(maxSize: 3, strategy: QueueStrategy::Fifo));
        $this->assertSame(EnqueueResult::Enqueued, $queue->enqueue(1, 'a'));
        $this->assertSame(EnqueueResult::Enqueued, $queue->enqueue(2, 'b'));
        $this->assertSame(EnqueueResult::Enqueued, $queue->enqueue(3, 'c'));
        $this->assertSame(EnqueueResult::Full, $queue->enqueue(4, 'd'));
        $this->assertSame(3, $queue->len());
        $this->assertSame(1, $queue->peek()->sequence);
    }

    public function testLifoEvictsOldestWhenFull(): void
    {
        $queue = new MessageQueue(new QueueConfig(maxSize: 3, strategy: QueueStrategy::Lifo));
        $queue->enqueue(1, 'a');
        $queue->enqueue(2, 'b');
        $queue->enqueue(3, 'c');
        $result = $queue->enqueue(4, 'd');
        $this->assertSame(EnqueueResult::EnqueuedWithEviction, $result);
        $this->assertSame(3, $queue->len());
        $this->assertSame(2, $queue->peek()->sequence);
    }

    public function testLifoMultipleEvictions(): void
    {
        $queue = new MessageQueue(new QueueConfig(maxSize: 2, strategy: QueueStrategy::Lifo));
        $queue->enqueue(1, 'a');
        $queue->enqueue(2, 'b');
        $queue->enqueue(3, 'c');
        $queue->enqueue(4, 'd');

        $msgs = $queue->drain();
        $this->assertCount(2, $msgs);
        $this->assertSame(3, $msgs[0]->sequence);
        $this->assertSame(4, $msgs[1]->sequence);
    }

    public function testDrainReturnsInOrder(): void
    {
        $queue = new MessageQueue();
        $queue->enqueue(1, 'a');
        $queue->enqueue(2, 'b');
        $queue->enqueue(3, 'c');

        $msgs = $queue->drain();
        $this->assertCount(3, $msgs);
        $this->assertSame(1, $msgs[0]->sequence);
        $this->assertSame(2, $msgs[1]->sequence);
        $this->assertSame(3, $msgs[2]->sequence);
        $this->assertTrue($queue->isEmpty());
    }

    public function testClearDiscardsAll(): void
    {
        $queue = new MessageQueue();
        $queue->enqueue(1, 'a');
        $queue->enqueue(2, 'b');
        $queue->clear();
        $this->assertTrue($queue->isEmpty());
        $this->assertSame(1000, $queue->remainingCapacity());
    }

    public function testExpireStaleWithZeroMaxAge(): void
    {
        $queue = new MessageQueue(new QueueConfig(maxAge: 0.0));
        $queue->enqueue(1, 'a');
        $msgs = $queue->drain();
        $this->assertCount(0, $msgs);
    }

    public function testPayloadPreserved(): void
    {
        $queue = new MessageQueue();
        $payload = str_repeat("\xDE\xAD", 50);
        $queue->enqueue(42, $payload);
        $msgs = $queue->drain();
        $this->assertSame($payload, $msgs[0]->payload);
        $this->assertSame(42, $msgs[0]->sequence);
    }

    // --- HeartbeatConfig ---

    public function testDefaultHeartbeatConfig(): void
    {
        $config = new HeartbeatConfig();
        $this->assertSame(30.0, $config->interval);
        $this->assertSame(90.0, $config->timeout);
    }

    public function testAggressiveHeartbeatConfig(): void
    {
        $config = HeartbeatConfig::aggressive();
        $this->assertSame(5.0, $config->interval);
        $this->assertSame(15.0, $config->timeout);
    }

    public function testRelaxedHeartbeatConfig(): void
    {
        $config = HeartbeatConfig::relaxed();
        $this->assertSame(60.0, $config->interval);
        $this->assertSame(180.0, $config->timeout);
    }

    public function testTimeoutIs3xInterval(): void
    {
        $default = new HeartbeatConfig();
        $this->assertSame($default->interval * 3, $default->timeout);

        $aggressive = HeartbeatConfig::aggressive();
        $this->assertSame($aggressive->interval * 3, $aggressive->timeout);

        $relaxed = HeartbeatConfig::relaxed();
        $this->assertSame($relaxed->interval * 3, $relaxed->timeout);
    }

    // --- HeartbeatMonitor ---

    public function testMonitorNotTimedOutInitially(): void
    {
        $monitor = new HeartbeatMonitor();
        $this->assertFalse($monitor->isTimedOut());
    }

    public function testMonitorNotNeedingHeartbeatInitially(): void
    {
        $monitor = new HeartbeatMonitor();
        $this->assertFalse($monitor->shouldSendHeartbeat());
    }

    public function testMonitorTimeUntilHeartbeatPositive(): void
    {
        $monitor = new HeartbeatMonitor();
        $until = $monitor->timeUntilNextHeartbeat();
        $this->assertGreaterThan(0.0, $until);
        $this->assertLessThanOrEqual(30.0, $until);
    }

    public function testMonitorTimeUntilTimeoutPositive(): void
    {
        $monitor = new HeartbeatMonitor();
        $until = $monitor->timeUntilTimeout();
        $this->assertGreaterThan(0.0, $until);
        $this->assertLessThanOrEqual(90.0, $until);
    }

    public function testMonitorTimedOutWithZeroTimeout(): void
    {
        $monitor = new HeartbeatMonitor(new HeartbeatConfig(timeout: 0.0));
        $this->assertTrue($monitor->isTimedOut());
    }

    public function testMonitorShouldSendWithZeroInterval(): void
    {
        $monitor = new HeartbeatMonitor(new HeartbeatConfig(interval: 0.0));
        $this->assertTrue($monitor->shouldSendHeartbeat());
    }

    public function testMonitorConfigAccessible(): void
    {
        $config = HeartbeatConfig::aggressive();
        $monitor = new HeartbeatMonitor($config);
        $this->assertSame(5.0, $monitor->config()->interval);
        $this->assertSame(15.0, $monitor->config()->timeout);
    }

    public function testMonitorLastActivityAccessible(): void
    {
        $monitor = new HeartbeatMonitor();
        $this->assertGreaterThan(0.0, $monitor->lastActivity());
    }
}
