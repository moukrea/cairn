<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\HeartbeatConfig;
use Cairn\HeartbeatMonitor;
use Cairn\Protocol\MessageType;
use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;

/**
 * Transport-level heartbeat scheduler.
 *
 * Coordinates heartbeat sending and timeout detection at the transport layer.
 * Uses the session-level HeartbeatMonitor for timing and emits events when
 * heartbeats should be sent or when a timeout is detected.
 *
 * Integration with ReactPHP:
 *   $scheduler = new HeartbeatScheduler($config);
 *   Loop::addPeriodicTimer(1.0, fn() => $scheduler->tick());
 *   $scheduler->on('send_heartbeat', fn() => $transport->send(...));
 *   $scheduler->on('timeout', fn() => $session->transition(SessionState::Disconnected));
 *
 * Matches spec/07-reconnection-sessions.md section 6.
 */
final class HeartbeatScheduler implements EventEmitterInterface
{
    use EventEmitterTrait;

    private HeartbeatMonitor $monitor;
    private bool $running = false;
    private ?TimerInterface $loopTimer = null;
    private ?LoopInterface $loop = null;

    public function __construct(
        HeartbeatConfig $config = new HeartbeatConfig(),
    ) {
        $this->monitor = new HeartbeatMonitor($config);
    }

    /**
     * Attach to a ReactPHP event loop for automatic periodic ticking.
     *
     * Creates a periodic timer (default 1 second) that calls tick()
     * automatically. Replaces manual Loop::addPeriodicTimer() integration.
     *
     * @param LoopInterface $loop ReactPHP event loop
     * @param float $interval Timer interval in seconds (default 1.0)
     */
    public function attachLoop(LoopInterface $loop, float $interval = 1.0): void
    {
        $this->detachLoop();
        $this->loop = $loop;
        $this->loopTimer = $loop->addPeriodicTimer($interval, function (): void {
            $this->tick();
        });
    }

    /**
     * Detach from the ReactPHP event loop, cancelling the periodic timer.
     */
    public function detachLoop(): void
    {
        if ($this->loopTimer !== null && $this->loop !== null) {
            $this->loop->cancelTimer($this->loopTimer);
            $this->loopTimer = null;
        }
        $this->loop = null;
    }

    /**
     * Start the heartbeat scheduler.
     */
    public function start(): void
    {
        $this->running = true;
    }

    /**
     * Stop the heartbeat scheduler.
     */
    public function stop(): void
    {
        $this->running = false;
    }

    /**
     * Whether the scheduler is running.
     */
    public function isRunning(): bool
    {
        return $this->running;
    }

    /**
     * Tick the scheduler -- call periodically (e.g., every 1 second).
     *
     * Checks if a heartbeat needs to be sent or if the connection has timed out.
     * Emits 'send_heartbeat' or 'timeout' events as appropriate.
     */
    public function tick(): void
    {
        if (!$this->running) {
            return;
        }

        if ($this->monitor->isTimedOut()) {
            $this->emit('timeout', []);
            return;
        }

        if ($this->monitor->shouldSendHeartbeat()) {
            $this->monitor->recordHeartbeatSent();
            $this->emit('send_heartbeat', []);
        }
    }

    /**
     * Record that data was received (any data, not just heartbeats).
     *
     * Resets the timeout counter per spec:
     * "Receipt of any data resets the timeout counter."
     */
    public function recordActivity(): void
    {
        $this->monitor->recordActivity();
    }

    /**
     * Get the underlying heartbeat monitor.
     */
    public function monitor(): HeartbeatMonitor
    {
        return $this->monitor;
    }

    /**
     * Get the time until the next heartbeat should be sent (seconds).
     */
    public function timeUntilNextHeartbeat(): float
    {
        return $this->monitor->timeUntilNextHeartbeat();
    }

    /**
     * Get the time until the connection times out (seconds).
     */
    public function timeUntilTimeout(): float
    {
        return $this->monitor->timeUntilTimeout();
    }
}
