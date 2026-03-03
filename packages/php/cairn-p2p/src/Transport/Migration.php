<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\Error\CairnException;
use Cairn\SessionState;
use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;

/**
 * Exponential backoff configuration (spec section 2).
 *
 * Matches packages/rs/cairn-p2p/src/session/reconnection.rs BackoffConfig.
 */
final class BackoffConfig
{
    public function __construct(
        /** Initial delay before the first retry (seconds). */
        public readonly float $initialDelay = 1.0,
        /** Maximum delay between retries (seconds). */
        public readonly float $maxDelay = 60.0,
        /** Multiplicative factor for each attempt. */
        public readonly float $factor = 2.0,
    ) {
    }
}

/**
 * Tracks exponential backoff state across reconnection attempts.
 *
 * Delay = min(initialDelay * factor^attempt + jitter, maxDelay)
 * Jitter = random(0, 0.5 * delay) for decorrelation.
 *
 * Matches packages/rs/cairn-p2p/src/session/reconnection.rs BackoffState.
 */
final class BackoffState
{
    private int $currentAttempt = 0;

    public function __construct(
        private readonly BackoffConfig $config = new BackoffConfig(),
    ) {
    }

    /**
     * Calculate and return the next delay in seconds, advancing the attempt counter.
     */
    public function nextDelay(): float
    {
        $delay = $this->config->initialDelay * ($this->config->factor ** $this->currentAttempt);
        $delay = min($delay, $this->config->maxDelay);
        $this->currentAttempt++;
        return $delay;
    }

    /**
     * Calculate the next delay with jitter.
     *
     * Jitter = random(0, 0.5 * baseDelay), added to the base delay.
     */
    public function nextDelayWithJitter(): float
    {
        $base = $this->nextDelay();
        $jitter = (mt_rand() / mt_getrandmax()) * 0.5 * $base;
        return min($base + $jitter, $this->config->maxDelay);
    }

    /**
     * Reset the attempt counter (called on successful reconnection).
     */
    public function reset(): void
    {
        $this->currentAttempt = 0;
    }

    /**
     * Get the current attempt number.
     */
    public function attempt(): int
    {
        return $this->currentAttempt;
    }

    /**
     * Get the backoff configuration.
     */
    public function config(): BackoffConfig
    {
        return $this->config;
    }

    /**
     * Schedule a reconnection attempt using ReactPHP timer instead of blocking sleep.
     *
     * Calculates the next delay with jitter and schedules the callback
     * on the event loop after that delay.
     *
     * @param LoopInterface $loop ReactPHP event loop
     * @param callable(): void $reconnectFn Callback to execute on timer
     * @return TimerInterface The scheduled timer (can be cancelled)
     */
    public function scheduleReconnect(LoopInterface $loop, callable $reconnectFn): TimerInterface
    {
        $delay = $this->nextDelayWithJitter();
        return $loop->addTimer($delay, $reconnectFn);
    }
}

/**
 * Cryptographic proof for session resumption (spec section 3).
 */
final class ChallengeProof
{
    public function __construct(
        /** The signed challenge bytes. */
        public readonly string $signature,
        /** The public key used to sign (for verification). */
        public readonly string $publicKey,
    ) {
    }
}

/**
 * Session resumption request sent by the reconnecting peer (spec section 3).
 */
final class SessionResumptionRequest
{
    public function __construct(
        public readonly string $sessionId,
        public readonly ChallengeProof $proof,
        public readonly int $lastSeenSeq,
        public readonly int $timestamp,
        public readonly string $nonce,
    ) {
    }
}

/**
 * Network change event.
 */
final class NetworkChange
{
    public function __construct(
        public readonly NetworkChangeType $type,
        public readonly string $interface,
        public readonly ?string $oldAddress = null,
        public readonly ?string $newAddress = null,
    ) {
    }

    public function __toString(): string
    {
        return match ($this->type) {
            NetworkChangeType::InterfaceUp => sprintf('interface up: %s', $this->interface),
            NetworkChangeType::InterfaceDown => sprintf('interface down: %s', $this->interface),
            NetworkChangeType::AddressChanged => sprintf(
                'address changed on %s: %s',
                $this->interface,
                $this->newAddress ?? 'unknown',
            ),
        };
    }
}

/**
 * Monitors network interface changes by polling.
 *
 * On Linux, polls /proc/net/route for interface changes.
 * Cross-platform fallback: polls gethostbyname(gethostname()) for IP changes.
 *
 * Matches packages/rs/cairn-p2p/src/session/reconnection.rs NetworkMonitor.
 */
final class NetworkMonitor implements EventEmitterInterface
{
    use EventEmitterTrait;

    /** @var array<string, string> Last known addresses per interface */
    private array $knownAddresses = [];
    private ?string $lastHostAddress = null;
    private ?TimerInterface $loopTimer = null;
    private ?LoopInterface $loop = null;

    public function __construct(
        private readonly float $pollInterval = 5.0,
    ) {
    }

    /**
     * Attach to a ReactPHP event loop for automatic periodic polling.
     *
     * Creates a periodic timer that calls poll() at the configured interval.
     *
     * @param LoopInterface $loop ReactPHP event loop
     * @param float|null $interval Override poll interval (defaults to constructor value)
     */
    public function attachLoop(LoopInterface $loop, ?float $interval = null): void
    {
        $this->detachLoop();
        $this->loop = $loop;
        $pollInterval = $interval ?? $this->pollInterval;
        $this->loopTimer = $loop->addPeriodicTimer($pollInterval, function (): void {
            $this->poll();
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
     * Perform a single poll cycle to detect network changes.
     *
     * @return list<NetworkChange>
     */
    public function poll(): array
    {
        $changes = [];

        if (PHP_OS_FAMILY === 'Linux' && is_readable('/proc/net/route')) {
            $changes = $this->pollLinuxRoutes();
        } else {
            $changes = $this->pollHostname();
        }

        foreach ($changes as $change) {
            $this->emit('network_change', [$change]);
        }

        return $changes;
    }

    /**
     * Get the poll interval in seconds.
     */
    public function pollInterval(): float
    {
        return $this->pollInterval;
    }

    /**
     * Report an external network change event.
     */
    public function reportChange(NetworkChange $change): void
    {
        $this->emit('network_change', [$change]);
    }

    /**
     * Poll /proc/net/route for interface changes (Linux).
     *
     * @return list<NetworkChange>
     */
    private function pollLinuxRoutes(): array
    {
        $changes = [];
        $content = @file_get_contents('/proc/net/route');
        if ($content === false) {
            return $changes;
        }

        $lines = explode("\n", trim($content));
        $currentInterfaces = [];

        // Skip header line
        for ($i = 1; $i < count($lines); $i++) {
            $fields = preg_split('/\s+/', $lines[$i]);
            if ($fields === false || count($fields) < 2) {
                continue;
            }
            $iface = $fields[0];
            $currentInterfaces[$iface] = true;

            if (!isset($this->knownAddresses[$iface])) {
                // New interface
                $changes[] = new NetworkChange(
                    type: NetworkChangeType::InterfaceUp,
                    interface: $iface,
                );
                $this->knownAddresses[$iface] = '';
            }
        }

        // Check for removed interfaces
        foreach ($this->knownAddresses as $iface => $_) {
            if (!isset($currentInterfaces[$iface])) {
                $changes[] = new NetworkChange(
                    type: NetworkChangeType::InterfaceDown,
                    interface: $iface,
                );
                unset($this->knownAddresses[$iface]);
            }
        }

        return $changes;
    }

    /**
     * Poll gethostbyname() for IP changes (cross-platform).
     *
     * @return list<NetworkChange>
     */
    private function pollHostname(): array
    {
        $changes = [];
        $hostname = gethostname();
        if ($hostname === false) {
            return $changes;
        }

        $currentAddr = gethostbyname($hostname);
        if ($currentAddr === $hostname) {
            // DNS resolution failed
            return $changes;
        }

        if ($this->lastHostAddress !== null && $this->lastHostAddress !== $currentAddr) {
            $changes[] = new NetworkChange(
                type: NetworkChangeType::AddressChanged,
                interface: 'default',
                oldAddress: $this->lastHostAddress,
                newAddress: $currentAddr,
            );
        }

        $this->lastHostAddress = $currentAddr;

        return $changes;
    }
}
