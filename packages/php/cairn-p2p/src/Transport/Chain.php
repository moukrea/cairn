<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\Error\CairnException;
use React\Promise\PromiseInterface;

use function React\Promise\reject;

/**
 * Transport type in the fallback chain.
 *
 * PHP chain excludes QUIC (priority 1) and WebTransport (priority 7).
 * Matches packages/rs/cairn-p2p/src/transport/fallback.rs.
 */
enum TransportType: string
{
    /** Priority 2: STUN-assisted UDP hole punch. */
    case StunHolePunch = 'stun_hole_punch';
    /** Priority 3: Direct TCP. */
    case Tcp = 'tcp';
    /** Priority 4: TURN relay (UDP). */
    case TurnUdp = 'turn_udp';
    /** Priority 5: TURN relay (TCP). */
    case TurnTcp = 'turn_tcp';
    /** Priority 6: WebSocket over TLS (port 443). */
    case WebSocketTls = 'websocket_tls';
    /** Priority 8: Circuit Relay v2. */
    case CircuitRelayV2 = 'circuit_relay_v2';
    /** Priority 9: HTTPS long-polling (port 443). */
    case HttpsLongPoll = 'https_long_poll';

    /**
     * Priority number (lower = better).
     */
    public function priority(): int
    {
        return match ($this) {
            self::StunHolePunch => 2,
            self::Tcp => 3,
            self::TurnUdp => 4,
            self::TurnTcp => 5,
            self::WebSocketTls => 6,
            self::CircuitRelayV2 => 8,
            self::HttpsLongPoll => 9,
        };
    }

    /**
     * Whether this transport is available in Tier 0 (zero-config).
     */
    public function tier0Available(): bool
    {
        return match ($this) {
            self::StunHolePunch, self::Tcp, self::CircuitRelayV2 => true,
            default => false,
        };
    }

    /**
     * All PHP transport types in priority order.
     *
     * @return list<self>
     */
    public static function allInOrder(): array
    {
        return [
            self::StunHolePunch,
            self::Tcp,
            self::TurnUdp,
            self::TurnTcp,
            self::WebSocketTls,
            self::CircuitRelayV2,
            self::HttpsLongPoll,
        ];
    }

    /**
     * Human-readable label.
     */
    public function label(): string
    {
        return match ($this) {
            self::StunHolePunch => 'STUN-assisted UDP hole punch',
            self::Tcp => 'Direct TCP',
            self::TurnUdp => 'TURN relay (UDP)',
            self::TurnTcp => 'TURN relay (TCP)',
            self::WebSocketTls => 'WebSocket/TLS (443)',
            self::CircuitRelayV2 => 'Circuit Relay v2',
            self::HttpsLongPoll => 'HTTPS long-polling (443)',
        };
    }
}

/**
 * Configuration for a single transport attempt.
 */
final class TransportAttempt
{
    public function __construct(
        public readonly TransportType $type,
        public readonly float $timeout,
        public readonly bool $available,
    ) {
    }
}

/**
 * Result of attempting a single transport in the fallback chain.
 */
final class TransportAttemptResult
{
    public function __construct(
        public readonly TransportType $type,
        public readonly ?string $error,
        public readonly bool $skipped,
        public readonly float $durationSeconds,
    ) {
    }

    public function __toString(): string
    {
        if ($this->skipped) {
            return sprintf('%s: skipped (not configured)', $this->type->label());
        }
        if ($this->error !== null) {
            return sprintf('%s: failed (%s) [%.3fs]', $this->type->label(), $this->error, $this->durationSeconds);
        }
        return sprintf('%s: success [%.3fs]', $this->type->label(), $this->durationSeconds);
    }
}

/**
 * Transport config controlling which transports are enabled.
 */
final class TransportConfig
{
    public function __construct(
        public readonly bool $stunEnabled = true,
        public readonly bool $tcpEnabled = true,
        public readonly bool $turnUdpEnabled = false,
        public readonly bool $turnTcpEnabled = false,
        public readonly bool $websocketEnabled = false,
        public readonly bool $circuitRelayEnabled = false,
        public readonly bool $httpsLongPollEnabled = false,
        public readonly float $perTransportTimeout = 10.0,
    ) {
    }

    /**
     * Create a Tier 0 (zero-config) transport configuration.
     * Only priorities 2, 3, 8 are available.
     */
    public static function tier0(float $timeout = 10.0): self
    {
        return new self(
            stunEnabled: true,
            tcpEnabled: true,
            turnUdpEnabled: false,
            turnTcpEnabled: false,
            websocketEnabled: false,
            circuitRelayEnabled: true,
            httpsLongPollEnabled: false,
            perTransportTimeout: $timeout,
        );
    }

    /**
     * Create a full transport configuration (all transports available).
     */
    public static function full(float $timeout = 10.0): self
    {
        return new self(
            stunEnabled: true,
            tcpEnabled: true,
            turnUdpEnabled: true,
            turnTcpEnabled: true,
            websocketEnabled: true,
            circuitRelayEnabled: true,
            httpsLongPollEnabled: true,
            perTransportTimeout: $timeout,
        );
    }

    /**
     * Check if a transport type is enabled.
     */
    public function isEnabled(TransportType $type): bool
    {
        return match ($type) {
            TransportType::StunHolePunch => $this->stunEnabled,
            TransportType::Tcp => $this->tcpEnabled,
            TransportType::TurnUdp => $this->turnUdpEnabled,
            TransportType::TurnTcp => $this->turnTcpEnabled,
            TransportType::WebSocketTls => $this->websocketEnabled,
            TransportType::CircuitRelayV2 => $this->circuitRelayEnabled,
            TransportType::HttpsLongPoll => $this->httpsLongPollEnabled,
        };
    }
}

/**
 * Transport fallback chain for PHP.
 *
 * Executes transports in priority order (2-9, skipping 1 and 7).
 * Supports both sequential and parallel probing.
 *
 * Matches packages/rs/cairn-p2p/src/transport/fallback.rs.
 */
final class TransportChain
{
    /** @var list<TransportAttempt> */
    private array $transports;
    private bool $parallelMode;

    public function __construct(TransportConfig $config, bool $parallelMode = false)
    {
        $this->parallelMode = $parallelMode;
        $this->transports = [];

        foreach (TransportType::allInOrder() as $type) {
            $this->transports[] = new TransportAttempt(
                type: $type,
                timeout: $config->perTransportTimeout,
                available: $config->isEnabled($type),
            );
        }
    }

    /**
     * Create a Tier 0 fallback chain.
     */
    public static function tier0(float $timeout = 10.0): self
    {
        return new self(TransportConfig::tier0($timeout));
    }

    /**
     * Get the transport attempts in priority order.
     *
     * @return list<TransportAttempt>
     */
    public function transports(): array
    {
        return $this->transports;
    }

    /**
     * Whether parallel probing is enabled.
     */
    public function parallelMode(): bool
    {
        return $this->parallelMode;
    }

    /**
     * Execute the fallback chain sequentially.
     *
     * Tries each available transport in priority order. Returns a promise
     * that resolves with [TransportType, result] on first success, or
     * rejects with CairnException on all failures.
     *
     * @param callable(TransportType, float): PromiseInterface $attemptFn
     * @return PromiseInterface<array{0: TransportType, 1: mixed}>
     */
    public function execute(callable $attemptFn): PromiseInterface
    {
        return $this->executeSequential($attemptFn);
    }

    /**
     * Sequential execution: attempt each transport in priority order.
     *
     * @param callable(TransportType, float): PromiseInterface $attemptFn
     * @return PromiseInterface<array{0: TransportType, 1: mixed}>
     */
    private function executeSequential(callable $attemptFn): PromiseInterface
    {
        /** @var list<TransportAttemptResult> $results */
        $results = [];

        // Build a chain of promises
        $promise = reject(new CairnException('no transports'));

        foreach ($this->transports as $attempt) {
            if (!$attempt->available) {
                $results[] = new TransportAttemptResult(
                    type: $attempt->type,
                    error: null,
                    skipped: true,
                    durationSeconds: 0.0,
                );
                continue;
            }

            $type = $attempt->type;
            $timeout = $attempt->timeout;

            // Chain: if the previous failed, try this one
            if (count($results) === 0 && empty(array_filter($results, fn($r) => !$r->skipped))) {
                // First non-skipped attempt
                $promise = $attemptFn($type, $timeout)->then(
                    fn($value) => [$type, $value],
                    function (\Throwable $e) use ($type, &$results) {
                        $results[] = new TransportAttemptResult(
                            type: $type,
                            error: $e->getMessage(),
                            skipped: false,
                            durationSeconds: 0.0,
                        );
                        throw $e;
                    },
                );
            } else {
                $promise = $promise->then(
                    null,
                    function () use ($attemptFn, $type, $timeout, &$results) {
                        return $attemptFn($type, $timeout)->then(
                            fn($value) => [$type, $value],
                            function (\Throwable $e) use ($type, &$results) {
                                $results[] = new TransportAttemptResult(
                                    type: $type,
                                    error: $e->getMessage(),
                                    skipped: false,
                                    durationSeconds: 0.0,
                                );
                                throw $e;
                            },
                        );
                    },
                );
            }
        }

        // If all fail, throw a diagnostic error
        return $promise->then(null, function () use (&$results) {
            throw self::buildExhaustedError($results);
        });
    }

    /**
     * Build a TransportExhausted error with diagnostic details.
     *
     * @param list<TransportAttemptResult> $results
     */
    private static function buildExhaustedError(array $results): CairnException
    {
        $details = array_map(fn($r) => (string) $r, $results);
        $detailsStr = implode('; ', $details);

        $hasUnavailable = false;
        foreach ($results as $r) {
            if ($r->skipped) {
                $hasUnavailable = true;
                break;
            }
        }

        $suggestion = $hasUnavailable
            ? 'deploy companion infrastructure (TURN relay, WebSocket relay on port 443) to enable additional transport fallbacks'
            : 'check network connectivity and firewall rules';

        return new CairnException(sprintf(
            'all transports exhausted: %s (suggestion: %s)',
            $detailsStr,
            $suggestion,
        ));
    }
}

/**
 * Connection quality metrics.
 */
final class ConnectionQuality
{
    public function __construct(
        /** Round-trip latency in seconds. */
        public readonly float $latency = 0.0,
        /** Jitter (latency variance) in seconds. */
        public readonly float $jitter = 0.0,
        /** Packet loss ratio (0.0 = none, 1.0 = total loss). */
        public readonly float $packetLossRatio = 0.0,
    ) {
    }
}

/**
 * Thresholds that trigger proactive transport migration.
 */
final class QualityThresholds
{
    public function __construct(
        /** Trigger probing when latency exceeds this value (seconds). */
        public readonly float $maxLatency = 0.5,
        /** Trigger probing when jitter exceeds this value (seconds). */
        public readonly float $maxJitter = 0.1,
        /** Trigger probing when packet loss exceeds this ratio. */
        public readonly float $maxPacketLoss = 0.05,
    ) {
    }
}

/**
 * Connection quality monitor.
 */
final class ConnectionQualityMonitor
{
    public function __construct(
        private readonly QualityThresholds $thresholds = new QualityThresholds(),
    ) {
    }

    /**
     * Check whether a quality sample exceeds any threshold.
     */
    public function isDegraded(ConnectionQuality $quality): bool
    {
        return $quality->latency > $this->thresholds->maxLatency
            || $quality->jitter > $this->thresholds->maxJitter
            || $quality->packetLossRatio > $this->thresholds->maxPacketLoss;
    }

    /**
     * Get the configured thresholds.
     */
    public function thresholds(): QualityThresholds
    {
        return $this->thresholds;
    }
}
