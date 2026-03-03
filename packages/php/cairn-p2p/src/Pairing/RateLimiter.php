<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Error\CairnException;

/**
 * Rate limiter for pairing attempts (acceptor-side).
 *
 * Protects the 40-bit entropy of pin codes against brute-force attacks.
 *
 * Controls:
 * - 5 attempts per 30-second sliding window from any source (configurable)
 * - 10 total failed attempts -> auto-invalidate current pin (configurable)
 * - 2-second progressive delay after each failed PAKE attempt (configurable)
 *
 * Matches packages/rs/cairn-p2p/src/pairing/rate_limit.rs.
 */
final class RateLimiter
{
    /** Default maximum attempts per sliding window. */
    public const DEFAULT_MAX_ATTEMPTS_PER_WINDOW = 5;

    /** Default sliding window duration in seconds. */
    public const DEFAULT_WINDOW_SECONDS = 30;

    /** Default maximum total failures before auto-invalidation. */
    public const DEFAULT_MAX_TOTAL_FAILURES = 10;

    /** Default progressive delay per failure in seconds. */
    public const DEFAULT_DELAY_PER_FAILURE = 2.0;

    private int $maxAttemptsPerWindow;
    private int $windowSeconds;
    private int $maxTotalFailures;
    private float $delayPerFailure;

    /**
     * Per-source tracking: source => [timestamps]
     *
     * @var array<string, list<float>>
     */
    private array $sourceAttempts = [];

    /**
     * Per-source failure count.
     *
     * @var array<string, int>
     */
    private array $sourceFailures = [];

    /** Total failure count across all sources. */
    private int $totalFailures = 0;

    public function __construct(
        int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS_PER_WINDOW,
        int $windowSeconds = self::DEFAULT_WINDOW_SECONDS,
        int $maxTotalFailures = self::DEFAULT_MAX_TOTAL_FAILURES,
        float $delayPerFailure = self::DEFAULT_DELAY_PER_FAILURE,
        ?int $maxAttemptsPerWindow = null,
    ) {
        $this->maxAttemptsPerWindow = $maxAttemptsPerWindow ?? $maxAttempts;
        $this->windowSeconds = $windowSeconds;
        $this->maxTotalFailures = $maxTotalFailures;
        $this->delayPerFailure = $delayPerFailure;
    }

    /**
     * Check if a new attempt from this source is allowed.
     *
     * Returns the required delay in seconds before processing.
     *
     * @throws CairnException If rate limited or auto-invalidated
     */
    public function checkRateLimit(string $source): float
    {
        // Check if pin has been auto-invalidated
        if ($this->isInvalidated()) {
            throw new CairnException(sprintf(
                'pin auto-invalidated after %d total failures',
                $this->totalFailures,
            ));
        }

        $now = hrtime(true) / 1_000_000_000.0; // nanoseconds to seconds

        // Initialize source state if needed
        if (!isset($this->sourceAttempts[$source])) {
            $this->sourceAttempts[$source] = [];
        }
        if (!isset($this->sourceFailures[$source])) {
            $this->sourceFailures[$source] = 0;
        }

        // Remove expired entries from the sliding window
        $windowStart = $now - $this->windowSeconds;
        $this->sourceAttempts[$source] = array_values(array_filter(
            $this->sourceAttempts[$source],
            static fn(float $ts) => $ts > $windowStart,
        ));

        // Check window limit
        $currentAttempts = count($this->sourceAttempts[$source]);
        if ($currentAttempts >= $this->maxAttemptsPerWindow) {
            throw new CairnException(sprintf(
                'rate limit exceeded: %d attempts in %d-second window',
                $currentAttempts,
                $this->windowSeconds,
            ));
        }

        // Record this attempt
        $this->sourceAttempts[$source][] = $now;

        // Compute progressive delay based on failure count
        return $this->delayPerFailure * $this->sourceFailures[$source];
    }

    /**
     * Record a failed attempt from this source.
     */
    public function recordFailure(string $source): void
    {
        if (!isset($this->sourceFailures[$source])) {
            $this->sourceFailures[$source] = 0;
        }
        $this->sourceFailures[$source]++;
        $this->totalFailures++;
    }

    /**
     * Record a successful attempt (resets per-source failure count).
     */
    public function recordSuccess(string $source): void
    {
        if (isset($this->sourceFailures[$source])) {
            $this->sourceFailures[$source] = 0;
        }
    }

    /**
     * Check if the pin has been auto-invalidated (>= maxTotalFailures).
     */
    public function isInvalidated(): bool
    {
        return $this->totalFailures >= $this->maxTotalFailures;
    }

    /**
     * Check if an attempt from this source is allowed (simple boolean interface).
     *
     * Returns true if the attempt is within the rate limit, false otherwise.
     */
    public function attempt(string $source): bool
    {
        $now = hrtime(true) / 1_000_000_000.0;

        if (!isset($this->sourceAttempts[$source])) {
            $this->sourceAttempts[$source] = [];
        }

        // Remove expired entries from the sliding window
        $windowStart = $now - $this->windowSeconds;
        $this->sourceAttempts[$source] = array_values(array_filter(
            $this->sourceAttempts[$source],
            static fn(float $ts) => $ts > $windowStart,
        ));

        // Check window limit
        if (count($this->sourceAttempts[$source]) >= $this->maxAttemptsPerWindow) {
            return false;
        }

        // Record this attempt
        $this->sourceAttempts[$source][] = $now;
        return true;
    }

    /**
     * Reset the rate limiter. If a source is given, reset only that source.
     * If no source is given, reset all state.
     */
    public function reset(?string $source = null): void
    {
        if ($source !== null) {
            unset($this->sourceAttempts[$source]);
            unset($this->sourceFailures[$source]);
            return;
        }

        $this->sourceAttempts = [];
        $this->sourceFailures = [];
        $this->totalFailures = 0;
    }

    /**
     * Get the total failure count.
     */
    public function totalFailures(): int
    {
        return $this->totalFailures;
    }
}
