import { CairnError } from '../errors.js';

/** Default maximum attempts per sliding window. */
const DEFAULT_MAX_PER_WINDOW = 5;
/** Default sliding window duration in milliseconds. */
const DEFAULT_WINDOW_MS = 30_000;
/** Default maximum total failures before auto-invalidation. */
const DEFAULT_MAX_TOTAL_FAILURES = 10;
/** Default progressive delay per failure in milliseconds. */
const DEFAULT_DELAY_PER_FAILURE_MS = 2_000;

/** Per-source tracking state. */
interface SourceState {
  attempts: number[];
  failureCount: number;
}

/** Rate limit check result. */
export interface RateLimitResult {
  allowed: boolean;
  waitMs: number;
  reason?: string;
}

/**
 * Rate limiter for pairing attempts.
 *
 * Enforced by the acceptor (the peer that generates the pin code).
 * Protects the 40-bit entropy of pin codes against brute-force attacks.
 *
 * Controls (matching Rust):
 * - 5 attempts per 30-second sliding window from any source
 * - 10 total failed attempts -> auto-invalidate current pin
 * - 2-second progressive delay after each failed PAKE attempt
 */
export class PairingRateLimiter {
  private readonly maxPerWindow: number;
  private readonly windowMs: number;
  private readonly maxTotalFailures: number;
  private readonly delayPerFailureMs: number;
  private sources = new Map<string, SourceState>();
  private _totalFailures = 0;

  constructor(config?: {
    maxPerWindow?: number;
    windowMs?: number;
    maxTotalFailures?: number;
    delayPerFailureMs?: number;
  }) {
    this.maxPerWindow = config?.maxPerWindow ?? DEFAULT_MAX_PER_WINDOW;
    this.windowMs = config?.windowMs ?? DEFAULT_WINDOW_MS;
    this.maxTotalFailures = config?.maxTotalFailures ?? DEFAULT_MAX_TOTAL_FAILURES;
    this.delayPerFailureMs = config?.delayPerFailureMs ?? DEFAULT_DELAY_PER_FAILURE_MS;
  }

  /**
   * Check if a new attempt from this source is allowed.
   *
   * Returns the result with allowed status and required wait time.
   * If not allowed, throws CairnError.
   */
  check(source: string): RateLimitResult {
    // Check auto-invalidation
    if (this.isInvalidated) {
      throw new CairnError(
        'PAIRING',
        `pin auto-invalidated after ${this._totalFailures} total failures`,
      );
    }

    const now = Date.now();
    let state = this.sources.get(source);
    if (!state) {
      state = { attempts: [], failureCount: 0 };
      this.sources.set(source, state);
    }

    // Remove expired entries from sliding window
    const cutoff = now - this.windowMs;
    state.attempts = state.attempts.filter(t => t > cutoff);

    // Check window limit
    if (state.attempts.length >= this.maxPerWindow) {
      return {
        allowed: false,
        waitMs: 0,
        reason: `rate limit exceeded: ${state.attempts.length} attempts in ${this.windowMs}ms window`,
      };
    }

    // Record this attempt
    state.attempts.push(now);

    // Compute progressive delay based on failure count
    const waitMs = this.delayPerFailureMs * state.failureCount;

    return { allowed: true, waitMs };
  }

  /** Record a failed attempt from this source. */
  recordFailure(source: string): void {
    let state = this.sources.get(source);
    if (!state) {
      state = { attempts: [], failureCount: 0 };
      this.sources.set(source, state);
    }
    state.failureCount++;
    this._totalFailures++;
  }

  /** Record a successful attempt (resets per-source failure count). */
  recordSuccess(source: string): void {
    const state = this.sources.get(source);
    if (state) {
      state.failureCount = 0;
    }
  }

  /** Check if the pin has been auto-invalidated. */
  get isInvalidated(): boolean {
    return this._totalFailures >= this.maxTotalFailures;
  }

  /** Get the total failure count across all sources. */
  get totalFailures(): number {
    return this._totalFailures;
  }

  /** Reset the rate limiter (e.g., when a new pin is generated). */
  reset(): void {
    this.sources.clear();
    this._totalFailures = 0;
  }
}
