// Exponential backoff (spec/07 section 2)

/** Exponential backoff configuration. */
export interface BackoffConfig {
  /** Initial delay before the first retry (ms). Default: 1000. */
  initialDelayMs: number;
  /** Maximum delay between retries (ms). Default: 60000. */
  maxDelayMs: number;
  /** Multiplicative factor for each attempt. Default: 2.0. */
  factor: number;
}

/** Default backoff config. */
export function defaultBackoffConfig(): BackoffConfig {
  return { initialDelayMs: 1000, maxDelayMs: 60_000, factor: 2.0 };
}

/**
 * Tracks exponential backoff state across reconnection attempts.
 *
 * Delay = initialDelay * factor^attempt, capped at maxDelay.
 * Drives the Reconnecting -> Suspended -> Reconnecting cycle.
 */
export class ExponentialBackoff {
  private readonly _config: BackoffConfig;
  private _attempt: number = 0;

  constructor(config?: Partial<BackoffConfig>) {
    const defaults = defaultBackoffConfig();
    this._config = {
      initialDelayMs: config?.initialDelayMs ?? defaults.initialDelayMs,
      maxDelayMs: config?.maxDelayMs ?? defaults.maxDelayMs,
      factor: config?.factor ?? defaults.factor,
    };
  }

  /** Calculate and return the next delay (ms), advancing the attempt counter. */
  nextDelay(): number {
    const delay = this._config.initialDelayMs * Math.pow(this._config.factor, this._attempt);
    this._attempt++;
    return Math.min(delay, this._config.maxDelayMs);
  }

  /** Reset the attempt counter (called on successful reconnection). */
  reset(): void {
    this._attempt = 0;
  }

  /** Get the current attempt number. */
  get attempt(): number {
    return this._attempt;
  }

  /** Get the backoff configuration. */
  get config(): BackoffConfig {
    return this._config;
  }
}
