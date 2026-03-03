// Heartbeat and keepalive system (spec/07 section 6)

/** Heartbeat configuration. */
export interface HeartbeatConfig {
  /** Interval at which heartbeats are sent (ms). Default: 30000. */
  intervalMs: number;
  /** Time without any data before declaring disconnection (ms). Default: 90000 (3x interval). */
  timeoutMs: number;
}

/** Default heartbeat config. */
export function defaultHeartbeatConfig(): HeartbeatConfig {
  return { intervalMs: 30_000, timeoutMs: 90_000 };
}

/** Aggressive preset for real-time applications (5s interval, 15s timeout). */
export function aggressiveHeartbeatConfig(): HeartbeatConfig {
  return { intervalMs: 5_000, timeoutMs: 15_000 };
}

/** Relaxed preset for background sync (60s interval, 180s timeout). */
export function relaxedHeartbeatConfig(): HeartbeatConfig {
  return { intervalMs: 60_000, timeoutMs: 180_000 };
}

/**
 * Monitors heartbeat timing and determines connection liveness.
 *
 * Both peers send Heartbeat (0x0400) independently at the configured interval.
 * Receipt of any data (not just heartbeats) resets the timeout counter.
 * If no data within timeout, the connection should transition to Disconnected.
 */
export class HeartbeatMonitor {
  readonly config: HeartbeatConfig;
  private _lastActivity: number;
  private _lastHeartbeatSent: number;

  constructor(config?: HeartbeatConfig) {
    this.config = config ?? defaultHeartbeatConfig();
    const now = Date.now();
    this._lastActivity = now;
    this._lastHeartbeatSent = now;
  }

  /** Record that data was received (any data, not just heartbeats). Resets timeout counter. */
  recordActivity(): void {
    this._lastActivity = Date.now();
  }

  /** Record that a heartbeat was sent. */
  recordHeartbeatSent(): void {
    this._lastHeartbeatSent = Date.now();
  }

  /** Check whether the connection has timed out. */
  isTimedOut(): boolean {
    return Date.now() - this._lastActivity >= this.config.timeoutMs;
  }

  /** Check whether it is time to send a heartbeat. */
  shouldSendHeartbeat(): boolean {
    return Date.now() - this._lastHeartbeatSent >= this.config.intervalMs;
  }

  /** Duration (ms) until the next heartbeat should be sent. Returns 0 if overdue. */
  timeUntilNextHeartbeat(): number {
    return Math.max(0, this.config.intervalMs - (Date.now() - this._lastHeartbeatSent));
  }

  /** Duration (ms) until the connection times out. Returns 0 if already timed out. */
  timeUntilTimeout(): number {
    return Math.max(0, this.config.timeoutMs - (Date.now() - this._lastActivity));
  }

  /** Get the timestamp of the last recorded activity. */
  get lastActivity(): number {
    return this._lastActivity;
  }
}
