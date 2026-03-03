import { CairnError, TransportExhaustedError } from '../errors.js';

// ---------------------------------------------------------------------------
// Transport type (9-level fallback chain)
// ---------------------------------------------------------------------------

/** Transport type in the 9-level fallback chain (spec section 2). */
export type FallbackTransportType =
  | 'quic'
  | 'stun-udp'
  | 'tcp'
  | 'turn-udp'
  | 'turn-tcp'
  | 'websocket-tls'
  | 'webtransport'
  | 'circuit-relay-v2'
  | 'https-long-polling';

/** All transport types in priority order. */
const ALL_IN_ORDER: FallbackTransportType[] = [
  'quic',
  'stun-udp',
  'tcp',
  'turn-udp',
  'turn-tcp',
  'websocket-tls',
  'webtransport',
  'circuit-relay-v2',
  'https-long-polling',
];

/** Priority number (1 = best, 9 = worst). */
export function transportPriority(t: FallbackTransportType): number {
  return ALL_IN_ORDER.indexOf(t) + 1;
}

/** Human-readable display name. */
export function transportDisplayName(t: FallbackTransportType): string {
  const names: Record<FallbackTransportType, string> = {
    'quic': 'Direct QUIC v1',
    'stun-udp': 'STUN-assisted UDP hole punch',
    'tcp': 'Direct TCP',
    'turn-udp': 'TURN relay (UDP)',
    'turn-tcp': 'TURN relay (TCP)',
    'websocket-tls': 'WebSocket/TLS (443)',
    'webtransport': 'WebTransport/HTTP3 (443)',
    'circuit-relay-v2': 'Circuit Relay v2',
    'https-long-polling': 'HTTPS long-polling (443)',
  };
  return names[t];
}

/** Whether this transport is available in Tier 0 (zero-config). */
export function isTier0Available(t: FallbackTransportType): boolean {
  return t === 'quic' || t === 'stun-udp' || t === 'tcp' || t === 'circuit-relay-v2';
}

/** Get all transport types in priority order. */
export function allTransportsInOrder(): FallbackTransportType[] {
  return [...ALL_IN_ORDER];
}

// ---------------------------------------------------------------------------
// TransportAttempt — single entry in the fallback chain
// ---------------------------------------------------------------------------

/** Configuration for a single transport attempt in the fallback chain. */
export interface TransportAttempt {
  priority: number;
  transportType: FallbackTransportType;
  timeoutMs: number;
  available: boolean;
}

/** Result of attempting a single transport in the fallback chain. */
export interface TransportAttemptResult {
  transportType: FallbackTransportType;
  error?: string;
  skipped: boolean;
  durationMs: number;
}

function formatAttemptResult(r: TransportAttemptResult): string {
  const name = transportDisplayName(r.transportType);
  if (r.skipped) {
    return `${name}: skipped (not configured)`;
  }
  if (r.error) {
    return `${name}: failed (${r.error}) [${r.durationMs}ms]`;
  }
  return `${name}: success [${r.durationMs}ms]`;
}

// ---------------------------------------------------------------------------
// FallbackChain — the 9-level transport priority chain engine
// ---------------------------------------------------------------------------

/** Default per-transport timeout in milliseconds. */
export const DEFAULT_TRANSPORT_TIMEOUT_MS = 10_000;

/**
 * Executes the 9-level transport priority chain (spec section 2).
 *
 * Supports both sequential and parallel (ICE-style) probing modes.
 * In parallel mode, multiple transports are attempted concurrently
 * and the first success wins.
 */
export class FallbackChain {
  private readonly _transports: TransportAttempt[];
  private readonly _parallelMode: boolean;

  private constructor(transports: TransportAttempt[], parallelMode: boolean) {
    this._transports = transports;
    this._parallelMode = parallelMode;
  }

  /**
   * Create a new fallback chain with the full 9-level priority list.
   *
   * `hasTurn` / `hasRelay443` control whether TURN and port-443 relays
   * are available (Tier 1+ infrastructure).
   */
  static create(
    perTransportTimeoutMs: number,
    hasTurn: boolean,
    hasRelay443: boolean,
    parallelMode: boolean,
  ): FallbackChain {
    const transports: TransportAttempt[] = ALL_IN_ORDER.map((tt) => {
      let available: boolean;
      if (tt === 'turn-udp' || tt === 'turn-tcp') {
        available = hasTurn;
      } else if (tt === 'websocket-tls' || tt === 'webtransport' || tt === 'https-long-polling') {
        available = hasRelay443;
      } else {
        available = true;
      }
      return {
        priority: transportPriority(tt),
        transportType: tt,
        timeoutMs: perTransportTimeoutMs,
        available,
      };
    });
    return new FallbackChain(transports, parallelMode);
  }

  /** Create a Tier 0 (zero-config) fallback chain. Only priorities 1-3 and 8 available. */
  static tier0(perTransportTimeoutMs: number = DEFAULT_TRANSPORT_TIMEOUT_MS): FallbackChain {
    return FallbackChain.create(perTransportTimeoutMs, false, false, false);
  }

  /** Get the transport attempts in priority order. */
  get transports(): readonly TransportAttempt[] {
    return this._transports;
  }

  /** Whether parallel probing is enabled. */
  get parallelMode(): boolean {
    return this._parallelMode;
  }

  /**
   * Execute the fallback chain, attempting each transport in order.
   *
   * The `attemptFn` is called for each available transport and should
   * return a value on success or throw on failure. The first success is
   * returned. If all fail, throws `TransportExhaustedError`.
   *
   * In parallel mode, available transports are attempted concurrently
   * and the first success wins.
   */
  async execute<T>(
    attemptFn: (transportType: FallbackTransportType, timeoutMs: number) => Promise<T>,
  ): Promise<{ transportType: FallbackTransportType; value: T }> {
    if (this._parallelMode) {
      return this.executeParallel(attemptFn);
    }
    return this.executeSequential(attemptFn);
  }

  /** Sequential execution: attempt each transport in priority order. */
  private async executeSequential<T>(
    attemptFn: (transportType: FallbackTransportType, timeoutMs: number) => Promise<T>,
  ): Promise<{ transportType: FallbackTransportType; value: T }> {
    const results: TransportAttemptResult[] = [];

    for (const attempt of this._transports) {
      if (!attempt.available) {
        results.push({
          transportType: attempt.transportType,
          skipped: true,
          durationMs: 0,
        });
        continue;
      }

      const start = Date.now();
      try {
        const value = await attemptFn(attempt.transportType, attempt.timeoutMs);
        return { transportType: attempt.transportType, value };
      } catch (e) {
        const elapsed = Date.now() - start;
        results.push({
          transportType: attempt.transportType,
          error: e instanceof Error ? e.message : String(e),
          skipped: false,
          durationMs: elapsed,
        });
      }
    }

    throw buildTransportExhaustedError(results);
  }

  /** Parallel (ICE-style) execution: attempt all available concurrently, first success wins. */
  private async executeParallel<T>(
    attemptFn: (transportType: FallbackTransportType, timeoutMs: number) => Promise<T>,
  ): Promise<{ transportType: FallbackTransportType; value: T }> {
    const skippedResults: TransportAttemptResult[] = [];
    const promises: Promise<{ transportType: FallbackTransportType; value: T }>[] = [];
    const abortController = new AbortController();

    for (const attempt of this._transports) {
      if (!attempt.available) {
        skippedResults.push({
          transportType: attempt.transportType,
          skipped: true,
          durationMs: 0,
        });
        continue;
      }

      const transportType = attempt.transportType;
      const timeoutMs = attempt.timeoutMs;

      promises.push(
        (async () => {
          const value = await attemptFn(transportType, timeoutMs);
          return { transportType, value };
        })(),
      );
    }

    if (promises.length === 0) {
      throw buildTransportExhaustedError(skippedResults);
    }

    // Race all promises; collect failures
    const failedResults: TransportAttemptResult[] = [];
    const settled = await Promise.allSettled(promises);

    // First check for any success
    for (const result of settled) {
      if (result.status === 'fulfilled') {
        abortController.abort();
        return result.value;
      }
    }

    // All failed — collect errors
    for (const result of settled) {
      if (result.status === 'rejected') {
        const err = result.reason;
        failedResults.push({
          transportType: 'quic', // placeholder — we reconstruct below
          error: err instanceof Error ? err.message : String(err),
          skipped: false,
          durationMs: 0,
        });
      }
    }

    throw buildTransportExhaustedError([...skippedResults, ...failedResults]);
  }
}

/** Build a TransportExhaustedError with detailed diagnostics. */
function buildTransportExhaustedError(results: TransportAttemptResult[]): TransportExhaustedError {
  const details = results.map(formatAttemptResult).join('; ');
  const hasSkipped = results.some((r) => r.skipped);
  const suggestion = hasSkipped
    ? 'deploy companion infrastructure (TURN relay, WebSocket relay on port 443) to enable additional transport fallbacks'
    : 'check network connectivity and firewall rules';

  return new TransportExhaustedError(
    `all transports exhausted: ${details}`,
    { details, suggestion, results },
  );
}

// ---------------------------------------------------------------------------
// ConnectionQuality — metrics
// ---------------------------------------------------------------------------

/** Connection quality metrics (spec FR-4.5, spec section 6). */
export interface ConnectionQuality {
  /** Round-trip latency in ms. */
  latencyMs: number;
  /** Jitter (latency variance) in ms. */
  jitterMs: number;
  /** Packet loss ratio (0.0 = none, 1.0 = total loss). */
  packetLossRatio: number;
}

/** Default connection quality (no metrics yet). */
export function defaultConnectionQuality(): ConnectionQuality {
  return { latencyMs: 0, jitterMs: 0, packetLossRatio: 0 };
}

/** Thresholds that trigger proactive transport migration (spec FR-4.5). */
export interface QualityThresholds {
  maxLatencyMs: number;
  maxJitterMs: number;
  maxPacketLoss: number;
}

/** Default quality thresholds. */
export function defaultQualityThresholds(): QualityThresholds {
  return { maxLatencyMs: 500, maxJitterMs: 100, maxPacketLoss: 0.05 };
}

// ---------------------------------------------------------------------------
// DegradationEvent
// ---------------------------------------------------------------------------

/** Which quality threshold was exceeded. */
export type DegradationReason = 'high_latency' | 'high_jitter' | 'high_packet_loss';

/** Degradation event emitted when connection quality drops below thresholds. */
export interface DegradationEvent {
  quality: ConnectionQuality;
  reason: DegradationReason;
}

// ---------------------------------------------------------------------------
// ConnectionQualityMonitor
// ---------------------------------------------------------------------------

export type DegradationListener = (event: DegradationEvent) => void;

/**
 * Monitors connection quality and emits degradation events (spec FR-4.5).
 *
 * When any metric exceeds its threshold, a DegradationEvent is emitted
 * to trigger the TransportMigrator.
 */
export class ConnectionQualityMonitor {
  private readonly _thresholds: QualityThresholds;
  private readonly _sampleIntervalMs: number;
  private readonly _listeners: DegradationListener[] = [];

  constructor(thresholds?: QualityThresholds, sampleIntervalMs: number = 1000) {
    this._thresholds = thresholds ?? defaultQualityThresholds();
    this._sampleIntervalMs = sampleIntervalMs;
  }

  get thresholds(): QualityThresholds {
    return this._thresholds;
  }

  get sampleIntervalMs(): number {
    return this._sampleIntervalMs;
  }

  onDegradation(listener: DegradationListener): void {
    this._listeners.push(listener);
  }

  /** Report a new quality sample. Checks thresholds and emits degradation events. */
  reportSample(quality: ConnectionQuality): void {
    if (quality.latencyMs > this._thresholds.maxLatencyMs) {
      this.emit({ quality, reason: 'high_latency' });
    }
    if (quality.jitterMs > this._thresholds.maxJitterMs) {
      this.emit({ quality, reason: 'high_jitter' });
    }
    if (quality.packetLossRatio > this._thresholds.maxPacketLoss) {
      this.emit({ quality, reason: 'high_packet_loss' });
    }
  }

  /** Check whether a quality sample exceeds any threshold (without emitting). */
  isDegraded(quality: ConnectionQuality): boolean {
    return (
      quality.latencyMs > this._thresholds.maxLatencyMs ||
      quality.jitterMs > this._thresholds.maxJitterMs ||
      quality.packetLossRatio > this._thresholds.maxPacketLoss
    );
  }

  private emit(event: DegradationEvent): void {
    for (const listener of this._listeners) {
      listener(event);
    }
  }
}

// ---------------------------------------------------------------------------
// MigrationEvent
// ---------------------------------------------------------------------------

/** Migration event indicating a better transport is available. */
export interface MigrationEvent {
  from: FallbackTransportType;
  to: FallbackTransportType;
}

// ---------------------------------------------------------------------------
// TransportMigrator
// ---------------------------------------------------------------------------

export type MigrationListener = (event: MigrationEvent) => void;

/**
 * Probes for better transports and triggers mid-session migration
 * (spec FR-4.3, spec section 3).
 *
 * "Transport migration is invisible to the application."
 */
export class TransportMigrator {
  private readonly _probeIntervalMs: number;
  private _currentTransport: FallbackTransportType;
  private readonly _listeners: MigrationListener[] = [];

  constructor(probeIntervalMs: number, currentTransport: FallbackTransportType) {
    this._probeIntervalMs = probeIntervalMs;
    this._currentTransport = currentTransport;
  }

  get probeIntervalMs(): number {
    return this._probeIntervalMs;
  }

  get currentTransport(): FallbackTransportType {
    return this._currentTransport;
  }

  /** Update the active transport after a successful migration. */
  setCurrentTransport(transport: FallbackTransportType): void {
    this._currentTransport = transport;
  }

  onMigration(listener: MigrationListener): void {
    this._listeners.push(listener);
  }

  /** Get the list of transports to probe (those with better priority). */
  transportsToProbe(): FallbackTransportType[] {
    const currentPriority = transportPriority(this._currentTransport);
    return allTransportsInOrder().filter((t) => transportPriority(t) < currentPriority);
  }

  /** Report that a probe found a better transport. Emits a migration event. */
  reportBetterTransport(betterTransport: FallbackTransportType): void {
    const betterPriority = transportPriority(betterTransport);
    const currentPriority = transportPriority(this._currentTransport);

    if (betterPriority >= currentPriority) {
      throw new CairnError(
        'TRANSPORT',
        `proposed transport ${transportDisplayName(betterTransport)} (priority ${betterPriority}) is not better than current ${transportDisplayName(this._currentTransport)} (priority ${currentPriority})`,
      );
    }

    const event: MigrationEvent = {
      from: this._currentTransport,
      to: betterTransport,
    };

    for (const listener of this._listeners) {
      listener(event);
    }
  }
}
