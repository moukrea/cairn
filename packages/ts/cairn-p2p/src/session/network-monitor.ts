// Network change detection (spec/07 section 7)

/** Network change events detected by OS-level monitoring. */
export type NetworkChange =
  | { type: 'interface_up'; interface: string }
  | { type: 'interface_down'; interface: string }
  | { type: 'address_changed'; interface: string; oldAddr?: string; newAddr: string };

export type NetworkChangeListener = (change: NetworkChange) => void;

/**
 * Monitors network interface changes and emits NetworkChange events.
 *
 * On detecting network changes, the library proactively triggers reconnection
 * rather than waiting for heartbeat timeout.
 *
 * - Node.js: uses `os.networkInterfaces()` polling
 * - Browser: uses `navigator.connection` and `online`/`offline` events
 */
export class NetworkMonitor {
  private readonly _listeners: NetworkChangeListener[] = [];
  private _polling = false;
  private _pollTimer: ReturnType<typeof setInterval> | null = null;
  private _lastInterfaces: Map<string, string[]> = new Map();

  /** Subscribe to network change events. */
  onChange(listener: NetworkChangeListener): void {
    this._listeners.push(listener);
  }

  /** Report a network change event (for external/platform code). */
  reportChange(change: NetworkChange): void {
    for (const listener of this._listeners) {
      listener(change);
    }
  }

  /**
   * Start monitoring for network changes.
   *
   * In browser: listens for online/offline events.
   * In Node.js: polls os.networkInterfaces() at the given interval.
   */
  start(pollIntervalMs: number = 5000): void {
    if (this._polling) return;
    this._polling = true;

    if (typeof globalThis.window !== 'undefined' && typeof globalThis.addEventListener === 'function') {
      // Browser environment
      globalThis.addEventListener('online', () => {
        this.reportChange({ type: 'interface_up', interface: 'browser' });
      });
      globalThis.addEventListener('offline', () => {
        this.reportChange({ type: 'interface_down', interface: 'browser' });
      });
    } else {
      // Node.js environment — poll os.networkInterfaces()
      this.pollInterfaces();
      this._pollTimer = setInterval(() => {
        this.pollInterfaces();
      }, pollIntervalMs);
    }
  }

  /** Stop monitoring for network changes. */
  stop(): void {
    this._polling = false;
    if (this._pollTimer !== null) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  }

  /** Whether monitoring is active. */
  get isPolling(): boolean {
    return this._polling;
  }

  /** Poll Node.js network interfaces and emit changes. */
  private pollInterfaces(): void {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const os = require('os');
      const ifaces = os.networkInterfaces() as Record<string, Array<{ address: string; family: string }>>;

      const current = new Map<string, string[]>();

      for (const [name, addrs] of Object.entries(ifaces)) {
        if (!addrs) continue;
        const addresses = addrs
          .filter((a: { family: string }) => a.family === 'IPv4' || a.family === 'IPv6')
          .map((a: { address: string }) => a.address);
        current.set(name, addresses);
      }

      if (this._lastInterfaces.size > 0) {
        // Check for interfaces that went down
        for (const [name] of this._lastInterfaces) {
          if (!current.has(name)) {
            this.reportChange({ type: 'interface_down', interface: name });
          }
        }

        // Check for interfaces that came up or addresses that changed
        for (const [name, addrs] of current) {
          const prev = this._lastInterfaces.get(name);
          if (!prev) {
            this.reportChange({ type: 'interface_up', interface: name });
          } else {
            // Check for address changes
            const prevSet = new Set(prev);
            for (const addr of addrs) {
              if (!prevSet.has(addr)) {
                this.reportChange({
                  type: 'address_changed',
                  interface: name,
                  newAddr: addr,
                });
              }
            }
          }
        }
      }

      this._lastInterfaces = current;
    } catch {
      // os module not available or other error
    }
  }
}
