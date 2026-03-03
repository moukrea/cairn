import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ExponentialBackoff, defaultBackoffConfig } from '../../src/session/backoff.js';
import {
  HeartbeatMonitor,
  defaultHeartbeatConfig,
  aggressiveHeartbeatConfig,
  relaxedHeartbeatConfig,
} from '../../src/session/heartbeat.js';
import { NetworkMonitor } from '../../src/session/network-monitor.js';
import type { NetworkChange } from '../../src/session/network-monitor.js';
import { MessageQueue, defaultQueueConfig } from '../../src/session/message-queue.js';
import type { EnqueueResult, QueuedMessage } from '../../src/session/message-queue.js';

// --- ExponentialBackoff ---

describe('ExponentialBackoff', () => {
  it('default config', () => {
    const config = defaultBackoffConfig();
    expect(config.initialDelayMs).toBe(1000);
    expect(config.maxDelayMs).toBe(60_000);
    expect(config.factor).toBe(2.0);
  });

  it('default sequence: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s', () => {
    const backoff = new ExponentialBackoff();
    expect(backoff.nextDelay()).toBe(1000);
    expect(backoff.nextDelay()).toBe(2000);
    expect(backoff.nextDelay()).toBe(4000);
    expect(backoff.nextDelay()).toBe(8000);
    expect(backoff.nextDelay()).toBe(16000);
    expect(backoff.nextDelay()).toBe(32000);
    expect(backoff.nextDelay()).toBe(60000); // capped
    expect(backoff.nextDelay()).toBe(60000); // stays capped
  });

  it('attempt counter', () => {
    const backoff = new ExponentialBackoff();
    expect(backoff.attempt).toBe(0);
    backoff.nextDelay();
    expect(backoff.attempt).toBe(1);
    backoff.nextDelay();
    expect(backoff.attempt).toBe(2);
  });

  it('reset', () => {
    const backoff = new ExponentialBackoff();
    backoff.nextDelay();
    backoff.nextDelay();
    expect(backoff.attempt).toBe(2);

    backoff.reset();
    expect(backoff.attempt).toBe(0);
    expect(backoff.nextDelay()).toBe(1000);
  });

  it('custom config', () => {
    const backoff = new ExponentialBackoff({
      initialDelayMs: 100,
      maxDelayMs: 5000,
      factor: 3.0,
    });
    expect(backoff.nextDelay()).toBe(100);     // 100 * 3^0
    expect(backoff.nextDelay()).toBe(300);     // 100 * 3^1
    expect(backoff.nextDelay()).toBe(900);     // 100 * 3^2
    expect(backoff.nextDelay()).toBe(2700);    // 100 * 3^3
    expect(backoff.nextDelay()).toBe(5000);    // 100 * 3^4 = 8100 -> capped
  });

  it('max delay cap with many attempts', () => {
    const backoff = new ExponentialBackoff();
    for (let i = 0; i < 20; i++) {
      backoff.nextDelay();
    }
    // After many attempts, should be capped at 60s
    expect(backoff.nextDelay()).toBe(60000);
  });

  it('partial config uses defaults', () => {
    const backoff = new ExponentialBackoff({ maxDelayMs: 10000 });
    expect(backoff.config.initialDelayMs).toBe(1000);
    expect(backoff.config.maxDelayMs).toBe(10000);
    expect(backoff.config.factor).toBe(2.0);
  });
});

// --- HeartbeatMonitor ---

describe('HeartbeatMonitor', () => {
  it('default config', () => {
    const config = defaultHeartbeatConfig();
    expect(config.intervalMs).toBe(30_000);
    expect(config.timeoutMs).toBe(90_000);
  });

  it('aggressive config', () => {
    const config = aggressiveHeartbeatConfig();
    expect(config.intervalMs).toBe(5_000);
    expect(config.timeoutMs).toBe(15_000);
  });

  it('relaxed config', () => {
    const config = relaxedHeartbeatConfig();
    expect(config.intervalMs).toBe(60_000);
    expect(config.timeoutMs).toBe(180_000);
  });

  it('timeout is 3x interval for all presets', () => {
    const d = defaultHeartbeatConfig();
    expect(d.timeoutMs).toBe(d.intervalMs * 3);
    const a = aggressiveHeartbeatConfig();
    expect(a.timeoutMs).toBe(a.intervalMs * 3);
    const r = relaxedHeartbeatConfig();
    expect(r.timeoutMs).toBe(r.intervalMs * 3);
  });

  it('not timed out initially', () => {
    const monitor = new HeartbeatMonitor();
    expect(monitor.isTimedOut()).toBe(false);
  });

  it('not needing heartbeat initially', () => {
    const monitor = new HeartbeatMonitor();
    expect(monitor.shouldSendHeartbeat()).toBe(false);
  });

  it('time until heartbeat positive initially', () => {
    const monitor = new HeartbeatMonitor();
    const until = monitor.timeUntilNextHeartbeat();
    expect(until).toBeGreaterThan(0);
    expect(until).toBeLessThanOrEqual(30_000);
  });

  it('time until timeout positive initially', () => {
    const monitor = new HeartbeatMonitor();
    const until = monitor.timeUntilTimeout();
    expect(until).toBeGreaterThan(0);
    expect(until).toBeLessThanOrEqual(90_000);
  });

  it('timed out with zero timeout', () => {
    const monitor = new HeartbeatMonitor({ intervalMs: 1000, timeoutMs: 0 });
    expect(monitor.isTimedOut()).toBe(true);
  });

  it('should send with zero interval', () => {
    const monitor = new HeartbeatMonitor({ intervalMs: 0, timeoutMs: 10_000 });
    expect(monitor.shouldSendHeartbeat()).toBe(true);
  });

  it('record activity resets timeout', () => {
    const monitor = new HeartbeatMonitor({ intervalMs: 1000, timeoutMs: 0 });
    expect(monitor.isTimedOut()).toBe(true);

    // Change to non-zero timeout and record activity
    (monitor as any).config.timeoutMs = 60_000;
    monitor.recordActivity();
    expect(monitor.isTimedOut()).toBe(false);
  });

  it('record heartbeat sent resets send timer', () => {
    const monitor = new HeartbeatMonitor({ intervalMs: 0, timeoutMs: 10_000 });
    expect(monitor.shouldSendHeartbeat()).toBe(true);

    (monitor as any).config.intervalMs = 30_000;
    monitor.recordHeartbeatSent();
    expect(monitor.shouldSendHeartbeat()).toBe(false);
  });

  it('lastActivity accessible', () => {
    const monitor = new HeartbeatMonitor();
    const now = Date.now();
    expect(Math.abs(monitor.lastActivity - now)).toBeLessThan(100);
  });
});

// --- NetworkMonitor ---

describe('NetworkMonitor', () => {
  it('reports changes to listeners', () => {
    const monitor = new NetworkMonitor();
    const changes: NetworkChange[] = [];
    monitor.onChange((c) => changes.push(c));

    monitor.reportChange({ type: 'interface_up', interface: 'wlan0' });

    expect(changes.length).toBe(1);
    expect(changes[0].type).toBe('interface_up');
    if (changes[0].type === 'interface_up') {
      expect(changes[0].interface).toBe('wlan0');
    }
  });

  it('reports multiple events', () => {
    const monitor = new NetworkMonitor();
    const changes: NetworkChange[] = [];
    monitor.onChange((c) => changes.push(c));

    monitor.reportChange({ type: 'interface_up', interface: 'wlan0' });
    monitor.reportChange({ type: 'address_changed', interface: 'wlan0', newAddr: '10.0.0.5' });
    monitor.reportChange({ type: 'interface_down', interface: 'eth0' });

    expect(changes.length).toBe(3);
    expect(changes[0].type).toBe('interface_up');
    expect(changes[1].type).toBe('address_changed');
    expect(changes[2].type).toBe('interface_down');
  });

  it('start and stop polling', () => {
    const monitor = new NetworkMonitor();
    expect(monitor.isPolling).toBe(false);

    monitor.start(60_000); // long interval so it doesn't actually poll
    expect(monitor.isPolling).toBe(true);

    monitor.stop();
    expect(monitor.isPolling).toBe(false);
  });

  it('double start is safe', () => {
    const monitor = new NetworkMonitor();
    monitor.start(60_000);
    monitor.start(60_000); // should not throw
    expect(monitor.isPolling).toBe(true);
    monitor.stop();
  });

  it('multiple listeners', () => {
    const monitor = new NetworkMonitor();
    const a: NetworkChange[] = [];
    const b: NetworkChange[] = [];
    monitor.onChange((c) => a.push(c));
    monitor.onChange((c) => b.push(c));

    monitor.reportChange({ type: 'interface_up', interface: 'eth0' });

    expect(a.length).toBe(1);
    expect(b.length).toBe(1);
  });
});

// --- MessageQueue ---

describe('MessageQueue', () => {
  it('default config', () => {
    const config = defaultQueueConfig();
    expect(config.enabled).toBe(true);
    expect(config.maxSize).toBe(1000);
    expect(config.maxAgeMs).toBe(3_600_000);
    expect(config.strategy).toBe('fifo');
  });

  it('starts empty', () => {
    const queue = new MessageQueue();
    expect(queue.isEmpty).toBe(true);
    expect(queue.length).toBe(0);
    expect(queue.remainingCapacity).toBe(1000);
  });

  it('enqueue success', () => {
    const queue = new MessageQueue();
    const result = queue.enqueue(1, new Uint8Array([1, 2, 3]));
    expect(result).toBe('enqueued');
    expect(queue.length).toBe(1);
    expect(queue.isEmpty).toBe(false);
  });

  it('enqueue multiple', () => {
    const queue = new MessageQueue();
    queue.enqueue(1, new Uint8Array([1]));
    queue.enqueue(2, new Uint8Array([2]));
    queue.enqueue(3, new Uint8Array([3]));
    expect(queue.length).toBe(3);
    expect(queue.remainingCapacity).toBe(997);
  });

  it('peek', () => {
    const queue = new MessageQueue();
    expect(queue.peek()).toBeUndefined();

    queue.enqueue(1, new Uint8Array([10, 20]));
    const msg = queue.peek()!;
    expect(msg.sequence).toBe(1);
    expect(msg.payload).toEqual(new Uint8Array([10, 20]));
    expect(queue.length).toBe(1); // peek doesn't consume
  });

  it('disabled queue rejects', () => {
    const queue = new MessageQueue({ enabled: false });
    expect(queue.enqueue(1, new Uint8Array([1]))).toBe('disabled');
    expect(queue.isEmpty).toBe(true);
  });

  it('FIFO rejects when full', () => {
    const queue = new MessageQueue({ maxSize: 3, strategy: 'fifo' });
    expect(queue.enqueue(1, new Uint8Array([1]))).toBe('enqueued');
    expect(queue.enqueue(2, new Uint8Array([2]))).toBe('enqueued');
    expect(queue.enqueue(3, new Uint8Array([3]))).toBe('enqueued');
    expect(queue.enqueue(4, new Uint8Array([4]))).toBe('full');
    expect(queue.length).toBe(3);
    expect(queue.peek()!.sequence).toBe(1); // oldest preserved
  });

  it('LIFO evicts oldest when full', () => {
    const queue = new MessageQueue({ maxSize: 3, strategy: 'lifo' });
    queue.enqueue(1, new Uint8Array([1]));
    queue.enqueue(2, new Uint8Array([2]));
    queue.enqueue(3, new Uint8Array([3]));
    expect(queue.enqueue(4, new Uint8Array([4]))).toBe('enqueued_with_eviction');
    expect(queue.length).toBe(3);
    expect(queue.peek()!.sequence).toBe(2); // seq 1 evicted
  });

  it('LIFO multiple evictions', () => {
    const queue = new MessageQueue({ maxSize: 2, strategy: 'lifo' });
    queue.enqueue(1, new Uint8Array([1]));
    queue.enqueue(2, new Uint8Array([2]));
    queue.enqueue(3, new Uint8Array([3])); // evicts 1
    queue.enqueue(4, new Uint8Array([4])); // evicts 2

    expect(queue.length).toBe(2);
    const msgs = queue.drain();
    expect(msgs[0].sequence).toBe(3);
    expect(msgs[1].sequence).toBe(4);
  });

  it('drain returns in order', () => {
    const queue = new MessageQueue();
    queue.enqueue(1, new Uint8Array([10]));
    queue.enqueue(2, new Uint8Array([20]));
    queue.enqueue(3, new Uint8Array([30]));

    const msgs = queue.drain();
    expect(msgs.length).toBe(3);
    expect(msgs[0].sequence).toBe(1);
    expect(msgs[1].sequence).toBe(2);
    expect(msgs[2].sequence).toBe(3);
    expect(queue.isEmpty).toBe(true);
  });

  it('clear discards all', () => {
    const queue = new MessageQueue();
    queue.enqueue(1, new Uint8Array([1]));
    queue.enqueue(2, new Uint8Array([2]));
    expect(queue.length).toBe(2);

    queue.clear();
    expect(queue.isEmpty).toBe(true);
    expect(queue.remainingCapacity).toBe(1000);
  });

  it('stale message expiry with zero maxAge', () => {
    const queue = new MessageQueue({ maxAgeMs: 0 });
    queue.enqueue(1, new Uint8Array([1]));
    // With zero maxAge, message is immediately stale
    queue.enqueue(2, new Uint8Array([2]));

    const msgs = queue.drain();
    expect(msgs.length).toBe(0);
  });

  it('messages maintain insertion order', () => {
    const queue = new MessageQueue();
    for (let seq = 9; seq >= 0; seq--) {
      queue.enqueue(seq, new Uint8Array([seq]));
    }
    const msgs = queue.drain();
    // Insertion order: 9, 8, 7, ..., 0
    for (let i = 0; i < msgs.length; i++) {
      expect(msgs[i].sequence).toBe(9 - i);
    }
  });

  it('payload preserved', () => {
    const queue = new MessageQueue();
    const payload = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    queue.enqueue(42, payload);

    const msgs = queue.drain();
    expect(msgs[0].payload).toEqual(payload);
    expect(msgs[0].sequence).toBe(42);
  });

  it('remaining capacity decreases', () => {
    const queue = new MessageQueue({ maxSize: 5 });
    expect(queue.remainingCapacity).toBe(5);

    queue.enqueue(1, new Uint8Array([]));
    expect(queue.remainingCapacity).toBe(4);

    queue.enqueue(2, new Uint8Array([]));
    queue.enqueue(3, new Uint8Array([]));
    expect(queue.remainingCapacity).toBe(2);
  });

  it('partial config uses defaults', () => {
    const queue = new MessageQueue({ maxSize: 500 });
    expect(queue.config.maxSize).toBe(500);
    expect(queue.config.maxAgeMs).toBe(3_600_000);
    expect(queue.config.strategy).toBe('fifo');
    expect(queue.config.enabled).toBe(true);
  });
});
