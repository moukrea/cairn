import { describe, it, expect } from 'vitest';
import { deriveSas, verifySas } from '../../src/pairing/sas-flow.js';
import { CustomPairingMechanism } from '../../src/pairing/adapter.js';
import type { PairingMechanismAdapter } from '../../src/pairing/adapter.js';
import { PairingRateLimiter } from '../../src/pairing/rate-limit.js';
import { unpair, handlePairRevoke } from '../../src/pairing/unpairing.js';
import { CairnError } from '../../src/errors.js';

// --- SAS Flow ---

describe('SAS flow', () => {
  it('numeric SAS derives 6-digit code', () => {
    const hash = new Uint8Array(32).fill(0x42);
    const result = deriveSas(hash, 'numeric');
    expect(result.type).toBe('numeric');
    expect(result.display.length).toBe(6);
    expect(result.display).toMatch(/^\d{6}$/);
  });

  it('emoji SAS derives 4 emojis', () => {
    const hash = new Uint8Array(32).fill(0x42);
    const result = deriveSas(hash, 'emoji');
    expect(result.type).toBe('emoji');
    expect(result.emojis).toBeDefined();
    expect(result.emojis!.length).toBe(4);
    expect(result.display.length).toBeGreaterThan(0);
  });

  it('same transcript produces same SAS', () => {
    const hash = new Uint8Array(32).fill(0x99);
    const sas1 = deriveSas(hash, 'numeric');
    const sas2 = deriveSas(hash, 'numeric');
    expect(sas1.display).toBe(sas2.display);
  });

  it('different transcripts produce different SAS', () => {
    const hash1 = new Uint8Array(32).fill(0x01);
    const hash2 = new Uint8Array(32).fill(0x02);
    const sas1 = deriveSas(hash1, 'numeric');
    const sas2 = deriveSas(hash2, 'numeric');
    expect(sas1.display).not.toBe(sas2.display);
  });

  it('verifySas returns true for matching SAS', () => {
    const hash = new Uint8Array(32).fill(0x42);
    const local = deriveSas(hash, 'numeric');
    const remote = deriveSas(hash, 'numeric');
    expect(verifySas(local, remote)).toBe(true);
  });

  it('verifySas returns false for mismatched SAS', () => {
    const local = deriveSas(new Uint8Array(32).fill(0x01), 'numeric');
    const remote = deriveSas(new Uint8Array(32).fill(0x02), 'numeric');
    expect(verifySas(local, remote)).toBe(false);
  });

  it('verifySas returns false for different types', () => {
    const hash = new Uint8Array(32).fill(0x42);
    const numeric = deriveSas(hash, 'numeric');
    const emoji = deriveSas(hash, 'emoji');
    expect(verifySas(numeric, emoji)).toBe(false);
  });

  it('emoji SAS is deterministic', () => {
    const hash = new Uint8Array(32).fill(0x77);
    const e1 = deriveSas(hash, 'emoji');
    const e2 = deriveSas(hash, 'emoji');
    expect(e1.display).toBe(e2.display);
    expect(e1.emojis).toEqual(e2.emojis);
  });
});

// --- Custom Adapter ---

describe('Custom pairing adapter', () => {
  const passthroughAdapter: PairingMechanismAdapter = {
    name: 'passthrough',
    async generatePayload(data: Uint8Array) { return data; },
    async consumePayload(data: Uint8Array) {
      return { pakeCredential: data };
    },
    async derivePakeInput(data: Uint8Array) { return data; },
  };

  it('passthrough generate and consume roundtrip', async () => {
    const mechanism = new CustomPairingMechanism(passthroughAdapter);
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = await mechanism.generatePayload(data);
    expect(encoded).toEqual(data);

    const decoded = await mechanism.consumePayload(encoded);
    expect(decoded.pakeCredential).toEqual(data);
  });

  it('derive PAKE input', async () => {
    const mechanism = new CustomPairingMechanism(passthroughAdapter);
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const pakeInput = await mechanism.derivePakeInput(data);
    expect(pakeInput).toEqual(data);
  });

  it('mechanism name', () => {
    const mechanism = new CustomPairingMechanism(passthroughAdapter);
    expect(mechanism.name).toBe('passthrough');
  });

  it('failing adapter generate', async () => {
    const failingAdapter: PairingMechanismAdapter = {
      name: 'failing',
      async generatePayload() { throw new Error('device not available'); },
      async consumePayload() { throw new Error('invalid format'); },
      async derivePakeInput() { throw new Error('hardware error'); },
    };
    const mechanism = new CustomPairingMechanism(failingAdapter);
    await expect(mechanism.generatePayload(new Uint8Array([1]))).rejects.toThrow('device not available');
  });

  it('failing adapter consume', async () => {
    const failingAdapter: PairingMechanismAdapter = {
      name: 'failing',
      async generatePayload() { throw new Error('device not available'); },
      async consumePayload() { throw new Error('invalid format'); },
      async derivePakeInput() { throw new Error('hardware error'); },
    };
    const mechanism = new CustomPairingMechanism(failingAdapter);
    await expect(mechanism.consumePayload(new Uint8Array([1]))).rejects.toThrow('invalid format');
  });

  it('failing adapter derive', async () => {
    const failingAdapter: PairingMechanismAdapter = {
      name: 'failing',
      async generatePayload() { throw new Error('device not available'); },
      async consumePayload() { throw new Error('invalid format'); },
      async derivePakeInput() { throw new Error('hardware error'); },
    };
    const mechanism = new CustomPairingMechanism(failingAdapter);
    await expect(mechanism.derivePakeInput(new Uint8Array([1]))).rejects.toThrow('hardware error');
  });
});

// --- Rate Limiting ---

describe('PairingRateLimiter', () => {
  it('creates with default config', () => {
    const rl = new PairingRateLimiter();
    expect(rl.totalFailures).toBe(0);
    expect(rl.isInvalidated).toBe(false);
  });

  it('first attempt allowed with zero delay', () => {
    const rl = new PairingRateLimiter();
    const result = rl.check('source-1');
    expect(result.allowed).toBe(true);
    expect(result.waitMs).toBe(0);
  });

  it('five attempts allowed within window', () => {
    const rl = new PairingRateLimiter();
    for (let i = 0; i < 5; i++) {
      const result = rl.check('source-1');
      expect(result.allowed).toBe(true);
    }
  });

  it('sixth attempt rejected within window', () => {
    const rl = new PairingRateLimiter();
    for (let i = 0; i < 5; i++) {
      rl.check('source-1');
    }
    const result = rl.check('source-1');
    expect(result.allowed).toBe(false);
  });

  it('different sources have independent windows', () => {
    const rl = new PairingRateLimiter();
    for (let i = 0; i < 5; i++) {
      rl.check('source-1');
    }
    const result = rl.check('source-2');
    expect(result.allowed).toBe(true);
  });

  it('progressive delay increases with failures', () => {
    const rl = new PairingRateLimiter();

    // First: no failures, zero delay
    const r1 = rl.check('source-1');
    expect(r1.waitMs).toBe(0);

    rl.recordFailure('source-1');

    // Second: 1 failure * 2000ms = 2000ms
    const r2 = rl.check('source-1');
    expect(r2.waitMs).toBe(2000);

    rl.recordFailure('source-1');

    // Third: 2 failures * 2000ms = 4000ms
    const r3 = rl.check('source-1');
    expect(r3.waitMs).toBe(4000);
  });

  it('record success resets source delay', () => {
    const rl = new PairingRateLimiter();

    rl.check('source-1');
    rl.recordFailure('source-1');
    rl.recordFailure('source-1');

    const r1 = rl.check('source-1');
    expect(r1.waitMs).toBe(4000);

    rl.recordSuccess('source-1');

    const r2 = rl.check('source-1');
    expect(r2.waitMs).toBe(0);
  });

  it('auto-invalidation after max failures', () => {
    const rl = new PairingRateLimiter();

    for (let i = 0; i < 10; i++) {
      rl.check(`source-${i}`);
      rl.recordFailure(`source-${i}`);
    }

    expect(rl.isInvalidated).toBe(true);
    expect(rl.totalFailures).toBe(10);

    expect(() => rl.check('source-new')).toThrow('auto-invalidated');
  });

  it('reset clears all state', () => {
    const rl = new PairingRateLimiter();

    for (let i = 0; i < 5; i++) {
      rl.check(`source-${i}`);
      rl.recordFailure(`source-${i}`);
    }
    expect(rl.totalFailures).toBe(5);

    rl.reset();

    expect(rl.totalFailures).toBe(0);
    expect(rl.isInvalidated).toBe(false);
    const result = rl.check('source-0');
    expect(result.allowed).toBe(true);
  });

  it('custom config', () => {
    const rl = new PairingRateLimiter({
      maxPerWindow: 3,
      windowMs: 10_000,
      maxTotalFailures: 5,
      delayPerFailureMs: 1000,
    });

    // 3 allowed
    for (let i = 0; i < 3; i++) {
      expect(rl.check('src').allowed).toBe(true);
    }
    // 4th rejected
    expect(rl.check('src').allowed).toBe(false);

    // Custom failure threshold
    rl.reset();
    for (let i = 0; i < 5; i++) {
      rl.check(`s-${i}`);
      rl.recordFailure(`s-${i}`);
    }
    expect(rl.isInvalidated).toBe(true);
  });

  it('custom delay per failure', () => {
    const rl = new PairingRateLimiter({
      maxPerWindow: 10,
      windowMs: 60_000,
      maxTotalFailures: 20,
      delayPerFailureMs: 3000,
    });

    rl.check('src');
    rl.recordFailure('src');

    const r1 = rl.check('src');
    expect(r1.waitMs).toBe(3000);

    rl.recordFailure('src');
    const r2 = rl.check('src');
    expect(r2.waitMs).toBe(6000);
  });

  it('total failures across sources', () => {
    const rl = new PairingRateLimiter();

    rl.check('a'); rl.recordFailure('a');
    rl.check('b'); rl.recordFailure('b');
    rl.check('c'); rl.recordFailure('c');

    expect(rl.totalFailures).toBe(3);
  });

  it('success does not reduce total failures', () => {
    const rl = new PairingRateLimiter();
    rl.check('src');
    rl.recordFailure('src');
    expect(rl.totalFailures).toBe(1);

    rl.recordSuccess('src');
    expect(rl.totalFailures).toBe(1); // total still accumulates
  });

  it('record success on unknown source is noop', () => {
    const rl = new PairingRateLimiter();
    rl.recordSuccess('nonexistent');
    expect(rl.totalFailures).toBe(0);
  });
});

// --- Unpairing ---

describe('Unpairing', () => {
  function makePeerStore() {
    const peers = new Set<string>();
    const toKey = (id: Uint8Array) => Array.from(id).join(',');
    return {
      add(id: Uint8Array) { peers.add(toKey(id)); },
      isPaired(id: Uint8Array) { return peers.has(toKey(id)); },
      removePeer(id: Uint8Array) {
        const key = toKey(id);
        if (peers.has(key)) {
          peers.delete(key);
          return true;
        }
        return false;
      },
    };
  }

  it('unpair removes peer and returns event', () => {
    const store = makePeerStore();
    const peerId = new Uint8Array(32).fill(0x01);
    store.add(peerId);

    const event = unpair(peerId, store.isPaired.bind(store), store.removePeer.bind(store));
    expect(event.type).toBe('local_unpair_completed');
    expect(event.peerId).toEqual(peerId);
    expect(store.isPaired(peerId)).toBe(false);
  });

  it('unpair unknown peer throws', () => {
    const store = makePeerStore();
    const peerId = new Uint8Array(32).fill(0x01);

    expect(() => unpair(peerId, store.isPaired.bind(store), store.removePeer.bind(store))).toThrow('peer not found');
  });

  it('unpair does not affect other peers', () => {
    const store = makePeerStore();
    const peer1 = new Uint8Array(32).fill(0x01);
    const peer2 = new Uint8Array(32).fill(0x02);
    store.add(peer1);
    store.add(peer2);

    unpair(peer1, store.isPaired.bind(store), store.removePeer.bind(store));

    expect(store.isPaired(peer1)).toBe(false);
    expect(store.isPaired(peer2)).toBe(true);
  });

  it('handlePairRevoke removes peer', () => {
    const store = makePeerStore();
    const peerId = new Uint8Array(32).fill(0x02);
    store.add(peerId);

    const event = handlePairRevoke(peerId, store.removePeer.bind(store));
    expect(event.type).toBe('remote_peer_unpaired');
    expect(event.peerId).toEqual(peerId);
    expect(store.isPaired(peerId)).toBe(false);
  });

  it('handlePairRevoke for unknown peer succeeds', () => {
    const store = makePeerStore();
    const peerId = new Uint8Array(32).fill(0x03);

    const event = handlePairRevoke(peerId, store.removePeer.bind(store));
    expect(event.type).toBe('remote_peer_unpaired');
  });

  it('handlePairRevoke does not affect other peers', () => {
    const store = makePeerStore();
    const peer1 = new Uint8Array(32).fill(0x01);
    const peer2 = new Uint8Array(32).fill(0x02);
    store.add(peer1);
    store.add(peer2);

    handlePairRevoke(peer1, store.removePeer.bind(store));

    expect(store.isPaired(peer1)).toBe(false);
    expect(store.isPaired(peer2)).toBe(true);
  });
});
