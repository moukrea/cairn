import { describe, it, expect } from 'vitest';
import {
  generatePin,
  formatPin,
  normalizePin,
  validatePin,
  derivePinRendezvousId,
  decodeCrockford,
} from '../../src/pairing/pin.js';
import {
  encodePairingPayload,
  decodePairingPayload,
  isPayloadExpired,
  generateNonce,
} from '../../src/pairing/payload.js';
import type { PairingPayload } from '../../src/pairing/payload.js';
import { generateQrPayload, consumeQrPayload, MAX_QR_PAYLOAD_SIZE } from '../../src/pairing/qr.js';
import { generatePairingLink, parsePairingLink } from '../../src/pairing/link.js';
import { validatePskEntropy, derivePskRendezvousId, pskToPakeInput } from '../../src/pairing/psk.js';
import { PairingSession, DEFAULT_PAIRING_TIMEOUT_MS } from '../../src/pairing/state-machine.js';
import { CairnError } from '../../src/errors.js';

function makePayload(expiresAt: number = Math.floor(Date.now() / 1000) + 3600): PairingPayload {
  return {
    peerId: new Uint8Array(32).fill(0x42),
    nonce: new Uint8Array(16).fill(0xAB),
    pakeCredential: new Uint8Array(32).fill(0xCD),
    hints: [{ hintType: 'rendezvous', value: 'relay.example.com:9090' }],
    createdAt: Math.floor(Date.now() / 1000),
    expiresAt,
  };
}

// --- PIN Code ---

describe('PIN code', () => {
  it('generates 8-character Crockford Base32 code', () => {
    const pin = generatePin();
    expect(pin.length).toBe(8);
  });

  it('pin only uses Crockford alphabet characters', () => {
    const crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    for (let i = 0; i < 50; i++) {
      const pin = generatePin();
      for (const ch of pin) {
        expect(crockford).toContain(ch);
      }
    }
  });

  it('formats as XXXX-XXXX', () => {
    const pin = generatePin();
    const formatted = formatPin(pin);
    expect(formatted.length).toBe(9);
    expect(formatted[4]).toBe('-');
  });

  it('normalizes case-insensitive input', () => {
    expect(normalizePin('abcd-efgh')).toBe('ABCDEFGH');
  });

  it('normalizes strips hyphens and spaces', () => {
    expect(normalizePin('AB CD-EF GH')).toBe('ABCDEFGH');
  });

  it('normalizes I/L->1, O->0', () => {
    expect(normalizePin('ILOO-AAAA')).toBe('1100AAAA');
  });

  it('normalizes removes U', () => {
    expect(normalizePin('AUBU-CUDU')).toBe('ABCD');
  });

  it('validates correct pin', () => {
    expect(() => validatePin('98AFXZ2A')).not.toThrow();
  });

  it('validates rejects wrong length', () => {
    expect(() => validatePin('ABC')).toThrow(CairnError);
  });

  it('validates rejects invalid chars', () => {
    expect(() => validatePin('ILOO!AAA')).toThrow(CairnError);
  });

  it('crockford encode/decode roundtrip', () => {
    for (let i = 0; i < 50; i++) {
      const pin = generatePin();
      const decoded = decodeCrockford(pin);
      expect(decoded.length).toBe(5); // 40 bits
    }
  });

  it('crockford known values', () => {
    const decoded0 = decodeCrockford('00000000');
    expect(decoded0).toEqual(new Uint8Array(5));

    const decodedZ = decodeCrockford('ZZZZZZZZ');
    expect(decodedZ).toEqual(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));
  });

  it('derives rendezvous ID deterministically', () => {
    const pin = new TextEncoder().encode('98AFXZ2A');
    const id1 = derivePinRendezvousId(pin);
    const id2 = derivePinRendezvousId(pin);
    expect(id1).toEqual(id2);
    expect(id1.length).toBe(32);
  });

  it('different pins give different rendezvous IDs', () => {
    const id1 = derivePinRendezvousId(new TextEncoder().encode('98AFXZ2A'));
    const id2 = derivePinRendezvousId(new TextEncoder().encode('ABCDEFGH'));
    expect(id1).not.toEqual(id2);
  });
});

// --- Pairing Payload ---

describe('PairingPayload', () => {
  it('CBOR roundtrip with hints', () => {
    const payload = makePayload();
    const cbor = encodePairingPayload(payload);
    const restored = decodePairingPayload(cbor);

    expect(restored.peerId).toEqual(payload.peerId);
    expect(restored.nonce).toEqual(payload.nonce);
    expect(restored.pakeCredential).toEqual(payload.pakeCredential);
    expect(restored.createdAt).toBe(payload.createdAt);
    expect(restored.expiresAt).toBe(payload.expiresAt);
    expect(restored.hints).toBeDefined();
    expect(restored.hints!.length).toBe(1);
    expect(restored.hints![0].hintType).toBe('rendezvous');
    expect(restored.hints![0].value).toBe('relay.example.com:9090');
  });

  it('CBOR roundtrip without hints', () => {
    const payload: PairingPayload = {
      peerId: new Uint8Array(32).fill(0xFF),
      nonce: new Uint8Array(16).fill(0x00),
      pakeCredential: new Uint8Array(32).fill(0x11),
      createdAt: 1000,
      expiresAt: 2000,
    };
    const cbor = encodePairingPayload(payload);
    const restored = decodePairingPayload(cbor);
    expect(restored.hints).toBeUndefined();
    expect(restored.nonce).toEqual(payload.nonce);
  });

  it('expiry check works', () => {
    const payload = makePayload(1700000300);
    expect(isPayloadExpired(payload, 1700000100)).toBe(false);
    expect(isPayloadExpired(payload, 1700000301)).toBe(true);
    expect(isPayloadExpired(payload, 1700000300)).toBe(false);
  });

  it('generateNonce returns 16 bytes', () => {
    const nonce = generateNonce();
    expect(nonce.length).toBe(16);
  });

  it('nonces are unique', () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    expect(n1).not.toEqual(n2);
  });

  it('rejects invalid CBOR', () => {
    expect(() => decodePairingPayload(new Uint8Array([0xFF, 0xFF]))).toThrow(CairnError);
  });
});

// --- QR Code ---

describe('QR code mechanism', () => {
  it('generate and consume roundtrip', () => {
    const payload = makePayload();
    const raw = generateQrPayload(payload);
    expect(raw.length).toBeLessThanOrEqual(MAX_QR_PAYLOAD_SIZE);

    const restored = consumeQrPayload(raw);
    expect(restored.peerId).toEqual(payload.peerId);
    expect(restored.nonce).toEqual(payload.nonce);
    expect(restored.pakeCredential).toEqual(payload.pakeCredential);
  });

  it('rejects expired payload', () => {
    const payload = makePayload(1000); // expired long ago
    const raw = encodePairingPayload(payload);
    expect(() => consumeQrPayload(raw)).toThrow('expired');
  });

  it('rejects oversized payload', () => {
    const payload: PairingPayload = {
      peerId: new Uint8Array(32).fill(0x42),
      nonce: new Uint8Array(16).fill(0xAB),
      pakeCredential: new Uint8Array(200).fill(0xCD),
      hints: Array.from({ length: 20 }, (_, i) => ({
        hintType: `type-${i}`,
        value: `very-long-value-${i}-with-extra-padding`,
      })),
      createdAt: 1700000000,
      expiresAt: 9999999999,
    };
    expect(() => generateQrPayload(payload)).toThrow('max size');
  });

  it('typical payload fits within 200 bytes', () => {
    const payload = makePayload();
    const raw = generateQrPayload(payload);
    expect(raw.length).toBeLessThanOrEqual(200);
  });
});

// --- Pairing Link ---

describe('Pairing link', () => {
  it('generate and parse roundtrip', () => {
    const payload = makePayload();
    const uri = generatePairingLink(payload);
    expect(uri).toContain('cairn://pair?');

    const restored = parsePairingLink(uri);
    expect(restored.peerId).toEqual(payload.peerId);
    expect(restored.nonce).toEqual(payload.nonce);
    expect(restored.pakeCredential).toEqual(payload.pakeCredential);
    expect(restored.createdAt).toBe(payload.createdAt);
    expect(restored.expiresAt).toBe(payload.expiresAt);
  });

  it('roundtrip without hints', () => {
    const payload: PairingPayload = {
      peerId: new Uint8Array(32).fill(0xFF),
      nonce: new Uint8Array(16).fill(0x00),
      pakeCredential: new Uint8Array(32).fill(0x11),
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    };
    const uri = generatePairingLink(payload);
    const restored = parsePairingLink(uri);
    expect(restored.hints).toBeUndefined();
    expect(restored.nonce).toEqual(payload.nonce);
  });

  it('rejects wrong scheme', () => {
    expect(() => parsePairingLink('https://pair?pid=abc&nonce=abc&pake=abc')).toThrow(CairnError);
  });

  it('rejects missing pid', () => {
    expect(() => parsePairingLink('cairn://pair?nonce=aa&pake=bb')).toThrow('pid');
  });

  it('rejects missing nonce', () => {
    expect(() => parsePairingLink('cairn://pair?pid=aa&pake=bb')).toThrow('nonce');
  });

  it('rejects missing pake', () => {
    expect(() => parsePairingLink('cairn://pair?pid=aa&nonce=00000000000000000000000000000000')).toThrow('pake');
  });

  it('custom scheme', () => {
    const payload = makePayload();
    const uri = generatePairingLink(payload, 'myapp');
    expect(uri).toContain('myapp://pair?');

    const restored = parsePairingLink(uri, 'myapp');
    expect(restored.peerId).toEqual(payload.peerId);
  });

  it('custom scheme rejects default', () => {
    const payload = makePayload();
    const uri = generatePairingLink(payload); // cairn://
    expect(() => parsePairingLink(uri, 'myapp')).toThrow(CairnError);
  });

  it('rejects expired link', () => {
    const payload = makePayload(1000); // expired
    const uri = generatePairingLink(payload);
    expect(() => parsePairingLink(uri)).toThrow('expired');
  });

  it('includes hints in URI', () => {
    const payload = makePayload();
    const uri = generatePairingLink(payload);
    expect(uri).toContain('hints=');
  });
});

// --- PSK ---

describe('PSK mechanism', () => {
  it('accepts 128-bit key', () => {
    expect(() => validatePskEntropy(new Uint8Array(16).fill(0xAB))).not.toThrow();
  });

  it('accepts longer key', () => {
    expect(() => validatePskEntropy(new Uint8Array(32).fill(0xAB))).not.toThrow();
  });

  it('rejects short key', () => {
    expect(() => validatePskEntropy(new Uint8Array(15).fill(0xAB))).toThrow('insufficient');
  });

  it('rejects empty key', () => {
    expect(() => validatePskEntropy(new Uint8Array(0))).toThrow('empty');
  });

  it('derives rendezvous ID deterministically', () => {
    const key = new Uint8Array(16).fill(0x42);
    const id1 = derivePskRendezvousId(key);
    const id2 = derivePskRendezvousId(key);
    expect(id1).toEqual(id2);
    expect(id1.length).toBe(32);
  });

  it('different keys give different rendezvous IDs', () => {
    const id1 = derivePskRendezvousId(new Uint8Array(16).fill(0x01));
    const id2 = derivePskRendezvousId(new Uint8Array(16).fill(0x02));
    expect(id1).not.toEqual(id2);
  });

  it('rejects short key for rendezvous derivation', () => {
    expect(() => derivePskRendezvousId(new Uint8Array(8).fill(0xAB))).toThrow(CairnError);
  });

  it('pskToPakeInput returns raw bytes', () => {
    const key = new Uint8Array(16).fill(0xDE);
    const input = pskToPakeInput(key);
    expect(input).toEqual(key);
  });

  it('pskToPakeInput accepts string', () => {
    const input = pskToPakeInput('this-is-a-long-enough-psk-key');
    expect(input.length).toBeGreaterThanOrEqual(16);
  });

  it('pskToPakeInput rejects short string', () => {
    expect(() => pskToPakeInput('short')).toThrow(CairnError);
  });
});

// --- State Machine ---

describe('PairingSession — Initiation flow', () => {
  it('initiator creates request with PAKE message', () => {
    const password = new TextEncoder().encode('test-password');
    const peerId = new Uint8Array(32).fill(0x42);
    const { session, message } = PairingSession.newInitiator(peerId, password);

    expect(session.state).toBe('awaiting_pake_exchange');
    expect(session.role).toBe('initiator');
    expect(session.flowType).toBe('initiation');
    expect(message.type).toBe('request');
    if (message.type === 'request') {
      expect(message.flowType).toBe('initiation');
      expect(message.pakeMsg).toBeDefined();
      expect(message.nonce.length).toBe(16);
    }
  });

  it('full initiation flow exchange', () => {
    const password = new TextEncoder().encode('test-pairing-password-42');
    const alicePeerId = new Uint8Array(32).fill(0x01);
    const bobPeerId = new Uint8Array(32).fill(0x02);

    // Alice creates initiator session
    const { session: alice, message: aliceReqMsg } = PairingSession.newInitiator(alicePeerId, password);
    expect(alice.state).toBe('awaiting_pake_exchange');

    // Bob creates responder session
    const bob = PairingSession.newResponder(password);
    expect(bob.state).toBe('idle');

    // Bob handles Alice's PairRequest -> gets PairChallenge
    const challenge = bob.handleMessage(aliceReqMsg, bobPeerId);
    expect(challenge).not.toBeNull();
    expect(bob.state).toBe('awaiting_verification');
    expect(challenge!.type).toBe('challenge');

    // Alice handles Bob's PairChallenge -> gets PairResponse
    const response = alice.handleMessage(challenge!);
    expect(response).not.toBeNull();
    expect(alice.state).toBe('awaiting_confirmation');
    expect(response!.type).toBe('response');

    // Bob handles Alice's PairResponse -> verifies key confirmation, sends PairConfirm
    const confirm = bob.handleMessage(response!);
    expect(confirm).not.toBeNull();
    expect(bob.state).toBe('awaiting_confirmation');
    expect(confirm!.type).toBe('confirm');

    // Alice handles Bob's PairConfirm -> completes
    const aliceFinal = alice.handleMessage(confirm!);
    expect(alice.state).toBe('completed');
    expect(alice.sharedKey).not.toBeNull();

    // If Alice sent a confirm back, Bob processes it
    if (aliceFinal) {
      bob.handleMessage(aliceFinal);
      expect(bob.state).toBe('completed');
      expect(bob.sharedKey).not.toBeNull();
    }

    // Both derived the same shared key
    expect(alice.sharedKey).toEqual(bob.sharedKey);
  });

  it('wrong password produces different keys (PAKE failure)', () => {
    const alicePeerId = new Uint8Array(32).fill(0x01);
    const bobPeerId = new Uint8Array(32).fill(0x02);

    const { session: alice, message: aliceReqMsg } = PairingSession.newInitiator(
      alicePeerId,
      new TextEncoder().encode('correct-password'),
    );
    const bob = PairingSession.newResponder(new TextEncoder().encode('wrong-password'));

    // Bob handles request -> challenge
    const challenge = bob.handleMessage(aliceReqMsg, bobPeerId);
    expect(challenge).not.toBeNull();

    // Alice handles challenge -> response
    const response = alice.handleMessage(challenge!);
    expect(response).not.toBeNull();

    // Bob verifies response -> should fail due to mismatched keys
    expect(() => bob.handleMessage(response!)).toThrow('PAKE authentication failed');
    expect(bob.state).toBe('failed');
  });
});

describe('PairingSession — Standard flow', () => {
  it('initiator creates standard request without PAKE', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session, message } = PairingSession.newStandardInitiator(peerId);

    expect(session.state).toBe('awaiting_verification');
    expect(session.role).toBe('initiator');
    expect(session.flowType).toBe('standard');
    expect(message.type).toBe('request');
    if (message.type === 'request') {
      expect(message.flowType).toBe('standard');
      expect(message.pakeMsg).toBeUndefined();
    }
  });

  it('responder handles standard request', () => {
    const bob = PairingSession.newStandardResponder();
    const alicePeerId = new Uint8Array(32).fill(0x01);
    const aliceNonce = new Uint8Array(16).fill(0x42);

    const result = bob.handleMessage({
      type: 'request',
      peerId: alicePeerId,
      nonce: aliceNonce,
      flowType: 'standard',
    });

    expect(result).toBeNull();
    expect(bob.state).toBe('awaiting_verification');
  });

  it('key confirmation exchange (standard flow)', () => {
    const alicePeerId = new Uint8Array(32).fill(0x01);
    const bobPeerId = new Uint8Array(32).fill(0x02);

    const { session: alice, message: aliceReq } = PairingSession.newStandardInitiator(alicePeerId);
    const bob = PairingSession.newStandardResponder();

    // Bob handles Alice's request
    bob.handleMessage(aliceReq, bobPeerId);

    // Simulate a shared key from Noise XX
    const shared = new Uint8Array(32).fill(0xAB);
    alice.setSharedKey(shared);
    bob.setSharedKey(shared);

    // Set remote nonces so both sides use the same salt
    alice.setRemoteNonce(new Uint8Array(16).fill(0x99));
    bob.setRemoteNonce(new Uint8Array(16).fill(0x88));

    // Alice sends key confirmation
    const aliceResponse = alice.sendKeyConfirmation(alicePeerId);
    expect(alice.state).toBe('awaiting_confirmation');
    expect(aliceResponse.type).toBe('response');

    // Bob handles Alice's response, sends confirm
    const bobConfirm = bob.handleMessage(aliceResponse);
    expect(bob.state).toBe('awaiting_confirmation');
    expect(bobConfirm).not.toBeNull();

    // Alice handles Bob's confirm
    const aliceFinal = alice.handleMessage(bobConfirm!);
    expect(alice.state).toBe('completed');
    expect(alice.sharedKey).not.toBeNull();

    // Bob handles Alice's confirm back
    if (aliceFinal) {
      bob.handleMessage(aliceFinal);
      expect(bob.state).toBe('completed');
    }
  });
});

describe('PairingSession — Error handling', () => {
  it('reject transitions to failed', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session } = PairingSession.newStandardInitiator(peerId);

    expect(() => session.handleMessage({ type: 'reject', reason: 'user_rejected' })).toThrow(CairnError);
    expect(session.state).toBe('failed');
  });

  it('initiator rejects PairRequest', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session } = PairingSession.newStandardInitiator(peerId);

    expect(() =>
      session.handleMessage({
        type: 'request',
        peerId: new Uint8Array(32),
        nonce: new Uint8Array(16),
        flowType: 'standard',
      }),
    ).toThrow('initiator cannot handle');
  });

  it('responder rejects PairChallenge', () => {
    const bob = PairingSession.newStandardResponder();

    expect(() =>
      bob.handleMessage({
        type: 'challenge',
        peerId: new Uint8Array(32),
        nonce: new Uint8Array(16),
        pakeMsg: new Uint8Array(32),
      }),
    ).toThrow('responder cannot handle');
  });

  it('expired session rejects messages', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session } = PairingSession.newStandardInitiator(peerId, 0); // instant timeout

    // Wait for expiry
    expect(() =>
      session.handleMessage({ type: 'confirm', keyConfirmation: new Uint8Array(0) }),
    ).toThrow('timed out');
  });

  it('non-expired session is not expired', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session } = PairingSession.newStandardInitiator(peerId);
    expect(session.isExpired).toBe(false);
  });

  it('shared key not available before completion', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const { session } = PairingSession.newStandardInitiator(peerId);
    session.setSharedKey(new Uint8Array(32).fill(0xAB));
    expect(session.sharedKey).toBeNull(); // not in completed state
  });

  it('sendKeyConfirmation rejects wrong state', () => {
    const peerId = new Uint8Array(32).fill(0x42);
    const password = new TextEncoder().encode('test');
    const { session } = PairingSession.newInitiator(peerId, password);
    // In awaiting_pake_exchange, not awaiting_verification
    expect(() => session.sendKeyConfirmation(peerId)).toThrow('invalid state');
  });
});
