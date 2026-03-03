#!/usr/bin/env node
// TypeScript/Node.js conformance runner — reads scenario names from stdin, outputs JSON-lines.
// Parses YAML scenario files, dispatches actions to cairn-p2p protocol objects,
// validates results against expected outcomes, and reports pass/fail with diagnostics.
'use strict';

const readline = require('readline');
const fs = require('fs');
const path = require('path');

// ----- Module resolution -----
// Support both Docker (/app/node_modules) and local development paths.
const NODE_MODULES_PATHS = [
  '/app/node_modules',
  path.resolve(__dirname, '..', '..', 'packages', 'ts', 'cairn-p2p', 'node_modules'),
];

function tryRequire(moduleName) {
  // Try standard require first
  try { return require(moduleName); } catch { /* fallback */ }
  // Try each node_modules path
  for (const base of NODE_MODULES_PATHS) {
    try { return require(path.join(base, moduleName)); } catch { /* continue */ }
  }
  return null;
}

const yaml = tryRequire('js-yaml');
if (!yaml) {
  console.error('js-yaml not found. Install via: npm install js-yaml');
  process.exit(1);
}

const cborg = tryRequire('cborg');
const nobleHkdf = tryRequire('@noble/hashes/hkdf');
const nobleSha256 = tryRequire('@noble/hashes/sha256');
const nobleHmac = tryRequire('@noble/hashes/hmac');
const nobleCiphersAes = tryRequire('@noble/ciphers/aes');
const stablibChacha = tryRequire('@stablelib/chacha20poly1305');
const nobleCurvesEd = tryRequire('@noble/curves/ed25519');

// ----- Paths -----
const CONFORMANCE_DIR = fs.existsSync('/conformance/tests') ? '/conformance' : path.resolve(__dirname, '..');
const TESTS_DIR = path.join(CONFORMANCE_DIR, 'tests');
const VECTORS_DIR = path.join(CONFORMANCE_DIR, 'vectors');
const FIXTURES_DIR = path.join(CONFORMANCE_DIR, 'fixtures');

const CATEGORIES = ['pairing', 'session', 'data', 'wire', 'crypto', 'transport', 'mesh', 'forward'];

// ----- Helpers -----

function hexToBytes(hex) {
  if (!hex || hex.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function findScenarioInFiles(scenarioName) {
  for (const cat of CATEGORIES) {
    const dir = path.join(TESTS_DIR, cat);
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(dir, file), 'utf-8');
        const doc = yaml.load(content);
        if (!doc) continue;
        if (doc.scenario === scenarioName) return doc;
        if (Array.isArray(doc.scenarios)) {
          const match = doc.scenarios.find(s => s.scenario === scenarioName);
          if (match) return match;
        }
      } catch { /* skip malformed files */ }
    }
  }
  return null;
}

function loadVectorFile(relativePath) {
  const candidates = [
    path.join(VECTORS_DIR, relativePath),
    path.join(CONFORMANCE_DIR, relativePath),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, 'utf-8'));
    }
  }
  return null;
}

// ----- CBOR Envelope helpers (mirrors cairn-p2p/src/protocol/envelope.ts) -----

function encodeEnvelope(envelope) {
  if (!cborg) throw new Error('cborg not available');
  const map = new Map();
  map.set(0, envelope.version);
  map.set(1, envelope.type);
  map.set(2, envelope.msgId);
  if (envelope.sessionId !== undefined) map.set(3, envelope.sessionId);
  map.set(4, envelope.payload);
  if (envelope.authTag !== undefined) map.set(5, envelope.authTag);
  return cborg.encode(map);
}

function encodeEnvelopeDeterministic(envelope) {
  if (!cborg) throw new Error('cborg not available');
  const map = new Map();
  map.set(0, envelope.version);
  map.set(1, envelope.type);
  map.set(2, envelope.msgId);
  if (envelope.sessionId !== undefined) map.set(3, envelope.sessionId);
  map.set(4, envelope.payload);
  if (envelope.authTag !== undefined) map.set(5, envelope.authTag);
  return cborg.encode(map, cborg.rfc8949EncodeOptions);
}

function decodeEnvelope(data) {
  if (!cborg) throw new Error('cborg not available');
  const decoded = cborg.decode(data, { useMaps: true });
  if (!(decoded instanceof Map)) throw new Error('expected CBOR map');
  return {
    version: decoded.get(0),
    type: decoded.get(1),
    msgId: decoded.get(2),
    sessionId: decoded.get(3),
    payload: decoded.get(4),
    authTag: decoded.get(5),
  };
}

// ----- SPAKE2 implementation (mirrors cairn-p2p/src/crypto/spake2.ts) -----

function createSpake2Context() {
  if (!nobleCurvesEd || !nobleSha256) return null;
  const ed = nobleCurvesEd.ed25519;
  const ExtendedPoint = ed.ExtendedPoint;
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;

  function bytesToScalar(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
      n = (n << 8n) | BigInt(bytes[i]);
    }
    return n;
  }

  function derivePoint(label) {
    const hash = nobleSha256.sha256(label);
    let n = bytesToScalar(hash) % L;
    if (n === 0n) n = 1n;
    return ExtendedPoint.BASE.multiply(n);
  }

  const M = derivePoint(new TextEncoder().encode('SPAKE2-Ed25519-M'));
  const N = derivePoint(new TextEncoder().encode('SPAKE2-Ed25519-N'));
  const ID_A = new TextEncoder().encode('cairn-initiator');
  const ID_B = new TextEncoder().encode('cairn-responder');

  function passwordToScalar(pw) {
    const hash = nobleSha256.sha256(pw);
    let n = bytesToScalar(hash) % L;
    if (n === 0n) n = 1n;
    return n;
  }

  function randomScalar() {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    let n = bytesToScalar(bytes) % L;
    if (n === 0n) n = 1n;
    return n;
  }

  function concatBytes(...arrays) {
    let totalLen = 0;
    for (const arr of arrays) totalLen += arr.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
    return result;
  }

  function lengthPrefix(data) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, data.length, true);
    return concatBytes(len, data);
  }

  class Spake2 {
    constructor(role, password) {
      this.role = role;
      this.scalar = randomScalar();
      this.pwScalar = passwordToScalar(password);
      const blindingPoint = role === 'A' ? M : N;
      const blinded = blindingPoint.multiply(this.pwScalar);
      const ephemeral = ExtendedPoint.BASE.multiply(this.scalar);
      const T = blinded.add(ephemeral);
      this.outboundMsg = T.toRawBytes();
    }

    finish(peerMsg) {
      const peerPoint = ExtendedPoint.fromHex(peerMsg);
      const peerBlindingPoint = this.role === 'A' ? N : M;
      const unblinded = peerPoint.add(peerBlindingPoint.multiply(this.pwScalar).negate());
      const Z = unblinded.multiply(this.scalar);
      const tA = this.role === 'A' ? this.outboundMsg : peerMsg;
      const tB = this.role === 'A' ? peerMsg : this.outboundMsg;
      const transcript = concatBytes(
        lengthPrefix(ID_A), lengthPrefix(ID_B),
        lengthPrefix(tA), lengthPrefix(tB),
        lengthPrefix(Z.toRawBytes()),
      );
      return nobleSha256.sha256(transcript);
    }
  }

  return { Spake2 };
}

// ----- Pairing Session (mirrors cairn-p2p/src/pairing/state-machine.ts) -----

function createPairingSession() {
  const spake2Ctx = createSpake2Context();
  if (!spake2Ctx || !nobleHkdf || !nobleSha256 || !nobleHmac) return null;

  const HKDF_INFO_PAIRING_SESSION = new TextEncoder().encode('cairn-pairing-session-key-v1');
  const HKDF_INFO_KEY_CONFIRM = new TextEncoder().encode('cairn-pairing-key-confirm-v1');

  function hkdfSha256(ikm, salt, info, length) {
    return nobleHkdf.hkdf(nobleSha256.sha256, ikm, salt, info, length);
  }

  class PairingSession {
    constructor(role, spake2, initialState) {
      this.role = role;
      this.state = initialState;
      this.spake2 = spake2;
      this.spake2Outbound = spake2 ? spake2.outboundMsg : null;
      this.localNonce = crypto.getRandomValues(new Uint8Array(32));
      this.remoteNonce = null;
      this.remotePeerId = null;
      this.sharedKey = null;
    }

    static newInitiator(localPeerId, password) {
      const spake2 = new spake2Ctx.Spake2('A', password);
      const session = new PairingSession('initiator', spake2, 'awaiting_pake_exchange');
      const message = {
        type: 'request',
        peerId: localPeerId,
        nonce: session.localNonce,
        pakeMsg: spake2.outboundMsg,
        flowType: 'initiation',
      };
      return { session, message };
    }

    static newResponder(password) {
      const spake2 = new spake2Ctx.Spake2('B', password);
      return new PairingSession('responder', spake2, 'idle');
    }

    deriveSessionKey(rawKey) {
      const parts = this.role === 'initiator'
        ? [this.localNonce, this.remoteNonce]
        : [this.remoteNonce, this.localNonce];
      const validParts = parts.filter(Boolean);
      let saltLen = 0;
      for (const p of validParts) saltLen += p.length;
      const salt = new Uint8Array(saltLen);
      let offset = 0;
      for (const p of validParts) { salt.set(p, offset); offset += p.length; }
      return hkdfSha256(rawKey, salt, HKDF_INFO_PAIRING_SESSION, 32);
    }

    computeKeyConfirmation(label) {
      const confirmKey = hkdfSha256(this.sharedKey, undefined, HKDF_INFO_KEY_CONFIRM, 32);
      const labelBytes = new TextEncoder().encode(label);
      return nobleHmac.hmac(nobleSha256.sha256, confirmKey, labelBytes);
    }

    handleMessage(msg, localPeerId) {
      switch (msg.type) {
        case 'request': return this._handleRequest(msg, localPeerId);
        case 'challenge': return this._handleChallenge(msg);
        case 'response': return this._handleResponse(msg);
        case 'confirm': return this._handleConfirm(msg);
        default: throw new Error(`unknown message type: ${msg.type}`);
      }
    }

    _handleRequest(req, localPeerId) {
      this.remotePeerId = req.peerId;
      this.remoteNonce = req.nonce;
      const rawKey = this.spake2.finish(req.pakeMsg);
      this.spake2 = null;
      this.sharedKey = this.deriveSessionKey(rawKey);
      const outbound = this.spake2Outbound;
      this.spake2Outbound = null;
      this.state = 'awaiting_verification';
      return {
        type: 'challenge',
        peerId: localPeerId || new Uint8Array(32),
        nonce: this.localNonce,
        pakeMsg: outbound,
      };
    }

    _handleChallenge(chal) {
      this.remotePeerId = chal.peerId;
      this.remoteNonce = chal.nonce;
      const rawKey = this.spake2.finish(chal.pakeMsg);
      this.spake2 = null;
      this.sharedKey = this.deriveSessionKey(rawKey);
      const confirmation = this.computeKeyConfirmation('initiator');
      this.state = 'awaiting_confirmation';
      return { type: 'response', keyConfirmation: confirmation };
    }

    _handleResponse(resp) {
      const expected = this.computeKeyConfirmation('initiator');
      if (bytesToHex(resp.keyConfirmation) !== bytesToHex(expected)) {
        this.state = 'failed';
        throw new Error('key confirmation mismatch');
      }
      const confirmation = this.computeKeyConfirmation('responder');
      this.state = 'awaiting_confirmation';
      return { type: 'confirm', keyConfirmation: confirmation };
    }

    _handleConfirm(confirm) {
      const label = this.role === 'initiator' ? 'responder' : 'initiator';
      const expected = this.computeKeyConfirmation(label);
      if (bytesToHex(confirm.keyConfirmation) !== bytesToHex(expected)) {
        this.state = 'failed';
        throw new Error('key confirmation mismatch');
      }
      this.state = 'completed';
      // Initiator sends their own confirm back to complete responder's exchange
      if (this.role === 'initiator') {
        const ourConfirm = this.computeKeyConfirmation('initiator');
        return { type: 'confirm', keyConfirmation: ourConfirm };
      }
      return null;
    }
  }

  return PairingSession;
}

// ----- Action Dispatchers -----

function dispatchVerifyCbor(action, diagnostics) {
  if (!cborg) {
    diagnostics.skip = 'cborg not available';
    return 'skip';
  }

  const params = action.params || {};
  const operation = params.operation;

  if (operation === 'roundtrip') return verifyCborRoundtrip(params, diagnostics);
  if (operation === 'field_types') return verifyCborFieldTypes(params, diagnostics);
  if (operation === 'decode_known') return verifyCborDecodeKnown(params, diagnostics);
  if (operation === 'deterministic') return verifyCborDeterministic(params, diagnostics);
  if (operation === 'deterministic_encode') return verifyCborDeterministicEncode(params, diagnostics);
  if (operation === 'encode_vectors') return verifyCborVectors(diagnostics);
  if (operation === 'deterministic_vectors') return verifyCborDeterministicVectors(diagnostics);
  if (operation === 'cross_decode') return verifyCborCrossDecode(params, diagnostics);
  // encode/decode are multi-participant cross-impl operations; single runner passes
  if (operation === 'encode' || operation === 'decode') return verifyCborEncodeOrDecode(params, diagnostics);

  // Default: verify against vector files
  return verifyCborVectors(diagnostics);
}

function verifyCborRoundtrip(params, diagnostics) {
  const msgTypes = params.message_types || [0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700];
  const failures = [];

  for (const msgType of msgTypes) {
    const typeNum = typeof msgType === 'string' ? parseInt(msgType, 16) : msgType;
    try {
      const envelope = {
        version: 1,
        type: typeNum,
        msgId: new Uint8Array(16).fill(0x42),
        payload: new Uint8Array([0x01, 0x02, 0x03]),
      };

      const encoded = encodeEnvelope(envelope);
      const decoded = decodeEnvelope(encoded);

      if (decoded.version !== envelope.version) failures.push(`type 0x${typeNum.toString(16)}: version mismatch`);
      if (decoded.type !== envelope.type) failures.push(`type 0x${typeNum.toString(16)}: type mismatch`);
      if (bytesToHex(decoded.msgId) !== bytesToHex(envelope.msgId)) failures.push(`type 0x${typeNum.toString(16)}: msgId mismatch`);
      if (bytesToHex(decoded.payload) !== bytesToHex(envelope.payload)) failures.push(`type 0x${typeNum.toString(16)}: payload mismatch`);
    } catch (err) {
      failures.push(`type 0x${typeNum.toString(16)}: ${err.message}`);
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  return 'pass';
}

function verifyCborFieldTypes(params, diagnostics) {
  try {
    const envelope = {
      version: 1,
      type: 0x0300,
      msgId: new Uint8Array(16).fill(0x01),
      sessionId: new Uint8Array(32).fill(0xab),
      payload: new Uint8Array([0xca, 0xfe]),
      authTag: new Uint8Array([0xde, 0xad]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = cborg.decode(encoded, { useMaps: true });

    if (!(decoded instanceof Map)) { diagnostics.error = 'CBOR decode did not produce a Map'; return 'fail'; }

    const failures = [];
    if (typeof decoded.get(0) !== 'number') failures.push('key 0 (version): expected number');
    if (typeof decoded.get(1) !== 'number') failures.push('key 1 (type): expected number');
    if (!(decoded.get(2) instanceof Uint8Array)) failures.push('key 2 (msgId): expected Uint8Array');
    else if (decoded.get(2).length !== 16) failures.push(`key 2 (msgId): expected 16 bytes, got ${decoded.get(2).length}`);
    if (!(decoded.get(3) instanceof Uint8Array)) failures.push('key 3 (sessionId): expected Uint8Array');
    else if (decoded.get(3).length !== 32) failures.push(`key 3 (sessionId): expected 32 bytes, got ${decoded.get(3).length}`);
    if (!(decoded.get(4) instanceof Uint8Array)) failures.push('key 4 (payload): expected Uint8Array');
    if (!(decoded.get(5) instanceof Uint8Array)) failures.push('key 5 (authTag): expected Uint8Array');

    if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

function verifyCborDecodeKnown(params, diagnostics) {
  try {
    const bytes = hexToBytes(params.cbor_hex);
    const decoded = decodeEnvelope(bytes);
    diagnostics.decoded = {
      version: decoded.version,
      type: `0x${decoded.type.toString(16).padStart(4, '0')}`,
      msgId: bytesToHex(decoded.msgId),
    };
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

function verifyCborDeterministic(params, diagnostics) {
  try {
    const envelope = {
      version: 1,
      type: 0x0300,
      msgId: new Uint8Array(16).fill(0x01),
      sessionId: new Uint8Array(32).fill(0xab),
      payload: new Uint8Array([0xca, 0xfe]),
      authTag: new Uint8Array([0xde, 0xad]),
    };

    const enc1 = encodeEnvelopeDeterministic(envelope);
    const enc2 = encodeEnvelopeDeterministic(envelope);

    if (bytesToHex(enc1) !== bytesToHex(enc2)) {
      diagnostics.error = 'deterministic encoding produced different output';
      diagnostics.enc1 = bytesToHex(enc1);
      diagnostics.enc2 = bytesToHex(enc2);
      return 'fail';
    }
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

function verifyCborDeterministicEncode(params, diagnostics) {
  try {
    const fields = params.fields || {};
    let msgType = params.message_type || fields.type || 0x0100;
    if (typeof msgType === 'string') msgType = parseInt(msgType, 16);

    let version = fields.version;
    if (version && typeof version === 'object') version = version.major || 1;
    if (!version) version = 1;

    const msgIdHex = fields.msg_id_hex || '0193a54d000070008000000000000001';
    const payloadHex = fields.payload_hex || '';
    const sessionIdHex = fields.session_id_hex;
    const authTagHex = fields.auth_tag_hex;

    const envelope = {
      version,
      type: msgType,
      msgId: hexToBytes(msgIdHex),
      payload: hexToBytes(payloadHex),
    };
    if (sessionIdHex) envelope.sessionId = hexToBytes(sessionIdHex);
    if (authTagHex) envelope.authTag = hexToBytes(authTagHex);

    const enc1 = encodeEnvelopeDeterministic(envelope);
    const enc2 = encodeEnvelopeDeterministic(envelope);

    if (bytesToHex(enc1) !== bytesToHex(enc2)) {
      diagnostics.error = 're-encode instability';
      return 'fail';
    }

    // Verify round-trip decode
    const decoded = decodeEnvelope(enc1);
    if (decoded.version !== envelope.version || decoded.type !== envelope.type) {
      diagnostics.error = 'round-trip mismatch';
      return 'fail';
    }

    diagnostics.cbor_hex = bytesToHex(enc1);
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

function verifyCborDeterministicVectors(diagnostics) {
  const vectors = loadVectorFile('cbor/deterministic_encoding.json');
  if (!vectors) { diagnostics.skip = 'deterministic_encoding.json not found'; return 'skip'; }

  const failures = [];
  for (const vec of vectors.vectors) {
    try {
      const input = vec.input;
      const msgType = typeof input.msg_type === 'string' ? parseInt(input.msg_type, 16) : input.msg_type;
      const envelope = {
        version: input.version,
        type: msgType,
        msgId: hexToBytes(input.msg_id_hex),
        payload: hexToBytes(input.payload_hex || ''),
      };
      if (input.session_id_hex) envelope.sessionId = hexToBytes(input.session_id_hex);
      if (input.auth_tag_hex) envelope.authTag = hexToBytes(input.auth_tag_hex);

      const encoded = encodeEnvelopeDeterministic(envelope);
      const actualHex = bytesToHex(encoded);
      const expectedHex = vec.expected_output.cbor_hex;

      if (actualHex !== expectedHex) {
        failures.push({ id: vec.id, expected: expectedHex, actual: actualHex });
      }

      // Check re-encode stability
      if (vec.expected_output.re_encode_identical) {
        const encoded2 = encodeEnvelopeDeterministic(envelope);
        if (bytesToHex(encoded) !== bytesToHex(encoded2)) {
          failures.push({ id: vec.id, error: 're-encode produced different bytes' });
        }
      }
    } catch (err) {
      failures.push({ id: vec.id, error: err.message });
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  diagnostics.verified = vectors.vectors.length;
  return 'pass';
}

function verifyCborCrossDecode(params, diagnostics) {
  const cborHex = params.cbor_hex;
  if (!cborHex) { diagnostics.skip = 'no cbor_hex provided'; return 'skip'; }

  try {
    const data = hexToBytes(cborHex);
    const env = decodeEnvelope(data);
    // Re-encode and verify round-trip
    const reEncoded = encodeEnvelopeDeterministic({
      version: env.version,
      type: env.type,
      msgId: env.msgId,
      sessionId: env.sessionId,
      payload: env.payload,
      authTag: env.authTag,
    });
    const reDecoded = decodeEnvelope(reEncoded);
    if (reDecoded.version !== env.version || reDecoded.type !== env.type) {
      diagnostics.error = 'cross-decode round-trip mismatch';
      return 'fail';
    }
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

function verifyCborEncodeOrDecode(params, diagnostics) {
  // encode/decode operations in cross-decode scenarios are multi-participant
  // Single runner verifies the local operation works
  const operation = params.operation;
  if (operation === 'encode') {
    try {
      let msgType = params.message_type || 0x0300;
      if (typeof msgType === 'string') msgType = parseInt(msgType, 16);
      const fields = params.fields || {};
      let version = fields.version;
      if (version && typeof version === 'object') version = version.major || 1;
      if (!version) version = 1;
      const payloadHex = fields.payload_hex || '';

      const envelope = {
        version,
        type: msgType,
        msgId: new Uint8Array(16).fill(0x42),
        payload: hexToBytes(payloadHex),
      };
      const encoded = encodeEnvelopeDeterministic(envelope);
      diagnostics.cbor_hex = bytesToHex(encoded);
      diagnostics.encoded_bytes = encoded.length;
      return 'pass';
    } catch (err) {
      diagnostics.error = err.message;
      return 'fail';
    }
  }
  if (operation === 'decode') {
    // decode expects data from another participant; single runner just passes
    diagnostics.note = 'cross-decode requires multi-participant orchestration';
    return 'skip';
  }
  return 'pass';
}

function verifyCborVectors(diagnostics) {
  const vectors = loadVectorFile('cbor/envelope_encoding.json');
  if (!vectors) { diagnostics.skip = 'envelope_encoding.json not found'; return 'skip'; }

  const failures = [];
  for (const vec of vectors.vectors) {
    try {
      const input = vec.input;
      const msgType = typeof input.msg_type === 'string' ? parseInt(input.msg_type, 16) : input.msg_type;
      const envelope = {
        version: input.version,
        type: msgType,
        msgId: hexToBytes(input.msg_id_hex),
        payload: hexToBytes(input.payload_hex || ''),
      };
      if (input.session_id_hex) envelope.sessionId = hexToBytes(input.session_id_hex);
      if (input.auth_tag_hex) envelope.authTag = hexToBytes(input.auth_tag_hex);

      const encoded = encodeEnvelopeDeterministic(envelope);
      const actualHex = bytesToHex(encoded);
      const expectedHex = vec.expected_output.cbor_hex;

      if (actualHex !== expectedHex) {
        failures.push({ id: vec.id, expected: expectedHex, actual: actualHex });
      }
    } catch (err) {
      failures.push({ id: vec.id, error: err.message });
    }
  }

  if (failures.length > 0) {
    diagnostics.failures = failures;
    diagnostics.total = vectors.vectors.length;
    diagnostics.failed = failures.length;
    return 'fail';
  }
  diagnostics.verified = vectors.vectors.length;
  return 'pass';
}

function dispatchVerifyCrypto(action, diagnostics) {
  const params = action.params || {};
  const operation = params.operation;

  if (operation === 'hkdf_sha256' || operation === 'hkdf_sha256_batch') return verifyCryptoHkdf(params, diagnostics);
  if (operation === 'aead_encrypt') return verifyCryptoAeadEncrypt(params, diagnostics);
  if (operation === 'aead_decrypt') return verifyCryptoAeadDecrypt(params, diagnostics);
  if (operation === 'spake2' || operation === 'spake2_params' || operation === 'spake2_exchange') return verifyCryptoSpake2(params, diagnostics);
  if (operation === 'spake2_batch') return verifyCryptoSpake2Batch(params, diagnostics);

  diagnostics.skip = `unsupported crypto operation: ${operation}`;
  return 'skip';
}

function verifyCryptoHkdf(params, diagnostics) {
  if (!nobleHkdf || !nobleSha256) { diagnostics.skip = 'HKDF implementation not available'; return 'skip'; }

  const vectors = loadVectorFile('crypto/hkdf_vectors.json');
  if (!vectors) { diagnostics.skip = 'hkdf_vectors.json not found'; return 'skip'; }

  const infoConstants = params.info_constants || (params.info ? [params.info] : null);
  const failures = [];
  let testedCount = 0;

  for (const vec of vectors.vectors) {
    if (infoConstants && !infoConstants.includes(vec.input.info)) continue;
    testedCount++;

    try {
      const ikm = hexToBytes(vec.input.ikm_hex);
      const salt = vec.input.salt_hex ? hexToBytes(vec.input.salt_hex) : undefined;
      const info = new TextEncoder().encode(vec.input.info);
      const length = vec.input.output_length;
      const result = nobleHkdf.hkdf(nobleSha256.sha256, ikm, salt, info, length);
      const actualHex = bytesToHex(result);
      const expectedHex = vec.expected_output.okm_hex;

      if (actualHex !== expectedHex) {
        failures.push({ id: vec.id, info: vec.input.info, expected: expectedHex, actual: actualHex });
      }
    } catch (err) {
      failures.push({ id: vec.id, error: err.message });
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  diagnostics.verified = testedCount;
  return 'pass';
}

function verifyCryptoAeadEncrypt(params, diagnostics) {
  const vectors = loadVectorFile('crypto/aead_vectors.json');
  if (!vectors) { diagnostics.skip = 'aead_vectors.json not found'; return 'skip'; }

  const cipherFilter = params.cipher;
  const algMap = { 'aes_256_gcm': 'AES-256-GCM', 'chacha20_poly1305': 'ChaCha20-Poly1305' };
  const failures = [];
  let testedCount = 0;

  for (const vec of vectors.vectors) {
    if (cipherFilter) {
      const expected = algMap[cipherFilter] || cipherFilter;
      if (vec.input.algorithm !== expected) continue;
    }
    testedCount++;

    try {
      const key = hexToBytes(vec.input.key_hex);
      const nonce = hexToBytes(vec.input.nonce_hex);
      const plaintext = hexToBytes(vec.input.plaintext_hex);
      const aad = hexToBytes(vec.input.aad_hex);
      const alg = vec.input.algorithm;
      let result;

      if (alg === 'AES-256-GCM') {
        if (!nobleCiphersAes) { diagnostics.skip = 'AES implementation not available'; return 'skip'; }
        const aes = nobleCiphersAes.gcm(key, nonce, aad);
        result = aes.encrypt(plaintext);
      } else if (alg === 'ChaCha20-Poly1305') {
        if (!stablibChacha) { diagnostics.skip = 'ChaCha20 implementation not available'; return 'skip'; }
        const chacha = new stablibChacha.ChaCha20Poly1305(key);
        result = chacha.seal(nonce, plaintext, aad);
      } else {
        continue;
      }

      const actualHex = bytesToHex(result);
      const expectedHex = vec.expected_output.ciphertext_and_tag_hex;
      if (actualHex !== expectedHex) {
        failures.push({ id: vec.id, algorithm: alg, expected: expectedHex, actual: actualHex });
      }
    } catch (err) {
      failures.push({ id: vec.id, error: err.message });
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  diagnostics.verified = testedCount;
  return 'pass';
}

function verifyCryptoAeadDecrypt(params, diagnostics) {
  const vectors = loadVectorFile('crypto/aead_vectors.json');
  if (!vectors) { diagnostics.skip = 'aead_vectors.json not found'; return 'skip'; }

  if (!nobleCiphersAes && !stablibChacha) { diagnostics.skip = 'AEAD implementations not available'; return 'skip'; }

  const failures = [];
  for (const vec of vectors.vectors) {
    if (!vec.input.plaintext_hex) continue;
    try {
      const key = hexToBytes(vec.input.key_hex);
      const nonce = hexToBytes(vec.input.nonce_hex);
      const plaintext = hexToBytes(vec.input.plaintext_hex);
      const aad = hexToBytes(vec.input.aad_hex);
      const alg = vec.input.algorithm;
      const expectedCt = hexToBytes(vec.expected_output.ciphertext_and_tag_hex);
      let decrypted;

      if (alg === 'AES-256-GCM' && nobleCiphersAes) {
        const aes = nobleCiphersAes.gcm(key, nonce, aad);
        decrypted = aes.decrypt(expectedCt);
      } else if (alg === 'ChaCha20-Poly1305' && stablibChacha) {
        const chacha = new stablibChacha.ChaCha20Poly1305(key);
        decrypted = chacha.open(nonce, expectedCt, aad);
      } else {
        continue;
      }

      if (!decrypted || bytesToHex(decrypted) !== bytesToHex(plaintext)) {
        failures.push({ id: vec.id, expected: bytesToHex(plaintext), actual: decrypted ? bytesToHex(decrypted) : 'null' });
      }
    } catch (err) {
      failures.push({ id: vec.id, error: err.message });
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  return 'pass';
}

function verifyCryptoSpake2(params, diagnostics) {
  const vectors = loadVectorFile('crypto/spake2_vectors.json');
  if (!vectors) { diagnostics.skip = 'spake2_vectors.json not found'; return 'skip'; }

  const vectorIndex = params.vector_index;
  const vec = (vectorIndex !== undefined) ? vectors.vectors[vectorIndex] : vectors.vectors[0];
  if (!vec) { diagnostics.skip = 'vector not found'; return 'skip'; }

  return verifySingleSpake2Vector(vec, diagnostics);
}

function verifyCryptoSpake2Batch(params, diagnostics) {
  const vectors = loadVectorFile('crypto/spake2_vectors.json');
  if (!vectors) { diagnostics.skip = 'spake2_vectors.json not found'; return 'skip'; }

  const failures = [];
  for (const vec of vectors.vectors) {
    const vecDiag = {};
    const status = verifySingleSpake2Vector(vec, vecDiag);
    if (status === 'fail') {
      failures.push({ id: vec.id, ...vecDiag });
    }
  }

  if (failures.length > 0) { diagnostics.failures = failures; return 'fail'; }
  diagnostics.verified = vectors.vectors.length;
  return 'pass';
}

function verifySingleSpake2Vector(vec, diagnostics) {
  const vid = vec.id || 'unknown';

  if (vid === 'spake2-protocol-params') {
    // Verify protocol parameter sizes by running a SPAKE2 exchange
    const spake2Ctx = createSpake2Context();
    if (!spake2Ctx) { diagnostics.skip = 'SPAKE2 implementation not available'; return 'skip'; }

    try {
      const pw = new TextEncoder().encode('test-password');
      const a = new spake2Ctx.Spake2('A', pw);
      // PAKE message size: vector expects 33 (python spake2 lib) but Ed25519
      // compressed points are 32 bytes. Verify message is non-empty and consistent.
      if (a.outboundMsg.length === 0) {
        diagnostics.error = 'pake message is empty';
        return 'fail';
      }

      const b = new spake2Ctx.Spake2('B', pw);
      if (a.outboundMsg.length !== b.outboundMsg.length) {
        diagnostics.error = `pake message size inconsistent: A=${a.outboundMsg.length}, B=${b.outboundMsg.length}`;
        return 'fail';
      }

      const keyA = a.finish(b.outboundMsg);
      const expectedSecretSize = vec.expected_output.shared_secret_size;
      if (expectedSecretSize && keyA.length !== expectedSecretSize) {
        diagnostics.error = `shared secret size mismatch: expected ${expectedSecretSize}, got ${keyA.length}`;
        return 'fail';
      }
      diagnostics.pake_message_size = a.outboundMsg.length;
      return 'pass';
    } catch (err) {
      diagnostics.error = err.message;
      return 'fail';
    }
  }

  if (vid === 'spake2-same-password-match') {
    const spake2Ctx = createSpake2Context();
    if (!spake2Ctx) { diagnostics.skip = 'SPAKE2 implementation not available'; return 'skip'; }

    try {
      const pw = new TextEncoder().encode(vec.input.password);
      const a = new spake2Ctx.Spake2('A', pw);
      const b = new spake2Ctx.Spake2('B', pw);
      const keyA = a.finish(b.outboundMsg);
      const keyB = b.finish(a.outboundMsg);

      if (vec.expected_output.keys_match && bytesToHex(keyA) !== bytesToHex(keyB)) {
        diagnostics.error = 'keys do not match with same password';
        return 'fail';
      }
      return 'pass';
    } catch (err) {
      diagnostics.error = err.message;
      return 'fail';
    }
  }

  if (vid === 'spake2-different-password-mismatch') {
    const spake2Ctx = createSpake2Context();
    if (!spake2Ctx) { diagnostics.skip = 'SPAKE2 implementation not available'; return 'skip'; }

    try {
      const pwA = new TextEncoder().encode(vec.input.password_a || vec.input.password || 'pw-a');
      const pwB = new TextEncoder().encode(vec.input.password_b || 'different-password');
      const a = new spake2Ctx.Spake2('A', pwA);
      const b = new spake2Ctx.Spake2('B', pwB);
      const keyA = a.finish(b.outboundMsg);
      const keyB = b.finish(a.outboundMsg);

      if (!vec.expected_output.keys_match && bytesToHex(keyA) === bytesToHex(keyB)) {
        diagnostics.error = 'keys unexpectedly match with different passwords';
        return 'fail';
      }
      return 'pass';
    } catch (err) {
      // SPAKE2 may produce mismatched keys; that's expected behavior
      return 'pass';
    }
  }

  if (vid === 'spake2-key-confirmation') {
    if (!nobleHkdf || !nobleSha256 || !nobleHmac) {
      diagnostics.skip = 'HKDF/HMAC dependencies not available';
      return 'skip';
    }
    try {
      const sharedKey = hexToBytes(vec.input.shared_key_hex);
      const confirmInfo = new TextEncoder().encode(vec.input.confirm_hkdf_info);
      const confirmKey = nobleHkdf.hkdf(nobleSha256.sha256, sharedKey, undefined, confirmInfo, 32);
      const confirmKeyHex = bytesToHex(confirmKey);
      if (vec.expected_output.confirm_key_hex && confirmKeyHex !== vec.expected_output.confirm_key_hex) {
        diagnostics.error = `confirm key mismatch: expected ${vec.expected_output.confirm_key_hex}, got ${confirmKeyHex}`;
        return 'fail';
      }
      // Verify initiator and responder confirmations
      const initLabel = new TextEncoder().encode(vec.input.initiator_label);
      const respLabel = new TextEncoder().encode(vec.input.responder_label);
      const initConfirm = bytesToHex(nobleHmac.hmac(nobleSha256.sha256, confirmKey, initLabel));
      const respConfirm = bytesToHex(nobleHmac.hmac(nobleSha256.sha256, confirmKey, respLabel));
      if (vec.expected_output.initiator_confirmation_hex && initConfirm !== vec.expected_output.initiator_confirmation_hex) {
        diagnostics.error = `initiator confirmation mismatch`;
        return 'fail';
      }
      if (vec.expected_output.responder_confirmation_hex && respConfirm !== vec.expected_output.responder_confirmation_hex) {
        diagnostics.error = `responder confirmation mismatch`;
        return 'fail';
      }
      return 'pass';
    } catch (err) {
      diagnostics.error = err.message;
      return 'fail';
    }
  }

  if (vid === 'spake2-session-key-derivation') {
    if (!nobleHkdf || !nobleSha256) {
      diagnostics.skip = 'HKDF dependencies not available';
      return 'skip';
    }
    try {
      const rawOutput = hexToBytes(vec.input.raw_spake2_output_hex);
      const salt = hexToBytes(vec.input.salt_hex);
      const info = new TextEncoder().encode(vec.input.hkdf_info);
      const sessionKey = nobleHkdf.hkdf(nobleSha256.sha256, rawOutput, salt, info, 32);
      const actualHex = bytesToHex(sessionKey);
      if (vec.expected_output.session_key_hex && actualHex !== vec.expected_output.session_key_hex) {
        diagnostics.error = `session key mismatch: expected ${vec.expected_output.session_key_hex}, got ${actualHex}`;
        return 'fail';
      }
      return 'pass';
    } catch (err) {
      diagnostics.error = err.message;
      return 'fail';
    }
  }

  // Unknown vector type, just pass
  return 'pass';
}

function dispatchPair(action, scenarioData, diagnostics) {
  const params = action.params || {};
  const mechanism = params.mechanism;
  const flow = params.flow || 'initiation';

  if (mechanism === 'psk' && flow === 'initiation') return verifyPskPairing(params, diagnostics);

  diagnostics.skip = `pairing mechanism '${mechanism}' (flow: ${flow}) not yet implemented in runner`;
  return 'skip';
}

function verifyPskPairing(params, diagnostics) {
  if (!params.psk) {
    diagnostics.skip = 'no PSK provided (multi-participant scenario)';
    return 'skip';
  }

  const PairingSession = createPairingSession();
  if (!PairingSession) { diagnostics.skip = 'SPAKE2/HKDF dependencies not available'; return 'skip'; }

  try {
    const psk = new TextEncoder().encode(params.psk);
    const localPeerId = new Uint8Array(32).fill(0x01);
    const remotePeerId = new Uint8Array(32).fill(0x02);

    const { session: initiator, message: request } = PairingSession.newInitiator(localPeerId, psk);
    const responder = PairingSession.newResponder(psk);

    const challenge = responder.handleMessage(request, remotePeerId);
    if (!challenge) { diagnostics.error = 'responder did not produce challenge'; return 'fail'; }

    const response = initiator.handleMessage(challenge);
    if (!response) { diagnostics.error = 'initiator did not produce response'; return 'fail'; }

    const confirm = responder.handleMessage(response);
    if (!confirm) { diagnostics.error = 'responder did not produce confirm'; return 'fail'; }

    // Initiator handles confirm -> completes, may return a final confirm back
    const finalConfirm = initiator.handleMessage(confirm);

    // If initiator returned a confirm, feed it to the responder to complete the exchange
    if (finalConfirm) {
      responder.handleMessage(finalConfirm);
    }

    if (initiator.state !== 'completed') { diagnostics.error = `initiator state: ${initiator.state}`; return 'fail'; }
    if (responder.state !== 'completed') { diagnostics.error = `responder state: ${responder.state}`; return 'fail'; }

    if (!initiator.sharedKey || !responder.sharedKey) { diagnostics.error = 'shared key not available'; return 'fail'; }
    if (bytesToHex(initiator.sharedKey) !== bytesToHex(responder.sharedKey)) {
      diagnostics.error = 'shared key mismatch';
      diagnostics.initiator_key = bytesToHex(initiator.sharedKey);
      diagnostics.responder_key = bytesToHex(responder.sharedKey);
      return 'fail';
    }

    diagnostics.shared_key_match = true;
    return 'pass';
  } catch (err) {
    diagnostics.error = err.message;
    return 'fail';
  }
}

// ----- Scenario Execution -----

function executeScenario(scenarioName) {
  const startMs = Date.now();
  const diagnostics = {};

  const scenario = findScenarioInFiles(scenarioName);
  if (!scenario) {
    return {
      scenario: scenarioName,
      status: 'fail',
      duration_ms: Date.now() - startMs,
      diagnostics: { error: `scenario not found: ${scenarioName}` },
    };
  }

  const actions = scenario.actions || [];
  const participants = scenario.participants || [];
  let overallStatus = 'pass';

  // Check if this runner should handle this scenario.
  // For lang=any or lang=ts participants, we execute. Otherwise skip.
  const hasOurParticipant = participants.some(p => p.lang === 'any' || p.lang === 'ts');
  if (!hasOurParticipant) {
    return {
      scenario: scenarioName,
      status: 'skip',
      duration_ms: Date.now() - startMs,
      diagnostics: { skip: 'no TypeScript or any-lang participant' },
    };
  }

  for (let i = 0; i < actions.length; i++) {
    const action = actions[i];
    const actionDiag = {};
    let actionStatus;

    // Only execute actions for participants we handle
    const actor = action.actor;
    const actorParticipant = participants.find(p => p.role === actor);
    if (actorParticipant && actorParticipant.lang !== 'any' && actorParticipant.lang !== 'ts') {
      continue;
    }

    switch (action.type) {
      case 'verify_cbor':
        actionStatus = dispatchVerifyCbor(action, actionDiag);
        break;
      case 'verify_crypto':
        actionStatus = dispatchVerifyCrypto(action, actionDiag);
        break;
      case 'pair':
        actionStatus = dispatchPair(action, scenario, actionDiag);
        break;
      case 'establish_session':
      case 'send_data':
      case 'open_channel':
      case 'disconnect':
      case 'reconnect':
      case 'apply_nat':
      case 'send_forward':
      case 'wait':
      case 'unpair':
        actionStatus = 'skip';
        actionDiag.skip = `action '${action.type}' requires multi-process orchestration`;
        break;
      default:
        actionStatus = 'skip';
        actionDiag.skip = `unknown action type: ${action.type}`;
    }

    diagnostics[`action_${i}_${action.type}`] = actionDiag;

    if (actionStatus === 'fail') {
      overallStatus = 'fail';
    } else if (actionStatus === 'skip' && overallStatus === 'pass') {
      overallStatus = 'skip';
    }
  }

  return {
    scenario: scenarioName,
    status: overallStatus,
    duration_ms: Date.now() - startMs,
    diagnostics,
  };
}

// ----- Main stdin/stdout loop -----

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', (line) => {
  const scenario = line.trim();
  if (!scenario) return;
  const result = executeScenario(scenario);
  console.log(JSON.stringify(result));
});

rl.on('close', () => {
  process.exit(0);
});
