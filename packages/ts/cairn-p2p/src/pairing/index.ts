// Pairing module — mechanisms, state machine (tasks 033-034)

export type { PairingPayload, ConnectionHint } from './payload.js';
export { encodePairingPayload, decodePairingPayload, isPayloadExpired, generateNonce } from './payload.js';

export {
  generatePin,
  formatPin,
  normalizePin,
  validatePin,
  derivePinRendezvousId,
  decodeCrockford,
} from './pin.js';

export { generateQrPayload, consumeQrPayload, QR_DEFAULT_TTL_MS, MAX_QR_PAYLOAD_SIZE } from './qr.js';

export { generatePairingLink, parsePairingLink } from './link.js';

export { validatePskEntropy, derivePskRendezvousId, pskToPakeInput } from './psk.js';

export type {
  PairingFlowType,
  PairingState,
  PairingRole,
  PairRejectReason,
  PairingMessage,
} from './state-machine.js';
export { PairingSession, DEFAULT_PAIRING_TIMEOUT_MS } from './state-machine.js';

export type { SasType, SasResult } from './sas-flow.js';
export { deriveSas, verifySas } from './sas-flow.js';

export type { PairingMechanismAdapter } from './adapter.js';
export { CustomPairingMechanism } from './adapter.js';

export type { RateLimitResult } from './rate-limit.js';
export { PairingRateLimiter } from './rate-limit.js';

export type { UnpairingEvent } from './unpairing.js';
export { unpair, handlePairRevoke } from './unpairing.js';
