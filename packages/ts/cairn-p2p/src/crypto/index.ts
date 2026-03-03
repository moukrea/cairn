// Crypto module — Ed25519, X25519, HKDF, AEAD, Noise XX, SPAKE2, SAS, Double Ratchet (tasks 030-032)

export { IdentityKeypair, peerIdFromPublicKey, verifySignature } from './identity.js';
export { X25519Keypair } from './exchange.js';
export {
  hkdfSha256,
  HKDF_INFO_SESSION_KEY,
  HKDF_INFO_RENDEZVOUS,
  HKDF_INFO_SAS,
  HKDF_INFO_CHAIN_KEY,
  HKDF_INFO_MESSAGE_KEY,
} from './hkdf.js';
export { aeadEncrypt, aeadDecrypt, NONCE_SIZE, KEY_SIZE, TAG_SIZE } from './aead.js';
export type { Role, HandshakeResult, StepOutput } from './noise.js';
export { NoiseXXHandshake } from './noise.js';
export { deriveNumericSas, deriveEmojiSas, EMOJI_TABLE } from './sas.js';
export type { Spake2Role } from './spake2.js';
export { Spake2 } from './spake2.js';
export type { RatchetHeader, RatchetConfig } from './double-ratchet.js';
export { DoubleRatchet } from './double-ratchet.js';
