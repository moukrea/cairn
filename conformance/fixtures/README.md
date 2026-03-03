# Conformance Test Fixtures

Shared test data for cross-language conformance testing. All fixtures are CBOR-encoded
for consistency with the cairn wire protocol.

## Directory Structure

```
fixtures/
├── cbor/           Known-good CBOR byte sequences for every message type
├── keys/           Cryptographic test vectors (Ed25519, X25519, SPAKE2, HKDF, AEAD)
├── ratchet/        Double Ratchet state vectors
└── pairing/        Pairing payload fixtures (QR, PIN, link, PSK)
```

## CBOR Byte Sequences (`cbor/`)

Each file contains a binary CBOR envelope. All implementations must:
- Decode each fixture and extract correct field values
- Re-encode the same logical message and produce byte-identical output
  (when deterministic encoding is required)

## Cryptographic Test Vectors (`keys/`)

| File | Contents |
|------|----------|
| `ed25519-vectors.cbor` | Test keypairs with known signatures |
| `x25519-vectors.cbor` | Test keypairs with known DH shared secrets |
| `spake2-vectors.cbor` | Password, identities, expected shared secret |
| `hkdf-vectors.cbor` | IKM, salt, info, expected output |
| `aead-vectors.cbor` | Key, nonce, plaintext, AAD, expected ciphertext+tag |

## Double Ratchet Vectors (`ratchet/`)

| File | Contents |
|------|----------|
| `ratchet-vectors.cbor` | Initial root key, DH keypairs, message sequence, expected ciphertext |

## Pairing Fixtures (`pairing/`)

- QR code payloads (raw CBOR bytes, max 256 bytes)
- PIN codes (Crockford Base32 strings with expected PAKE credentials)
- Pairing link URIs
- PSK values (128-bit minimum entropy)
