# Cryptographic Test Vectors

All fixtures are CBOR-encoded for consistency with the cairn wire protocol.
Binary `.cbor` files will be generated from the Rust reference implementation.

## Files

| File | Contents |
|------|----------|
| `ed25519-vectors.cbor` | Test Ed25519 keypairs with known signatures for test messages |
| `x25519-vectors.cbor` | Test X25519 keypairs with known DH shared secrets |
| `spake2-vectors.cbor` | Password, identity strings, expected shared secret for SPAKE2 |
| `hkdf-vectors.cbor` | IKM, salt, info, expected output for HKDF-SHA256 |
| `aead-vectors.cbor` | Key, nonce, plaintext, AAD, expected ciphertext+tag for AES-256-GCM and ChaCha20-Poly1305 |

## Vector Format (CBOR structure)

### ed25519-vectors.cbor
```
[
  {
    "secret_key": bytes(32),
    "public_key": bytes(32),
    "message": bytes,
    "signature": bytes(64)
  },
  ...
]
```

### x25519-vectors.cbor
```
[
  {
    "private_key_a": bytes(32),
    "public_key_a": bytes(32),
    "private_key_b": bytes(32),
    "public_key_b": bytes(32),
    "shared_secret": bytes(32)
  },
  ...
]
```

### spake2-vectors.cbor
```
[
  {
    "password": bytes,
    "identity_a": bytes,
    "identity_b": bytes,
    "expected_shared_secret": bytes(32)
  },
  ...
]
```

### hkdf-vectors.cbor
```
[
  {
    "ikm": bytes,
    "salt": bytes | null,
    "info": bytes,
    "output_length": uint,
    "expected_output": bytes
  },
  ...
]
```

### aead-vectors.cbor
```
[
  {
    "cipher": "aes_256_gcm" | "chacha20_poly1305",
    "key": bytes(32),
    "nonce": bytes(12),
    "plaintext": bytes,
    "aad": bytes,
    "ciphertext_with_tag": bytes
  },
  ...
]
```
