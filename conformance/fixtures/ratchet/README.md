# Double Ratchet Test Vectors

CBOR-encoded ratchet state snapshots for cross-language conformance testing.

## ratchet-vectors.cbor

```
{
  "initial_state": {
    "root_key": bytes(32),
    "sender_dh_private": bytes(32),
    "sender_dh_public": bytes(32),
    "receiver_dh_public": bytes(32),
    "cipher": "aes_256_gcm",
    "max_skip": 100
  },
  "messages": [
    {
      "index": 0,
      "plaintext": bytes,
      "expected_header": {
        "dh_public": bytes(32),
        "prev_chain_len": uint,
        "msg_num": uint
      },
      "expected_ciphertext": bytes
    },
    ...
  ]
}
```

## Usage

1. Initialize Double Ratchet with `initial_state` values
2. For each message in `messages`:
   - Encrypt the plaintext
   - Verify the header matches `expected_header`
   - Verify the ciphertext matches `expected_ciphertext`
3. Nonce construction: `message_key[0..8]` + `msg_num` as big-endian u32 (12 bytes)
4. AAD: `RatchetHeader` serialized as JSON
