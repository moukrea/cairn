# Pairing Test Fixtures

Known-good pairing payloads for cross-language conformance testing.

## QR Code Payloads

`qr-payload-*.cbor` — Binary CBOR payloads for QR code mechanism.
Each file is raw CBOR bytes, max 256 bytes, containing:
- Peer ID (34-byte multihash)
- Nonce (32 bytes)
- PAKE commitment
- Discovery hints

## PIN Codes

`pin-vectors.json` — PIN code test vectors:
```json
{
  "vectors": [
    {
      "pin": "ABCD-EF01",
      "normalized": "ABCD-EF01",
      "pake_input": "<hex bytes>",
      "expected_shared_secret": "<hex bytes>"
    },
    {
      "pin": "aBcD-eF0l",
      "normalized": "ABCD-EF01",
      "comment": "i/l->1, o->0 normalization, case insensitive"
    }
  ]
}
```

## Pairing Links

`link-vectors.json` — Pairing link URI test vectors:
```json
{
  "vectors": [
    {
      "uri": "cairn://pair?pid=<base58>&nonce=<hex>&pake=<hex>&hints=mdns,dht",
      "parsed": {
        "peer_id": "<base58>",
        "nonce": "<hex>",
        "pake_commitment": "<hex>",
        "hints": ["mdns", "dht"]
      }
    }
  ]
}
```

## PSK Values

`psk-vectors.json` — Pre-shared key test vectors with minimum 128-bit entropy.
