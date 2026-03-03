# CBOR Byte Sequence Fixtures

Known-good CBOR envelope byte sequences for every message type in the registry.
Each `.cbor` file contains the exact binary CBOR encoding.

## Message Type Registry

| Range | Category | Example Types |
|-------|----------|---------------|
| `0x01xx` | Handshake | NoiseInit, NoiseResponse, NoiseFinalize |
| `0x02xx` | Pairing | PairRequest, PairCommit, PairConfirm, PairReject, PairRevoke |
| `0x03xx` | Data | DataMessage, DataAck, DataNack |
| `0x04xx` | Session | SessionInit, SessionResume, Heartbeat |
| `0x05xx` | Discovery | RendezvousAnnounce, RendezvousQuery |
| `0x06xx` | Mesh | MeshRouteRequest, MeshRouteResponse, MeshData |
| `0x07xx` | Forward | ForwardRequest, ForwardAck, ForwardDeliver, ForwardPurge |

## File Naming

`<message_type_hex>.cbor` — e.g., `0100.cbor` for HandshakeInit

## Verification

All implementations must:
1. Decode each fixture and extract correct field values
2. Re-encode the same logical message and produce byte-identical output
   (when deterministic encoding is required per RFC 8949 section 4.2)
