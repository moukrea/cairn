# SESSION_RESUME Implementation Plan

## Architecture Overview

Session resumption allows two cairn peers to restore an encrypted session after
a transport disruption (network drop, page refresh, process restart) without a
full Noise XX handshake. The ratchet state, sequence counters, and session
identity survive the disruption. This avoids the 2-round-trip, 3-message Noise
handshake and immediately resumes encrypted communication.

### Flow Diagram

```
  Initiator (reconnecting)                  Responder (accepting)
  ─────────────────────────                 ─────────────────────
  1. Detect ConnectionClosed
  2. Load saved session for remote peer
  3. Transition: Disconnected → Reconnecting
  4. Exponential backoff dial loop
  5. Dial succeeds
  6. Build SESSION_RESUME envelope          →
     (session_id, HMAC proof,
      last_rx_seq, nonce, timestamp)
                                            7. Lookup session by ID
                                            8. Validate expiry (< 24h)
                                            9. Verify HMAC proof
                                           10. Check nonce not replayed
                                           11. Build SESSION_RESUME_ACK   →
                                               (last_rx_seq)
  12. Receive ACK
  13. Both sides:
      - Advance ratchet epoch
      - Perform DH ratchet step (fresh keys)
      - Retransmit queued msgs > peer's last_rx
      - Transition: Reconnecting → Reconnected → Connected

  On failure (expired, bad proof, unknown session):
  14. Responder sends SESSION_EXPIRED
  15. Initiator falls back to full Noise XX handshake
```

---

## Phase 1: Session State Persistence (Rust)

### Goal
Save enough state after handshake completion so a node can resume the session
after restart, and reload it on startup.

### Serialization Format

A new `SavedSession` struct, serialized as JSON then stored via the KeyStore:

```rust
// session/persistence.rs
#[derive(Serialize, Deserialize)]
pub struct SavedSession {
    pub session_id: [u8; 16],          // UUID v7 bytes
    pub remote_libp2p_peer_id: String, // libp2p PeerId string (multiformat)
    pub remote_cairn_peer_id: [u8; 32],// SHA-256(remote Ed25519 public key)
    pub ratchet_state: Vec<u8>,        // DoubleRatchet.export_state() output
    pub sequence_tx: u64,
    pub sequence_rx: u64,
    pub ratchet_epoch: u32,
    pub created_at_unix: u64,          // SystemTime as unix secs
    pub last_activity_unix: u64,
    pub expiry_secs: u64,              // default 86400 (24h)
}
```

**Storage key convention**: `session:<remote_libp2p_peer_id>` in the keystore.

### New File: `session/persistence.rs`

Functions:

1. `save_session(keystore, saved: &SavedSession) -> Result<()>`
   - Serializes `SavedSession` to JSON, stores at `session:<peer_id>`.

2. `load_session(keystore, remote_peer_id: &str) -> Result<Option<SavedSession>>`
   - Retrieves from keystore, deserializes. Returns `None` if key missing.
   - Validates `created_at_unix + expiry_secs > now`. Returns `None` if expired
     (and deletes the stale entry).

3. `delete_session(keystore, remote_peer_id: &str) -> Result<()>`

4. `list_saved_sessions(keystore) -> Result<Vec<SavedSession>>`
   - The KeyStore trait does not have a `list_keys` method. Two options:
     a. Add `list_keys(&self, prefix: &str)` to the KeyStore trait (breaking change).
     b. Store a separate index key `session:_index` containing a JSON array of
        peer ID strings.
   - **Decision**: Option (b) — avoids breaking the KeyStore trait. The index is
     updated on save/delete. On load, stale entries are pruned.

### Changes to `api/node.rs`

**After handshake completion** (both `connect_transport` initiator path at ~line 896
and inbound responder path at ~line 338):

```rust
// After creating the ratchet and session:
let saved = SavedSession {
    session_id: *session_id.as_bytes(),
    remote_libp2p_peer_id: remote_str.clone(),
    remote_cairn_peer_id: /* from handshake result remote_static */,
    ratchet_state: ratchet.export_state(),
    sequence_tx: 0,
    sequence_rx: 0,
    ratchet_epoch: 0,
    created_at_unix: now_unix(),
    last_activity_unix: now_unix(),
    expiry_secs: 86400,
};
if let Some(ref ks) = self.keystore {
    persistence::save_session(ks.as_ref(), &saved).await.ok();
}
```

**On node startup** (new method `load_saved_sessions`):
- Called from `start_transport()` after the swarm is built.
- Loads all saved sessions from the keystore index.
- For each non-expired session: restores `DoubleRatchet` via `import_state`,
  creates an `ApiSession` in `Disconnected` state (no swarm wiring yet —
  transport wiring happens on successful resume).
- Stores them in `self.sessions` keyed by remote peer ID.

**ApiNode needs a new field**:
```rust
keystore: Option<Arc<dyn KeyStore>>,
```
Populated from config (`CairnConfig` already has `storage_backend`).

### Test Plan (Phase 1)
- Unit: `SavedSession` serde roundtrip
- Unit: Save + load + delete via InMemoryKeyStore
- Unit: Expired session returns `None` from `load_session`
- Unit: Index maintained correctly across save/delete
- Integration: Two nodes handshake, save, drop sessions, reload from keystore,
  verify ratchet state bytes match

---

## Phase 2: SESSION_RESUME Protocol (Rust)

### Goal
Implement the wire-level resume protocol: message encoding, proof generation,
proof verification, and the send/receive flow.

### Proof Mechanism

HMAC-SHA256 over a canonical input, using the current root key from the ratchet
as the HMAC key:

```
proof = HMAC-SHA256(root_key, nonce || timestamp_be8 || session_id)
```

- `root_key`: Extracted from `RatchetState` via a new accessor.
  **Problem**: `RatchetState.root_key` is private. Options:
  a. Add `pub fn root_key(&self) -> &[u8; 32]` to `DoubleRatchet`.
  b. Derive a separate "session resumption key" from the root key via HKDF.
  - **Decision**: Option (b) — never expose the root key directly. Add
    `pub fn derive_resumption_key(&self) -> [u8; 32]` that returns
    `HKDF-SHA256(root_key, info="cairn-session-resume-v1")`. This also means
    the resumption key changes with each DH ratchet step, providing forward
    secrecy for the proof.
- `nonce`: 32 random bytes, generated fresh for each resume attempt.
- `timestamp`: Unix seconds as 8-byte big-endian.
- `session_id`: 16 bytes (UUID v7).

### Payload Encoding (CBOR)

SESSION_RESUME payload (msg_type 0x0200):
```cbor
{
  0: h'<session_id 16 bytes>',
  1: h'<proof 32 bytes>',
  2: <last_rx_sequence uint64>,
  3: <timestamp uint64>,
  4: h'<nonce 32 bytes>'
}
```

SESSION_RESUME_ACK payload (msg_type 0x0201):
```cbor
{
  0: <last_rx_sequence uint64>
}
```

SESSION_EXPIRED payload (msg_type 0x0202):
```cbor
{
  0: <reason_code uint8>   // 1=expired, 2=not_found, 3=invalid_proof, 4=replay
}
```

### Changes to `session/reconnection.rs`

Extend with:

1. **ChallengeProof** — change from signature-based to HMAC-based:
   ```rust
   pub struct ResumeProof {
       pub hmac: [u8; 32],
       pub nonce: [u8; 32],
       pub timestamp: u64,
   }
   ```

2. **`generate_resume_proof(resumption_key, session_id, nonce, timestamp) -> ResumeProof`**

3. **`verify_resume_proof(resumption_key, session_id, proof) -> bool`**

4. **`encode_session_resume(session_id, proof, last_rx_seq) -> Vec<u8>`** — CBOR encode

5. **`decode_session_resume(payload) -> Result<(SessionId, ResumeProof, u64)>`** — CBOR decode

6. **`encode_session_resume_ack(last_rx_seq) -> Vec<u8>`**

7. **`decode_session_resume_ack(payload) -> Result<u64>`**

8. **Nonce tracking** — `NonceCache` with a bounded `HashSet<[u8; 32]>` plus
   a timestamp window (reject timestamps older than 5 minutes). This prevents
   replay of captured SESSION_RESUME messages.

### Changes to `crypto/ratchet.rs`

Add to `DoubleRatchet`:
```rust
pub fn derive_resumption_key(&self) -> Result<[u8; 32]> {
    let mut output = [0u8; 32];
    exchange::hkdf_sha256(
        &self.state.root_key,
        None,
        b"cairn-session-resume-v1",
        &mut output,
    )?;
    Ok(output)
}
```

### Changes to `api/node.rs`

**Initiator side** (in `connect_transport` or a new `resume_transport`):

Before attempting full handshake, check if a saved session exists for the remote
peer. If so:

1. Load `SavedSession` from keystore.
2. Reconstruct `DoubleRatchet` from saved state.
3. Derive resumption key.
4. Build and send SESSION_RESUME envelope.
5. Wait for response with timeout.
6. On ACK: advance ratchet epoch, retransmit queued messages, transition to Connected.
7. On EXPIRED/reject: delete saved session, fall back to full handshake.

Implementation approach: Add a method `try_resume_transport` that returns
`Result<Option<ApiSession>>`. `connect_transport` calls it first; if it returns
`None`, falls through to the existing handshake path.

**Responder side** (in the event loop):

Add a new match arm in the `RequestReceived` handler:
```rust
Ok(env) if env.msg_type == message_types::SESSION_RESUME => {
    // Decode payload
    // Look up session by session_id in self.sessions
    // If found and not expired:
    //   - Verify HMAC proof using session's resumption key
    //   - Check nonce not replayed
    //   - Send SESSION_RESUME_ACK with our last_rx_seq
    //   - Advance ratchet epoch
    //   - Retransmit queued messages
    //   - Transition to Connected
    // If not found or invalid:
    //   - Send SESSION_EXPIRED with reason code
}
```

### Post-Resume Ratchet Advancement

After resume, both sides must advance the ratchet to get fresh keys:
1. Increment `ratchet_epoch` on the session.
2. Perform a DH ratchet step: both sides generate new X25519 keypairs and
   exchange them in the first message after resume. This happens naturally —
   the first data message after resume will trigger a DH ratchet step since
   the sender generates a new keypair.

   **But**: We need to explicitly trigger a ratchet step on the *responder*
   side too, so both sides have fresh keys even if no message is sent
   immediately. Add `ratchet_step_for_resume()` to `DoubleRatchet` that
   generates a new DH keypair without sending a message — this advances the
   root chain and creates new chain keys.

   **Simpler alternative**: Just increment the epoch counter. The ratchet
   already advances on the next send/receive. The brief window between resume
   and first message uses the old chain keys, which is acceptable since both
   sides just proved possession of the session key.

   **Decision**: Increment epoch only. The Double Ratchet's natural advancement
   provides forward secrecy within one message. Forcing a ratchet step without
   a message exchange is complex and error-prone.

### Test Plan (Phase 2)
- Unit: `generate_resume_proof` / `verify_resume_proof` roundtrip
- Unit: Wrong key → verify fails
- Unit: Replayed nonce rejected by NonceCache
- Unit: Stale timestamp rejected
- Unit: CBOR encode/decode roundtrip for all three message types
- Integration: Two nodes connect, save session, drop transport, reconnect with
  SESSION_RESUME, verify messages flow bidirectionally after resume
- Integration: Expired session → falls back to full handshake

---

## Phase 3: Auto-Reconnect on Transport Loss (Rust)

### Goal
When the libp2p connection drops, automatically attempt session resumption using
exponential backoff.

### Trigger: `ConnectionClosed` Event

Currently the event loop fires `Event::StateChanged { state: Disconnected }` on
`CairnSwarmEvent::ConnectionClosed`. Extend this to:

1. Look up the session for the disconnected peer.
2. Transition session state: `Connected → Disconnected → Reconnecting`.
3. Spawn a reconnection task with the peer's known addresses.

### Reconnection Task

```rust
async fn reconnection_loop(
    node: Arc<ApiNode>,  // or relevant fields
    remote_peer_id: String,
    addrs: Vec<String>,
    backoff: BackoffConfig,
) {
    let mut state = BackoffState::new(backoff);
    loop {
        let delay = state.next_delay();
        tokio::time::sleep(delay).await;

        // Try to dial
        match node.try_resume_transport(&remote_peer_id, &addrs).await {
            Ok(Some(_session)) => {
                // Resume succeeded
                state.reset();
                return;
            }
            Ok(None) => {
                // Resume not possible, try full handshake
                match node.connect_transport(&remote_peer_id, &addrs).await {
                    Ok(_) => return,
                    Err(_) => { /* continue backoff loop */ }
                }
            }
            Err(_) => { /* continue backoff loop */ }
        }

        // Check max duration
        if state.attempt() > 20 {  // or time-based check
            // Transition to Failed
            return;
        }
    }
}
```

### Changes to `api/node.rs`

1. **Store known addresses per peer** — new field on `ApiNode`:
   ```rust
   peer_addresses: Arc<RwLock<HashMap<String, Vec<String>>>>,
   ```
   Populated during `connect_transport` and during inbound connections (from
   the libp2p connection's observed addresses).

2. **ConnectionClosed handler** — instead of just emitting an event, also:
   ```rust
   CairnSwarmEvent::ConnectionClosed { peer_id } => {
       let peer_str = peer_id.to_string();
       // Emit disconnected event (existing)
       // Spawn reconnection task (new)
       if let Some(addrs) = peer_addresses.read().await.get(&peer_str) {
           let addrs = addrs.clone();
           tokio::spawn(reconnection_loop(...));
       }
   }
   ```

3. **Cancellation**: Store `JoinHandle` for each reconnection task so it can be
   cancelled if the user calls `unpair()` or `close()`.

### Changes to `ApiSession`

The session needs to know about its message queue contents for retransmission.
Currently `MessageQueue` is already there. After successful resume:

```rust
let queued = session.message_queue.lock().await.drain();
for msg in queued {
    if msg.sequence > peer_last_rx {
        session.send(&channel, &msg.payload).await?;
    }
}
```

### Test Plan (Phase 3)
- Integration: Two nodes connected, kill transport on one side, verify
  reconnection happens within backoff window
- Integration: Verify messages sent during disconnection are retransmitted
  after resume
- Integration: Verify `unpair()` cancels reconnection task
- Unit: BackoffState sequence matches expected delays (already tested)

---

## Phase 4: Browser Persistence (TypeScript — jaunt web client)

### Goal
After a page refresh, the browser can reconnect to the host without re-pairing,
using the saved session state.

### What to Save (IndexedDB via idb-keyval)

```typescript
// web/src/lib/store.ts — new type
interface SavedCairnSession {
  identitySecret: number[];        // Ed25519 secret key (32 bytes as array)
  hostLibp2pPeerId: string;        // host's libp2p PeerId string
  hostAddrs: string[];             // host's /ws multiaddrs
  sessionId: number[];             // 16 bytes
  ratchetState: number[];          // DoubleRatchet.exportState() as array
  sequenceTx: number;
  sequenceRx: number;
  ratchetEpoch: number;
  createdAt: number;               // unix ms
  hostName: string;                // display name
  profileFragment: string;         // original URL fragment for re-pairing
}
```

Storage key: `cairn-session` in idb-keyval.

### Save Points

In `web/src/lib/cairn.ts`, after `connectToHost` succeeds:

```typescript
export async function saveSessionState(): Promise<void> {
  if (!node || !session) return;
  const identity = node.identity;
  if (!identity) return;

  const saved: SavedCairnSession = {
    identitySecret: Array.from(identity.secretBytes()),
    hostLibp2pPeerId: store.peerId(),
    hostAddrs: /* from profile */,
    sessionId: /* from session */,
    ratchetState: Array.from(session.ratchet?.exportState() ?? new Uint8Array()),
    sequenceTx: /* from session */,
    sequenceRx: 0,
    ratchetEpoch: 0,
    createdAt: Date.now(),
    hostName: store.hostName(),
    profileFragment: window.location.hash.slice(1),
  };
  await set('cairn-session', saved);
}
```

**Problem**: `NodeSession` does not expose `ratchet`, `sequenceTx`, or
`sessionId` publicly. We need to add getters or use the `_` prefixed internals
via casting (which is what the jaunt code already does for `state` and `outbox`).

**Decision**: Add public getters to `NodeSession` in cairn TS:
- `get sessionRatchetState(): Uint8Array | null` — calls `exportState()` if ratchet exists
- `get sequenceCounter(): number`

### Load on Page Mount

In `PairingScreen.tsx` `onMount`, before checking the URL fragment:

```typescript
onMount(async () => {
  // Check for saved session FIRST (before URL fragment check)
  const saved = await get('cairn-session') as SavedCairnSession | undefined;
  if (saved && !isExpired(saved)) {
    await tryReconnect(saved);
    return;
  }

  // Existing fragment-based pairing flow...
  const fragment = window.location.hash.slice(1);
  if (fragment) { ... }
});
```

### New Function: `tryReconnect` (in `cairn.ts`)

```typescript
export async function tryReconnect(saved: SavedCairnSession): Promise<boolean> {
  try {
    // 1. Create node with saved identity (not a random one)
    const config: Partial<CairnConfig> = { storageBackend: 'memory' };
    node = await Node.createWithIdentity(config, saved.identitySecret);

    // 2. Start transport
    await node.startTransport();

    // 3. Try connectTransport (which will attempt SESSION_RESUME
    //    internally if the host recognizes the session)
    session = await node.connectTransport(saved.hostLibp2pPeerId, saved.hostAddrs);

    // 4. Wire up message handlers (same as connectToHost)
    wireSessionHandlers();

    store.setConnected(true);
    store.setHostName(saved.hostName);
    store.setPeerId(saved.hostLibp2pPeerId);
    store.setView('sessions');
    return true;
  } catch (e) {
    console.warn('[jaunt] Resume failed, clearing saved session:', e);
    await del('cairn-session');
    return false;
  }
}
```

### Node.createWithIdentity

New static method on the TS `Node` class:
```typescript
static async createWithIdentity(
  config: Partial<CairnConfig>,
  identitySecret: number[],
): Promise<Node> {
  const resolved = resolveConfig(config);
  const node = new Node(resolved);
  node._identity = await IdentityKeypair.fromBytes(new Uint8Array(identitySecret));
  return node;
}
```

This is critical: the host identifies us by our Ed25519-derived libp2p PeerId.
If we generate a new identity on refresh, the host won't recognize us.

### Session Expiry Check

```typescript
function isExpired(saved: SavedCairnSession): boolean {
  const EXPIRY_MS = 24 * 60 * 60 * 1000;  // 24 hours
  return Date.now() - saved.createdAt > EXPIRY_MS;
}
```

### Clearing Saved State

- On explicit `disconnect()`: delete from IndexedDB.
- On `unpair()`: delete from IndexedDB.
- On session expiry check failure: delete from IndexedDB.
- On resume failure: delete from IndexedDB.

### Test Plan (Phase 4)
- Manual: Connect to host, refresh page, verify reconnection without re-pairing
- Manual: Connect, wait >24h (or fake timestamp), refresh, verify re-pairing screen shown
- Unit: `isExpired` logic
- Unit: `SavedCairnSession` roundtrip through IndexedDB mock

---

## Phase 5: Port Resume Protocol to TypeScript

### Goal
Mirror the Rust SESSION_RESUME/ACK encoding, proof generation, and protocol
handling in the TS cairn package so the browser can be either side of a resume.

### New File: `session/reconnection.ts`

Types and functions mirroring the Rust side:

```typescript
interface ResumeProof {
  hmac: Uint8Array;    // 32 bytes
  nonce: Uint8Array;   // 32 bytes
  timestamp: number;   // unix seconds
}

function generateResumeProof(
  resumptionKey: Uint8Array,
  sessionId: Uint8Array,
  nonce: Uint8Array,
  timestamp: number,
): ResumeProof;

function verifyResumeProof(
  resumptionKey: Uint8Array,
  sessionId: Uint8Array,
  proof: ResumeProof,
): boolean;

function encodeSessionResume(
  sessionId: Uint8Array,
  proof: ResumeProof,
  lastRxSeq: number,
): Uint8Array;

function decodeSessionResume(
  payload: Uint8Array,
): { sessionId: Uint8Array; proof: ResumeProof; lastRxSeq: number };

function encodeSessionResumeAck(lastRxSeq: number): Uint8Array;
function decodeSessionResumeAck(payload: Uint8Array): number;
```

HMAC-SHA256 implementation: Use `@noble/hashes/hmac` + `@noble/hashes/sha256`
(already a transitive dep via `@noble/ed25519`).

### New File: `session/persistence.ts`

Storage adapter interface (mirrors the Rust pattern):

```typescript
interface SessionStore {
  save(peerId: string, state: SavedSession): Promise<void>;
  load(peerId: string): Promise<SavedSession | null>;
  delete(peerId: string): Promise<void>;
  listAll(): Promise<SavedSession[]>;
}
```

Two implementations:
- `MemorySessionStore` — for tests and server-mode Node.js
- `IndexedDBSessionStore` — for browser (wraps idb-keyval)

### Changes to `crypto/double-ratchet.ts`

Add `deriveResumptionKey(): Uint8Array` mirroring the Rust method.

### Changes to `node.ts`

1. **Protocol handler** — add `SESSION_RESUME` (0x0200) handling in the
   `libp2pNode.handle(CAIRN_PROTOCOL, ...)` callback:
   ```typescript
   if (requestEnv.type === SESSION_RESUME) {
     await this._handleSessionResume(requestEnv, remotePeerIdStr, stream);
   }
   ```

2. **`_handleSessionResume` method** — validates, sends ACK or EXPIRED.

3. **`connectTransport` modification** — before starting the handshake, check
   if a saved session exists for this peer. If so, attempt resume first.
   On failure, fall through to full handshake.

4. **`Node.createWithIdentity`** — new factory method (as described in Phase 4).

### Changes to `node.ts` — `NodeSession`

Add public getters needed for persistence:
```typescript
get sessionRatchetState(): Uint8Array | null {
  return this._ratchet?.exportState() ?? null;
}
get sequenceCounter(): number {
  return this._sequenceCounter;
}
```

### Test Plan (Phase 5)
- Unit: `generateResumeProof` / `verifyResumeProof` roundtrip
- Unit: Wrong key verification fails
- Unit: CBOR encode/decode roundtrip
- Unit: `deriveResumptionKey` output matches Rust (cross-language vector test)
- Integration (Node.js): Two TS nodes, connect, save state, resume

---

## Implementation Units (for parallel agents)

### Unit 1: Session Persistence — Rust
**Files**: `session/persistence.rs` (new), `session/mod.rs` (add `pub mod persistence`)
**Scope**: `SavedSession` struct, save/load/delete/list functions, index management
**Tests**: All persistence unit tests
**Depends on**: Nothing (pure data + KeyStore trait)

### Unit 2: Resume Protocol Primitives — Rust
**Files**: `session/reconnection.rs` (extend), `crypto/ratchet.rs` (add `derive_resumption_key`)
**Scope**: ResumeProof, HMAC proof gen/verify, CBOR encode/decode for SESSION_RESUME/ACK/EXPIRED, NonceCache
**Tests**: All proof and encoding unit tests
**Depends on**: Nothing (pure crypto + codec)

### Unit 3: Resume Protocol Wiring — Rust
**Files**: `api/node.rs`
**Scope**: `try_resume_transport`, resume responder handler in event loop, save session after handshake, load sessions on startup, keystore field on ApiNode
**Tests**: Integration tests (2-node resume, fallback to handshake)
**Depends on**: Units 1, 2

### Unit 4: Auto-Reconnect — Rust
**Files**: `api/node.rs`
**Scope**: ConnectionClosed handler spawns reconnection_loop, peer address tracking, cancellation on unpair/close
**Tests**: Integration tests (disconnect → auto-reconnect)
**Depends on**: Unit 3

### Unit 5: Resume Protocol — TypeScript
**Files**: `session/reconnection.ts` (new), `session/persistence.ts` (new), `crypto/double-ratchet.ts` (extend), `node.ts` (extend), `session/index.ts` (re-export)
**Scope**: Mirror of Rust resume primitives, Node.createWithIdentity, protocol handler, NodeSession getters
**Tests**: Unit + integration in TS test suite
**Depends on**: Unit 2 (need to verify cross-language HMAC vectors match)

### Unit 6: Browser Persistence — jaunt web client
**Files**: `web/src/lib/cairn.ts` (extend), `web/src/lib/store.ts` (extend), `web/src/components/PairingScreen.tsx` (extend)
**Scope**: SavedCairnSession type, save/load/clear, tryReconnect, PairingScreen onMount check
**Tests**: Manual (browser page refresh reconnection)
**Depends on**: Unit 5

---

## Key Design Decisions & Rationale

### 1. HMAC proof instead of signature-based proof
The existing `ChallengeProof` struct uses Ed25519 signatures. HMAC-SHA256 with
the ratchet-derived resumption key is simpler, faster, and proves possession of
the session key (which is what we care about) rather than possession of the
identity key (which proves nothing about session continuity).

### 2. Derived resumption key, not raw root key
Never expose the ratchet's root key. Derive a purpose-specific key via HKDF
with domain separation (`cairn-session-resume-v1`). If the resumption key is
compromised, it cannot be used to decrypt messages or derive other chain keys.

### 3. Session index in keystore instead of trait extension
Adding `list_keys` to the KeyStore trait would break all existing implementations.
A secondary index key is more compatible and sufficient for the small number of
saved sessions (typically 1-5 peers).

### 4. Epoch increment only (no forced ratchet step)
After resume, both sides increment the ratchet epoch counter. The Double Ratchet
naturally advances on the next message exchange. Forcing a ratchet step without
message exchange requires inventing a synthetic message, which adds complexity
and risks desynchronizing the two sides.

### 5. Browser identity persistence is critical
The host identifies the browser by its libp2p PeerId, which is derived from the
Ed25519 identity keypair. On page refresh, the browser must reuse the same
identity. `Node.createWithIdentity` allows this.

### 6. SESSION_EXPIRED instead of silent fallback
When resume fails, the responder sends an explicit SESSION_EXPIRED message with
a reason code. This is better than silence because: (a) the initiator knows to
fall back immediately instead of waiting for a timeout, and (b) diagnostics/logs
can show why the resume failed.

### 7. Nonce + timestamp for replay protection
A nonce alone prevents replay but requires unbounded storage of seen nonces.
Adding a timestamp window (5 minutes) bounds the nonce cache size: nonces older
than 5 minutes can be evicted since they'd be rejected by timestamp check anyway.

---

## Backward Compatibility

- Nodes that don't support SESSION_RESUME will respond with an unknown message
  type error (or no response). The initiator's timeout triggers fallback to
  full handshake.
- The SESSION_RESUME and SESSION_RESUME_ACK message type codes (0x0200, 0x0201)
  are already allocated in the message type registry.
- No changes to existing handshake flow. SESSION_RESUME is attempted first;
  on failure, the existing path runs unchanged.
- The `SavedSession` format is versioned implicitly by its JSON structure.
  Future changes can add optional fields with defaults.

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Ratchet state desync after resume | Both sides verify sequence counters in resume. If counters don't match, fall back to full handshake. |
| Saved session encrypted with weak key | FilesystemKeyStore uses Argon2id + AES-256-GCM. InMemory is ephemeral. Browser uses IndexedDB (no encryption needed — same-origin policy). |
| Clock skew breaks timestamp validation | 5-minute window is generous. If both sides have >5min skew, the handshake fallback still works. |
| Browser IndexedDB quota exceeded | A single saved session is ~2KB. IndexedDB quotas are typically 50MB+. |
| Race between auto-reconnect and manual connect | Reconnection task checks session state before each attempt. If session is already Connected (manual reconnect succeeded), the task exits. |
