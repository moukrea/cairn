# 03 - Getting Started Content

## Cross-references
- Depends on: `01-docusaurus-setup.md` for the LanguageTabs component, MDX usage pattern, and Docusaurus project structure

## Overview

Three documentation pages under `website/docs/getting-started/`:
1. `installation.md` -- per-language install instructions
2. `quick-start.md` -- migrated from existing `docs/getting-started.md`, restructured with LanguageTabs
3. `first-app.md` -- complete runnable minimal P2P chat app

All code examples use the `LanguageTabs` component and must show all 5 languages (Rust, TypeScript, Go, Python, PHP).

## Content Migration Source

The primary source for `installation.md` and `quick-start.md` is the existing file `docs/getting-started.md`. Code examples must match the verified API from that file. Do not invent new API calls.

Additional verified sources: `demo/messaging/*/` (demo code), `README.md` (overview examples).

---

## File 1: `website/docs/getting-started/installation.md`

### Content

Per-language install instructions with a prerequisites table:

| Language   | Version  | Package Manager | Install Command                                              |
|------------|----------|-----------------|--------------------------------------------------------------|
| Rust       | 1.75+    | Cargo           | `cargo add cairn-p2p`                                        |
| TypeScript | Node 18+ | npm             | `npm install cairn-p2p`                                      |
| Go         | 1.24+    | Go modules      | `go get github.com/moukrea/cairn/packages/go/cairn-p2p`     |
| Python     | 3.11+    | pip             | `pip install cairn-p2p`                                      |
| PHP        | 8.2+     | Composer        | `composer require moukrea/cairn-p2p`                         |

Each language section includes:
1. **Prerequisites** (language version, package manager)
2. **Install command** (from table above)
3. **Verification command** -- an import/use statement to confirm installation works

Verification examples (use LanguageTabs):

**Rust:**
```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
println!("Peer ID: {}", node.peer_id());
```

**TypeScript:**
```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);
```

**Go:**
```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, err := cairn.Create()
if err != nil { log.Fatal(err) }
fmt.Println("Peer ID:", node.PeerID())
```

**Python:**
```python
from cairn import create

node = await create()
print(f"Peer ID: {node.peer_id}")
```

**PHP:**
```php
use Cairn\Node;

$node = Node::create();
echo "Peer ID: " . $node->peerId() . "\n";
```

4. **Common issues** -- brief troubleshooting tips per language

---

## File 2: `website/docs/getting-started/quick-start.md`

### Migration Source

This file is migrated and restructured from the existing `docs/getting-started.md`. Preserve the exact code examples from that file. The only structural change is wrapping per-language code blocks in `LanguageTabs` + `TabItem` components instead of listing them under language-name headers.

### Content Structure

Opening: "Set up an encrypted P2P channel in 15 minutes. This guide walks through installing cairn, pairing two peers, establishing a session, and sending messages -- in all 5 supported languages."

#### Step 1: Create a Node

Description: "A `Node` is your local peer. Creating one generates an Ed25519 identity and starts the transport layer with zero-config defaults."

LanguageTabs with these exact code blocks:

**Rust:**
```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
println!("Peer ID: {}", node.peer_id());
```

**TypeScript:**
```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);
```

**Go:**
```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, err := cairn.Create()
if err != nil { log.Fatal(err) }
fmt.Println("Peer ID:", node.PeerID())
```

**Python:**
```python
from cairn import create

node = await create()
print(f"Peer ID: {node.peer_id}")
```

**PHP:**
```php
use Cairn\Node;

$node = Node::create();
echo "Peer ID: " . $node->peerId() . "\n";
```

#### Step 2: Pair with a Peer

Description: "Pairing establishes mutual trust between two devices using a shared secret (PIN, QR code, or link). One peer initiates, the other responds."

Sub-section: **PIN Pairing**

**Initiator** -- generates a PIN and displays it (LanguageTabs):

**Rust:**
```rust
let pairing_data = node.pair_generate_pin().await?;
println!("PIN: {}", pairing_data.pin); // e.g., "A1B2-C3D4"
```

**TypeScript:**
```typescript
const { pin } = await node.pairGeneratePin();
console.log(`PIN: ${pin}`);
```

**Go:**
```go
data, err := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
```

**Python:**
```python
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
```

**PHP:**
```php
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\n";
```

**Responder** -- enters the PIN displayed by the initiator (LanguageTabs):

**Rust:**
```rust
let peer_id = node.pair_enter_pin("A1B2-C3D4").await?;
println!("Paired with: {}", peer_id);
```

**TypeScript:**
```typescript
const peerId = await node.pairEnterPin('A1B2-C3D4');
console.log(`Paired with: ${peerId}`);
```

**Go:**
```go
peerId, err := node.PairEnterPin("A1B2-C3D4")
fmt.Println("Paired with:", peerId)
```

**Python:**
```python
peer_id = await node.pair_enter_pin("A1B2-C3D4")
print(f"Paired with: {peer_id}")
```

**PHP:**
```php
$peerId = $node->pairEnterPin('A1B2-C3D4');
echo "Paired with: " . $peerId . "\n";
```

#### Step 3: Establish a Session

Description: "After pairing, open an encrypted session. Sessions use a Noise XX handshake followed by a double ratchet for forward secrecy."

LanguageTabs:

**Rust:**
```rust
let session = node.connect(&peer_id).await?;
```

**TypeScript:**
```typescript
const session = await node.connect(peerId);
```

**Go:**
```go
session, err := node.Connect(peerId)
```

**Python:**
```python
session = await node.connect(peer_id)
```

**PHP:**
```php
$session = $node->connect($peerId);
```

#### Step 4: Send a Message

Description: "Send encrypted data over the session. Messages are delivered through the best available transport."

LanguageTabs:

**Rust:**
```rust
session.send("chat", b"hello from Rust").await?;
```

**TypeScript:**
```typescript
await session.send('chat', Buffer.from('hello from TypeScript'));
```

**Go:**
```go
err = session.Send("chat", []byte("hello from Go"))
```

**Python:**
```python
await session.send("chat", b"hello from Python")
```

**PHP:**
```php
$session->send('chat', 'hello from PHP');
```

#### Step 5: Receive Messages

Description: "Register a handler to receive incoming messages on a channel."

LanguageTabs:

**Rust:**
```rust
let mut events = node.subscribe();
while let Some(event) = events.recv().await {
    match event {
        Event::MessageReceived { peer_id, channel, data } => {
            println!("[{}] {}: {}", channel, peer_id, String::from_utf8_lossy(&data));
        }
        _ => {}
    }
}
```

**TypeScript:**
```typescript
node.on('message', (peerId, channel, data) => {
    console.log(`[${channel}] ${peerId}: ${data.toString()}`);
});
```

**Go:**
```go
for event := range node.Events() {
    if msg, ok := event.(cairn.MessageEvent); ok {
        fmt.Printf("[%s] %s: %s\n", msg.Channel, msg.PeerID, msg.Data)
    }
}
```

**Python:**
```python
async for event in node.events():
    if event.type == NodeEventType.MESSAGE_RECEIVED:
        print(f"[{event.channel}] {event.peer_id}: {event.data.decode()}")
```

**PHP:**
```php
$node->on('message', function (string $peerId, string $channel, string $data) {
    echo "[$channel] $peerId: $data\n";
});
```

#### Step 6: Handle Reconnection

Description: "Sessions automatically reconnect after network disruptions. Listen for state changes to update your UI."

LanguageTabs:

**Rust:**
```rust
match event {
    Event::StateChanged { peer_id, state } => {
        println!("Peer {} state: {:?}", peer_id, state);
    }
    _ => {}
}
```

**TypeScript:**
```typescript
node.on('session_state', (peerId, state) => {
    console.log(`Peer ${peerId} state: ${state}`);
});
```

**Go:**
```go
if sc, ok := event.(cairn.StateChangedEvent); ok {
    fmt.Printf("Peer %s state: %s\n", sc.PeerID, sc.State)
}
```

**Python:**
```python
if event.type == NodeEventType.STATE_CHANGED:
    print(f"Peer {event.peer_id} state: {event.state}")
```

**PHP:**
```php
$node->on('session_state', function (string $peerId, string $state) {
    echo "Peer $peerId state: $state\n";
});
```

Connection states: `connecting` -> `connected` -> `reconnecting` -> `connected` (or `disconnected`).

### Next Steps Footer

- Link to `first-app.md` for a complete runnable example
- Link to Guides section for deeper topics (pairing methods, sessions, channels)
- Link to Demo Applications for working examples

---

## File 3: `website/docs/getting-started/first-app.md`

### Content

A complete, runnable example: a minimal P2P chat application in under 50 lines per language.

### Structure

1. **Introduction**: "Build a minimal peer-to-peer chat app. Two terminals, one initiator, one responder. Under 50 lines of code."

2. **Setup**: Two terminals side by side. Terminal A is the initiator, Terminal B is the responder.

3. **Full code listing** per language (use LanguageTabs). Each listing is a single self-contained file that:
   - Creates a node
   - Checks CLI args to determine initiator vs responder mode
   - Initiator: generates PIN, waits for pairing, connects, reads stdin and sends messages
   - Responder: enters PIN from CLI arg, waits for pairing, connects, reads stdin and sends messages
   - Both: print received messages to stdout

4. **Running instructions**:
   - Terminal A: `{run-command} --pair-pin` (prints PIN)
   - Terminal B: `{run-command} --enter-pin A1B2-C3D4` (enters the PIN from Terminal A)
   - Both terminals can now type messages

5. **Expected output**: Show sample terminal output demonstrating the exchange.

### Implementation Notes

- Use the same API patterns shown in `docs/getting-started.md` (verified code)
- Use the same API patterns shown in the messaging demo for each language (`demo/messaging/*/`)
- The chat app should be the simplest possible end-to-end example
- Do not add features beyond basic send/receive (no channels menu, no status commands)
