# Getting Started with cairn

Set up an encrypted P2P channel in 15 minutes. This guide walks through installing cairn, pairing two peers, establishing a session, and sending messages -- in all 5 supported languages.

## Prerequisites

| Language   | Version | Install Command              |
|------------|---------|------------------------------|
| Rust       | 1.75+   | `cargo add cairn-p2p`        |
| TypeScript | Node 18+| `npm install cairn-p2p`      |
| Go         | 1.24+   | `go get github.com/moukrea/cairn/packages/go/cairn-p2p` |
| Python     | 3.11+   | `pip install cairn-p2p`      |
| PHP        | 8.2+    | `composer require moukrea/cairn-p2p` |

## Step 1: Create a Node

A `Node` is your local peer. Creating one generates an Ed25519 identity and starts the transport layer with zero-config defaults.

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

## Step 2: Pair with a Peer

Pairing establishes mutual trust between two devices using a shared secret (PIN, QR code, or link). One peer initiates, the other responds.

### PIN Pairing

**Initiator** -- generates a PIN and displays it:

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

**Responder** -- enters the PIN displayed by the initiator:

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

## Step 3: Establish a Session

After pairing, open an encrypted session. Sessions use a Noise XX handshake followed by a double ratchet for forward secrecy.

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

## Step 4: Send a Message

Send encrypted data over the session. Messages are delivered through the best available transport.

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

## Step 5: Receive Messages

Register a handler to receive incoming messages on a channel.

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

## Step 6: Handle Reconnection

Sessions automatically reconnect after network disruptions. Listen for state changes to update your UI.

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

## Next Steps

- **Demo applications**: See `demo/` for working examples (messaging, folder sync, server node)
- **Infrastructure tiers**: Deploy signaling and TURN relay for improved connectivity -- see `services/`
- **Conformance tests**: Verify cross-language interop -- see `conformance/`
- **API reference**: Each language package has its own README under `packages/{lang}/cairn-p2p/`

## License

Licensed under the [MIT License](../LICENSE).
