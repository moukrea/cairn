---
sidebar_position: 2
title: Quick Start
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Quick Start

Set up an encrypted P2P channel in 15 minutes. This guide walks through installing cairn, pairing two peers, establishing a session, and sending messages -- in all 5 supported languages.

## Step 1: Create a Node

A `Node` is your local peer. Creating one generates an Ed25519 identity and starts the transport layer with zero-config defaults.

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
println!("Peer ID: {}", node.peer_id());
```

</TabItem>
<TabItem value="typescript">

```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, err := cairn.Create()
if err != nil { log.Fatal(err) }
fmt.Println("Peer ID:", node.PeerID())
```

</TabItem>
<TabItem value="python">

```python
from cairn import create

node = await create()
print(f"Peer ID: {node.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;

$node = Node::create();
echo "Peer ID: " . $node->peerId() . "\n";
```

</TabItem>
</LanguageTabs>

## Step 2: Pair with a Peer

Pairing establishes mutual trust between two devices using a shared secret (PIN, QR code, or link). One peer initiates, the other responds.

### PIN Pairing

**Initiator** -- generates a PIN and displays it:

<LanguageTabs>
<TabItem value="rust">

```rust
let pairing_data = node.pair_generate_pin().await?;
println!("PIN: {}", pairing_data.pin); // e.g., "A1B2-C3D4"
```

</TabItem>
<TabItem value="typescript">

```typescript
const { pin } = await node.pairGeneratePin();
console.log(`PIN: ${pin}`);
```

</TabItem>
<TabItem value="go">

```go
data, err := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
```

</TabItem>
<TabItem value="python">

```python
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
```

</TabItem>
<TabItem value="php">

```php
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\n";
```

</TabItem>
</LanguageTabs>

**Responder** -- enters the PIN displayed by the initiator:

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_enter_pin("A1B2-C3D4").await?;
println!("Paired with: {}", peer_id);
```

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairEnterPin('A1B2-C3D4');
console.log(`Paired with: ${peerId}`);
```

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairEnterPin("A1B2-C3D4")
fmt.Println("Paired with:", peerId)
```

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_enter_pin("A1B2-C3D4")
print(f"Paired with: {peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairEnterPin('A1B2-C3D4');
echo "Paired with: " . $peerId . "\n";
```

</TabItem>
</LanguageTabs>

## Step 3: Establish a Session

After pairing, open an encrypted session. Sessions use a Noise XX handshake followed by a double ratchet for forward secrecy.

<LanguageTabs>
<TabItem value="rust">

```rust
let session = node.connect(&peer_id).await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
const session = await node.connect(peerId);
```

</TabItem>
<TabItem value="go">

```go
session, err := node.Connect(peerId)
```

</TabItem>
<TabItem value="python">

```python
session = await node.connect(peer_id)
```

</TabItem>
<TabItem value="php">

```php
$session = $node->connect($peerId);
```

</TabItem>
</LanguageTabs>

## Step 4: Send a Message

Send encrypted data over the session. Messages are delivered through the best available transport.

<LanguageTabs>
<TabItem value="rust">

```rust
session.send("chat", b"hello from Rust").await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
await session.send('chat', Buffer.from('hello from TypeScript'));
```

</TabItem>
<TabItem value="go">

```go
err = session.Send("chat", []byte("hello from Go"))
```

</TabItem>
<TabItem value="python">

```python
await session.send("chat", b"hello from Python")
```

</TabItem>
<TabItem value="php">

```php
$session->send('chat', 'hello from PHP');
```

</TabItem>
</LanguageTabs>

## Step 5: Receive Messages

Register a handler to receive incoming messages on a channel.

<LanguageTabs>
<TabItem value="rust">

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

</TabItem>
<TabItem value="typescript">

```typescript
node.on('message', (peerId, channel, data) => {
    console.log(`[${channel}] ${peerId}: ${data.toString()}`);
});
```

</TabItem>
<TabItem value="go">

```go
for event := range node.Events() {
    if msg, ok := event.(cairn.MessageEvent); ok {
        fmt.Printf("[%s] %s: %s\n", msg.Channel, msg.PeerID, msg.Data)
    }
}
```

</TabItem>
<TabItem value="python">

```python
async for event in node.events():
    if event.type == NodeEventType.MESSAGE_RECEIVED:
        print(f"[{event.channel}] {event.peer_id}: {event.data.decode()}")
```

</TabItem>
<TabItem value="php">

```php
$node->on('message', function (string $peerId, string $channel, string $data) {
    echo "[$channel] $peerId: $data\n";
});
```

</TabItem>
</LanguageTabs>

## Step 6: Handle Reconnection

Sessions automatically reconnect after network disruptions. Listen for state changes to update your UI.

<LanguageTabs>
<TabItem value="rust">

```rust
match event {
    Event::StateChanged { peer_id, state } => {
        println!("Peer {} state: {:?}", peer_id, state);
    }
    _ => {}
}
```

</TabItem>
<TabItem value="typescript">

```typescript
node.on('session_state', (peerId, state) => {
    console.log(`Peer ${peerId} state: ${state}`);
});
```

</TabItem>
<TabItem value="go">

```go
if sc, ok := event.(cairn.StateChangedEvent); ok {
    fmt.Printf("Peer %s state: %s\n", sc.PeerID, sc.State)
}
```

</TabItem>
<TabItem value="python">

```python
if event.type == NodeEventType.STATE_CHANGED:
    print(f"Peer {event.peer_id} state: {event.state}")
```

</TabItem>
<TabItem value="php">

```php
$node->on('session_state', function (string $peerId, string $state) {
    echo "Peer $peerId state: $state\n";
});
```

</TabItem>
</LanguageTabs>

Connection states: `connecting` -> `connected` -> `reconnecting` -> `connected` (or `disconnected`).

## Next Steps

- **[First App](./first-app.md)** -- Build a complete runnable P2P chat in under 50 lines
- **[Guides](/docs/guides/pairing)** -- Deep dive into pairing methods, sessions, and channels
- **[Demo Applications](/docs/demos/messaging)** -- Explore working example applications
