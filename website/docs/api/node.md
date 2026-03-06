---
sidebar_position: 1
title: "Node"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Node

The `Node` is the core object in cairn. It represents your local peer, manages identity, handles pairing, and establishes encrypted sessions.

## Constructor / Factory

Create a new cairn node with optional configuration.

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{CairnConfig, create, create_server};

// Default configuration
let node = create(CairnConfig::default())?;
node.start().await?;

// Server mode
let server = create_server(CairnConfig::default())?;
server.start().await?;
```

**Signature**: `create(config: CairnConfig) -> Result<Node, CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
import { create, createServer } from 'cairn-p2p';

// Default configuration
const node = create({});
await node.start();

// Server mode
const server = createServer({});
await server.start();
```

**Signature**: `create(config?: Record<string, unknown>): Node`

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

// Default configuration
node, err := cairn.Create(cairn.DefaultConfig())
node.Start()

// Server mode
server, err := cairn.CreateServer(cairn.DefaultConfig())
server.Start()
```

**Signature**: `Create(config Config) (*Node, error)`

</TabItem>
<TabItem value="python">

```python
from cairn import create, create_server

# Default configuration
node = create({})
await node.start()

# Server mode
server = create_server({})
await server.start()
```

**Signature**: `create(config: dict) -> Node`

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;
use Cairn\Config;

// Default configuration
$node = Node::create(Config::defaults());
$node->start();

// Server mode
$server = Node::createServer(Config::defaults());
$server->start();
```

**Signature**: `Node::create(array $config): Node`

</TabItem>
</LanguageTabs>

## Pairing Methods

### `pair_generate_pin`

Generate a PIN code for the initiator side of PIN pairing. Returns the PIN string and, once the responder enters it, the paired peer's ID.

<LanguageTabs>
<TabItem value="rust">

```rust
let data = node.pair_generate_pin().await?;
println!("PIN: {}", data.pin);
let peer_id = data.peer_id; // available after responder enters PIN
```

**Signature**: `pair_generate_pin() -> Result<PairingData, CairnError>`

**Returns**: `PairingData { pin: String, peer_id: PeerID }`

</TabItem>
<TabItem value="typescript">

```typescript
const { pin, peerId } = await node.pairGeneratePin();
console.log(`PIN: ${pin}`);
```

**Signature**: `pairGeneratePin(): Promise<{ pin: string, peerId: string }>`

</TabItem>
<TabItem value="go">

```go
data, err := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
peerId := data.PeerID
```

**Signature**: `PairGeneratePin() (*PairingData, error)`

**Returns**: `PairingData { Pin string, PeerID string }`

</TabItem>
<TabItem value="python">

```python
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
peer_id = data.peer_id
```

**Signature**: `pair_generate_pin() -> PairingData`

**Returns**: `PairingData(pin: str, peer_id: str)`

</TabItem>
<TabItem value="php">

```php
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\n";
$peerId = $data->peerId;
```

**Signature**: `pairGeneratePin(): PairingData`

**Returns**: `PairingData { pin: string, peerId: string }`

</TabItem>
</LanguageTabs>

### `pair_enter_pin`

Enter a PIN code as the responder. Returns the paired peer's ID.

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_enter_pin("A1B2-C3D4").await?;
```

**Signature**: `pair_enter_pin(pin: &str) -> Result<PeerID, CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairEnterPin('A1B2-C3D4');
```

**Signature**: `pairEnterPin(pin: string): Promise<string>`

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairEnterPin("A1B2-C3D4")
```

**Signature**: `PairEnterPin(pin string) (string, error)`

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_enter_pin("A1B2-C3D4")
```

**Signature**: `pair_enter_pin(pin: str) -> str`

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairEnterPin('A1B2-C3D4');
```

**Signature**: `pairEnterPin(string $pin): string`

</TabItem>
</LanguageTabs>

### `pair_generate_link`

Generate a pairing link URI as the initiator. The URI can be shared via any channel.

<LanguageTabs>
<TabItem value="rust">

```rust
let data = node.pair_generate_link().await?;
println!("Link: {}", data.uri);
let peer_id = data.peer_id;
```

**Signature**: `pair_generate_link() -> Result<LinkData, CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
const { uri, peerId } = await node.pairGenerateLink();
```

**Signature**: `pairGenerateLink(): Promise<{ uri: string, peerId: string }>`

</TabItem>
<TabItem value="go">

```go
data, err := node.PairGenerateLink()
fmt.Println("Link:", data.URI)
```

**Signature**: `PairGenerateLink() (*LinkData, error)`

</TabItem>
<TabItem value="python">

```python
data = await node.pair_generate_link()
print(f"Link: {data.uri}")
```

**Signature**: `pair_generate_link() -> LinkData`

</TabItem>
<TabItem value="php">

```php
$data = $node->pairGenerateLink();
echo "Link: " . $data->uri . "\n";
```

**Signature**: `pairGenerateLink(): LinkData`

</TabItem>
</LanguageTabs>

### `pair_from_link`

Accept a pairing link as the responder. Returns the paired peer's ID.

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_from_link(&uri).await?;
```

**Signature**: `pair_from_link(uri: &str) -> Result<PeerID, CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairFromLink(uri);
```

**Signature**: `pairFromLink(uri: string): Promise<string>`

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairFromLink(uri)
```

**Signature**: `PairFromLink(uri string) (string, error)`

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_from_link(uri)
```

**Signature**: `pair_from_link(uri: str) -> str`

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairFromLink($uri);
```

**Signature**: `pairFromLink(string $uri): string`

</TabItem>
</LanguageTabs>

## Connection

### `connect`

Open an encrypted session with a paired peer. Returns a `Session` object for sending and receiving messages.

<LanguageTabs>
<TabItem value="rust">

```rust
let session = node.connect(&peer_id).await?;
```

**Signature**: `connect(peer_id: &PeerID) -> Result<Session, CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
const session = await node.connect(peerId);
```

**Signature**: `connect(peerId: string): Promise<Session>`

</TabItem>
<TabItem value="go">

```go
session, err := node.Connect(peerId)
```

**Signature**: `Connect(peerID string) (*Session, error)`

</TabItem>
<TabItem value="python">

```python
session = await node.connect(peer_id)
```

**Signature**: `connect(peer_id: str) -> Session`

</TabItem>
<TabItem value="php">

```php
$session = $node->connect($peerId);
```

**Signature**: `connect(string $peerId): Session`

</TabItem>
</LanguageTabs>

## Events

Subscribe to node events (messages, state changes, peer connections/disconnections). The subscription mechanism varies by language.

<LanguageTabs>
<TabItem value="rust">

```rust
let mut events = node.subscribe();
while let Some(event) = events.recv().await {
    match event {
        Event::MessageReceived { peer_id, channel, data } => {
            println!("[{}] {}: {}", channel, peer_id, String::from_utf8_lossy(&data));
        }
        Event::PeerConnected { peer_id } => {
            println!("Connected: {}", peer_id);
        }
        Event::PeerDisconnected { peer_id } => {
            println!("Disconnected: {}", peer_id);
        }
        Event::StateChanged { peer_id, state } => {
            println!("State: {} -> {:?}", peer_id, state);
        }
        _ => {}
    }
}
```

**Signature**: `subscribe() -> broadcast::Receiver<Event>`

Returns a broadcast stream of `Event` values.

</TabItem>
<TabItem value="typescript">

```typescript
node.on('message', (peerId, channel, data) => {
    console.log(`[${channel}] ${peerId}: ${data.toString()}`);
});

node.on('session_state', (peerId, state) => {
    console.log(`${peerId} state: ${state}`);
});
```

**Signature**: `on(event: string, callback: Function): void`

Events: `'message'`, `'session_state'`, `'peer_connected'`, `'peer_disconnected'`

</TabItem>
<TabItem value="go">

```go
for event := range node.Events() {
    switch e := event.(type) {
    case cairn.MessageEvent:
        fmt.Printf("[%s] %s: %s\n", e.Channel, e.PeerID, e.Data)
    case cairn.StateChangedEvent:
        fmt.Printf("%s state: %s\n", e.PeerID, e.State)
    }
}
```

**Signature**: `Events() <-chan Event`

Returns a channel of `Event` interface values.

</TabItem>
<TabItem value="python">

```python
async for event in node.events():
    if event.type == "MessageReceived":
        print(f"[{event.channel}] {event.peer_id}: {event.data.decode()}")
    elif event.type == "StateChanged":
        print(f"{event.peer_id} state: {event.state}")
```

**Signature**: `events() -> AsyncIterator[NodeEvent]`

Returns an async iterator of `NodeEvent` objects.

</TabItem>
<TabItem value="php">

```php
$node->on('message', function (string $peerId, string $channel, string $data) {
    echo "[$channel] $peerId: $data\n";
});

$node->on('session_state', function (string $peerId, string $state) {
    echo "$peerId state: $state\n";
});
```

**Signature**: `on(string $event, callable $callback): void`

Events: `'message'`, `'session_state'`, `'peer_connected'`, `'peer_disconnected'`

</TabItem>
</LanguageTabs>

## Info

### `peer_id`

Returns the local peer's identifier (Base58-encoded Ed25519 public key).

<LanguageTabs>
<TabItem value="rust">

```rust
let id = node.peer_id();
println!("Peer ID: {}", id);
```

**Type**: `peer_id() -> PeerID` (method)

</TabItem>
<TabItem value="typescript">

```typescript
console.log(`Peer ID: ${node.peerId}`);
```

**Type**: `peerId: string` (property)

</TabItem>
<TabItem value="go">

```go
fmt.Println("Peer ID:", node.PeerID())
```

**Type**: `PeerID() string` (method)

</TabItem>
<TabItem value="python">

```python
print(f"Peer ID: {node.peer_id}")
```

**Type**: `peer_id: str` (property)

</TabItem>
<TabItem value="php">

```php
echo "Peer ID: " . $node->peerId() . "\n";
```

**Type**: `peerId(): string` (method)

</TabItem>
</LanguageTabs>
