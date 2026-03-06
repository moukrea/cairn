---
sidebar_position: 4
title: "Server Mode"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Server Mode

Server mode turns a cairn peer into an always-on node that provides store-and-forward messaging, traffic relaying, and multi-device synchronization.

## What Server Mode Enables

### Store-and-Forward

When a peer goes offline, messages sent to it are stored on the server node. When the peer reconnects, queued messages are delivered automatically. No messages are lost due to temporary disconnections.

### Personal Relay

The server peer can relay traffic between peers that cannot connect directly -- for example, when both are behind restrictive NATs. Unlike a public relay, your server node is under your control and only relays traffic for your paired peers.

### Multi-Device Sync

The server acts as a hub for syncing data across multiple devices. All devices pair with the server, and the server forwards messages between them. This is the foundation for applications like folder sync across a laptop, phone, and desktop.

## Configuration Options

Enable server mode when creating a node by using `create_server` instead of `create`:

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{Node, CairnConfig, create_server};

let mut config = CairnConfig::default();
config.storage_path = Some("/var/lib/cairn/data".into());
config.max_message_retention_secs = Some(86400 * 7); // 7 days

let node = create_server(config)?;
node.start().await?;
println!("Server Peer ID: {}", node.peer_id());
```

</TabItem>
<TabItem value="typescript">

```typescript
import { createServer } from 'cairn-p2p';

const node = createServer({
  storagePath: '/var/lib/cairn/data',
  maxMessageRetentionSecs: 86400 * 7, // 7 days
});
await node.start();
console.log(`Server Peer ID: ${node.peerId}`);
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

config := cairn.DefaultConfig()
config.StoragePath = "/var/lib/cairn/data"
config.MaxMessageRetentionSecs = 86400 * 7 // 7 days

node, err := cairn.CreateServer(config)
if err != nil { log.Fatal(err) }
node.Start()
fmt.Println("Server Peer ID:", node.PeerID())
```

</TabItem>
<TabItem value="python">

```python
from cairn import create_server

node = create_server({
    "storage_path": "/var/lib/cairn/data",
    "max_message_retention_secs": 86400 * 7,  # 7 days
})
await node.start()
print(f"Server Peer ID: {node.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;
use Cairn\Config;

$config = Config::defaults();
$config['storage_path'] = '/var/lib/cairn/data';
$config['max_message_retention_secs'] = 86400 * 7; // 7 days

$node = Node::createServer($config);
$node->start();
echo "Server Peer ID: " . $node->peerId() . "\n";
```

</TabItem>
</LanguageTabs>

## Headless Pairing

Server nodes typically run unattended, so interactive PIN entry is impractical. cairn supports two headless pairing methods.

### Pre-Shared Key (PSK)

Configure the server with a PSK. Clients pair by providing the same key -- no interactive PIN exchange required.

<LanguageTabs>
<TabItem value="rust">

```rust
// Server side
let mut config = CairnConfig::default();
config.psk = Some("my-secret-pairing-key".into());
let node = create_server(config)?;
node.start().await?;
// Server automatically accepts peers that present this PSK

// Client side
let peer_id = node.pair_with_psk("my-secret-pairing-key", server_peer_id).await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
// Server side
const node = createServer({ psk: 'my-secret-pairing-key' });
await node.start();

// Client side
const peerId = await node.pairWithPsk('my-secret-pairing-key', serverPeerId);
```

</TabItem>
<TabItem value="go">

```go
// Server side
config := cairn.DefaultConfig()
config.PSK = "my-secret-pairing-key"
node, _ := cairn.CreateServer(config)
node.Start()

// Client side
peerId, err := node.PairWithPSK("my-secret-pairing-key", serverPeerID)
```

</TabItem>
<TabItem value="python">

```python
# Server side
node = create_server({"psk": "my-secret-pairing-key"})
await node.start()

# Client side
peer_id = await node.pair_with_psk("my-secret-pairing-key", server_peer_id)
```

</TabItem>
<TabItem value="php">

```php
// Server side
$config = Config::defaults();
$config['psk'] = 'my-secret-pairing-key';
$node = Node::createServer($config);
$node->start();

// Client side
$peerId = $node->pairWithPsk('my-secret-pairing-key', $serverPeerId);
```

</TabItem>
</LanguageTabs>

### Pre-Approved Peers

Configure the server with a list of peer IDs that are automatically accepted without any pairing ceremony.

<LanguageTabs>
<TabItem value="rust">

```rust
let mut config = CairnConfig::default();
config.approved_peers = vec![
    "5Hb7...peer1".into(),
    "8Kx2...peer2".into(),
];
let node = create_server(config)?;
node.start().await?;
// Listed peers can connect directly without pairing
```

</TabItem>
<TabItem value="typescript">

```typescript
const node = createServer({
  approvedPeers: ['5Hb7...peer1', '8Kx2...peer2'],
});
await node.start();
```

</TabItem>
<TabItem value="go">

```go
config := cairn.DefaultConfig()
config.ApprovedPeers = []string{"5Hb7...peer1", "8Kx2...peer2"}
node, _ := cairn.CreateServer(config)
node.Start()
```

</TabItem>
<TabItem value="python">

```python
node = create_server({
    "approved_peers": ["5Hb7...peer1", "8Kx2...peer2"],
})
await node.start()
```

</TabItem>
<TabItem value="php">

```php
$config = Config::defaults();
$config['approved_peers'] = ['5Hb7...peer1', '8Kx2...peer2'];
$node = Node::createServer($config);
$node->start();
```

</TabItem>
</LanguageTabs>

## Integration with Signaling and Relay Infrastructure

A server-mode peer works alongside the cairn signaling and relay infrastructure:

- **Signaling**: The server connects to a signaling server for peer discovery. Clients find the server through signaling rather than hardcoding IP addresses.
- **Relay (TURN)**: If direct connections fail (e.g., restrictive NATs), the server can use a TURN relay as a fallback transport.

Configure these when creating the server node:

<LanguageTabs>
<TabItem value="rust">

```rust
let mut config = CairnConfig::default();
config.signal_servers = vec!["ws://signal.example.com:8443".into()];
config.turn_servers = vec!["turn:relay.example.com:3478".into()];
let node = create_server(config)?;
```

</TabItem>
<TabItem value="typescript">

```typescript
const node = createServer({
  signalServers: ['ws://signal.example.com:8443'],
  turnServers: ['turn:relay.example.com:3478'],
});
```

</TabItem>
<TabItem value="go">

```go
config := cairn.DefaultConfig()
config.SignalServers = []string{"ws://signal.example.com:8443"}
config.TurnServers = []string{"turn:relay.example.com:3478"}
node, _ := cairn.CreateServer(config)
```

</TabItem>
<TabItem value="python">

```python
node = create_server({
    "signal_servers": ["ws://signal.example.com:8443"],
    "turn_servers": ["turn:relay.example.com:3478"],
})
```

</TabItem>
<TabItem value="php">

```php
$config = Config::defaults();
$config['signal_servers'] = ['ws://signal.example.com:8443'];
$config['turn_servers'] = ['turn:relay.example.com:3478'];
$node = Node::createServer($config);
```

</TabItem>
</LanguageTabs>

For details on deploying signaling and relay servers, see the [Infrastructure](/docs/infrastructure/overview) documentation.
