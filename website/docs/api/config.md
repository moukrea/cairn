---
sidebar_position: 4
title: "Configuration"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Configuration

Configure a cairn node at creation time. All options have sensible defaults -- a zero-config node works out of the box (Tier 0).

## Configuration Options

| Option             | Type    | Default     | Description                                              |
|--------------------|---------|-------------|----------------------------------------------------------|
| Signal server      | string  | `null`      | WebSocket URL of the signaling server (`wss://...`)      |
| Signal auth token  | string  | `null`      | Bearer token for signaling server authentication         |
| TURN server        | string  | `null`      | TURN relay URI (`turn:host:port`)                        |
| TURN username      | string  | `null`      | TURN credential username                                 |
| TURN password      | string  | `null`      | TURN credential password                                 |
| Server mode        | boolean | `false`     | Enable server mode (store-and-forward, personal relay)   |
| Storage path       | string  | `null`      | Persistence directory for server mode data               |
| Mesh enabled       | boolean | `false`     | Enable multi-hop mesh routing                            |
| Identity seed      | bytes   | random      | 32-byte seed for deterministic Ed25519 identity          |
| Listen address     | string  | `0.0.0.0:0` | Local address to bind for incoming connections           |

## Full Configuration Example

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{CairnConfig, create};

let config = CairnConfig {
    signal_server: Some("wss://signal.example.com".into()),
    signal_auth_token: Some("my-token".into()),
    turn_server: Some("turn:relay.example.com:3478".into()),
    turn_username: Some("user".into()),
    turn_password: Some("pass".into()),
    server_mode: false,
    storage_path: None,
    mesh_enabled: true,
    identity_seed: None, // random identity
    listen_addr: Some("0.0.0.0:0".into()),
    ..CairnConfig::default()
};
let node = create(config)?;
node.start().await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create({
    signalServer: 'wss://signal.example.com',
    signalAuthToken: 'my-token',
    turnServer: 'turn:relay.example.com:3478',
    turnUsername: 'user',
    turnPassword: 'pass',
    serverMode: false,
    storagePath: undefined,
    meshEnabled: true,
    identitySeed: undefined, // random identity
    listenAddr: '0.0.0.0:0',
});
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

config := cairn.DefaultConfig()
config.SignalServer = "wss://signal.example.com"
config.SignalAuthToken = "my-token"
config.TurnServer = "turn:relay.example.com:3478"
config.TurnUsername = "user"
config.TurnPassword = "pass"
config.ServerMode = false
config.MeshEnabled = true
config.ListenAddr = "0.0.0.0:0"
node, _ := cairn.Create(config)
```

</TabItem>
<TabItem value="python">

```python
from cairn import create

node = await create(
    signal_server="wss://signal.example.com",
    signal_auth_token="my-token",
    turn_server="turn:relay.example.com:3478",
    turn_username="user",
    turn_password="pass",
    server_mode=False,
    mesh_enabled=True,
    listen_addr="0.0.0.0:0",
)
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;

$node = Node::create([
    'signalServer' => 'wss://signal.example.com',
    'signalAuthToken' => 'my-token',
    'turnServer' => 'turn:relay.example.com:3478',
    'turnUsername' => 'user',
    'turnPassword' => 'pass',
    'serverMode' => false,
    'meshEnabled' => true,
    'listenAddr' => '0.0.0.0:0',
]);
```

</TabItem>
</LanguageTabs>

## Defaults

With no configuration, a node uses:
- **DHT/mDNS** for peer discovery (no signaling server)
- **Public STUN** for NAT traversal (no relay)
- **Random identity** generated on each creation
- **No server mode** (pure peer-to-peer)
- **No mesh routing** (direct connections only)
