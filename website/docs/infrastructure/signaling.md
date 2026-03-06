---
sidebar_position: 2
title: "Signaling Server"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Signaling Server

The signaling server enables fast peer discovery and connection setup. It is optional -- cairn works without it using DHT/mDNS (Tier 0) -- but adding a signaling server reduces discovery time from 5-30 seconds to under 1 second.

## What the Signaling Server Does

- **WebSocket rendezvous**: Peers connect to the signaling server via WebSocket. When two peers want to find each other, the server routes messages between them.
- **CBOR message routing**: Signaling messages are CBOR-encoded and forwarded between peers during connection setup (ICE candidates, SDP offers/answers).
- **No access to content**: The signaling server only routes handshake messages. All application data is encrypted end-to-end -- the server cannot read it.
- **Stateless**: No data is written to disk. The server routes messages in memory only.

## Docker Deployment

```bash
docker run -d \
  -p 443:443 \
  -e CAIRN_SIGNAL_AUTH_TOKEN=your-secret-token \
  -e CAIRN_SIGNAL_TLS_CERT=/certs/cert.pem \
  -e CAIRN_SIGNAL_TLS_KEY=/certs/key.pem \
  -v /path/to/certs:/certs:ro \
  ghcr.io/moukrea/cairn-signal
```

For development (plaintext WebSocket, no auth):

```bash
docker run -d \
  -p 8080:8080 \
  -e CAIRN_SIGNAL_LISTEN_ADDR=0.0.0.0:8080 \
  ghcr.io/moukrea/cairn-signal
```

## Configuration Reference

All options can be set via CLI flags or environment variables.

| Flag             | Environment Variable          | Default        | Description                                      |
|------------------|-------------------------------|----------------|--------------------------------------------------|
| `--listen-addr`  | `CAIRN_SIGNAL_LISTEN_ADDR`    | `0.0.0.0:443`  | Listen address (host:port)                       |
| `--tls-cert`     | `CAIRN_SIGNAL_TLS_CERT`       | --              | Path to TLS certificate chain (PEM)              |
| `--tls-key`      | `CAIRN_SIGNAL_TLS_KEY`        | --              | Path to TLS private key (PEM)                    |
| `--auth-token`   | `CAIRN_SIGNAL_AUTH_TOKEN`     | --              | Bearer token for client authentication           |

## TLS

Provide PEM certificate and key files for encrypted WebSocket connections (`wss://`). Both `--tls-cert` and `--tls-key` must be provided together. If omitted, the server runs in plaintext WebSocket mode (`ws://`).

For production, use TLS. You can obtain certificates from Let's Encrypt or use a reverse proxy (nginx, Caddy) that handles TLS termination.

## Authentication

Set `CAIRN_SIGNAL_AUTH_TOKEN` to require an `Authorization: Bearer <token>` header on all WebSocket upgrade requests. Without it, the server accepts all connections.

Clients must include the same token in their configuration (see below).

## Client-Side Configuration

Point your cairn nodes at your signaling server:

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{CairnConfig, create};

let config = CairnConfig {
    signal_server: Some("wss://signal.example.com".into()),
    signal_auth_token: Some("your-secret-token".into()),
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
    signalAuthToken: 'your-secret-token',
});
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

config := cairn.DefaultConfig()
config.SignalServer = "wss://signal.example.com"
config.SignalAuthToken = "your-secret-token"
node, _ := cairn.Create(config)
```

</TabItem>
<TabItem value="python">

```python
from cairn import create

node = await create(
    signal_server="wss://signal.example.com",
    signal_auth_token="your-secret-token",
)
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;

$node = Node::create([
    'signalServer' => 'wss://signal.example.com',
    'signalAuthToken' => 'your-secret-token',
]);
```

</TabItem>
</LanguageTabs>

## Logging

Control log levels via the `RUST_LOG` environment variable:

```bash
# Default: info level
RUST_LOG=info cairn-signal

# Debug level for cairn modules
RUST_LOG=cairn_signal=debug cairn-signal
```
