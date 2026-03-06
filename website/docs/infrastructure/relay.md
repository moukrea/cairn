---
sidebar_position: 3
title: "Relay Server"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Relay Server

The TURN relay server provides media relay for cairn peers that cannot establish direct connections due to symmetric NATs or restrictive firewalls. It implements RFC 8656.

## What the TURN Relay Does

- **Relays traffic** when direct P2P connection fails (symmetric NAT, corporate firewalls, carrier-grade NAT)
- **Standard TURN protocol** over UDP, with optional TLS support
- **End-to-end encrypted** -- the relay forwards ciphertext and cannot read message content
- **Automatic fallback** -- clients attempt direct connection first and fall back to relay only when needed

## Docker Deployment

```bash
docker run -d \
  -p 3478:3478/udp \
  -p 443:443 \
  -p 8080:8080 \
  -e CAIRN_RELAY_REST_SECRET=your-api-secret \
  -e CAIRN_RELAY_TLS_CERT=/certs/cert.pem \
  -e CAIRN_RELAY_TLS_KEY=/certs/key.pem \
  -v /path/to/certs:/certs:ro \
  ghcr.io/moukrea/cairn-relay
```

For development (no TLS, static credentials):

```bash
docker run -d \
  -p 3478:3478/udp \
  -e CAIRN_RELAY_CREDENTIALS=user1:pass1 \
  ghcr.io/moukrea/cairn-relay
```

## Configuration Reference

All options can be set via CLI flags or environment variables.

| Flag              | Environment Variable          | Default          | Description                                          |
|-------------------|-------------------------------|------------------|------------------------------------------------------|
| `--listen-addr`   | `CAIRN_RELAY_LISTEN_ADDR`     | `0.0.0.0:3478`   | TURN UDP listen address                              |
| `--port-range`    | `CAIRN_RELAY_PORT_RANGE`      | `49152-65535`     | Relay port range (format: start-end)                 |
| `--credentials`   | `CAIRN_RELAY_CREDENTIALS`     | --                | Static credentials (format: user:pass, comma-separated) |
| `--rest-secret`   | `CAIRN_RELAY_REST_SECRET`     | --                | Shared secret for REST API credential provisioning   |
| `--tls-cert`      | `CAIRN_RELAY_TLS_CERT`        | --                | TLS certificate path (for TURN-over-TLS)             |
| `--tls-key`       | `CAIRN_RELAY_TLS_KEY`         | --                | TLS private key path                                 |
| `--tls-addr`      | `CAIRN_RELAY_TLS_ADDR`        | `0.0.0.0:443`    | TLS listen address                                   |
| `--api-addr`      | `CAIRN_RELAY_API_ADDR`        | `127.0.0.1:8080` | REST API listen address                              |
| `--realm`         | `CAIRN_RELAY_REALM`           | `cairn`           | TURN realm                                           |
| `--turn-uri`      | `CAIRN_RELAY_URI`             | auto-generated    | TURN URI advertised in REST API responses            |

## TLS

Provide PEM certificate and key files for TURN-over-TLS on port 443. This is recommended for production to ensure signaling data is protected in transit, even though application data is already end-to-end encrypted.

## Credential Management

### Static Credentials

Set credentials directly via environment variable:

```bash
CAIRN_RELAY_CREDENTIALS="user1:pass1,user2:pass2"
```

### Dynamic Credentials via REST API

When `CAIRN_RELAY_REST_SECRET` is configured, the relay exposes a REST API for dynamic TURN credential provisioning.

**Request:**

```bash
curl -H "Authorization: Bearer your-api-secret" \
  "http://127.0.0.1:8080/credentials?ttl=600"
```

**Response:**

```json
{
  "username": "1709312345:cairn-temp",
  "password": "base64-hmac-credential",
  "ttl": 600,
  "uris": ["turn:relay.example.com:3478"]
}
```

Credentials are time-limited (default TTL: 3600 seconds). The REST API uses constant-time comparison for Bearer token authentication.

## Client-Side Configuration

Point your cairn nodes at your relay server:

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{CairnConfig, create};

let config = CairnConfig {
    turn_server: Some("turn:relay.example.com:3478".into()),
    turn_username: Some("user1".into()),
    turn_password: Some("pass1".into()),
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
    turnServer: 'turn:relay.example.com:3478',
    turnUsername: 'user1',
    turnPassword: 'pass1',
});
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

config := cairn.DefaultConfig()
config.TurnServer = "turn:relay.example.com:3478"
config.TurnUsername = "user1"
config.TurnPassword = "pass1"
node, _ := cairn.Create(config)
```

</TabItem>
<TabItem value="python">

```python
from cairn import create

node = await create(
    turn_server="turn:relay.example.com:3478",
    turn_username="user1",
    turn_password="pass1",
)
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;

$node = Node::create([
    'turnServer' => 'turn:relay.example.com:3478',
    'turnUsername' => 'user1',
    'turnPassword' => 'pass1',
]);
```

</TabItem>
</LanguageTabs>
