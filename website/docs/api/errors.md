---
sidebar_position: 5
title: "Errors"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Errors

cairn uses structured error types to distinguish between different failure categories. Each language follows its idiomatic error handling pattern.

## Error Categories

| Category        | Description                                                    | Examples                                       |
|-----------------|----------------------------------------------------------------|------------------------------------------------|
| **Connection**  | Failed to establish or maintain a connection                   | Timeout, peer unreachable, NAT traversal failed |
| **Pairing**     | Pairing process failed                                         | Invalid PIN, pairing rejected, SPAKE2 failure   |
| **Session**     | Error during an active session                                 | Send failed, session closed, encryption error   |
| **Configuration** | Invalid configuration values                                 | Invalid URL, missing required fields            |
| **Transport**   | Low-level transport failure                                    | WebSocket failure, TURN relay failure, mDNS failure |

## Error Handling Patterns

<LanguageTabs>
<TabItem value="rust">

cairn uses `Result<T, CairnError>`. Handle errors with `match` or the `?` operator.

```rust
use cairn_p2p::error::CairnError;

match node.connect(&peer_id).await {
    Ok(session) => {
        println!("Connected!");
    }
    Err(CairnError::Connection(e)) => {
        eprintln!("Connection failed: {}", e);
    }
    Err(CairnError::Pairing(e)) => {
        eprintln!("Pairing issue: {}", e);
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}

// Or use the ? operator for propagation
let session = node.connect(&peer_id).await?;
session.send("chat", b"hello").await?;
```

</TabItem>
<TabItem value="typescript">

cairn throws `CairnError` instances. Use `try/catch` and check the `code` property.

```typescript
import { CairnError } from 'cairn-p2p';

try {
    const session = await node.connect(peerId);
    await session.send('chat', Buffer.from('hello'));
} catch (err) {
    if (err instanceof CairnError) {
        switch (err.code) {
            case 'CONNECTION_TIMEOUT':
                console.error('Peer unreachable:', err.message);
                break;
            case 'PAIRING_REJECTED':
                console.error('Pairing failed:', err.message);
                break;
            default:
                console.error('Error:', err.code, err.message);
        }
    }
}
```

</TabItem>
<TabItem value="go">

cairn returns `error` values. Use type assertions to inspect specific error types.

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

session, err := node.Connect(peerId)
if err != nil {
    var connErr *cairn.ConnectionError
    var pairErr *cairn.PairingError
    switch {
    case errors.As(err, &connErr):
        fmt.Println("Connection failed:", connErr)
    case errors.As(err, &pairErr):
        fmt.Println("Pairing failed:", pairErr)
    default:
        fmt.Println("Error:", err)
    }
    return
}

err = session.Send("chat", []byte("hello"))
if err != nil {
    fmt.Println("Send failed:", err)
}
```

</TabItem>
<TabItem value="python">

cairn raises `CairnError` and its subclasses. Use `try/except` with specific exception types.

```python
from cairn import create, CairnError, ConnectionError, PairingError

try:
    session = await node.connect(peer_id)
    await session.send("chat", b"hello")
except ConnectionError as e:
    print(f"Connection failed: {e}")
except PairingError as e:
    print(f"Pairing failed: {e}")
except CairnError as e:
    print(f"Error: {e}")
```

</TabItem>
<TabItem value="php">

cairn throws `CairnException` and its subclasses. Use `try/catch` with specific exception types.

```php
use Cairn\Node;
use Cairn\Exception\CairnException;
use Cairn\Exception\ConnectionException;
use Cairn\Exception\PairingException;

try {
    $session = $node->connect($peerId);
    $session->send('chat', 'hello');
} catch (ConnectionException $e) {
    echo "Connection failed: " . $e->getMessage() . "\n";
} catch (PairingException $e) {
    echo "Pairing failed: " . $e->getMessage() . "\n";
} catch (CairnException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

</TabItem>
</LanguageTabs>

## Common Error Codes

| Code                    | Category      | Description                                     |
|-------------------------|---------------|-------------------------------------------------|
| `CONNECTION_TIMEOUT`    | Connection    | Peer did not respond within the timeout period  |
| `PEER_UNREACHABLE`      | Connection    | No transport path to the peer could be found    |
| `NAT_TRAVERSAL_FAILED`  | Connection    | All NAT traversal methods exhausted             |
| `INVALID_PIN`           | Pairing       | The entered PIN does not match                  |
| `PAIRING_REJECTED`      | Pairing       | The remote peer rejected the pairing request    |
| `SPAKE2_FAILURE`        | Pairing       | SPAKE2 key exchange failed                      |
| `SESSION_CLOSED`        | Session       | Operation attempted on a closed session         |
| `SEND_FAILED`           | Session       | Message could not be delivered                  |
| `INVALID_CONFIG`        | Configuration | Configuration value is invalid                  |
| `TRANSPORT_FAILURE`     | Transport     | Underlying transport connection failed          |
