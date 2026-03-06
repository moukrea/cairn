---
sidebar_position: 2
title: "Session Lifecycle"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Session Lifecycle

A session is an encrypted channel between two paired peers. Sessions handle connection management, automatic reconnection, and forward-secret message delivery.

## Connection States

Sessions move through a simple state machine:

```
connecting -> connected -> reconnecting -> connected
                                        \-> disconnected
```

| State          | Description                                         |
|----------------|-----------------------------------------------------|
| `connecting`   | Noise XX handshake in progress                      |
| `connected`    | Session active, messages can be sent and received    |
| `reconnecting` | Transport dropped, attempting to re-establish        |
| `disconnected` | Session ended or reconnection failed                 |

## Automatic Reconnection

When a transport drops (e.g., switching from WiFi to cellular), sessions automatically attempt to reconnect. Key properties:

- **Double Ratchet state is preserved** -- no re-pairing is needed. The ratchet picks up where it left off.
- **Transport-agnostic** -- sessions persist across transport changes. A connection that started over WebRTC can resume over a relay, or vice versa.
- **Transparent to your app** -- messages sent during reconnection are queued and delivered once the session is re-established.

## Event Handling for State Changes

Listen for `StateChanged` events to update your UI or trigger application logic when a session's state changes.

<LanguageTabs>
<TabItem value="rust">

```rust
let mut events = node.subscribe();
while let Some(event) = events.recv().await {
    match event {
        Event::StateChanged { peer_id, state } => {
            println!("Peer {} state: {:?}", peer_id, state);
        }
        _ => {}
    }
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
for event := range node.Events() {
    if sc, ok := event.(cairn.StateChangedEvent); ok {
        fmt.Printf("Peer %s state: %s\n", sc.PeerID, sc.State)
    }
}
```

</TabItem>
<TabItem value="python">

```python
async for event in node.events():
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

The `state` value is one of: `connecting`, `connected`, `reconnecting`, `disconnected`.

## Session Properties

You can inspect a session's current state and the peer it is connected to.

<LanguageTabs>
<TabItem value="rust">

```rust
let session = node.connect(&peer_id).await?;
println!("Peer: {}", session.peer_id());
println!("State: {:?}", session.state());
```

</TabItem>
<TabItem value="typescript">

```typescript
const session = await node.connect(peerId);
console.log(`Peer: ${session.peerId}`);
console.log(`State: ${session.state}`);
```

</TabItem>
<TabItem value="go">

```go
session, _ := node.Connect(peerId)
fmt.Println("Peer:", session.PeerID())
fmt.Println("State:", session.State())
```

</TabItem>
<TabItem value="python">

```python
session = await node.connect(peer_id)
print(f"Peer: {session.peer_id}")
print(f"State: {session.state}")
```

</TabItem>
<TabItem value="php">

```php
$session = $node->connect($peerId);
echo "Peer: " . $session->peerId() . "\n";
echo "State: " . $session->state() . "\n";
```

</TabItem>
</LanguageTabs>
