---
sidebar_position: 3
title: "Events"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Events

cairn nodes emit events for incoming messages, connection state changes, and peer discovery. The subscription mechanism varies by language.

## MessageReceived

Emitted when an encrypted message arrives from a paired peer.

**Payload**:
| Field     | Type   | Description                        |
|-----------|--------|------------------------------------|
| `peer_id` | string | Sender's peer ID                  |
| `channel` | string | Channel name the message was sent on |
| `data`    | bytes  | Decrypted message payload          |

<LanguageTabs>
<TabItem value="rust">

```rust
let mut events = node.subscribe();
while let Some(event) = events.recv().await {
    if let Event::MessageReceived { peer_id, channel, data } = event {
        println!("[{}] {}: {}", channel, peer_id, String::from_utf8_lossy(&data));
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
    if event.type == "MessageReceived":
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

## StateChanged

Emitted when a peer's connection state changes. Use this to update UI or trigger reconnection logic.

**Payload**:
| Field     | Type   | Description                                                     |
|-----------|--------|-----------------------------------------------------------------|
| `peer_id` | string | Peer whose connection state changed                            |
| `state`   | string | One of: `connecting`, `connected`, `reconnecting`, `disconnected` |

**State transitions**: `connecting` &rarr; `connected` &rarr; `reconnecting` &rarr; `connected` (or `disconnected`)

<LanguageTabs>
<TabItem value="rust">

```rust
if let Event::StateChanged { peer_id, state } = event {
    println!("Peer {} state: {:?}", peer_id, state);
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
if event.type == "StateChanged":
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

## PeerDiscovered

Emitted when a paired peer is discovered on the network via mDNS (local network), DHT (internet), or signaling server.

**Payload**:
| Field     | Type   | Description                     |
|-----------|--------|---------------------------------|
| `peer_id` | string | Peer ID of the discovered peer |

<LanguageTabs>
<TabItem value="rust">

```rust
if let Event::PeerDiscovered { peer_id } = event {
    println!("Discovered peer: {}", peer_id);
}
```

</TabItem>
<TabItem value="typescript">

```typescript
node.on('peer_discovered', (peerId) => {
    console.log(`Discovered peer: ${peerId}`);
});
```

</TabItem>
<TabItem value="go">

```go
if disc, ok := event.(cairn.PeerDiscoveredEvent); ok {
    fmt.Println("Discovered peer:", disc.PeerID)
}
```

</TabItem>
<TabItem value="python">

```python
if event.type == "PeerDiscovered":
    print(f"Discovered peer: {event.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$node->on('peer_discovered', function (string $peerId) {
    echo "Discovered peer: $peerId\n";
});
```

</TabItem>
</LanguageTabs>

## PeerLost

Emitted when a previously discovered peer is no longer reachable on the network.

**Payload**:
| Field     | Type   | Description                   |
|-----------|--------|-------------------------------|
| `peer_id` | string | Peer ID of the lost peer     |

<LanguageTabs>
<TabItem value="rust">

```rust
if let Event::PeerLost { peer_id } = event {
    println!("Lost peer: {}", peer_id);
}
```

</TabItem>
<TabItem value="typescript">

```typescript
node.on('peer_lost', (peerId) => {
    console.log(`Lost peer: ${peerId}`);
});
```

</TabItem>
<TabItem value="go">

```go
if lost, ok := event.(cairn.PeerLostEvent); ok {
    fmt.Println("Lost peer:", lost.PeerID)
}
```

</TabItem>
<TabItem value="python">

```python
if event.type == "PeerLost":
    print(f"Lost peer: {event.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$node->on('peer_lost', function (string $peerId) {
    echo "Lost peer: $peerId\n";
});
```

</TabItem>
</LanguageTabs>
