---
sidebar_position: 2
title: "Session"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Session

A `Session` represents an encrypted connection to a paired peer. Sessions are created by calling `connect()` on a `Node` and provide methods for sending messages and inspecting connection state.

## send(channel, data)

Send an encrypted message over the session.

**Parameters:**

| Parameter | Type   | Description                                                  |
|-----------|--------|--------------------------------------------------------------|
| `channel` | string | Channel name. Use `""` for the default channel.              |
| `data`    | bytes  | Message payload (binary or UTF-8 encoded text).              |

<LanguageTabs>
<TabItem value="rust">

```rust
// Send to a named channel
session.send("chat", b"hello").await?;

// Send to the default channel
session.send("", b"default message").await?;
```

**Signature:** `async fn send(&self, channel: &str, data: &[u8]) -> Result<(), CairnError>`

</TabItem>
<TabItem value="typescript">

```typescript
// Send to a named channel
await session.send('chat', Buffer.from('hello'));

// Send to the default channel
await session.send('', Buffer.from('default message'));
```

**Signature:** `send(channel: string, data: Buffer): Promise<void>`

</TabItem>
<TabItem value="go">

```go
// Send to a named channel
session.Send("chat", []byte("hello"))

// Send to the default channel
session.Send("", []byte("default message"))
```

**Signature:** `func (s *Session) Send(channel string, data []byte) error`

</TabItem>
<TabItem value="python">

```python
# Send to a named channel
await session.send("chat", b"hello")

# Send to the default channel
await session.send("", b"default message")
```

**Signature:** `async def send(self, channel: str, data: bytes) -> None`

</TabItem>
<TabItem value="php">

```php
// Send to a named channel
$session->send('chat', 'hello');

// Send to the default channel
$session->send('', 'default message');
```

**Signature:** `public function send(string $channel, string $data): void`

</TabItem>
</LanguageTabs>

## close()

Close the session and release resources. The remote peer receives a `disconnected` state change event.

<LanguageTabs>
<TabItem value="rust">

```rust
session.close().await;
```

**Signature:** `async fn close(&self)`

</TabItem>
<TabItem value="typescript">

```typescript
session.close();
```

**Signature:** `close(): void`

</TabItem>
<TabItem value="go">

```go
session.Close()
```

**Signature:** `func (s *Session) Close() error`

</TabItem>
<TabItem value="python">

```python
await session.close()
```

**Signature:** `async def close(self) -> None`

</TabItem>
<TabItem value="php">

```php
$session->close();
```

**Signature:** `public function close(): void`

</TabItem>
</LanguageTabs>

## State Properties

Inspect the current session state and remote peer identity.

### Current State

The session state is one of: `connecting`, `connected`, `reconnecting`, `disconnected`.

<LanguageTabs>
<TabItem value="rust">

```rust
let state = session.state(); // SessionState enum
println!("State: {:?}", state);
```

**Type:** `fn state(&self) -> SessionState`

</TabItem>
<TabItem value="typescript">

```typescript
const state = session.state; // "connected" | "reconnecting" | ...
console.log(`State: ${state}`);
```

**Type:** `state: string` (readonly property)

</TabItem>
<TabItem value="go">

```go
state := session.State() // "connected", "reconnecting", ...
fmt.Println("State:", state)
```

**Type:** `func (s *Session) State() string`

</TabItem>
<TabItem value="python">

```python
state = session.state  # "connected", "reconnecting", ...
print(f"State: {state}")
```

**Type:** `state: str` (readonly property)

</TabItem>
<TabItem value="php">

```php
$state = $session->state(); // "connected", "reconnecting", ...
echo "State: $state\n";
```

**Type:** `public function state(): string`

</TabItem>
</LanguageTabs>

### Remote Peer ID

Get the peer ID of the remote end of this session.

<LanguageTabs>
<TabItem value="rust">

```rust
let peer = session.peer_id();
println!("Connected to: {}", peer);
```

**Type:** `fn peer_id(&self) -> &PeerID`

</TabItem>
<TabItem value="typescript">

```typescript
const peer = session.peerId;
console.log(`Connected to: ${peer}`);
```

**Type:** `peerId: string` (readonly property)

</TabItem>
<TabItem value="go">

```go
peer := session.PeerID()
fmt.Println("Connected to:", peer)
```

**Type:** `func (s *Session) PeerID() string`

</TabItem>
<TabItem value="python">

```python
peer = session.peer_id
print(f"Connected to: {peer}")
```

**Type:** `peer_id: str` (readonly property)

</TabItem>
<TabItem value="php">

```php
$peer = $session->peerId();
echo "Connected to: $peer\n";
```

**Type:** `public function peerId(): string`

</TabItem>
</LanguageTabs>
