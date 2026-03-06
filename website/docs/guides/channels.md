---
sidebar_position: 3
title: "Message Channels"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Message Channels

Channels let you logically separate different types of messages within a session. Use named channels to organize traffic by purpose -- for example, `"chat"` for user messages, `"presence"` for online/offline status, and `"sync"` for data synchronization.

## Default Channel

Messages sent without a channel name go to the default channel. All subscribers receive default channel messages.

<LanguageTabs>
<TabItem value="rust">

```rust
session.send("", b"sent on default channel").await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
await session.send('', Buffer.from('sent on default channel'));
```

</TabItem>
<TabItem value="go">

```go
session.Send("", []byte("sent on default channel"))
```

</TabItem>
<TabItem value="python">

```python
await session.send("", b"sent on default channel")
```

</TabItem>
<TabItem value="php">

```php
$session->send('', 'sent on default channel');
```

</TabItem>
</LanguageTabs>

## Named Channels

Named channels allow logical separation of message types. Pass a channel name as the first argument to `send`:

<LanguageTabs>
<TabItem value="rust">

```rust
session.send("chat", b"hello").await?;
session.send("presence", b"online").await?;
session.send("sync", b"{\"key\": \"value\"}").await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
await session.send('chat', Buffer.from('hello'));
await session.send('presence', Buffer.from('online'));
await session.send('sync', Buffer.from('{"key": "value"}'));
```

</TabItem>
<TabItem value="go">

```go
session.Send("chat", []byte("hello"))
session.Send("presence", []byte("online"))
session.Send("sync", []byte(`{"key": "value"}`))
```

</TabItem>
<TabItem value="python">

```python
await session.send("chat", b"hello")
await session.send("presence", b"online")
await session.send("sync", b'{"key": "value"}')
```

</TabItem>
<TabItem value="php">

```php
$session->send('chat', 'hello');
$session->send('presence', 'online');
$session->send('sync', '{"key": "value"}');
```

</TabItem>
</LanguageTabs>

## Subscribing to Channels

Handle incoming messages and filter by channel name:

<LanguageTabs>
<TabItem value="rust">

```rust
let mut events = node.subscribe();
while let Some(event) = events.recv().await {
    match event {
        Event::MessageReceived { peer_id, channel, data } => {
            match channel.as_str() {
                "chat" => println!("Chat from {}: {}", peer_id, String::from_utf8_lossy(&data)),
                "presence" => println!("{} is {}", peer_id, String::from_utf8_lossy(&data)),
                "sync" => handle_sync(&data),
                _ => {}
            }
        }
        _ => {}
    }
}
```

</TabItem>
<TabItem value="typescript">

```typescript
node.on('message', (peerId, channel, data) => {
    switch (channel) {
        case 'chat':
            console.log(`Chat from ${peerId}: ${data.toString()}`);
            break;
        case 'presence':
            console.log(`${peerId} is ${data.toString()}`);
            break;
        case 'sync':
            handleSync(data);
            break;
    }
});
```

</TabItem>
<TabItem value="go">

```go
for event := range node.Events() {
    if msg, ok := event.(cairn.MessageEvent); ok {
        switch msg.Channel {
        case "chat":
            fmt.Printf("Chat from %s: %s\n", msg.PeerID, msg.Data)
        case "presence":
            fmt.Printf("%s is %s\n", msg.PeerID, msg.Data)
        case "sync":
            handleSync(msg.Data)
        }
    }
}
```

</TabItem>
<TabItem value="python">

```python
async for event in node.events():
    if event.type == NodeEventType.MESSAGE_RECEIVED:
        if event.channel == "chat":
            print(f"Chat from {event.peer_id}: {event.data.decode()}")
        elif event.channel == "presence":
            print(f"{event.peer_id} is {event.data.decode()}")
        elif event.channel == "sync":
            handle_sync(event.data)
```

</TabItem>
<TabItem value="php">

```php
$node->on('message', function (string $peerId, string $channel, string $data) {
    match ($channel) {
        'chat' => printf("Chat from %s: %s\n", $peerId, $data),
        'presence' => printf("%s is %s\n", $peerId, $data),
        'sync' => handleSync($data),
        default => null,
    };
});
```

</TabItem>
</LanguageTabs>

## Binary vs Text Data

Channels support both binary and text data. The data parameter accepts bytes in all languages:

| Language   | Binary Type   | Example                        |
|------------|---------------|--------------------------------|
| Rust       | `&[u8]`       | `b"raw bytes"`                 |
| TypeScript | `Buffer`      | `Buffer.from('text')`          |
| Go         | `[]byte`      | `[]byte("text")`               |
| Python     | `bytes`       | `b"raw bytes"`                 |
| PHP        | `string`      | `'text'` (PHP strings are binary-safe) |

Sending binary data (e.g., a file chunk):

<LanguageTabs>
<TabItem value="rust">

```rust
let image_bytes = std::fs::read("photo.png")?;
session.send("file", &image_bytes).await?;
```

</TabItem>
<TabItem value="typescript">

```typescript
import { readFileSync } from 'fs';
const imageBytes = readFileSync('photo.png');
await session.send('file', imageBytes);
```

</TabItem>
<TabItem value="go">

```go
imageBytes, _ := os.ReadFile("photo.png")
session.Send("file", imageBytes)
```

</TabItem>
<TabItem value="python">

```python
image_bytes = open("photo.png", "rb").read()
await session.send("file", image_bytes)
```

</TabItem>
<TabItem value="php">

```php
$imageBytes = file_get_contents('photo.png');
$session->send('file', $imageBytes);
```

</TabItem>
</LanguageTabs>
