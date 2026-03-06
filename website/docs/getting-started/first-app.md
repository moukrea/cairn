---
sidebar_position: 3
title: "First App: P2P Chat"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# First App: P2P Chat

Build a minimal peer-to-peer chat app. Two terminals, one initiator, one responder. Under 50 lines of code.

## Setup

Open two terminals side by side. Terminal A is the initiator, Terminal B is the responder.

## Full Code

<LanguageTabs>
<TabItem value="rust">

```rust
// chat.rs
use cairn_p2p::{Node, CairnConfig, create};
use cairn_p2p::api::NodeEvent;
use std::io::{self, BufRead};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let node = create(CairnConfig::default())?;
    node.start().await?;
    println!("Peer ID: {}", node.peer_id());

    let peer_id = if args.len() > 1 && args[1] == "--pair-pin" {
        let data = node.pair_generate_pin().await?;
        println!("PIN: {}", data.pin);
        println!("Waiting for peer...");
        data.peer_id
    } else if args.len() > 2 && args[1] == "--enter-pin" {
        node.pair_enter_pin(&args[2]).await?
    } else {
        eprintln!("Usage: chat --pair-pin | --enter-pin <PIN>");
        std::process::exit(1);
    };

    println!("Paired with: {}", peer_id);
    let session = node.connect(&peer_id).await?;
    println!("Connected!");

    // Receive messages in background
    let mut events = node.subscribe();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let NodeEvent::MessageReceived { peer_id, channel, data } = event {
                println!("[{}] {}: {}", channel, peer_id, String::from_utf8_lossy(&data));
            }
        }
    });

    // Read stdin and send
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        session.send("chat", line.as_bytes()).await?;
    }

    Ok(())
}
```

</TabItem>
<TabItem value="typescript">

```typescript
// chat.ts
import { Node } from 'cairn-p2p';

const args = process.argv.slice(2);
const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);

let peerId: string;

if (args[0] === '--pair-pin') {
  const { pin, peerId: id } = await node.pairGeneratePin();
  console.log(`PIN: ${pin}`);
  console.log('Waiting for peer...');
  peerId = id;
} else if (args[0] === '--enter-pin' && args[1]) {
  peerId = await node.pairEnterPin(args[1]);
} else {
  console.error('Usage: chat --pair-pin | --enter-pin <PIN>');
  process.exit(1);
}

console.log(`Paired with: ${peerId}`);
const session = await node.connect(peerId);
console.log('Connected!');

node.on('message', (id, channel, data) => {
  console.log(`[${channel}] ${id}: ${data.toString()}`);
});

const readline = await import('readline');
const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  await session.send('chat', Buffer.from(line));
}
```

</TabItem>
<TabItem value="go">

```go
// chat.go
package main

import (
	"bufio"
	"fmt"
	"os"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

func main() {
	node, err := cairn.Create(cairn.DefaultConfig())
	if err != nil { panic(err) }
	node.Start()
	fmt.Println("Peer ID:", node.PeerID())

	var peerID string
	if len(os.Args) > 1 && os.Args[1] == "--pair-pin" {
		data, _ := node.PairGeneratePin()
		fmt.Println("PIN:", data.Pin)
		fmt.Println("Waiting for peer...")
		peerID = data.PeerID
	} else if len(os.Args) > 2 && os.Args[1] == "--enter-pin" {
		peerID, _ = node.PairEnterPin(os.Args[2])
	} else {
		fmt.Fprintln(os.Stderr, "Usage: chat --pair-pin | --enter-pin <PIN>")
		os.Exit(1)
	}

	fmt.Println("Paired with:", peerID)
	session, _ := node.Connect(peerID)
	fmt.Println("Connected!")

	// Receive messages in background
	go func() {
		for event := range node.Events() {
			if msg, ok := event.(cairn.MessageEvent); ok {
				fmt.Printf("[%s] %s: %s\n", msg.Channel, msg.PeerID, msg.Data)
			}
		}
	}()

	// Read stdin and send
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		session.Send("chat", []byte(scanner.Text()))
	}
}
```

</TabItem>
<TabItem value="python">

```python
# chat.py
import asyncio, sys
from cairn import create

async def main():
    node = await create()
    print(f"Peer ID: {node.peer_id}")

    if len(sys.argv) > 1 and sys.argv[1] == "--pair-pin":
        data = await node.pair_generate_pin()
        print(f"PIN: {data.pin}")
        print("Waiting for peer...")
        peer_id = data.peer_id
    elif len(sys.argv) > 2 and sys.argv[1] == "--enter-pin":
        peer_id = await node.pair_enter_pin(sys.argv[2])
    else:
        print("Usage: chat --pair-pin | --enter-pin <PIN>", file=sys.stderr)
        sys.exit(1)

    print(f"Paired with: {peer_id}")
    session = await node.connect(peer_id)
    print("Connected!")

    async def receive():
        async for event in node.events():
            if event.type == "MessageReceived":
                print(f"[{event.channel}] {event.peer_id}: {event.data.decode()}")

    asyncio.create_task(receive())

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break
        await session.send("chat", line.strip())

asyncio.run(main())
```

</TabItem>
<TabItem value="php">

```php
<?php
// chat.php
require_once __DIR__ . '/vendor/autoload.php';
use Cairn\Node;

$node = Node::create();
$node->start();
echo "Peer ID: " . $node->peerId() . "\n";

if (($argv[1] ?? '') === '--pair-pin') {
    $data = $node->pairGeneratePin();
    echo "PIN: " . $data->pin . "\n";
    echo "Waiting for peer...\n";
    $peerId = $data->peerId;
} elseif (($argv[1] ?? '') === '--enter-pin' && isset($argv[2])) {
    $peerId = $node->pairEnterPin($argv[2]);
} else {
    fwrite(STDERR, "Usage: chat --pair-pin | --enter-pin <PIN>\n");
    exit(1);
}

echo "Paired with: $peerId\n";
$session = $node->connect($peerId);
echo "Connected!\n";

$node->on('message', function (string $id, string $channel, string $data) {
    echo "[$channel] $id: $data\n";
});

$stdin = fopen('php://stdin', 'r');
while (($line = fgets($stdin)) !== false) {
    $session->send('chat', trim($line));
}
fclose($stdin);
```

</TabItem>
</LanguageTabs>

## Running

Open two terminals and run the chat app in your language of choice.

**Terminal A** (initiator):

<LanguageTabs>
<TabItem value="rust">

```bash
cargo run -- --pair-pin
```

</TabItem>
<TabItem value="typescript">

```bash
npx tsx chat.ts --pair-pin
```

</TabItem>
<TabItem value="go">

```bash
go run chat.go --pair-pin
```

</TabItem>
<TabItem value="python">

```bash
python chat.py --pair-pin
```

</TabItem>
<TabItem value="php">

```bash
php chat.php --pair-pin
```

</TabItem>
</LanguageTabs>

Terminal A will print a PIN code (e.g., `A1B2-C3D4`). Copy it.

**Terminal B** (responder):

<LanguageTabs>
<TabItem value="rust">

```bash
cargo run -- --enter-pin A1B2-C3D4
```

</TabItem>
<TabItem value="typescript">

```bash
npx tsx chat.ts --enter-pin A1B2-C3D4
```

</TabItem>
<TabItem value="go">

```bash
go run chat.go --enter-pin A1B2-C3D4
```

</TabItem>
<TabItem value="python">

```bash
python chat.py --enter-pin A1B2-C3D4
```

</TabItem>
<TabItem value="php">

```bash
php chat.php --enter-pin A1B2-C3D4
```

</TabItem>
</LanguageTabs>

Both terminals can now type messages back and forth.

## Expected Output

```
Terminal A:
$ cargo run -- --pair-pin
Peer ID: <base58...>
PIN: A1B2-C3D4
Waiting for peer...
Paired with: <peer_id>
Connected!
> hello
[chat] <peer_id>: hi back!

Terminal B:
$ cargo run -- --enter-pin A1B2-C3D4
Peer ID: <base58...>
Paired with: <peer_id>
Connected!
[chat] <peer_id>: hello
> hi back!
```

## Next Steps

- Explore **[Guides](/docs/guides/pairing)** for deeper topics like QR pairing, sessions, and channels
- Check out the **[Messaging Demo](/docs/demos/messaging)** and **[Folder Sync Demo](/docs/demos/folder-sync)** for full-featured working examples
- Read the **[API Reference](/docs/api/node)** for complete API documentation
