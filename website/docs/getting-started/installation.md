---
sidebar_position: 1
title: Installation
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Installation

cairn is available for five languages. Pick yours and follow the steps below.

## Prerequisites

| Language   | Version  | Package Manager | Install Command                                              |
|------------|----------|-----------------|--------------------------------------------------------------|
| Rust       | 1.75+    | Cargo           | `cargo add cairn-p2p`                                        |
| TypeScript | Node 18+ | npm             | `npm install cairn-p2p`                                      |
| Go         | 1.24+    | Go modules      | `go get github.com/moukrea/cairn/packages/go/cairn-p2p`     |
| Python     | 3.11+    | pip             | `pip install cairn-p2p`                                      |
| PHP        | 8.2+     | Composer        | `composer require moukrea/cairn-p2p`                         |

## Install

<LanguageTabs>
<TabItem value="rust">

```bash
cargo add cairn-p2p
```

</TabItem>
<TabItem value="typescript">

```bash
npm install cairn-p2p
```

</TabItem>
<TabItem value="go">

```bash
go get github.com/moukrea/cairn/packages/go/cairn-p2p
```

</TabItem>
<TabItem value="python">

```bash
pip install cairn-p2p
```

</TabItem>
<TabItem value="php">

```bash
composer require moukrea/cairn-p2p
```

</TabItem>
</LanguageTabs>

## Verify Your Installation

Create a node and print your peer ID to confirm everything is working:

<LanguageTabs>
<TabItem value="rust">

```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
println!("Peer ID: {}", node.peer_id());
```

</TabItem>
<TabItem value="typescript">

```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);
```

</TabItem>
<TabItem value="go">

```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, err := cairn.Create()
if err != nil { log.Fatal(err) }
fmt.Println("Peer ID:", node.PeerID())
```

</TabItem>
<TabItem value="python">

```python
from cairn import create

node = await create()
print(f"Peer ID: {node.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
use Cairn\Node;

$node = Node::create();
echo "Peer ID: " . $node->peerId() . "\n";
```

</TabItem>
</LanguageTabs>

## Common Issues

<LanguageTabs>
<TabItem value="rust">

- **Minimum edition**: cairn requires Rust edition 2021 or later. Make sure your `Cargo.toml` has `edition = "2021"` or newer.
- **Async runtime**: cairn uses Tokio. Ensure you have `tokio` as a dependency with the `full` feature enabled.

</TabItem>
<TabItem value="typescript">

- **Node version**: cairn requires Node.js 18 or later. Run `node --version` to check.
- **ESM vs CJS**: cairn ships as ESM. If your project uses CommonJS, you may need to adjust your `tsconfig.json` or use dynamic `import()`.

</TabItem>
<TabItem value="go">

- **Module proxy**: If `go get` fails, try setting `GOPROXY=https://proxy.golang.org,direct`.
- **Go version**: cairn requires Go 1.24+. Run `go version` to check.

</TabItem>
<TabItem value="python">

- **Async required**: cairn uses `async/await`. You need Python 3.11+ and an async runtime like `asyncio`.
- **Virtual environment**: It is recommended to install cairn inside a virtual environment (`python -m venv .venv`).

</TabItem>
<TabItem value="php">

- **PHP version**: cairn requires PHP 8.2+. Run `php --version` to check.
- **FFI extension**: cairn uses PHP FFI to call the native Rust core. Make sure the `ffi` extension is enabled in your `php.ini`.

</TabItem>
</LanguageTabs>
