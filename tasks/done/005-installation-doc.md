# Task 005: Installation Documentation

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 003-language-tabs-component (needs LanguageTabs for per-language code blocks)

## Spec References
- spec/03-getting-started-content.md (File 1: installation.md)

## Scope
Create the installation documentation page at `website/docs/getting-started/installation.md` with per-language install instructions, prerequisites table, verification examples, and troubleshooting tips. Replace the placeholder file from task 002.

## Acceptance Criteria
- [ ] `website/docs/getting-started/installation.md` exists with full content (not placeholder)
- [ ] Prerequisites table with all 5 languages, versions, package managers, and install commands
- [ ] Per-language sections with prerequisites, install command, and verification code using LanguageTabs
- [ ] Common issues / troubleshooting section
- [ ] All code examples match the verified API from the spec
- [ ] `cd website && npm run build` succeeds

## Implementation Notes

### MDX Format
The file should be MDX (`.md` extension works with Docusaurus MDX parser). Import LanguageTabs and TabItem at the top.

### Frontmatter
```yaml
---
sidebar_position: 1
title: Installation
---
```

### Prerequisites Table

| Language   | Version  | Package Manager | Install Command                                              |
|------------|----------|-----------------|--------------------------------------------------------------|
| Rust       | 1.75+    | Cargo           | `cargo add cairn-p2p`                                        |
| TypeScript | Node 18+ | npm             | `npm install cairn-p2p`                                      |
| Go         | 1.24+    | Go modules      | `go get github.com/moukrea/cairn/packages/go/cairn-p2p`     |
| Python     | 3.11+    | pip             | `pip install cairn-p2p`                                      |
| PHP        | 8.2+     | Composer        | `composer require moukrea/cairn-p2p`                         |

### Verification Examples (use LanguageTabs)

**Rust:**
```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
println!("Peer ID: {}", node.peer_id());
```

**TypeScript:**
```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
console.log(`Peer ID: ${node.peerId}`);
```

**Go:**
```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, err := cairn.Create()
if err != nil { log.Fatal(err) }
fmt.Println("Peer ID:", node.PeerID())
```

**Python:**
```python
from cairn import create

node = await create()
print(f"Peer ID: {node.peer_id}")
```

**PHP:**
```php
use Cairn\Node;

$node = Node::create();
echo "Peer ID: " . $node->peerId() . "\n";
```

### Common Issues
Brief troubleshooting per language (e.g., Rust minimum edition, Node version mismatch, Go module proxy issues, Python async requirements, PHP extension requirements).

## Files to Create or Modify
- website/docs/getting-started/installation.md (replace placeholder)

## Verification Commands
- `cd website && npm run build`
