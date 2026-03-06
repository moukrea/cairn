# 02 - Landing Page

## Cross-references
- Depends on: `01-docusaurus-setup.md` for the LanguageTabs component, Docusaurus project structure, theme/styling conventions, and `custom.css`

## Overview

Build a custom React landing page at `website/src/pages/index.tsx`. The page has four sections: hero, feature grid, quick code example, and infrastructure tiers visual.

## File Path

`website/src/pages/index.tsx`

## Styling

- Use Docusaurus CSS modules (co-located `.module.css` file or inline styles)
- Minimal custom CSS
- Must be dark mode compatible (Docusaurus handles theme switching; use CSS variables from the theme)
- Global theme overrides go in `website/src/css/custom.css` (color mode default: `dark`, respect system preference)

## Section 1: Hero

- Logo image (from `website/static/img/cairn.png`)
- Tagline: `"Universal peer-to-peer connectivity library"`
- Subtitle: `"End-to-end encrypted. Five languages. Zero infrastructure required."`
- Two CTAs (call-to-action buttons):
  - **"Get Started"** -- links to `/docs/getting-started/installation`
  - **"View on GitHub"** -- links to the GitHub repository

## Section 2: Feature Grid

3-column layout with these cards:

### Card 1: "Five Languages, One Protocol"
Rust, TypeScript, Go, Python, PHP all interoperate.

### Card 2: "Secure by Default"
Noise XX + Double Ratchet, no opt-in required.

### Card 3: "Zero to Production"
Start with no infrastructure, add signaling/relay when needed.

## Section 3: Quick Code Example

Uses the `LanguageTabs` component (from `website/src/components/LanguageTabs.tsx`) to show the 5-line "create node, pair, send message" example from the README.

The code examples shown should be the verified examples from the existing codebase. Here are the patterns per language:

**Rust:**
```rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
let pairing = node.pair_generate_pin().await?;
println!("PIN: {}", pairing.pin);
// Responder enters PIN, then:
let session = node.connect(&peer_id).await?;
session.send("chat", b"hello").await?;
```

**TypeScript:**
```typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
const { pin } = await node.pairGeneratePin();
console.log(`PIN: ${pin}`);
// Responder enters PIN, then:
const session = await node.connect(peerId);
await session.send('chat', Buffer.from('hello'));
```

**Go:**
```go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, _ := cairn.Create()
data, _ := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
// Responder enters PIN, then:
session, _ := node.Connect(peerId)
session.Send("chat", []byte("hello"))
```

**Python:**
```python
from cairn import create

node = await create()
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
# Responder enters PIN, then:
session = await node.connect(peer_id)
await session.send("chat", b"hello")
```

**PHP:**
```php
use Cairn\Node;

$node = Node::create();
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\n";
// Responder enters PIN, then:
$session = $node->connect($peerId);
$session->send('chat', 'hello');
```

Do not invent new API calls. These examples must match existing methods in the library.

## Section 4: Infrastructure Tiers

Visual representation of Tier 0 / Tier 1 / Tier 2 with brief descriptions. Render this as a styled comparison (cards, table, or visual blocks).

### Tier 0 (Default)
- **Label**: "Zero Infrastructure"
- **Setup**: None
- **NAT traversal**: Public STUN, best-effort
- **Discovery speed**: 5-30s (DHT/mDNS)
- **Offline messages**: No
- **Always-on relay**: No
- **Multi-device sync**: Manual
- **Cost**: Free

### Tier 1 (Signaling + Relay)
- **Label**: "Signaling + Relay"
- **Setup**: 2 Docker containers
- **NAT traversal**: TURN relay, symmetric NAT
- **Discovery speed**: <1s (signaling)
- **Offline messages**: No
- **Always-on relay**: Yes
- **Multi-device sync**: Manual
- **Cost**: Free (Cloudflare) or ~$5/mo VPS

### Tier 2 (Server Peer)
- **Label**: "Server Peer"
- **Setup**: 3 Docker containers
- **NAT traversal**: Full
- **Discovery speed**: <1s
- **Offline messages**: Yes (store-and-forward)
- **Always-on relay**: Yes
- **Multi-device sync**: Automatic (hub)
- **Cost**: Same + storage
