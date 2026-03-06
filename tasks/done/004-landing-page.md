# Task 004: Landing Page

## Status
done

## Dependencies
- 001-docusaurus-scaffolding (needs Docusaurus project structure)
- 002-sidebar-css-assets (needs custom.css and static assets)
- 003-language-tabs-component (needs LanguageTabs for code example section)

## Spec References
- spec/02-landing-page.md

## Scope
Build the custom React landing page at `website/src/pages/index.tsx` with four sections: hero, feature grid, quick code example (using LanguageTabs), and infrastructure tiers visualization. Includes co-located CSS module for styling.

## Acceptance Criteria
- [ ] `website/src/pages/index.tsx` exists and renders four sections: Hero, Feature Grid, Code Example, Infrastructure Tiers
- [ ] Hero section shows logo, tagline ("Universal peer-to-peer connectivity library"), subtitle ("End-to-end encrypted. Five languages. Zero infrastructure required."), and two CTA buttons (Get Started -> /docs/getting-started/installation, View on GitHub -> GitHub repo)
- [ ] Feature grid has 3 cards: "Five Languages, One Protocol", "Secure by Default", "Zero to Production"
- [ ] Code example section uses LanguageTabs with verified code snippets for all 5 languages
- [ ] Infrastructure tiers section displays Tier 0/1/2 as styled comparison cards with all specified attributes
- [ ] Page is dark-mode compatible using Docusaurus CSS variables
- [ ] `cd website && npm run build` succeeds

## Implementation Notes

### Hero Section
- Logo: `<img src="/cairn/img/cairn.png" />`  (use `useBaseUrl` hook)
- Tagline: `"Universal peer-to-peer connectivity library"`
- Subtitle: `"End-to-end encrypted. Five languages. Zero infrastructure required."`
- CTA 1: "Get Started" -> link to `/docs/getting-started/installation`
- CTA 2: "View on GitHub" -> `https://github.com/moukrea/cairn`

### Feature Grid (3 columns)
1. **"Five Languages, One Protocol"** -- "Rust, TypeScript, Go, Python, PHP all interoperate."
2. **"Secure by Default"** -- "Noise XX + Double Ratchet, no opt-in required."
3. **"Zero to Production"** -- "Start with no infrastructure, add signaling/relay when needed."

### Code Example Section
Import and use the LanguageTabs component. Show the "create node, pair, send message" examples. Use these exact code snippets from the spec:

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

### Infrastructure Tiers Section
Render as styled comparison cards. Three tiers:

**Tier 0 (Default) -- "Zero Infrastructure":**
- Setup: None
- NAT traversal: Public STUN, best-effort
- Discovery speed: 5-30s (DHT/mDNS)
- Offline messages: No
- Always-on relay: No
- Multi-device sync: Manual
- Cost: Free

**Tier 1 -- "Signaling + Relay":**
- Setup: 2 Docker containers
- NAT traversal: TURN relay, symmetric NAT
- Discovery speed: <1s (signaling)
- Offline messages: No
- Always-on relay: Yes
- Multi-device sync: Manual
- Cost: Free (Cloudflare) or ~$5/mo VPS

**Tier 2 -- "Server Peer":**
- Setup: 3 Docker containers
- NAT traversal: Full
- Discovery speed: <1s
- Offline messages: Yes (store-and-forward)
- Always-on relay: Yes
- Multi-device sync: Automatic (hub)
- Cost: Same + storage

### Styling
Use a co-located CSS module file: `website/src/pages/index.module.css`. Use Docusaurus CSS variables for dark mode compatibility.

## Files to Create or Modify
- website/src/pages/index.tsx (new)
- website/src/pages/index.module.css (new)

## Verification Commands
- `cd website && npm run build`
