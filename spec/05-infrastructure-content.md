# 05 — Infrastructure, Demo Docs & README Update

## Cross-references
- **Depends on**: `01-docusaurus-setup.md` for the `LanguageTabs` component used in client-side configuration examples.
- **Depends on**: `04-guides-content.md` for server-mode guide (referenced from infrastructure/server-node.md).

---

## Overview

This module covers:
1. Infrastructure documentation (4 pages under `website/docs/infrastructure/`)
2. Cloudflare deployment guide (1 page under `website/docs/infrastructure/`)
3. Demo app walkthrough docs (3 pages under `website/docs/demos/`)
4. README update instructions

---

## File 1: `website/docs/infrastructure/overview.md`

### Purpose
The critical "value proposition" page. Explains when and why to add infrastructure.

**Frontmatter**: `title: "Infrastructure Overview"`, `sidebar_position: 1`

### Opening Paragraph
"cairn works out of the box with zero infrastructure. Here's when and why you'd want to add your own servers."

### Section: Tier Comparison Table

| | Tier 0 (Default) | Tier 1 (Signaling + Relay) | Tier 2 (Server Peer) |
|---|---|---|---|
| Setup | None | 2 Docker containers | 3 Docker containers |
| NAT traversal | Public STUN, best-effort | TURN relay, symmetric NAT | Full |
| Discovery speed | 5-30s (DHT/mDNS) | <1s (signaling) | <1s |
| Offline messages | No | No | Yes (store-and-forward) |
| Always-on relay | No | Yes | Yes |
| Multi-device sync | Manual | Manual | Automatic (hub) |
| Cost | Free | Free (Cloudflare) or ~$5/mo VPS | Same + storage |

### Section: Decision Flowchart
Text-based flowchart:
- "Are your peers on the same LAN?" -> Tier 0 is fine
- "Do peers have public IPs or simple NAT?" -> Tier 0 is fine
- "Are peers behind symmetric NAT or corporate firewalls?" -> Tier 1
- "Do you need offline message delivery or multi-device sync?" -> Tier 2

---

## File 2: `website/docs/infrastructure/signaling.md`

### Purpose
Signaling server setup and configuration. Content derived from `services/signaling/README.md`.

**Frontmatter**: `title: "Signaling Server"`, `sidebar_position: 2`

**Import block**:
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';
```

### Section: What the Signaling Server Does
- WebSocket rendezvous for peer discovery.
- Routes CBOR-encoded messages between peers during connection setup.
- Does not see message content (encrypted end-to-end).

### Section: Docker Deployment
```bash
docker run ghcr.io/moukrea/cairn-signal
```

### Section: Configuration Reference
Table of all `CAIRN_SIGNAL_*` environment variables. Extract exact variable names and defaults from `services/signaling/README.md`.

### Section: TLS Setup
How to configure TLS termination (direct or via reverse proxy).

### Section: Authentication
Bearer token authentication setup: set `CAIRN_SIGNAL_AUTH_TOKEN` env var, clients include token in connection.

### Section: Client-Side Configuration
Show how to point a cairn node at the signaling server in all 5 languages using `LanguageTabs`. Pattern:
- Rust: `.signal_server("wss://signal.example.com")`
- TypeScript: `{ signalServer: "wss://signal.example.com" }`
- Go: `cairn.WithSignalServer("wss://signal.example.com")`
- Python: `signal_server="wss://signal.example.com"`
- PHP: `['signalServer' => 'wss://signal.example.com']`

---

## File 3: `website/docs/infrastructure/relay.md`

### Purpose
TURN relay setup and configuration. Content derived from `services/relay/README.md`.

**Frontmatter**: `title: "Relay Server"`, `sidebar_position: 3`

**Import block**: Same as signaling.

### Section: What the TURN Relay Does
- Relays traffic when direct peer-to-peer connection fails (symmetric NAT, corporate firewalls).
- Standard TURN protocol over UDP.
- Does not see message content (encrypted end-to-end).

### Section: Docker Deployment
```bash
docker run ghcr.io/moukrea/cairn-relay
```

### Section: Configuration Reference
Table of all `CAIRN_RELAY_*` environment variables. Extract exact variable names and defaults from `services/relay/README.md`.

### Section: TLS Setup
How to configure TLS for the TURN server.

### Section: Credential Management
- **Static credentials**: Set via environment variables.
- **Dynamic credentials via REST**: REST API for creating/revoking TURN credentials.

### Section: Client-Side Configuration
Show how to point a cairn node at the relay in all 5 languages using `LanguageTabs`. Pattern:
- Rust: `.turn_server("turn:relay.example.com:3478")`
- TypeScript: `{ turnServer: "turn:relay.example.com:3478" }`
- Go: `cairn.WithTurnServer("turn:relay.example.com:3478")`
- Python: `turn_server="turn:relay.example.com:3478"`
- PHP: `['turnServer' => 'turn:relay.example.com:3478']`

---

## File 4: `website/docs/infrastructure/server-node.md`

### Purpose
Server-mode peer deployment. Content derived from `demo/server-node/README.md`.

**Frontmatter**: `title: "Server Node"`, `sidebar_position: 4`

### Section: What a Server-Mode Peer Enables
- **Store-and-forward mailbox**: Messages held for offline peers, delivered on reconnect.
- **Personal relay**: Relay traffic between peers that cannot connect directly.
- **Multi-device sync hub**: Central sync point for all paired devices.

### Section: Docker Deployment
```bash
docker run ghcr.io/moukrea/cairn-server
```

### Section: Configuration Reference
Table of all `CAIRN_*` environment variables for the server node. Extract from `demo/server-node/README.md`.

### Section: Management REST API Reference
Document the management REST API endpoints (list peers, approve pairing, health check, etc.). Extract from `demo/server-node/README.md`.

### Section: Headless Pairing Methods
- PSK (Pre-Shared Key) pairing.
- Pre-approved peer IDs.

### Section: Integration with Signaling + Relay
Docker Compose example for running the full Tier 2 stack:

```yaml
services:
  signaling:
    image: ghcr.io/moukrea/cairn-signal:latest
    environment:
      CAIRN_SIGNAL_LISTEN_ADDR: "0.0.0.0:8443"

  relay:
    image: ghcr.io/moukrea/cairn-relay:latest
    environment:
      CAIRN_RELAY_LISTEN_ADDR: "0.0.0.0:3478"

  server:
    build:
      context: ../../
      dockerfile: demo/server-node/Dockerfile
    environment:
      CAIRN_SIGNAL_SERVERS: "ws://signaling:8443"
      CAIRN_TURN_SERVERS: "turn:relay:3478"
      CAIRN_MGMT_ENABLED: "true"
    ports:
      - "9090:9090"
    volumes:
      - server-data:/data

volumes:
  server-data:
```

---

## File 5: `website/docs/infrastructure/cloudflare.md`

### Purpose
Cloudflare deployment guide for all infrastructure components.

**Frontmatter**: `title: "Cloudflare Deployment"`, `sidebar_position: 5`

### Section: Signaling on Cloudflare Workers
- Cloudflare Workers support WebSockets natively.
- Two approaches: (a) Cloudflare Worker proxying to a Durable Object, or (b) run `cairn-signal` behind a Cloudflare Tunnel (recommended — simpler, avoids Durable Objects complexity).
- Step-by-step for the tunnel approach:
  1. Install `cloudflared` on the VM running `cairn-signal`.
  2. Create a tunnel: `cloudflared tunnel create cairn-signal`.
  3. Configure DNS: point `signal.yourdomain.com` to the tunnel.
  4. Run `cairn-signal` listening on localhost, `cloudflared` tunnels traffic.
- Free tier compatibility: Workers free plan supports WebSockets; tunnel approach works on any VM.

### Section: Relay via Cloudflare Tunnel
- TURN requires UDP, which Cloudflare Workers does not support.
- Solution: run `cairn-relay` on a lightweight VM (e.g., free Oracle Cloud, $5 VPS) and expose the REST API via Cloudflare Tunnel, while the TURN UDP port is exposed directly on the VM's public IP.
- Step-by-step:
  1. Install `cloudflared` on the VM.
  2. Create a tunnel for the REST API (credential management).
  3. Configure DNS for the REST API endpoint.
  4. Expose the TURN UDP port (3478) directly — this requires a public IP.
  5. Clients connect to `turn:vm-public-ip:3478` for TURN, `https://relay-api.yourdomain.com` for credential management.

### Section: Server Node behind Cloudflare Tunnel
- Run `cairn-server` on a VPS.
- Expose the management API via Cloudflare Tunnel.
- TLS is handled by Cloudflare — no manual cert management needed.
- Step-by-step: create tunnel, configure DNS, run `cairn-server` with management API on localhost.

### Section: Cost Summary
- Signaling: free (Cloudflare Workers free tier or tunnel to a $0 VM).
- Relay: needs a $0-5/mo VM with a public IP for UDP.
- Server node: same VM can host relay + server.

### Section: Security Note
Never expose management API tokens in client-side code. The management API should only be accessible to operators, not end users.

---

## File 6: `website/docs/demos/messaging.md`

### Purpose
Chat demo walkthrough.

**Frontmatter**: `title: "Messaging Demo"`, `sidebar_position: 1`

### Section: What the Demo Does
Interactive P2P encrypted chat between two peers.

### Section: Running with Docker
```bash
docker run -it ghcr.io/moukrea/cairn-demo-messaging-rust
```
Available language variants: `-rust`, `-ts`, `-go`, `-py`, `-php`.

### Section: Running with Docker Compose
Two peers with optional signaling/relay:
```bash
# Basic (Tier 0)
docker compose up peer-a peer-b

# With infrastructure (Tier 1)
docker compose --profile infra up
```

### Section: CLI Flags
Extract from messaging demo README. Common flags: `--pair-pin`, `--enter-pin XXXX-XXXX`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link <uri>`, `--signal <url>`, `--turn <url>`, `--verbose`.

### Section: Interactive Commands
- `/status` — show connection status
- `/quit` — exit the demo

### Section: Connecting to Custom Servers
Show how to pass `--signal` and `--turn` flags to connect to custom infrastructure.

---

## File 7: `website/docs/demos/folder-sync.md`

### Purpose
Folder sync demo walkthrough.

**Frontmatter**: `title: "Folder Sync Demo"`, `sidebar_position: 2`

### Section: What the Demo Does
Real-time P2P file synchronization between two directories.

### Section: Running with Docker
```bash
docker run -it -v ./my-files:/sync ghcr.io/moukrea/cairn-demo-folder-sync-rust --dir /sync --pair-pin
```

### Section: Running with Docker Compose
Volume-mounted sync directories:
```bash
docker compose up peer-a peer-b
```
Sync dirs: `./sync-a` and `./sync-b` on host.

### Section: CLI Flags
`--dir <path>`, `--pair-pin`, `--enter-pin XXXX-XXXX`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link <uri>`, `--mesh`, `--server-hub`, `--signal <url>`, `--turn <url>`, `--verbose`.

### Section: Mesh Sync with 3+ Devices
How to use `--mesh` flag for multi-device sync scenarios.

---

## File 8: `website/docs/demos/server-node.md`

### Purpose
Server node demo walkthrough.

**Frontmatter**: `title: "Server Node Demo"`, `sidebar_position: 3`

### Section: What the Demo Does
An always-on server peer that provides store-and-forward, relay, and multi-device sync.

### Section: Running with Docker
```bash
docker run ghcr.io/moukrea/cairn-server
```

### Section: Docker Compose — Full Tier 2 Stack
Reference the docker-compose.yml from `demo/server-node/docker-compose.yml` (same as in infrastructure/server-node.md above).

### Section: Management API Examples
```bash
# Health check
curl http://localhost:9090/health

# List paired peers
curl http://localhost:9090/peers

# Approve a pairing request
curl -X POST http://localhost:9090/peers/approve -d '{"peer_id": "..."}'
```

---

## README Update Instructions

After the documentation site is live, update the root `README.md`:

1. Add a prominent link to `https://moukrea.github.io/cairn/` in the "Documentation" section.
2. Keep the README concise — it serves as a landing page, not comprehensive docs.
3. The existing quick-start code examples in the README should remain (they are good for GitHub visitors).
4. Add a brief "Documentation" section near the top with a link, e.g.:
   ```markdown
   ## Documentation

   Full documentation is available at [moukrea.github.io/cairn](https://moukrea.github.io/cairn/).
   ```
