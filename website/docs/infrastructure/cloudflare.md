---
sidebar_position: 5
title: "Cloudflare Deployment"
---

# Cloudflare Deployment

Deploy cairn infrastructure behind Cloudflare for free or near-free hosting with automatic TLS, DDoS protection, and global edge routing.

## Signaling Server

Two approaches for running the signaling server behind Cloudflare:

### Option A: Cloudflare Workers + Durable Objects

Deploy the signaling logic as a Cloudflare Worker with a Durable Object for WebSocket state. This approach runs entirely on Cloudflare's edge with no VM required.

:::note
This approach requires Cloudflare Workers Paid plan ($5/mo) for Durable Objects. For a free option, use Option B.
:::

### Option B: Cloudflare Tunnel (Recommended)

Run `cairn-signal` on any VM and expose it through a Cloudflare Tunnel. TLS is handled by Cloudflare automatically.

**Steps:**

1. Install `cloudflared` on the VM running `cairn-signal`:
   ```bash
   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
     -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared
   ```

2. Create a tunnel:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create cairn-signal
   ```

3. Configure DNS -- point `signal.yourdomain.com` to the tunnel:
   ```bash
   cloudflared tunnel route dns cairn-signal signal.yourdomain.com
   ```

4. Run the signaling server on localhost and start the tunnel:
   ```bash
   # Start cairn-signal (plaintext, tunnel handles TLS)
   cairn-signal --listen-addr 127.0.0.1:8080 --auth-token your-secret

   # Start the tunnel
   cloudflared tunnel --url http://127.0.0.1:8080 run cairn-signal
   ```

Clients connect to `wss://signal.yourdomain.com` -- Cloudflare handles TLS termination.

## Relay Server

TURN requires UDP, which Cloudflare Workers and Tunnels do not support. Use a hybrid approach:

1. **Run `cairn-relay` on a lightweight VM** with a public IP (free Oracle Cloud, $5/mo VPS)
2. **Expose the REST API via Cloudflare Tunnel** for credential provisioning
3. **Expose TURN UDP port 3478 directly** on the VM's public IP

```bash
# On the VM: start the relay
cairn-relay \
  --listen-addr 0.0.0.0:3478 \
  --rest-secret your-api-secret \
  --api-addr 127.0.0.1:8080

# Tunnel the REST API through Cloudflare
cloudflared tunnel --url http://127.0.0.1:8080 run cairn-relay-api
```

Client configuration:
- TURN server: `turn:<vm-public-ip>:3478` (direct UDP)
- Credentials API: `https://relay-api.yourdomain.com/credentials` (via Cloudflare Tunnel)

## Server Node

Run [cairn server node](/docs/infrastructure/server-node) on a VPS and expose the management API via Cloudflare Tunnel. TLS is handled by Cloudflare.

```bash
# Start the server node
cairn-server --listen-addr 127.0.0.1:9090

# Tunnel the management API
cloudflared tunnel --url http://127.0.0.1:9090 run cairn-server
```

## Cost Summary

| Component       | Hosting                              | Cost              |
|-----------------|--------------------------------------|-------------------|
| Signaling       | Cloudflare Tunnel to free VM         | Free              |
| Relay           | VM with public IP for UDP            | $0-5/mo           |
| Server node     | Same VM as relay                     | $0 (shared)       |
| **Total**       |                                      | **$0-5/mo**       |

A single low-cost VM can host all three components (signaling, relay, server node) with Cloudflare Tunnel handling TLS and HTTP routing.

## Security Notes

- **Management API tokens**: Never expose management API tokens or REST secrets in client-side code. These are for operators only.
- **Auth tokens**: Distribute `signalAuthToken` and TURN credentials to clients through your application's existing auth flow.
- **Cloudflare Access**: For additional security, place management endpoints behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/) to restrict access to authorized operators.
