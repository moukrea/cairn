# Task 025: Cloudflare Deployment Guide

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)
- 022-infra-signaling (references signaling server setup)
- 023-infra-relay (references relay server setup)
- 024-infra-server-node (references server node setup)

## Spec References
- spec/05-infrastructure-content.md (File 5: cloudflare.md)

## Scope
Create the Cloudflare deployment guide covering signaling on Cloudflare Workers/Tunnel, relay via Cloudflare Tunnel, server node behind Cloudflare Tunnel, cost summary, and security notes.

## Acceptance Criteria
- [x] File `website/docs/infrastructure/cloudflare.md` exists with frontmatter `title: "Cloudflare Deployment"`, `sidebar_position: 5`
- [x] Signaling section covers Workers approach and Tunnel approach (recommended) with step-by-step
- [x] Relay section explains UDP limitation and hybrid approach (REST via Tunnel, TURN direct)
- [x] Server node section covers Tunnel for management API
- [x] Cost summary section present
- [x] Security note about management API tokens
- [x] `cd website && npm run build` succeeds

## Implementation Notes
### Signaling on Cloudflare Workers
Two approaches: (a) Worker + Durable Object, (b) `cairn-signal` behind Cloudflare Tunnel (recommended).
Tunnel steps:
1. Install `cloudflared` on VM running `cairn-signal`
2. Create tunnel: `cloudflared tunnel create cairn-signal`
3. Configure DNS: point `signal.yourdomain.com` to tunnel
4. Run `cairn-signal` on localhost, `cloudflared` tunnels traffic

### Relay via Cloudflare Tunnel
TURN requires UDP — Workers don't support UDP. Solution:
1. Run `cairn-relay` on lightweight VM (free Oracle Cloud, $5 VPS)
2. Expose REST API via Cloudflare Tunnel
3. Expose TURN UDP port 3478 directly on VM public IP
4. Clients: `turn:vm-public-ip:3478` for TURN, `https://relay-api.yourdomain.com` for credentials

### Server Node behind Tunnel
Run `cairn-server` on VPS, expose management API via Tunnel, TLS handled by Cloudflare.

### Cost Summary
- Signaling: free (Workers free tier or tunnel to $0 VM)
- Relay: $0-5/mo VM with public IP for UDP
- Server node: same VM can host relay + server

### Security Note
Never expose management API tokens in client-side code. Management API for operators only.

## Files to Create or Modify
- website/docs/infrastructure/cloudflare.md (new)

## Verification Commands
- `cd website && npm run build`
