# Task 024: Server Node Documentation

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)

## Spec References
- spec/05-infrastructure-content.md (File 4: server-node.md)

## Scope
Create the server node infrastructure documentation covering what a server-mode peer enables, Docker deployment, configuration reference, management REST API, headless pairing, and a full Tier 2 Docker Compose stack example.

## Acceptance Criteria
- [x] File `website/docs/infrastructure/server-node.md` exists with frontmatter `title: "Server Node"`, `sidebar_position: 4`
- [x] Features section covers store-and-forward, personal relay, multi-device sync hub
- [x] Docker deployment with `docker run ghcr.io/moukrea/cairn-server`
- [x] Configuration reference table with all `CAIRN_*` server env vars (extracted from `demo/server-node/README.md`)
- [x] Management REST API reference with endpoints documented
- [x] Docker Compose example for full Tier 2 stack (signaling + relay + server)
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Features:
- **Store-and-forward mailbox**: Messages held for offline peers, delivered on reconnect
- **Personal relay**: Relay traffic between peers that cannot connect directly
- **Multi-device sync hub**: Central sync point for all paired devices

Docker: `docker run ghcr.io/moukrea/cairn-server`

Configuration: Extract `CAIRN_*` env vars from `demo/server-node/README.md`.

Management REST API: Extract endpoints from `demo/server-node/README.md` (list peers, approve pairing, health check, etc.).

Headless pairing: PSK and pre-approved peer IDs.

Docker Compose for Tier 2:
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

## Files to Create or Modify
- website/docs/infrastructure/server-node.md (new)

## Verification Commands
- `cd website && npm run build`
