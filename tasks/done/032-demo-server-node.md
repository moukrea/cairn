# Task 032: Demo Docs — Server Node

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)

## Spec References
- spec/05-infrastructure-content.md (File 8: server-node demo)

## Scope
Create the server node demo walkthrough documentation page covering Docker deployment, full Tier 2 Docker Compose stack, and management API examples.

## Acceptance Criteria
- [x] File `website/docs/demos/server-node.md` exists with frontmatter `title: "Server Node Demo"`, `sidebar_position: 3`
- [x] "What the Demo Does" section describes always-on server peer with store-and-forward, relay, multi-device sync
- [x] Docker run section with `docker run ghcr.io/moukrea/cairn-server`
- [x] Docker Compose section references full Tier 2 stack from `demo/server-node/docker-compose.yml`
- [x] Management API examples with curl commands (health, list peers, approve pairing)
- [x] `cd website && npm run build` succeeds

## Implementation Notes
Sections:
1. **What the Demo Does**: Always-on server peer providing store-and-forward, relay, and multi-device sync.
2. **Running with Docker**: `docker run ghcr.io/moukrea/cairn-server`
3. **Docker Compose — Full Tier 2 Stack**: Reference docker-compose.yml from `demo/server-node/docker-compose.yml` (same compose file as in infrastructure/server-node.md).
4. **Management API Examples**:
   ```bash
   # Health check
   curl http://localhost:9090/health

   # List paired peers
   curl http://localhost:9090/peers

   # Approve a pairing request
   curl -X POST http://localhost:9090/peers/approve -d '{"peer_id": "..."}'
   ```

## Files to Create or Modify
- website/docs/demos/server-node.md (new)

## Verification Commands
- `cd website && npm run build`
