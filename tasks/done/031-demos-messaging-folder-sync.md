# Task 031: Demo Docs — Messaging & Folder Sync

## Status
done

## Dependencies
- 002-sidebar-css-assets (needs sidebar config and placeholder docs structure)

## Spec References
- spec/05-infrastructure-content.md (File 6: messaging.md, File 7: folder-sync.md)

## Scope
Create the messaging demo walkthrough and folder sync demo walkthrough documentation pages covering Docker deployment, Docker Compose, CLI flags, interactive commands, and custom server configuration.

## Acceptance Criteria
- [x] File `website/docs/demos/messaging.md` exists with frontmatter `title: "Messaging Demo"`, `sidebar_position: 1`
- [x] Messaging demo covers Docker run, Docker Compose (Tier 0 and Tier 1), CLI flags, interactive commands, custom servers
- [x] File `website/docs/demos/folder-sync.md` exists with frontmatter `title: "Folder Sync Demo"`, `sidebar_position: 2`
- [x] Folder sync demo covers Docker run with volume mount, Docker Compose, CLI flags, mesh sync with 3+ devices
- [x] `cd website && npm run build` succeeds

## Implementation Notes
### messaging.md
Sections:
1. **What the Demo Does**: Interactive P2P encrypted chat between two peers.
2. **Running with Docker**: `docker run -it ghcr.io/moukrea/cairn-demo-messaging-rust`. Language variants: `-rust`, `-ts`, `-go`, `-py`, `-php`.
3. **Running with Docker Compose**:
   - Basic (Tier 0): `docker compose up peer-a peer-b`
   - With infrastructure (Tier 1): `docker compose --profile infra up`
4. **CLI Flags**: `--pair-pin`, `--enter-pin XXXX-XXXX`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link <uri>`, `--signal <url>`, `--turn <url>`, `--verbose`
5. **Interactive Commands**: `/status` (connection status), `/quit` (exit)
6. **Connecting to Custom Servers**: Pass `--signal` and `--turn` flags.

### folder-sync.md
Sections:
1. **What the Demo Does**: Real-time P2P file synchronization between two directories.
2. **Running with Docker**: `docker run -it -v ./my-files:/sync ghcr.io/moukrea/cairn-demo-folder-sync-rust --dir /sync --pair-pin`
3. **Running with Docker Compose**: `docker compose up peer-a peer-b`. Sync dirs: `./sync-a` and `./sync-b` on host.
4. **CLI Flags**: `--dir <path>`, `--pair-pin`, `--enter-pin XXXX-XXXX`, `--pair-qr`, `--scan-qr`, `--pair-link`, `--from-link <uri>`, `--mesh`, `--server-hub`, `--signal <url>`, `--turn <url>`, `--verbose`
5. **Mesh Sync with 3+ Devices**: How to use `--mesh` flag for multi-device sync scenarios.

## Files to Create or Modify
- website/docs/demos/messaging.md (new)
- website/docs/demos/folder-sync.md (new)

## Verification Commands
- `cd website && npm run build`
