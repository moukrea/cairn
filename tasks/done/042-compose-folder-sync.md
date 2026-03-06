# Task 042: Docker Compose -- Folder Sync Demo

## Status
done

## Dependencies
- 040-dockerfiles-folder-sync (Dockerfiles must exist for compose to reference)

## Spec References
- spec/07-demo-dockerization.md

## Scope
Create the Docker Compose file for the folder-sync demo that allows running two peers with volume-mounted sync directories.

## Acceptance Criteria
- [x] `demo/folder-sync/docker-compose.yml` exists and is valid YAML
- [x] Defines `peer-a` and `peer-b` services building from `Dockerfile.rust`
- [x] `peer-a` mounts `./sync-a:/sync` and uses `command: ["--dir", "/sync", "--pair-pin"]`
- [x] `peer-b` mounts `./sync-b:/sync` and uses `command: ["--dir", "/sync"]`
- [x] `docker compose -f demo/folder-sync/docker-compose.yml config` validates without errors

## Implementation Notes
Build context is `../../` (repo root) from the compose file location.

Exact compose file content from spec:

```yaml
services:
  peer-a:
    build:
      context: ../../
      dockerfile: demo/folder-sync/Dockerfile.rust
    volumes:
      - ./sync-a:/sync
    command: ["--dir", "/sync", "--pair-pin"]

  peer-b:
    build:
      context: ../../
      dockerfile: demo/folder-sync/Dockerfile.rust
    volumes:
      - ./sync-b:/sync
    command: ["--dir", "/sync"]
```

## Files to Create or Modify
- `demo/folder-sync/docker-compose.yml` (new)

## Verification Commands
- `docker compose -f demo/folder-sync/docker-compose.yml config`
