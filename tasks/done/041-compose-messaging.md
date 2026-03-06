# Task 041: Docker Compose -- Messaging Demo

## Status
done

## Dependencies
- 039-dockerfiles-messaging (Dockerfiles must exist for compose to reference)

## Spec References
- spec/07-demo-dockerization.md

## Scope
Create the Docker Compose file for the messaging demo that allows running two peers locally with optional signaling and relay infrastructure.

## Acceptance Criteria
- [ ] `demo/messaging/docker-compose.yml` exists and is valid YAML
- [ ] Defines `peer-a` and `peer-b` services building from `Dockerfile.rust` with `stdin_open: true` and `tty: true`
- [ ] Defines `signaling` and `relay` services using published images under `profiles: ["infra"]`
- [ ] All services share a `cairn` network
- [ ] `docker compose -f demo/messaging/docker-compose.yml config` validates without errors
- [ ] Basic usage works: `docker compose up peer-a peer-b`
- [ ] Infrastructure usage works: `docker compose --profile infra up`

## Implementation Notes
Build context is `../../` (repo root) from the compose file location.

Exact compose file content from spec:

```yaml
services:
  peer-a:
    build:
      context: ../../
      dockerfile: demo/messaging/Dockerfile.rust
    stdin_open: true
    tty: true
    command: ["--pair-pin"]
    networks: [cairn]

  peer-b:
    build:
      context: ../../
      dockerfile: demo/messaging/Dockerfile.rust
    stdin_open: true
    tty: true
    # User enters PIN from peer-a
    networks: [cairn]

  # Optional infrastructure
  signaling:
    image: ghcr.io/moukrea/cairn-signal:latest
    networks: [cairn]
    profiles: ["infra"]

  relay:
    image: ghcr.io/moukrea/cairn-relay:latest
    networks: [cairn]
    profiles: ["infra"]

networks:
  cairn:
```

Usage:
- Basic (Tier 0): `docker compose up peer-a peer-b`
- With infrastructure (Tier 1): `docker compose --profile infra up`

## Files to Create or Modify
- `demo/messaging/docker-compose.yml` (new)

## Verification Commands
- `docker compose -f demo/messaging/docker-compose.yml config`
