# Task 043: Docker Compose -- Server Node

## Status
done

## Dependencies
- None

## Spec References
- spec/07-demo-dockerization.md

## Scope
Create the Docker Compose file for the server-node demo that runs a full Tier 2 stack with signaling, relay, and a server node with management API.

## Acceptance Criteria
- [ ] `demo/server-node/docker-compose.yml` exists and is valid YAML
- [ ] Defines `signaling`, `relay`, and `server` services with correct environment variables
- [ ] Server service exposes port `9090:9090` and mounts a `server-data` volume
- [ ] Server connects to signaling via `ws://signaling:8443` and relay via `turn:relay:3478`
- [ ] `docker compose -f demo/server-node/docker-compose.yml config` validates without errors

## Implementation Notes
The `demo/server-node/Dockerfile` already exists. This task only creates the compose file.

Exact compose file content from spec:

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
- `demo/server-node/docker-compose.yml` (new)

## Verification Commands
- `docker compose -f demo/server-node/docker-compose.yml config`
