# Task 045: CI/CD -- Demo Docker Image Publishing

## Status
done

## Dependencies
- 039-dockerfiles-messaging (messaging Dockerfiles must exist)
- 040-dockerfiles-folder-sync (folder-sync Dockerfiles must exist)

## Spec References
- spec/09-cicd-workflows.md

## Scope
Add a GitHub Actions workflow (or extend the existing `tag-release.yml`) to build and publish all demo Docker images to `ghcr.io` when a release tag is created. Uses a matrix strategy to build all 10 demo images plus the server-node image.

## Acceptance Criteria
- [x] Workflow triggers on release tag creation
- [x] Matrix strategy covers all 10 demo images (5 messaging + 5 folder-sync)
- [x] Each image is named `ghcr.io/moukrea/cairn-demo-{demo}-{lang}` and tagged with both `latest` and `{version}`
- [x] Images are built for both `linux/amd64` and `linux/arm64` platforms
- [x] Authenticates to GHCR using `GITHUB_TOKEN`
- [x] Server-node image (`ghcr.io/moukrea/cairn-server`) is also built and published
- [x] Smoke test: each image starts and prints help/usage when run with `--help`

## Implementation Notes
This can be added to the existing `.github/workflows/tag-release.yml` or a new `demo-images.yml`.

Matrix strategy from spec:

```yaml
strategy:
  matrix:
    include:
      - demo: messaging
        lang: rust
        dockerfile: demo/messaging/Dockerfile.rust
      - demo: messaging
        lang: ts
        dockerfile: demo/messaging/Dockerfile.typescript
      - demo: messaging
        lang: go
        dockerfile: demo/messaging/Dockerfile.go
      - demo: messaging
        lang: py
        dockerfile: demo/messaging/Dockerfile.python
      - demo: messaging
        lang: php
        dockerfile: demo/messaging/Dockerfile.php
      - demo: folder-sync
        lang: rust
        dockerfile: demo/folder-sync/Dockerfile.rust
      - demo: folder-sync
        lang: ts
        dockerfile: demo/folder-sync/Dockerfile.typescript
      - demo: folder-sync
        lang: go
        dockerfile: demo/folder-sync/Dockerfile.go
      - demo: folder-sync
        lang: py
        dockerfile: demo/folder-sync/Dockerfile.python
      - demo: folder-sync
        lang: php
        dockerfile: demo/folder-sync/Dockerfile.php
```

Each matrix entry produces: `ghcr.io/moukrea/cairn-demo-{demo}-{lang}`
Tagged with both `latest` and `{version}` (extracted from the release tag).

Authentication: `GITHUB_TOKEN` from the workflow (already configured for existing service images).

Target platforms: `linux/amd64`, `linux/arm64` (use `docker/build-push-action` with `platforms` option).

## Files to Create or Modify
- `.github/workflows/tag-release.yml` (modify) or `.github/workflows/demo-images.yml` (new)

## Verification Commands
- Validate YAML syntax of the workflow file
- `act` or manual inspection of workflow structure
