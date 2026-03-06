# 09 — CI/CD Workflows

## Cross-References

- **Depends on: `01-docusaurus-setup.md`** — The docs workflow builds the Docusaurus site defined there.
- **Depends on: `07-demo-dockerization.md`** — The tag-release workflow builds and pushes the Docker images defined there.

---

## 1. Documentation Deployment Workflow

### 1.1 File Path

`.github/workflows/docs.yml`

### 1.2 Trigger

Push to `main` branch that modifies files under `website/`.

### 1.3 Target

Docusaurus site deploys to `https://moukrea.github.io/cairn/`.

**Prerequisite**: GitHub repository setting must have Pages source set to "GitHub Actions".

### 1.4 Full Workflow

```yaml
name: Deploy Documentation

on:
  push:
    branches: [main]
    paths:
      - 'website/**'

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: website/package-lock.json
      - run: cd website && npm ci
      - run: cd website && npm run build
      - uses: actions/upload-pages-artifact@v3
        with:
          path: website/build

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

### 1.5 Build Commands

```bash
# Development
cd website && npm install && npm start

# Production build
cd website && npm ci && npm run build

# Output: website/build/ (static files)
```

### 1.6 Build Validation

The docs workflow must fail the build if:

- Any broken internal links (Docusaurus built-in check)
- Any missing images
- TypeScript compilation errors in custom components

---

## 2. Demo Docker Image Publishing

### 2.1 Integration Point

Add to the existing `.github/workflows/tag-release.yml` (or a new `demo-images.yml`).

### 2.2 Trigger

Build and push demo Docker images when a release tag is created.

### 2.3 Registry

All images published to `ghcr.io` under the `moukrea` namespace.

Authentication: `GITHUB_TOKEN` from the workflow (already configured for existing service images).

### 2.4 Matrix Strategy

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

The server-node image (`ghcr.io/moukrea/cairn-server`) is built separately (already has a Dockerfile at `demo/server-node/Dockerfile`).

### 2.5 Image Naming

Each matrix entry produces an image named:

```
ghcr.io/moukrea/cairn-demo-{demo}-{lang}
```

Tagged with both `latest` and `{version}` (from the release tag).

### 2.6 Target Platforms

All demo images must be built for:

- `linux/amd64`
- `linux/arm64`

---

## 3. CI Validation

- Docs workflow: build succeeds, deploy succeeds
- Tag-release workflow: demo images build and push to GHCR
- Smoke test: each Docker image starts and prints help/usage when run with `--help`
