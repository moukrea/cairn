# Task 008: Documentation CI/CD Workflow

## Status
done

## Dependencies
- 001-docusaurus-scaffolding (needs website/ directory with build scripts)

## Spec References
- spec/01-docusaurus-setup.md (CI/CD section)

## Scope
Create the GitHub Actions workflow file for building and deploying the Docusaurus site to GitHub Pages on pushes to `main` that modify files under `website/`.

## Acceptance Criteria
- [x] `.github/workflows/docs.yml` exists with correct workflow configuration
- [x] Workflow triggers on push to `main` with path filter `website/**`
- [x] Build job: checkout, setup Node 22, cache npm, `npm ci`, `npm run build`, upload pages artifact
- [x] Deploy job: depends on build, deploys to GitHub Pages
- [x] Correct permissions: `contents: read`, `pages: write`, `id-token: write`
- [x] Concurrency group `pages` with `cancel-in-progress: true`

## Implementation Notes

### File: `.github/workflows/docs.yml`

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

The site deploys to `https://moukrea.github.io/cairn/`. GitHub repository setting required: Pages source set to "GitHub Actions".

## Files to Create or Modify
- .github/workflows/docs.yml (new)

## Verification Commands
- `cat .github/workflows/docs.yml` (manual review -- cannot test GH Actions locally)
