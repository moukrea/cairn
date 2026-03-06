# Task 002: Sidebar Configuration, Custom CSS, and Static Assets

## Status
done

## Dependencies
- 001-docusaurus-scaffolding (needs docusaurus.config.ts and package.json)

## Spec References
- spec/01-docusaurus-setup.md

## Scope
Create the full sidebar navigation configuration, custom CSS theme overrides, and copy the cairn logo to the static assets directory. This completes the site shell so doc content tasks can build on it.

## Acceptance Criteria
- [x] `website/sidebars.ts` contains all six sidebar categories (Getting Started, Guides, Infrastructure, Demo Applications, API Reference, Internals) with correct document paths
- [x] `website/src/css/custom.css` exists with dark-mode-compatible theme overrides using Docusaurus CSS variables
- [x] `website/static/img/cairn.png` exists (copied from repo root `cairn.png`)
- [x] Placeholder `.md` files exist for all sidebar-referenced docs so the build doesn't break on missing files
- [x] `cd website && npm run build` succeeds without broken link errors

## Implementation Notes

### sidebars.ts
```typescript
import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
        'getting-started/first-app',
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      items: [
        'guides/pairing',
        'guides/sessions',
        'guides/channels',
        'guides/server-mode',
        'guides/mesh-routing',
      ],
    },
    {
      type: 'category',
      label: 'Infrastructure',
      items: [
        'infrastructure/overview',
        'infrastructure/signaling',
        'infrastructure/relay',
        'infrastructure/server-node',
        'infrastructure/cloudflare',
      ],
    },
    {
      type: 'category',
      label: 'Demo Applications',
      items: [
        'demos/messaging',
        'demos/folder-sync',
        'demos/server-node',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'api/node',
        'api/session',
        'api/events',
        'api/config',
        'api/errors',
      ],
    },
    {
      type: 'category',
      label: 'Internals',
      items: [
        'internals/wire-protocol',
        'internals/cryptography',
      ],
    },
  ],
};

export default sidebars;
```

### custom.css
Minimal CSS with Docusaurus CSS variables for dark mode compatibility. Set primary color to a cairn-themed tone. Example:
```css
:root {
  --ifm-color-primary: #2e8555;
  --ifm-color-primary-dark: #29784c;
  --ifm-color-primary-darker: #277148;
  --ifm-color-primary-darkest: #205d3b;
  --ifm-color-primary-light: #33925d;
  --ifm-color-primary-lighter: #359962;
  --ifm-color-primary-lightest: #3cad6e;
  --ifm-code-font-size: 95%;
  --docusaurus-highlighted-code-line-bg: rgba(0, 0, 0, 0.1);
}

[data-theme='dark'] {
  --ifm-color-primary: #25c2a0;
  --ifm-color-primary-dark: #21af90;
  --ifm-color-primary-darker: #1fa588;
  --ifm-color-primary-darkest: #1a8870;
  --ifm-color-primary-light: #29d5b0;
  --ifm-color-primary-lighter: #32d8b4;
  --ifm-color-primary-lightest: #4fddbf;
  --docusaurus-highlighted-code-line-bg: rgba(0, 0, 0, 0.3);
}
```

### Static Assets
Copy `cairn.png` from repo root to `website/static/img/cairn.png`.

### Placeholder Docs
Create minimal placeholder `.md` files for every sidebar entry (except getting-started/* which will be filled by tasks 005-007). Each placeholder should have a frontmatter title and a "Coming soon" note. This ensures the build succeeds. Directories needed:
- `website/docs/getting-started/`
- `website/docs/guides/`
- `website/docs/infrastructure/`
- `website/docs/demos/`
- `website/docs/api/`
- `website/docs/internals/`

## Files to Create or Modify
- website/sidebars.ts (new or replace placeholder from 001)
- website/src/css/custom.css (new)
- website/static/img/cairn.png (copy)
- website/docs/**/*.md (placeholder files, ~20 files)

## Verification Commands
- `cd website && npm run build`
- `test -f website/static/img/cairn.png`
