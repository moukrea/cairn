# Task 001: Docusaurus Scaffolding

## Status
done

## Dependencies
- None

## Spec References
- spec/01-docusaurus-setup.md

## Scope
Initialize the Docusaurus v3 project in the `website/` directory. Create `package.json` with all required dependencies, `docusaurus.config.ts` with full site configuration, and `tsconfig.json` for TypeScript support. This is the foundational task -- all other website tasks depend on it.

## Acceptance Criteria
- [x] `website/package.json` exists with correct dependencies (`@docusaurus/core: ^3.7`, `@docusaurus/preset-classic: ^3.7`, `@docusaurus/theme-common: ^3.7`, `react: ^19`, `react-dom: ^19`)
- [x] `website/docusaurus.config.ts` exists with correct config: title "cairn", tagline "Universal peer-to-peer connectivity", url `https://moukrea.github.io`, baseUrl `/cairn/`, dark mode default, navbar with logo + docs + GitHub links, footer with GitHub + license links
- [x] `website/tsconfig.json` exists for TypeScript support
- [x] `cd website && npm install` succeeds
- [x] `cd website && npm run build` succeeds (may have broken link warnings until docs are added -- that is expected)

## Implementation Notes

### package.json
Standard Docusaurus v3 package.json with these scripts:
- `start`: `docusaurus start`
- `build`: `docusaurus build`
- `swizzle`: `docusaurus swizzle`
- `deploy`: `docusaurus deploy`
- `clear`: `docusaurus clear`
- `serve`: `docusaurus serve`

Dependencies:
```
@docusaurus/core: ^3.7
@docusaurus/preset-classic: ^3.7
@docusaurus/theme-common: ^3.7
react: ^19
react-dom: ^19
```

Dev dependencies:
```
@docusaurus/module-type-aliases: ^3.7
@docusaurus/tsconfig: ^3.7
typescript: ~5.6
```

### docusaurus.config.ts
Key configuration values:
```typescript
{
  title: "cairn",
  tagline: "Universal peer-to-peer connectivity",
  url: "https://moukrea.github.io",
  baseUrl: "/cairn/",
  organizationName: "moukrea",
  projectName: "cairn",
  trailingSlash: false,
  onBrokenLinks: 'warn',    // warn during scaffolding phase; tighten later
  onBrokenMarkdownLinks: 'warn',

  presets: [
    ['classic', {
      docs: {
        sidebarPath: './sidebars.ts',
        editUrl: 'https://github.com/moukrea/cairn/tree/main/website/',
      },
    }],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'cairn',
      logo: { alt: 'cairn logo', src: 'img/cairn.png' },
      items: [
        { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
        { href: 'https://github.com/moukrea/cairn', label: 'GitHub', position: 'right' },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [{ label: 'Getting Started', to: '/docs/getting-started/installation' }],
        },
        {
          title: 'More',
          items: [
            { label: 'GitHub', href: 'https://github.com/moukrea/cairn' },
            { label: 'License', href: 'https://github.com/moukrea/cairn/blob/main/LICENSE' },
          ],
        },
      ],
    },
  },
}
```

### tsconfig.json
Extend `@docusaurus/tsconfig`:
```json
{
  "extends": "@docusaurus/tsconfig",
  "compilerOptions": {
    "baseUrl": "."
  }
}
```

Also create a minimal `website/sidebars.ts` (empty sidebar) and a placeholder `website/docs/index.md` so the build doesn't fail entirely. The full sidebar config is in task 002.

## Files to Create or Modify
- website/package.json (new)
- website/docusaurus.config.ts (new)
- website/tsconfig.json (new)

## Verification Commands
- `cd website && npm install`
- `cd website && npm run build`
