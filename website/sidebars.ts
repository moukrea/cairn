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
