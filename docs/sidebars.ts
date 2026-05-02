import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'intro',
    'installation',
    'quickstart',
    'configuration',
    'cli',
    {
      type: 'category',
      label: 'Providers',
      collapsed: false,
      items: [
        'providers/capabilities',
        'providers/local',
        'providers/bitwarden',
        'providers/bitwarden-sm',
        'providers/keepassxc-file',
      ],
    },
    {
      type: 'category',
      label: 'Integrations',
      items: ['ssh-agent', 'totp', 'pam'],
    },
    'troubleshooting',
    'faq',
    {
      type: 'category',
      label: 'Developers',
      collapsed: true,
      items: ['developers/wasm-provider-guide'],
    },
  ],
};

export default sidebars;
