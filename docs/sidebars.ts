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
      items: ['ssh-agent', 'totp', 'fido2-passkeys', 'pam'],
    },
    'troubleshooting',
    'faq',
    {
      type: 'category',
      label: 'Developers',
      collapsed: true,
      items: ['developers/wasm-provider-guide', 'developers/wasm-policy-sidecar'],
    },
  ],
};

export default sidebars;
