import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const versions: string[] = require('./versions.json');
const hasReleasedVersions = versions.length > 0;

const config: Config = {
  title: 'rosec',
  tagline: 'A Linux Secret Service daemon — multi-provider, with SSH agent and TOTP FUSE built in',
  favicon: 'img/favicon.svg',

  url: 'https://jmylchreest.github.io',
  baseUrl: '/rosec/',
  organizationName: 'jmylchreest',
  projectName: 'rosec',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'warn',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/jmylchreest/rosec/tree/main/docs/',
          includeCurrentVersion: true,
          ...(hasReleasedVersions ? {
            versions: {
              current: {
                label: 'main',
                path: 'next',
                banner: 'unreleased',
              },
            },
            lastVersion: versions[0],
          } : {}),
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      '@cmfcmf/docusaurus-search-local',
      {
        indexDocs: true,
        indexBlog: false,
        indexPages: true,
        language: 'en',
        maxSearchResults: 8,
      },
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },

    navbar: {
      title: 'rosec',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Documentation',
        },
        ...(hasReleasedVersions ? [{
          type: 'docsVersionDropdown' as const,
          position: 'right' as const,
          dropdownActiveClassDisabled: true,
        }] : []),
        {
          href: 'https://github.com/jmylchreest/rosec',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },

    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {label: 'Quickstart', to: '/docs/quickstart'},
            {label: 'Configuration', to: '/docs/configuration'},
            {label: 'CLI', to: '/docs/cli'},
            {label: 'FAQ', to: '/docs/faq'},
          ],
        },
        {
          title: 'Providers',
          items: [
            {label: 'Local vault', to: '/docs/providers/local'},
            {label: 'Bitwarden', to: '/docs/providers/bitwarden'},
            {label: 'KeePassXC', to: '/docs/providers/keepassxc-file'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/jmylchreest/rosec'},
            {label: 'Issues', href: 'https://github.com/jmylchreest/rosec/issues'},
            {label: 'Releases', href: 'https://github.com/jmylchreest/rosec/releases'},
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} rosec.`,
    },

    prism: {
      theme: prismThemes.vsDark,
      darkTheme: prismThemes.vsDark,
      additionalLanguages: ['bash', 'toml', 'rust', 'json', 'ini', 'yaml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
