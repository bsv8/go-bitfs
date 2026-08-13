const config = {
  title: 'go-bitfs',
  tagline: 'Source-driven BitFS v3 SDK documentation',
  favicon: 'img/favicon.svg',
  url: process.env.DOCS_SITE_URL || process.env.CF_PAGES_URL || 'http://localhost:3000',
  baseUrl: '/',
  organizationName: 'bsv8',
  projectName: 'go-bitfs',
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  markdown: {hooks: {onBrokenMarkdownLinks: 'throw'}},
  trailingSlash: false,
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh-CN'],
    localeConfigs: {
      en: {label: 'English', htmlLang: 'en-US'},
      'zh-CN': {label: '简体中文', htmlLang: 'zh-CN'},
    },
  },
  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: 'docs',
          sidebarPath: require.resolve('./sidebars.js'),
          showLastUpdateTime: true,
          editUrl: 'https://github.com/bsv8/go-bitfs/edit/main/website/',
        },
        blog: false,
        theme: {customCss: require.resolve('./src/css/custom.css')},
      },
    ],
  ],
  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'api',
        path: 'generated-api',
        routeBasePath: 'api',
        sidebarPath: require.resolve('./sidebars-api.js'),
        showLastUpdateTime: false,
      },
    ],
  ],
  themes: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {indexDocs: true, indexPages: true, indexBlog: false, language: ['en', 'zh'], highlightSearchTermsOnTargetPage: true},
    ],
  ],
  themeConfig: {
    image: 'img/go-bitfs-social-card.svg',
    navbar: {
      title: 'go-bitfs',
      logo: {alt: 'go-bitfs mark', src: 'img/logo.svg'},
      items: [
        {type: 'docSidebar', sidebarId: 'docsSidebar', position: 'left', label: 'Guides'},
        {to: '/api/', label: 'API Reference', position: 'left'},
        {href: 'https://github.com/bsv8/go-bitfs', label: 'GitHub', position: 'right'},
        {type: 'localeDropdown', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {title: 'Explore', items: [{label: 'Guides', to: '/docs/sdk/protocol-foundations-and-cbor'}, {label: 'API Reference', href: '/api/'}]},
        {title: 'Community', items: [{label: 'GitHub', href: 'https://github.com/bsv8/go-bitfs'}]},
      ],
      copyright: `Copyright © ${new Date().getFullYear()} go-bitfs contributors.`,
    },
    prism: {theme: require('prism-react-renderer').themes.github, darkTheme: require('prism-react-renderer').themes.dracula},
  },
};

module.exports = config;
