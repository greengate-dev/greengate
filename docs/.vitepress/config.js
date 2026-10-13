import { defineConfig } from 'vitepress'

// Escape {{ }} in rendered code blocks so Vue's template compiler doesn't
// try to evaluate GitHub Actions / shell expressions as interpolations.
function escapeTemplateInterpolations(md) {
  const escapeOutput = (html) =>
    html.replace(/\{\{/g, '&#123;&#123;').replace(/\}\}/g, '&#125;&#125;')

  const fence = md.renderer.rules.fence?.bind(md.renderer.rules)
  md.renderer.rules.fence = (tokens, idx, options, env, self) => {
    const result = fence
      ? fence(tokens, idx, options, env, self)
      : self.renderToken(tokens, idx, options)
    return escapeOutput(result)
  }

  const codeInline = md.renderer.rules.code_inline?.bind(md.renderer.rules)
  md.renderer.rules.code_inline = (tokens, idx, options, env, self) => {
    const result = codeInline
      ? codeInline(tokens, idx, options, env, self)
      : self.renderToken(tokens, idx, options)
    return escapeOutput(result)
  }
}

export default defineConfig({
  title: 'greengate',
  description: 'Dependency checks and install protection for developers, CI, and coding agents, with static repository gates and shared reports.',
  base: '/greengate/',

  head: [
    // Open Graph
    ['meta', { property: 'og:title', content: 'greengate: dependency checks and install protection' }],
    ['meta', { property: 'og:description', content: 'Review dependency changes, inspect installs, and report repository security checks from one Rust CLI.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:url', content: 'https://greengate-dev.github.io/greengate/' }],
    // Twitter Card
    ['meta', { name: 'twitter:card', content: 'summary' }],
    ['meta', { name: 'twitter:title', content: 'greengate: dependency checks and install protection' }],
    ['meta', { name: 'twitter:description', content: 'Dependency policy, install-time controls, secret scanning, and CI reports in one Rust CLI.' }],
    // Discovery keywords (Bing, Yandex, DuckDuckGo)
    ['meta', { name: 'keywords', content: 'rust devops cli, supply chain security, npm security, secret scanning, SAST, test impact analysis, kubernetes linting, coverage gate, dependency audit, CI CD security, greengate' }],
    ['link', { rel: 'icon', href: '/greengate/favicon.ico' }],
    ['link', { rel: 'canonical', href: 'https://greengate-dev.github.io/greengate/' }],
  ],

  markdown: {
    config: escapeTemplateInterpolations,
  },

  themeConfig: {
    logo: null,
    siteTitle: 'greengate',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/commands/install' },
      { text: 'Reference', link: '/reference/config' },
      { text: 'GitHub', link: 'https://github.com/greengate-dev/greengate' },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'CI/CD Integration', link: '/guide/ci-integration' },
          { text: 'Use Cases & Scenarios', link: '/guide/use-cases' },
          { text: 'Baselines & Exceptions', link: '/guide/baselines-and-exceptions' },
          { text: 'AI Agents', link: '/guide/agents' },
          { text: 'Migrating to 0.4', link: '/guide/migrating-to-0.4' },
          { text: 'Configuration File', link: '/reference/config' },
        ],
      },
      {
        text: 'Commands — Security',
        items: [
          { text: '🛡️ install', link: '/commands/install' },
          { text: 'watch-install (deprecated)', link: '/commands/watch-install' },
          { text: 'pip-install (deprecated)', link: '/commands/pip-install' },
          { text: 'cargo-add (deprecated)', link: '/commands/cargo-add' },
          { text: 'scan', link: '/commands/scan' },
          { text: 'ci-lint', link: '/commands/ci-lint' },
          { text: 'image-scan', link: '/commands/image-scan' },
          { text: 'audit', link: '/commands/audit' },
          { text: 'db', link: '/commands/db' },
          { text: 'deps', link: '/commands/deps' },
          { text: 'sbom', link: '/commands/sbom' },
        ],
      },
      {
        text: 'Commands — Quality',
        items: [
          { text: '🎯 tia', link: '/commands/tia' },
          { text: 'review', link: '/commands/review' },
          { text: 'provenance', link: '/commands/provenance' },
          { text: 'coverage', link: '/commands/coverage' },
          { text: 'lint', link: '/commands/lint' },
          { text: 'docker-lint', link: '/commands/docker-lint' },
        ],
      },
      {
        text: 'Commands — Workflow',
        items: [
          { text: 'run', link: '/commands/run' },
          { text: 'init', link: '/commands/init' },
          { text: 'install-hooks', link: '/commands/install-hooks' },
          { text: 'watch', link: '/commands/watch' },
          { text: 'check-config', link: '/commands/check-config' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/reference/config' },
          { text: 'Secret Patterns', link: '/reference/secret-patterns' },
          { text: 'SAST Rules', link: '/reference/sast-rules' },
          { text: 'Telemetry & Metrics', link: '/reference/telemetry' },
          { text: 'Exit Codes', link: '/reference/exit-codes' },
          { text: 'Report Schema', link: '/reference/report-schema' },
          { text: 'Output Formats', link: '/reference/output-formats' },
          { text: 'Limitations', link: '/reference/limitations' },
          { text: 'Roadmap', link: '/reference/roadmap' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/greengate-dev/greengate' },
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © greengate-dev',
    },

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/greengate-dev/greengate/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
