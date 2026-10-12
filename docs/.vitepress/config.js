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
  title: 'GreenGate',
  description: 'Rust CLI for zero-trust supply chain protection (npm/pip/cargo), secret scanning, AST-based SAST, AI-assisted triage, SBOM attestation, CI config linting, test impact analysis, coverage gates, and OTLP metrics — single zero-dependency binary.',
  base: '/greengate/',

  head: [
    // Open Graph
    ['meta', { property: 'og:title', content: 'GreenGate — Rust DevOps Security CLI' }],
    ['meta', { property: 'og:description', content: 'Zero-trust supply chain gate, secret scanning, AST-based SAST, test impact analysis, coverage gates, and Kubernetes linting — one Rust binary, no runtime dependencies.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:url', content: 'https://greengate-dev.github.io/greengate/' }],
    ['meta', { property: 'og:image', content: 'https://greengate-dev.github.io/greengate/og-image.png' }],
    // Twitter Card
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: 'GreenGate — Rust DevOps Security CLI' }],
    ['meta', { name: 'twitter:description', content: 'Zero-trust supply chain gate, secret scanning, SAST, test impact analysis, and coverage gates in a single Rust binary.' }],
    ['meta', { name: 'twitter:image', content: 'https://greengate-dev.github.io/greengate/og-image.png' }],
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
    siteTitle: 'GreenGate',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/commands/watch-install' },
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
          { text: '🔒 watch-install', link: '/commands/watch-install' },
          { text: '🐍 pip-install', link: '/commands/pip-install' },
          { text: '🦀 cargo-add', link: '/commands/cargo-add' },
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
          { text: 'coverage', link: '/commands/coverage' },
          { text: 'lint', link: '/commands/lint' },
          { text: 'docker-lint', link: '/commands/docker-lint' },
          { text: 'lighthouse', link: '/commands/lighthouse' },
          { text: 'reassure', link: '/commands/reassure' },
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
