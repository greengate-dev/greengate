---
layout: home

hero:
  name: greengate
  text: Dependency checks and install protection.
  tagline: Review dependency changes, inspect install scripts, and apply security gates from one Rust CLI. For developers, CI pipelines, and coding agents.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Gate an install
      link: /commands/install
    - theme: alt
      text: View on GitHub
      link: https://github.com/greengate-dev/greengate

features:
  - title: Install-time controls
    details: "Plan and inspect supported installs, then restrict scripts with Linux bubblewrap when available. Require isolation through policy. Package managers differ: Python metadata resolution can execute build code during planning."
  - title: Dependency review
    details: "Review lockfile changes for advisories, licenses, release risk, provenance signals, and available fixes. Apply registry and source policies across supported dependency files."
  - title: Coding-agent hooks
    details: "Check supported install commands before an agent executes them. The Claude Code hook denies blocking findings and asks for review when checks are uncertain."
  - title: Vulnerability audits
    details: "Audit supported registry dependencies with OSV or offline snapshots. Reports distinguish incomplete checks from a clean result."
  - title: Secrets and static analysis
    details: "Scan for secrets and PII, and inspect syntax trees for security signals in JavaScript, TypeScript, Python, Go, and Rust. Baselines and expiring exceptions keep accepted findings visible."
  - title: SBOMs and signing
    details: "Generate CycloneDX inventories with dependency graphs and metadata. Sign and verify files with cosign, using an expected signer identity. Signing does not certify compliance."
  - title: Repository quality gates
    details: "Check GitHub Actions workflows, Kubernetes manifests, Dockerfiles, coverage, and PR diffs. Suggest tests using direct static imports."
  - title: Reports for CI
    details: "Merge gate results into JSON or SARIF reports with passed, findings, incomplete, and error statuses. The CLI has no Node.js or Python runtime dependency; optional integrations need their own tools."
---

See [Getting started](/guide/getting-started) to install greengate and [Migrating to 0.4](/guide/migrating-to-0.4) for upgrade guidance.
