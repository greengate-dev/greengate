---
title: 'Getting Started with GreenGate'
description: 'Install GreenGate Rust DevOps CLI and run your first secret scan, supply chain check, and dependency audit in under a minute. Single binary for macOS, Linux, and Windows — no Node or Python required.'
---

# Getting Started

GreenGate is a single compiled Rust binary — no runtime dependencies, no package managers to fight.

## Installation

### Pre-compiled binary (recommended)

**macOS (Apple Silicon / M1+):**
```bash
curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-macos-arm64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**macOS (Intel):**
```bash
curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-macos-amd64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Linux (x64):**
```bash
curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Windows (x64) — PowerShell:**
```powershell
Invoke-WebRequest -Uri "https://github.com/greengate-dev/greengate/releases/latest/download/greengate-windows-amd64.exe" `
  -OutFile "$env:USERPROFILE\.local\bin\greengate.exe"
# Add $env:USERPROFILE\.local\bin to your PATH if not already present
```

### Build from source (requires Rust 1.85+)

```bash
cargo install --git https://github.com/greengate-dev/greengate
```

### Verify installation

```bash
greengate --version
# greengate 0.4.0
```

## Quick Start

```bash
# Supply-chain safe install — monitors for postinstall droppers in real time
greengate watch-install npm ci

# Scan for secrets and run SAST on JS/TS files
greengate scan

# Audit dependencies for known CVEs
greengate audit

# Analyze a PR: Complexity Score + new-code coverage gaps
greengate review --base main --coverage-file coverage/lcov.info

# Lint all Kubernetes YAML files
greengate lint --dir ./k8s

# Enforce 80% minimum test coverage
greengate coverage --file coverage/lcov.info --min 80

# Install as a git pre-commit hook
greengate install-hooks

# Gate on Lighthouse web performance scores
greengate lighthouse --url https://yourapp.com

# Gate on React component performance regressions
greengate reassure
```

## What GreenGate solves

| Problem | Command |
|---|---|
| Postinstall dropper attacking your npm install | `greengate watch-install` |
| Vulnerable dependencies shipping to production | `greengate audit` |
| Hardcoded secrets pushed to git | `greengate scan` |
| XSS, eval, command injection in JS/TS | `greengate scan` (SAST) |
| PR too complex — hard to estimate review time | `greengate review` |
| New code added without test coverage | `greengate review --coverage-file lcov.info` |
| Kubernetes manifests missing resource limits | `greengate lint` |
| Test coverage silently dropping | `greengate coverage` |
| Secrets committed before anyone notices | `greengate install-hooks` |
| Lighthouse score regressing between deploys | `greengate lighthouse` |
| React component render performance regressing | `greengate reassure` |

## Next steps

- Set up a [configuration file](/reference/config) to share settings across all commands
- Integrate with [GitHub Actions or GitLab CI](/guide/ci-integration)
- Explore individual [command references](/commands/scan)
- See [PR review](/commands/review) for the `review` subcommand
