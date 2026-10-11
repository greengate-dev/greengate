---
title: 'Roadmap — GreenGate'
description: 'GreenGate shipped features (test impact analysis, zero-trust supply chain hardening) and planned features: sandbox-install with network isolation, SBOM verification, Python/Go taint tracking.'
---

# Roadmap

This page tracks planned features and the reasoning behind their prioritisation.

---

## Planned

### Feature: `sandbox-install` (Full Network Isolation)

**Status:** Planned — implementation deferred pending architectural decision.

**What it does:**

`greengate sandbox-install` would go one level deeper than `watch-install`. Instead of observing what a package manager does on the host filesystem, it would run the entire install inside an isolated container, then extract only the verified output:

1. Pull a minimal `node:alpine` image via the Docker API
2. Mount the project's `package.json` / lock file read-only
3. Run `npm ci` (or equivalent) inside the container with `--network=none` (no outbound network access during install)
4. Cryptographically hash the container's `node_modules/` output and compare it against the expected dependency tree from the lock file
5. Extract only the verified `node_modules/` to the host

This provides a stronger guarantee than `watch-install` because:

| | `watch-install` | `sandbox-install` |
|---|---|---|
| Phantom file detection | Yes | Yes (no host filesystem to write to) |
| Static script analysis | Yes | Yes (pre-flight scan) |
| Network exfiltration during install | Detected via script scan | Blocked — `--network=none` |
| Host process isolation | No | Yes — install never runs on host |
| Requires Docker | No | Yes |

**Why it is deferred:**

The primary implementation dependency, `bollard` (the Rust Docker API crate), is fully async and requires a `tokio` runtime. GreenGate is currently synchronous (`rayon`-based). Adding `tokio` is a non-trivial architectural change and binary size increase that needs careful consideration before v1.0.

Additionally, `sandbox-install` requires Docker to be running on the host — which breaks GreenGate's zero-runtime-dependency guarantee for that command. The plan is to make it gracefully fail with a clear error when Docker is not present, rather than requiring it globally.

**Tracking:** Contributions welcome. See [CONTRIBUTING.md](https://github.com/greengate-dev/greengate/blob/main/CONTRIBUTING.md) for architecture guidance.

---

### Feature: SBOM-based install verification

Cross-reference the post-install `node_modules/` tree against the project's CycloneDX SBOM (`greengate sbom`) to detect packages that installed without appearing in the declared dependency graph. Complements `watch-install` for detecting dependency confusion attacks.

---

### Feature: `scan` improvements

- **Python taint tracking** — extend the existing JS/TS taint engine to Python (Flask/Django request sources → SQL/command injection sinks)
- **Go taint tracking** — similar, targeting `net/http` request sources
- **Rust taint tracking** — existing AST rules already flag `unsafe`, `Command::new`, `.unwrap()`, and `.expect()`; future analysis would track untrusted input into command arguments

---

## Not planned

| Feature | Reason |
|---|---|
| Native Windows exec-drop detection (beyond extension heuristics) | Requires PE parsing or Windows API calls — out of scope for a CLI tool |
| CI/CD platform plugins (GitHub Action, GitLab Component) | Tracked separately from the core binary |
| Web UI / dashboard | Out of scope — GreenGate is intentionally a CLI/CI tool |
