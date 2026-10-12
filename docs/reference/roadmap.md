---
title: 'Roadmap — GreenGate'
description: 'What shipped in GreenGate 0.4 (greengate install with sandboxed scripts, deps review, baselines and exceptions, agent hook) and what is planned: container isolation for macOS and Windows, SBOM verification, Python/Go taint tracking.'
---

# Roadmap

This page tracks planned features and the reasoning behind their prioritisation.

---

## Shipped in 0.4

- **[`greengate install`](/commands/install)** replaces the planned
  `sandbox-install`: no package code runs before the complete tree is
  checked, and install scripts run one package at a time in bubblewrap with
  no network, the system read-only and credentials masked — without Docker
  or an async runtime. `watch-install`, `pip-install` and `cargo-add` route
  through it and are removed in 0.5.
- **[`deps review`](/commands/deps#deps-review-what-a-change-does-to-the-dependency-tree)**
  with fix guidance, **[baselines and exceptions](/guide/baselines-and-exceptions)**,
  offline OSV snapshots, and the **[agent hook](/guide/agents)**.

## Planned

### Feature: container isolation for macOS and Windows

Bubblewrap isolation is Linux-only. Running install scripts in a Podman or
Docker container would extend the same guarantees to macOS and Windows
runners, for teams that have a container runtime.

---

### Feature: SBOM-based install verification

Cross-reference the post-install `node_modules/` tree against the project's CycloneDX SBOM (`greengate sbom`) to detect packages that installed without appearing in the declared dependency graph.

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
| GitLab Component and other CI plugins | Tracked separately from the core binary (the GitHub Action ships with it) |
| Web UI / dashboard | Out of scope — GreenGate is intentionally a CLI/CI tool |
