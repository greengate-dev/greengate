---
title: 'Roadmap: current scope and planned work'
description: 'Current greengate capabilities and directions for future development.'
---

# Roadmap

This page distinguishes current capabilities from planned work. Roadmap entries are not release commitments.

## Available in 0.4.0

- [`install`](/commands/install): dependency policy and script inspection, with Linux bubblewrap isolation for supported phases
- [`deps review`](/commands/deps): dependency changes, licenses, advisories, release signals, and available fix guidance
- [Baselines and exceptions](/guide/baselines-and-exceptions): change-aware gates and expiring risk waivers
- [Offline audits](/commands/db): OSV snapshots and freshness-aware fallback
- [Agent hooks](/guide/agents): checks for recognized dependency-install commands
- [Shared reports](/reference/report-schema): JSON and SARIF outputs with explicit incomplete and error states

The older `sandbox-install` proposal is implemented through `install`. Python planning may execute build code; isolation availability and package-manager differences remain [documented limitations](/reference/limitations).

## Planned directions

- Container-based isolation for macOS and Windows, where bubblewrap is unavailable
- Additional verification of installed dependency inventories against declared artifacts
- Deeper Python, Go, and Rust data-flow analysis beyond their current AST rules

These features are not available in 0.4.0. Test selection currently uses direct import matching rather than a complete dependency graph.

## Product scope

greengate focuses on dependency, security, and repository gates for developers and CI. Web performance commands (`lighthouse` and `reassure`) were removed in 0.4.0. A hosted dashboard and dynamic application testing are outside the current scope.
