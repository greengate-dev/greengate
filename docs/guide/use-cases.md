---
title: 'Use cases for greengate'
description: 'Apply dependency policy, install controls, agent checks, and repository security gates in local and CI workflows.'
---

# Use cases

Use greengate to review dependency changes, restrict supported install phases, and report repository checks in a shared format. These examples assume greengate is installed; see [Getting started](/guide/getting-started).

## Review a dependency change

```bash
greengate deps review --base origin/main
greengate deps check --base origin/main
greengate audit
```

The review reports changes, licenses, introduced and fixed advisories, release risk, and available remediation. `audit` separately covers known advisories for supported registry dependencies, including unchanged ones.

## Restrict an npm install in CI

On Linux with working bubblewrap:

```bash
greengate install --isolate bwrap npm ci
```

The gate fetches with lifecycle scripts disabled, inspects dependency scripts, and handles approved dependency scripts under restrictions. Project lifecycle scripts still run normally. For builds that need network access:

```toml
[supply_chain]
require_isolation = true
script_network = ["puppeteer"]
```

The unisolated fallback provides monitoring rather than prevention. Read the [package-manager boundaries](/commands/install) before enabling it.

## Check commands from a coding agent

```bash
greengate check-command -- "cd web && npm install some-package"
```

The check recognizes supported installs and evaluates their plans. It cannot discover an install hidden in an arbitrary script or alias. Python planning can run source-build code; the same isolation policy applies. See [AI agents](/guide/agents).

## Catch secrets before a commit

```bash
greengate install-hooks
greengate scan --staged
```

Run `scan` in CI as another check. Baselines and [expiring exceptions](/guide/baselines-and-exceptions) can retain existing or accepted findings without hiding them from reports.

## Combine repository gates

```toml
[pipeline]
steps = ["scan", "audit", "ci-lint", "coverage --min 80"]
```

```bash
greengate run --report gates.sarif
```

Generate coverage before running the pipeline. Add Kubernetes and Dockerfile checks when those files are part of your project:

```bash
greengate lint --dir ./k8s
greengate docker-lint --file Dockerfile
```

## Review complexity and coverage

```bash
greengate review --base origin/main --coverage-file coverage/lcov.info
```

The command reports a complexity heuristic and coverage for changed lines found in the report. Its review-time estimate is not a measured prediction of developer effort. Configure a coverage threshold and complexity budget to decide what blocks.

## Explore test selection

```bash
greengate tia --base origin/main --format json
```

TIA suggests tests whose direct static imports match changed source paths. It does not follow transitive imports or prove that omitted tests are unaffected. Run the full suite for config changes and whenever that coverage is required.

## Inventory dependencies

```bash
greengate sbom --output sbom.json
```

Use `--attest` with cosign to sign the file and an expected signer identity when verifying it. A signed dependency inventory does not certify build provenance or regulatory compliance. See [SBOM generation](/commands/sbom).
