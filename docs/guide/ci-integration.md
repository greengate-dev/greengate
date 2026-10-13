---
title: 'Run greengate in CI'
description: 'Install greengate in CI, run dependency and repository gates, and upload reports.'
---

# CI integration

Run greengate gates after checking out the repository and preparing the inputs each gate needs. Dependency installs need their package managers; coverage gates need an existing coverage report.

## Install greengate in GitHub Actions

Pin the binary version for reproducible CI. This example installs greengate 0.4.0 on a Linux x64 runner:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- name: Install greengate
  run: |
    curl -fsSL https://github.com/greengate-dev/greengate/releases/download/v0.4.0/greengate-linux-amd64 -o "$RUNNER_TEMP/greengate"
    sudo install -m 755 "$RUNNER_TEMP/greengate" /usr/local/bin/greengate
```

Git history is needed for merge-base checks.

## Gate installs and dependency changes

On Linux with working bubblewrap and an existing npm lockfile:

```yaml
- name: Install dependencies with required isolation
  run: greengate install --isolate bwrap npm ci
- name: Audit recorded dependencies
  run: greengate audit
```

Set up bubblewrap and the project's package manager before these steps. If isolation cannot run, `--isolate bwrap` fails rather than falling back.

To annotate dependency changes on pull requests, grant `contents: read`, `pull-requests: write`, and `checks: write`, then run:

```yaml
- name: Review dependency changes
  if: github.event_name == 'pull_request'
  env:
    GITHUB_TOKEN: ${{ github.token }}
  run: greengate deps review --annotate
```

Fork pull requests may not have write permissions. Keep reporting and annotation permissions separate from dependency-script execution.

## Run configured gates and retain reports

```toml
[pipeline]
steps = ["scan", "audit", "ci-lint", "coverage --min 80"]
```

Generate coverage before running that pipeline. To upload a shared SARIF report even when a gate fails:

```yaml
- name: Run gates
  run: greengate run --report gates.sarif
  continue-on-error: true
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: gates.sarif
```

SARIF upload needs `security-events: write`; that permission is separate from `checks: write` for annotations. `continue-on-error` makes the gate informational. Remove it, or explicitly enforce the gate's outcome after uploading, when findings should block CI.

Examples use action version tags for readability. Pin reviewed action commits in production; `ci-lint` flags mutable references.

## Composite action

Pin both the action code and downloaded binary:

```yaml
- uses: greengate-dev/greengate@v0.4.0
  with:
    version: v0.4.0
    profile: ci
    dependency-review: true
    report: gates.json
```

The `version` input controls the downloaded binary independently of the action ref. The action runs `greengate run`, optionally adds dependency review, and exposes `status`, `findings`, `incomplete`, and `report-path`. Prepare the configuration, inputs, history, and permissions first.

## GitLab and other runners

Install a binary or build the same reviewed source revision, then run ordinary CLI commands. For GitLab SAST output:

```yaml
secret-scan:
  script:
    - greengate scan --format gitlab > gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
```

The scan exit code controls job failure. Other platforms can consume JSON, SARIF, or supported JUnit output. See [output formats](/reference/output-formats) and [exit codes](/reference/exit-codes).

## Test-selection policy

[`tia`](/commands/tia) suggests tests using direct imports. It is not a complete selection guarantee. Preserve full-suite runs where needed, and do not skip testing solely because TIA returned an empty list.

## Local pre-commit checks

```bash
greengate install-hooks
```

The hook runs `scan --staged`. It requires greengate on `PATH` and can be bypassed with Git's normal hook controls; CI provides a separate gate.
