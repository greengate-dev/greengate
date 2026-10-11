---
title: 'Output Formats — GreenGate CLI Reference'
description: 'GreenGate output formats: SARIF 2.1.0, JSON, JUnit XML, GitLab SAST, and plain text. Upload findings to GitHub Security tab, SonarQube, or any major CI platform.'
---

# Output Formats

Every gate can write a unified report file with [`--report`](#report-files). In addition, the `scan` command supports five output formats via `--format`. The `review` command supports three formats (`text`, `json`, `sarif`) — see [review output formats](#review-command-formats) below.

## Report files (`--report`) {#report-files}

Every gate accepts the global `--report <path>` flag, which writes the result
to a file in addition to the normal output:

- a path ending in `.sarif` gets **SARIF 2.1.0**, ready for
  `github/codeql-action/upload-sarif`
- any other path gets a **`greengate.report/v1`** JSON document
  ([JSON Schema](/schema/report-v1.json))

```bash
greengate audit --report audit.json
greengate run --report gates.sarif     # one merged report for the whole pipeline
```

The report is written even when the gate fails or cannot run, so CI artifacts
are there exactly when you need them. A v1 report looks like:

```json
{
  "schema": "greengate.report/v1",
  "tool": { "name": "greengate", "version": "0.4.0" },
  "command": "audit",
  "status": "incomplete",
  "duration_ms": 812,
  "checks": [
    { "id": "lockfile:./package-lock.json", "status": "passed" },
    { "id": "osv", "status": "incomplete", "reason": "1 package(s) not checked: …" }
  ],
  "findings": [],
  "warnings": [],
  "suppressed": []
}
```

`status` is `passed`, `findings`, `incomplete` or `error`, and maps to the
[exit code](exit-codes.md). `warnings` are signals below the blocking threshold
or on an allowlist; `suppressed` are findings matched by a suppression. Neither
affects the status.

In SARIF, checks that did not complete appear as
`invocations[0].toolExecutionNotifications`, and `executionSuccessful` is
`false`, so a partial run is never shown as a clean one.

## text (default)

Human-readable output to stderr. A progress bar shows scan progress. Findings include file path and line number.

```bash
greengate scan
```

## json

Machine-readable JSON written to stdout. Status messages and progress go to stderr, so you can pipe stdout cleanly.

```bash
greengate scan --format json
greengate scan --format json | jq '.findings[] | select(.rule | startswith("SAST"))'
```

```json
{
  "total": 1,
  "findings": [
    {
      "rule": "SAST/EvalUsage",
      "file": "./src/utils.js",
      "line": 42,
      "severity": "critical"
    }
  ]
}
```

## sarif

SARIF 2.1.0 JSON written to stdout. Upload directly to GitHub Advanced Security for inline PR annotations.

```bash
greengate scan --format sarif > results.sarif
```

In GitHub Actions:

```yaml
- name: Secret & SAST Scan
  run: greengate scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## junit

JUnit XML written to stdout. Compatible with Jenkins, Azure DevOps, CircleCI, and any CI system that consumes JUnit test reports.

```bash
greengate scan --format junit > results.xml
```

Each finding becomes a `<testcase>` with a `<failure>` element. The suite name is `greengate` and the classname is the file path.

In Jenkins:
```groovy
sh 'greengate scan --format junit > results.xml || true'
junit 'results.xml'
```

In Azure DevOps:
```yaml
- script: greengate scan --format junit > results.xml
  continueOnError: true
- task: PublishTestResults@2
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: results.xml
```

## gitlab

GitLab SAST Security Scanner JSON (schema v15.0.6) written to stdout. Upload as a GitLab security artifact to display findings in Merge Request security reports.

```bash
greengate scan --format gitlab > gl-sast-report.json
```

In `.gitlab-ci.yml`:
```yaml
secret-scan:
  script:
    - greengate scan --format gitlab > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Severity mapping: `critical` → `Critical`, `high` → `High`, `medium` → `Medium`, `low` → `Low`.

---

## review command formats {#review-command-formats}

The `review` command outputs PR complexity and new-code coverage gap analysis in three formats.

### text (default)

```bash
greengate review --base HEAD~1
```

```
╔══ PR Review ════════════════════════════════╗
  Complexity Score : 47  (Normal Review ~23 min)
  Files changed    : 5
  Lines added/del  : +120 / -34
  Cyclomatic nodes : 18
╚═════════════════════════════════════════════╝

New-Code Coverage: 73.3%  ✗ (target: 80%)

  src/engine.rs      12/15 added lines covered  (80.0%) ✓
  src/scanner.rs      6/11 added lines covered  (54.5%) ✗
    Uncovered lines: 88, 89, 92, 95, 101
```

**Complexity tiers:**

| Score | Label |
|---|---|
| 0–20 | Quick Review |
| 21–50 | Normal Review |
| 51–100 | Complex Review |
| 101+ | Large PR — consider splitting |

### json

Machine-readable JSON to stdout.

```bash
greengate review --base HEAD~1 --format json | jq .
```

```json
{
  "complexity": {
    "score": 47,
    "tier": "Normal Review",
    "estimated_review_minutes": 23,
    "files_changed": 5,
    "lines_added": 120,
    "lines_removed": 34,
    "cyclomatic_nodes": 18
  },
  "coverage": {
    "new_code_coverage_pct": 73.3,
    "target_pct": 80.0,
    "covered_lines": 18,
    "uncovered_lines": 7,
    "files": [
      {
        "path": "src/engine.rs",
        "added_lines": 15,
        "covered": 12,
        "uncovered": 3,
        "coverage_pct": 80.0,
        "uncovered_line_numbers": [44, 57, 61]
      }
    ]
  },
  "passed": false
}
```

### sarif

SARIF 2.1.0 with one result per uncovered added line. Rule ID: `GG/NewCodeUncovered`, severity: `warning`.

```bash
greengate review --base HEAD~1 --format sarif > review.sarif
```

Upload to GitHub Advanced Security alongside `scan` SARIF output for unified inline annotations:

```yaml
- name: PR Review SARIF
  if: github.event_name == 'pull_request'
  run: |
    greengate review \
      --base "${{ github.event.pull_request.base.sha }}" \
      --coverage-file coverage/lcov.info \
      --format sarif > review.sarif || true

- name: Upload Review SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: review.sarif
  continue-on-error: true
```
