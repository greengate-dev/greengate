---
title: 'review — PR Complexity & Coverage Gate'
description: 'Analyze a pull request diff for a Complexity Score (estimated review time) and new-code coverage gaps. Fail CI when newly added lines are untested. Post GitHub Check Run annotations.'
---

# review — PR Diff Analyzer

Analyzes a pull request diff and outputs two things:

1. **Complexity Score** — a weighted composite that estimates how long the PR will take to review, derived from lines changed, files touched, and cyclomatic complexity of new code (detected via tree-sitter AST queries on JS/TS/Python/Go).
2. **New-code coverage gaps** — which newly added lines are NOT covered by the provided LCOV or Cobertura report, with a pass/fail gate against a configurable floor.

Both outputs are available on every commit, not just in CI — making this practical as a local pre-push check or a `greengate run` pipeline step.

## Usage

```
greengate review [OPTIONS]

Options:
      --base <REF>               Diff base: commit, branch, or tag [default: HEAD~1]
      --staged                   Diff staged changes instead of committed diff
      --coverage-file <FILE>     LCOV or Cobertura XML coverage file to cross-reference
      --min-coverage <PCT>       Minimum % coverage required for newly added lines [default: 80]
      --complexity-budget <N>    Fail if Complexity Score exceeds this; 0 = warn only [default: 0]
      --format <FMT>             Output format: text | json | sarif [default: text]
      --annotate                 Post results as a GitHub Check Run + PR comment
  -h, --help                     Print help
```

## Complexity Score

The score is computed on the **added lines only** (not deleted or context lines):

```
raw = (lines_added × 0.3)
    + (files_changed × 5.0)
    + (cyclomatic_nodes × 2.0)
    + (lines_removed × 0.1)

score = round(raw)
estimated_review_minutes = min(raw × 0.5, 120)
```

**Tier labels:**

| Score | Label | Estimated review time |
|---|---|---|
| 0 – 20 | Quick Review | < 10 min |
| 21 – 50 | Normal Review | 10 – 25 min |
| 51 – 100 | Complex Review | 25 – 50 min |
| 101+ | Large PR — consider splitting | > 50 min |

**Cyclomatic complexity** is counted by running tree-sitter queries over the added code:
- JS/TS/TSX/JSX: `if`, ternary, `switch case`, `for`, `while`, `do`, `catch`
- Python: `if`, `elif`, `for`, `while`, `except`, boolean operators, conditional expressions
- Go: `if`, `for`, `switch`, `select`, `binary_expression`
- Other file types: 0 (not counted, but lines/files still contribute to the score)

## New-code coverage gaps

When `--coverage-file` is provided, greengate cross-references the diff with the coverage report line by line:

| Line state | Outcome |
|---|---|
| In coverage report with `hits > 0` | **covered** — counts toward % |
| In coverage report with `hits == 0` | **uncovered** — gap, counts against % |
| Not in coverage report | **unmeasured** — excluded from % calculation (no penalty) |

Per-file and overall `new_code_coverage_pct` are computed from covered + uncovered lines only. The gate fails if `overall_pct < min_coverage`.

## Examples

```bash
# Complexity score only (no coverage gate)
greengate review --base main

# With coverage gate — fails if new-code coverage < 80%
greengate review --base main --coverage-file coverage/lcov.info --min-coverage 80

# Staged changes (before committing)
greengate review --staged --coverage-file coverage/lcov.info

# JSON output (machine-readable)
greengate review --base HEAD~1 --coverage-file coverage/lcov.info --format json

# SARIF output — upload uncovered lines to GitHub Security tab
greengate review --base HEAD~1 --coverage-file coverage/lcov.info --format sarif > review.sarif

# Set a hard complexity budget (fail if score > 100)
greengate review --base main --complexity-budget 100

# GitHub Actions — annotate PR with uncovered lines + score
greengate review \
  --base "${{ github.event.pull_request.base.sha }}" \
  --coverage-file coverage/lcov.info \
  --min-coverage 80 \
  --annotate
```

## Sample output (text)

```
╔══ PR Review ═══════════════════════════════════════╗
  Complexity Score : 47  (Normal Review, ~23 min)
  Files changed    : 5
  Lines added/del  : +120 / -34
  Cyclomatic nodes : 18
╚════════════════════════════════════════════════════╝

New-Code Coverage: 73.3%  ✗ (target: 80.0%)

  src/engine.rs                   12/15 added lines covered  (80.0%) ✓
  src/scanner.rs                   6/11 added lines covered  (54.5%) ✗
    Uncovered lines: 88, 89, 92, 95, 101

⚠️  Review gate FAILED.
Error: greengate review: quality gate failed.
```

## JSON output schema

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
    "overall_pct": 73.3,
    "min_required": 80.0,
    "passed": false,
    "files": [
      {
        "file": "src/scanner.rs",
        "added_lines": 11,
        "covered": 6,
        "uncovered": 5,
        "unmeasured": 0,
        "coverage_pct": 54.5,
        "uncovered_lines": [88, 89, 92, 95, 101]
      }
    ]
  },
  "passed": false
}
```

## Configuration

Configure defaults in `.greengate.toml`:

```toml
[review]
min_new_code_coverage = 80   # minimum % for newly added lines (default: 80)
complexity_budget = 0        # 0 = warn only; > 0 = fail threshold (default: 0)
```

CLI flags always override config values.

## GitHub integration (`--annotate`)

When run with `--annotate` and the `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and `GITHUB_SHA` environment variables present, `review` will:

1. Create a **GitHub Check Run** named `greengate review` with the Complexity Score as the title
2. Post a **per-line annotation** (warning level) for each uncovered added line
3. Post a **PR comment** with a markdown summary table

If any of the required environment variables are absent, `--annotate` is a no-op.

## Pipeline usage

```toml
[pipeline]
steps = [
  "scan",
  "review --base main --coverage-file coverage/lcov.info --min-coverage 80",
  "coverage --min 80",
  "audit",
]
```

## GitHub Actions

```yaml
- name: PR review (complexity + coverage gaps)
  if: github.event_name == 'pull_request'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_SHA: ${{ github.sha }}
  run: |
    greengate review \
      --base "${{ github.event.pull_request.base.sha }}" \
      --coverage-file coverage/lcov.info \
      --min-coverage 80 \
      --annotate
```

Required permissions:
```yaml
permissions:
  checks: write          # create Check Runs
  pull-requests: write   # post PR comments
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All gates passed (or no coverage file specified) |
| `1` | Coverage below threshold or complexity budget exceeded |
| `4` | Runtime error (e.g. the diff or coverage file could not be read) |

## Notes

- Coverage gaps are computed only for **measurable** lines — lines not present in the coverage report at all (e.g. blank lines, comments, or untested new files) are treated as **unmeasured** and excluded from the percentage calculation rather than counted as failures
- The complexity scoring runs tree-sitter on **added lines only** (not the full file). This means the score reflects only the new code being introduced, not background complexity in the file
- For non-git directories or when the diff is empty, the command exits 0 with a brief message
- SARIF output from `review` uses rule ID `GG/NewCodeUncovered` and severity `warning`; it can be uploaded to GitHub Advanced Security alongside the `scan` SARIF output
