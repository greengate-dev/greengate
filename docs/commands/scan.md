---
title: 'scan — Secret, PII & SAST Scanning'
description: 'Scan your codebase for hardcoded secrets, credentials, and PII using 25 built-in patterns plus AST-based SAST for JS, TS, Python, Go, and Rust. Supports --fix auto-redaction and --triage LLM false-positive classification.'
---

# scan — Secret, PII & SAST Scanning

Recursively scans eligible text files in the current directory for hardcoded secrets, credentials, and PII using 25 built-in regex patterns plus Shannon entropy detection. Respects `.gitignore` automatically.

For JavaScript, TypeScript, Python, Go, and Rust files the scanner additionally runs an AST-based SAST pass using tree-sitter, using syntax-aware rules and string-literal scoping. False positives and false negatives remain possible.

## Usage

```
greengate scan [OPTIONS]

Options:
  --format <FORMAT>    Output format: text (default), json, sarif, junit, gitlab
  --staged             Only scan git-staged files (git diff --cached)
  --changed-since <REF>
                       Only scan files changed since REF; every finding in
                       them counts (--since is a deprecated alias)
  --new-since [<REF>]  Only report findings that are new since the merge base
                       with REF (default in a pull request: its base branch)
  --history            Scan the entire git commit history (slow on large repos)
  --annotate           Post findings as a GitHub Check Run with per-line
                       annotations and a rich PR summary comment. Requires
                       GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA env vars.
  --update-baseline    Save current findings as the baseline (.greengate-baseline.json)
  --since-baseline     Only fail on findings not present in the saved baseline
  --blame              Enrich each finding with git blame info (author + commit)
  --fix                Auto-redact detected secrets in-place (replaces matched values with <REDACTED>)
  --dry-run            Preview what --fix would change without writing to disk
  --triage             Call an LLM to classify each finding as likely-real,
                       likely-false-positive, or uncertain
  -h, --help           Print help
```

## Examples

```bash
# Full scan — human-readable output
greengate scan

# Only scan what you're about to commit (fast, ideal for pre-commit)
greengate scan --staged

# Only findings this branch introduces
greengate scan --new-since origin/main

# Every finding in the files changed since the last commit
greengate scan --changed-since HEAD~1

# Output SARIF for GitHub Advanced Security PR annotations
greengate scan --format sarif > results.sarif

# Output JSON for custom tooling
greengate scan --format json | jq '.findings[].rule'

# JUnit XML for Jenkins / Azure DevOps
greengate scan --format junit > results.xml

# GitLab SAST Security Scanner JSON
greengate scan --format gitlab > gl-sast-report.json

# Enrich findings with git blame (author + commit hash)
greengate scan --blame

# Post findings directly to the GitHub Checks tab + PR summary comment
GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo GITHUB_SHA=abc123 \
greengate scan --annotate

# Preview what auto-redaction would change (no files written)
greengate scan --dry-run

# Auto-redact detected secrets in-place
greengate scan --fix

# Triage each finding with an LLM (requires ANTHROPIC_API_KEY by default)
greengate scan --triage
```

## Auto-fix (`--fix` / `--dry-run`)

`--fix` rewrites files in-place, replacing the matched secret value with `<REDACTED>`. SAST findings are listed but not modified — only secret/PII patterns that have a clearly bounded matched value are redacted.

**Workflow:**

```bash
# 1. Preview changes (no writes)
greengate scan --dry-run

# 2. Review the diff output, then apply
greengate scan --fix

# 3. Verify the result
git diff
```

`--dry-run` prints a unified diff-style preview showing exactly which characters would be replaced. No files are written.

## AI triage (`--triage`)

When enabled, each finding is sent to an LLM along with ~10 lines of surrounding context. The configured endpoint receives that source context and classifies it as likely-real, likely-false-positive, or uncertain and gives a one-sentence reason.

```
⚠️  Found 3 potential issue(s) — 1 triaged as false positive(s) and auto-suppressed, 2 require attention:

  - [HIGH] [SAST/CommandInjection] ./src/admin/shell.rs:88
    → Triage: LIKELY REAL (94%) — User-controlled cmd flows into Command::new with no sanitization.

  - [HIGH] [Secret/AwsAccessKey] ./tests/fixtures/creds.rs:12 [AUTO-SUPPRESSED]
    → Triage: LIKELY FALSE POSITIVE (91%) — Matches canonical AWS example key in test fixture.

  - [MEDIUM] [SAST/EvalUsage] ./src/utils/eval.rs:44
    → Triage: UNCERTAIN (55%) — eval() usage but surrounding context does not clarify intent.

  Triage summary: 1 likely real · 1 uncertain · 1 false positive (suppressed: 1) · 0 unavailable
```

**Setup:**

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (default)
greengate scan --triage
```

Configure model, endpoint, and auto-suppression threshold in `.greengate.toml`:

```toml
[triage]
model                   = "claude-haiku-4-5-20251001"
api_key_env             = "ANTHROPIC_API_KEY"
auto_suppress_threshold = 0.0    # annotate only; review before enabling suppression
context_lines           = 10
# endpoint = "http://localhost:11434/v1/chat/completions"  # Ollama / any OpenAI-compat
```

See the [configuration reference](/reference/config) section for full options and local model setup.

## AST-based SAST

When scanning `.js`, `.jsx`, `.ts`, `.tsx`, `.py`, `.go`, or `.rs` files, greengate uses tree-sitter to parse a real AST. This provides:

**String-literal scoping** — secret patterns only fire inside string and template literals, not comments or JSX text:

```ts
// AKIAQWERTYUIOPASDFGH          ← comment: NOT flagged
const key = "AKIAQWERTYUIOPASDFGH";  // ← synthetic key-shaped value: flagged
```

**Dangerous pattern detection** — structural rules that catch XSS, eval, command injection, unsafe deserialization, and more. See [SAST Rules](/reference/sast-rules) for the full list.

**Code smell rules** — flags long functions, too many parameters, and deep nesting (JS/TS only).

## Baseline mode

If your repository already has existing findings you can't fix immediately, the baseline workflow lets you suppress known findings and only fail on *new* ones introduced by a PR. Findings are matched by fingerprint, so a known finding stays known when lines are inserted above it, the code around it is edited, or its file is renamed. See [Baselines & Exceptions](/guide/baselines-and-exceptions) for how matching works, what the baseline stores, and `--new-since`, which needs no baseline file at all.

**Step 1: Save a baseline** (typically on your main branch)

```bash
greengate scan --update-baseline
# Writes .greengate-baseline.json — commit this file
```

**Step 2: Gate on new findings only** (in CI, on every PR)

```bash
greengate scan --since-baseline
# Only fails if new findings are introduced vs the baseline
```

```yaml
# GitHub Actions example
- name: Save baseline (main branch only)
  if: github.ref == 'refs/heads/main'
  run: greengate scan --update-baseline && git add .greengate-baseline.json

- name: Gate on new secrets only (PRs)
  if: github.event_name == 'pull_request'
  run: greengate scan --since-baseline
```

## Suppressing findings

Add `// greengate: ignore` on the same line to suppress a specific finding. Give a reason with `reason="…"` (or any text after the marker): the report lists every suppressed finding with it.

```ts
const legacyKey = "AKIAQWERTYUIOPASDFGH"; // greengate: ignore
el.innerHTML = sanitizedHtml;                 // greengate: ignore
```

Or on the line above to suppress the next line:

```python
# greengate: ignore reason="loaded from the environment at runtime"
AWS_KEY = load_from_env("AWS_ACCESS_KEY_ID")
```

To waive a finding for a limited time with an owner, use an exception in
`.greengate/exceptions.toml` instead. See
[Baselines & Exceptions](/guide/baselines-and-exceptions#governed-exceptions).

Suppress an entire rule class across the repo via `[sast]` in `.greengate.toml`:

```toml
[sast]
disabled_rules = ["SAST/RustUnwrap", "SMELL/LongFunction"]
```

## Sample output

```
ℹ️  Starting secret and PII scan...
ℹ️  Running SAST checks...
ℹ️  SAST: scanning 14 file(s)...
⚠️  Found 3 potential issue(s):
  - [CRITICAL] [AWS Access Key] src/config.ts:14
  - [CRITICAL] [SAST/EvalUsage] src/utils/parser.js:42
  - [HIGH] [SAST/InnerHTMLAssignment] src/components/Widget.tsx:88
Error: Scan failed: 3 secret(s)/PII found.
```

With `--blame`:
```
  - [CRITICAL] [AWS Access Key] src/config.ts:14
    blame: Alice Smith <alice@example.com> (abc12345)
```
