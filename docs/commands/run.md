---
title: 'run — Pipeline Executor'
description: 'Run all quality gate steps defined in .greengate.toml in order. A failing step halts the pipeline immediately with a non-zero exit code.'
---

# run — Pipeline Executor

Runs all pipeline steps defined in `.greengate.toml` in order. A failing step stops the pipeline immediately with a non-zero exit code.

## Usage

```bash
greengate run
```

## Configuration

Define your pipeline steps in `.greengate.toml`:

```toml
[pipeline]
steps = [
  "scan",
  "audit",
  "coverage --min 80",
  "lint --dir ./k8s",
  "docker-lint",
  "lighthouse",
  "reassure",
  "review --base HEAD~1",
]
```

Each step is a string that maps to an `greengate` subcommand, optionally followed by flags. All config values from `.greengate.toml` are applied automatically — CLI overrides in the step string take precedence.

## Available steps

| Step | Equivalent command |
|---|---|
| `scan` | `greengate scan` |
| `lint` | `greengate lint` |
| `docker-lint` | `greengate docker-lint` |
| `coverage` | `greengate coverage` |
| `audit` | `greengate audit` |
| `lighthouse` | `greengate lighthouse` |
| `reassure` | `greengate reassure` |
| `review` | `greengate review` |

## Step flags

You can pass flags inline in the step string:

```toml
[pipeline]
steps = [
  "scan --staged",
  "coverage --min 90",
  "lint --dir ./manifests",
  "lighthouse --url https://staging.myapp.com --min-performance 85",
]
```

`scan`, `audit` and `ci-lint` steps accept `--since-baseline`, and `scan` accepts
`--changed-since <ref>`. Exceptions in `.greengate/exceptions.toml` apply to
every step.

## Example output

```
ℹ️  Running pipeline: 4 step(s)

─── Step 1/4: scan ──────────────────────────────────────
ℹ️  Starting secret and PII scan...
✅ No secrets or PII found.
✅ Step 'scan' passed.

─── Step 2/4: audit ─────────────────────────────────────
ℹ️  Auditing dependencies for known CVEs...
✅ No known vulnerabilities found.
✅ Step 'audit' passed.

─── Step 3/4: coverage --min 80 ─────────────────────────
✅ Coverage: 84.2% (threshold: 80.0%)
✅ Step 'coverage' passed.

─── Step 4/4: docker-lint ───────────────────────────────
✅ Dockerfile passed all lint checks.
✅ Step 'docker-lint' passed.

✅ Pipeline passed (4 step(s)).
```

## CI usage

```yaml
- name: Install greengate
  run: |
    curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Run quality gates
  run: greengate run
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All steps passed |
| `1` | A step found policy violations |
| `3` | A step could not check everything (see `[policy] on_incomplete`) |
| `4` | A step could not run |

## Notes

- Steps run sequentially; the first step that does not pass stops the pipeline
- The exit code reflects the worst result among the steps that ran
- If no `[pipeline]` section is defined in `.greengate.toml`, the command exits with an error message instructing you to add one
- Use `greengate init` to generate a starter config with a default pipeline
