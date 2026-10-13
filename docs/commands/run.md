---
title: 'run — Pipeline Executor'
description: 'Run every quality gate step defined in .greengate.toml and get one merged report and one exit code — the worst result among the steps.'
---

# run — Pipeline Executor

Runs every pipeline step defined in `.greengate.toml`, in order, and merges
their results into one report and one exit code: the worst result among the
steps. A failing step does not stop the others, so one run shows everything
that needs fixing. Set `fail_fast` to stop at the first failure instead.

## Usage

```bash
greengate run                              # every step
greengate run --fail-fast                  # stop at the first step that does not pass
greengate run --report greengate.sarif     # the merged report, as SARIF or JSON
```

## Configuration

Define your pipeline steps in `.greengate.toml`:

```toml
[pipeline]
# Stop at the first step that does not pass (default: run every step).
fail_fast = false
steps = [
  "scan",
  "audit",
  "coverage --min 80",
  "lint --dir ./k8s",
  "docker-lint",
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
| `review` | `greengate review` |
| `tia` | `greengate tia` |
| `sbom` | `greengate sbom` |
| `deps-check` | `greengate deps check` |
| `deps-review` | `greengate deps review` |
| `ci-lint` | `greengate ci-lint` |

## Step flags

You can pass flags inline in the step string:

```toml
[pipeline]
steps = [
  "scan --staged",
  "coverage --min 90",
  "lint --dir ./manifests",
  "scan --new-since origin/main",
]
```

`deps-review` reviews the change's dependency updates (it accepts `--base` and
`--annotate`). `scan`, `audit` and `ci-lint` steps accept `--since-baseline`, and `scan` accepts
`--changed-since <ref>` or `--new-since [<ref>]`. A step given a flag it does
not take fails rather than ignoring it. Exceptions in `.greengate/exceptions.toml` apply to
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

Pin the binary version in CI; see [CI integration](/guide/ci-integration).

```yaml
- name: Install greengate
  run: |
    curl -fsSL https://github.com/greengate-dev/greengate/releases/download/v0.4.0/greengate-linux-amd64 \
      -o greengate
    sudo install -m 755 greengate /usr/local/bin/greengate

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

- Steps run sequentially, and all of them run unless `fail_fast` is set. With
  `fail_fast`, the steps after a failure are listed as *incomplete* ("not
  run"), never as passed
- The exit code reflects the worst result: findings outrank errors, errors
  outrank incomplete checks
- The merged report (`--report`) prefixes each check with its step, e.g.
  `audit/osv`, and ends with a per-step summary in the terminal
- If no `[pipeline]` section is defined in `.greengate.toml`, the command exits with an error message instructing you to add one
- Use `greengate init` to generate a starter config with a default pipeline
