---
title: 'Exit Codes — greengate CLI Reference'
description: 'greengate exit code reference: 0 passed, 1 findings, 2 usage error, 3 incomplete, 4 error. Designed for reliable CI pipeline scripting without stdout parsing.'
---

# Exit Codes

CI pipelines can rely on the exit code directly — no output parsing required.

| Code | Meaning |
|---|---|
| `0` | Passed — everything was checked and nothing violates policy |
| `1` | Findings — a check failed (secrets found, SAST issues, lint violations, coverage below threshold, vulnerabilities detected) |
| `2` | Usage error — unknown flag, invalid argument, or an invalid `.greengate.toml` |
| `3` | Incomplete — some checks could not run and nothing that did run found a problem |
| `4` | Error — the gate could not run (an unreadable input file, a failed `git` call, a wrapped package manager that failed) |

A gate that could not check everything is **not** a pass. Examples of
incomplete runs: the vulnerability database or a package registry was
unreachable, a manifest did not parse, `sbom --verify` ran without an expected
signer identity. To accept incomplete runs, set
`[policy] on_incomplete = "warn"` or pass the global `--allow-incomplete`
flag; the exit code becomes `0`, but the output still reports the run as
incomplete.

When a run has several results, the exit code reports the most actionable:
findings (`1`), then error (`4`), then incomplete (`3`).

`--no-fail` (on `image-scan`, `install` and the install wrappers) waives
findings only. An incomplete or failed run still exits `3` or `4`.

`run` exits with the worst result among its steps. `greengate hook
claude-code` always exits `0` and answers through its JSON output: exit `2`
would block the agent's command.

## In CI pipelines

```yaml
- name: Secret Scan
  run: greengate scan
  # Step fails automatically when exit code is 1
```

To continue the pipeline after a failure (e.g. to upload SARIF even when issues exist):

```yaml
- name: Secret Scan
  run: greengate scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```
