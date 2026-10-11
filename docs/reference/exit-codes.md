---
title: 'Exit Codes — GreenGate CLI Reference'
description: 'GreenGate exit code reference: 0 passed, 1 findings, 2 usage error, 3 incomplete. Designed for reliable CI pipeline scripting without stdout parsing.'
---

# Exit Codes

CI pipelines can rely on the exit code directly — no output parsing required.

| Code | Meaning |
|---|---|
| `0` | Passed — everything was checked and nothing violates policy |
| `1` | Findings — a check failed (secrets found, SAST issues, lint violations, coverage below threshold, vulnerabilities detected, performance regression) |
| `2` | Usage error — unknown flag or invalid argument |
| `3` | Incomplete — some checks could not run (for example, the vulnerability database was unreachable) and nothing that did run found a problem |

A gate that could not check everything is **not** a pass. To accept
incomplete runs, set `[policy] on_incomplete = "warn"` or pass
`--allow-incomplete`; the exit code becomes `0`, but the output still reports
the run as incomplete.

When a run has both findings and incomplete checks, it exits `1`.

::: info Transition in 0.4
`audit` reports incomplete runs with exit code `3`. Other commands are moving
to the same model during the 0.4 cycle; until then they exit `1` for both
findings and runtime errors.
:::

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
