---
title: 'Report Schema — greengate.report/v1'
description: 'The JSON document every greengate gate can write with --report: status, checks, findings, warnings and suppressions, with the exit-code mapping and a JSON Schema for validation.'
---

# Report schema: `greengate.report/v1`

Every gate writes the same document with `--report <path>` (SARIF instead
when the path ends in `.sarif`). `audit --format json` and `check-command`
print it on stdout. The JSON Schema is published at
[`/schema/report-v1.json`](/schema/report-v1.json).

```json
{
  "schema": "greengate.report/v1",
  "tool": { "name": "greengate", "version": "0.4.0" },
  "command": "audit",
  "status": "findings",
  "duration_ms": 812,
  "checks": [
    { "id": "lockfile:./package-lock.json", "status": "passed" },
    { "id": "osv", "status": "passed", "source": "OSV API" }
  ],
  "findings": [
    {
      "rule": "OSV/GHSA-35jh-r3h4-6jhm",
      "severity": "high",
      "location": { "kind": "package", "ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": "package-lock.json" },
      "message": "Command Injection in lodash",
      "remediation": "upgrade to >= 4.17.21",
      "reference": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      "fingerprint": "gg1:4e6a3e3823389d4f5be47988a349f655"
    }
  ],
  "warnings": [],
  "suppressed": []
}
```

## Status

| `status` | Meaning | Exit code |
|---|---|---|
| `passed` | everything was checked and nothing violates policy | `0` |
| `findings` | policy was violated; outranks the others | `1` |
| `incomplete` | some checks could not run, and nothing that ran found a problem | `3` (`0` with `--allow-incomplete` or `[policy] on_incomplete = "warn"`) |
| `error` | the gate, or a tool it wraps, failed | `4` |

Argument-parsing and configuration errors can exit `2` before a report is produced. Other early failures may also occur before report writing; a successful write requires a writable destination. See
[exit codes](exit-codes.md).

`--no-fail` can make a report with findings exit `0`; `--allow-incomplete` changes only the exit policy for incomplete runs. Report status is retained.

## Fields

- **`checks`**: each unit of verification (a lockfile read, a database query,
  a pipeline step) and whether it completed. A check that is not `passed`
  always has a `reason`. `source` says where its data came from, e.g. an
  offline snapshot and its age. In `run`, ids are prefixed with their step
  (`audit/osv`), and steps that were not run are `incomplete`.
- **`findings`**: policy violations. Any finding makes the status `findings`.
- **`warnings`**: signals below the blocking threshold (or allowlisted), and
  exceptions about to expire. They never affect the status.
- **`suppressed`**: findings a suppression covers, each with a `suppression`
  object saying why. They never affect the status.

### Finding

| Field | |
|---|---|
| `rule` | e.g. `AWS Access Key`, `OSV/GHSA-…`, `RELEASE/YoungRelease`, `CI/UnpinnedAction`, `LICENSE/Denied` |
| `severity` | `unknown`, `low`, `medium`, `high`, `critical` |
| `location` | `{kind: "file", path, line?}`, `{kind: "package", ecosystem, name, version?, source?}`, `{kind: "url", url}` or `{kind: "project"}` |
| `message` | what is wrong |
| `remediation` | how to fix it, when known |
| `reference` | a link (advisory page) or git blame |
| `fingerprint` | stable `gg1:` identity, present when the repository has a baseline; usable in [exceptions](../guide/baselines-and-exceptions.md#governed-exceptions) |
| `suppression` | in `suppressed`: why. On a finding: an exception that has expired (`expired: true`) |

### Suppression

| Field | |
|---|---|
| `kind` | `inline` (`greengate: ignore`), `exception`, `baseline` (or the `--new-since` base), `config` (`[audit] ignore_advisories`), `triage` |
| `id` | the exception id, a baseline fingerprint, or the `--new-since` base |
| `reason`, `owner`, `expires` | as recorded; `owner` and `expires` for exceptions |
| `expired` | the exception has expired and the finding counts again |

## Related documents

- `deps review --format json` prints a `greengate.deps-review/v1` document:
  `base`, `changes` (each package added, removed, upgraded or downgraded,
  with its license, advisories introduced and fixed, release signals and
  `fix` guidance), and the `report` above.
- `--report out.sarif` writes SARIF 2.1.0 for code-scanning upload. Checks
  that did not complete become tool-execution notifications, and
  `executionSuccessful` is `false`.
