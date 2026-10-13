---
title: 'audit — Dependency Vulnerability Audit'
description: 'Audit project dependencies for known vulnerabilities via OSV. Supports npm, Cargo, pinned PyPI requirements, and Go, with a 24-hour response cache.'
---

# audit — Dependency Vulnerability Audit

Audits project dependencies for known vulnerabilities by querying the [OSV database](https://osv.dev) (Open Source Vulnerabilities). Recursively discovers supported dependency files across the repository, including monorepo subprojects, and deduplicates packages before querying OSV.

## Supported ecosystems

| Ecosystem | Dependency files |
|---|---|
| Node.js | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (Yarn 1 and Berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` |
| Python | `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751), `requirements.txt` (`==` pins) |
| Rust | `Cargo.lock` |
| Go | `go.mod` (Go 1.17+, with `replace` directives), else `go.sum` |

Every eligible registry package in the lockfile is audited, including nested copies
(`node_modules/a/node_modules/b`) and transitive dependencies. Git, URL and
local-path dependencies have no registry version for OSV to match and are
listed but not audited. Maven (`pom.xml`), .NET/NuGet, Ruby (`Gemfile.lock`),
`Pipfile.lock` and the binary `bun.lockb` are not supported.

Two lockfiles for one ecosystem in one directory (say `package-lock.json`
beside `yarn.lock`) are both audited, with a warning that it is ambiguous
which one is installed. Skip dependency files — test fixtures, vendored
examples — with `[deps] exclude_patterns`.

OSV batch responses are cached for 24 hours.

## Offline mode

With snapshots downloaded by [`greengate db update`](db.md), `audit` can match
dependencies locally:

- `[audit] source = "auto"` (default) queries the OSV API and, if a query
  fails, answers from a snapshot no older than `max_db_age_hours` (default 24).
  The report notes that the fallback was used.
- `source = "offline"` or `--offline` uses only the snapshots and never calls
  the API. A missing or stale snapshot makes the run incomplete.
- `source = "online"` never uses snapshots.

Offline matching follows the OSV schema's version rules: SemVer ordering for
npm, crates.io and Go, PEP 440 for PyPI. A version it cannot order is reported
as incomplete, never as unaffected. The offline matcher has been compared with API results on a fixture corpus; version-format and snapshot coverage still limit matching.

## What "incomplete" means

`audit` passes when the supported registry dependencies were checked without blocking findings or tracked gaps. Non-registry packages are excluded from advisory matching. When
something could not be checked, the run is **incomplete** and exits `3` — it
is never reported as a pass. Causes:

- OSV could not be reached (and no fresh offline snapshot could answer), or
  answered for fewer packages than were queried
- OSV truncated a package's advisory list (paginated response)
- A dependency file could not be read
- `requirements.txt` lines that are not `==` pinned, `-r` includes, and
  editable (`-e`) installs, a `pylock.toml` entry without a version, and a
  binary `bun.lockb` — these name packages whose versions are unknown

Every incomplete check is listed with its reason. Findings still win: a run
that found vulnerabilities exits `1` even if some checks were incomplete.

To accept incomplete runs, pass the global `--allow-incomplete` flag or set
`[policy] on_incomplete = "warn"`. The exit code becomes `0`, but the output
and JSON report still say `incomplete`.

## Usage

```
greengate audit [OPTIONS]

Options:
      --format <FORMAT>   Output format [default: text] [possible values: text, json]
      --offline           Use only offline OSV snapshots (see `greengate db`)
      --update-baseline   Save current findings as the baseline
      --since-baseline    Only fail on findings not in the saved baseline
      --allow-incomplete  Exit 0 even when some checks could not run
  -h, --help              Print help
```

`--format json` writes a `greengate.report/v1` document to stdout:

```json
{
  "schema": "greengate.report/v1",
  "command": "audit",
  "status": "incomplete",
  "checks": [
    { "id": "lockfile:./package-lock.json", "status": "passed" },
    { "id": "osv", "status": "incomplete", "reason": "1 package(s) not checked: Failed to reach OSV API …" }
  ],
  "findings": [],
  "suppressed": []
}
```

`status` is one of `passed`, `findings`, `incomplete`, or `error`.

Set `GREENGATE_OSV_URL` to query an OSV-compatible mirror instead of
`https://api.osv.dev`.

## Suppressing known-acceptable advisories

Some transitive dependency vulnerabilities cannot be fixed by upgrading a direct dependency — the affected package is pulled in by a tool (webpack, jest, turbo) that has not yet released a compatible upgrade. Blanket-suppressing entire packages is too broad; instead, waive individual advisories, so that new advisories still fail the build.

Add an exception to `.greengate/exceptions.toml`. Each one needs a reason, an owner and an expiry date (at most `[policy] max_exception_days`, 90 by default, from today):

```toml
[[exception]]
id = "EX-3"
match = { advisory = "GHSA-2G4F-4PWH-QVX6", package = "ajv" }
reason = "ajv@6 is used only by webpack's schema tooling; no direct dependency to upgrade"
owner = "@frontend-platform"
expires = "2026-12-31"
ticket = "SEC-120"
```

When an exception expires, the advisory fails the build again and the output names the exception and its owner. Waived advisories are listed in the output and in the report's `suppressed` list, but do not fail the build. See [Baselines & Exceptions](/guide/baselines-and-exceptions#governed-exceptions).

To accept every advisory present today and fail only on new ones, record a baseline instead:

```bash
greengate audit --update-baseline   # writes .greengate-baseline.json; commit it
greengate audit --since-baseline    # in CI
```

A package upgrade that is still affected by the same advisory stays known.

### `ignore_advisories` (deprecated)

`[audit] ignore_advisories` in `.greengate.toml` still suppresses the listed IDs in 0.4, with a deprecation warning. It has no owner or expiry. Move it to exceptions with:

```bash
greengate exceptions migrate --owner @security
```

## Examples

```bash
# Audit from the current directory (auto-detects manifest)
greengate audit
```

## Sample output — findings present

```
ℹ️  Auditing dependencies via OSV...
⚠️  [suppressed] GHSA-2G4F-4PWH-QVX6 — ajv 6.12.6 (known acceptable transitive dep)
⚠️  Found 2 actionable vulnerability/ies:
  [GHSA-xxxx-yyyy-zzzz] openssl 0.10.55 — Use-after-free in X.509 certificate verification
  [GHSA-aaaa-bbbb-cccc] serde_json 1.0.85 — Stack overflow on deeply nested input
Audit failed: 2 known vulnerability/-ies found.
```

## Sample output — all clear

```
ℹ️  Auditing dependencies via OSV...
✅ No actionable vulnerabilities found (2 suppressed).
```

## In GitHub Actions

```yaml
- name: Dependency Audit
  run: greengate audit
```

Exits `0` when every dependency was checked and none has an actionable
advisory, `1` when advisories are found, and `3` when some dependencies could
not be checked. See [exit codes](../reference/exit-codes.md).

## Workflow: handling unfixable transitive dependencies

1. Run `greengate audit` and note the advisory IDs that fail.
2. For each failing advisory, check whether you control the affected package directly (i.e., it appears in your top-level `package.json` / `Cargo.toml`).
   - **Yes** — upgrade or pin to a patched version.
   - **No (transitive)** — check whether upgrading any *direct* dependency removes the transitive dep. If not, add an exception for the advisory with the reason, an owner and an expiry date.
3. Re-run `greengate audit` to confirm only waived advisories remain.
4. When an exception expires, the advisory fails the build again: re-evaluate it then, and renew the exception or fix the dependency.
