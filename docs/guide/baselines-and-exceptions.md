---
title: 'Baselines & Exceptions — Gate Only on What a Change Introduces'
description: 'Fail CI only on new findings with scan --new-since or a fingerprint baseline, and waive the rest with governed exceptions that carry an owner, a reason and an expiry date.'
---

# Baselines & Exceptions

A repository that adopts greengate usually has findings it cannot fix on day
one. greengate offers four ways to keep the gate useful anyway. Every one of
them keeps suppressed findings in the report's `suppressed` list, with the
reason, so nothing disappears silently.

| Need | Use |
|---|---|
| Fail a pull request only on what it introduces, with no file to maintain | `greengate scan --new-since` |
| Accept today's findings and fail on anything new, for `scan`, `audit` and `ci-lint` | a **baseline** (`--update-baseline` / `--since-baseline`) |
| Accept a specific finding for a limited time, with someone accountable | an **exception** in `.greengate/exceptions.toml` |
| Mark one line in the code as a known false positive | an inline `greengate: ignore` comment |

They apply in that order of precedence: inline comments, then exceptions, then
`--new-since`, then the baseline.

## New findings only: `scan --new-since`

```bash
greengate scan --new-since origin/main
```

greengate finds the merge base of `origin/main` and `HEAD`, and scans every file
changed since then twice: as it is now, and as it was at the merge base. A
finding counts only when it was not already there. Committed, staged,
unstaged and untracked changes are all included, and renamed files are
followed, so moving a file does not make its old findings new.

In a GitHub Actions pull request the ref can be left out: `--new-since` uses the
pull request's base branch (`origin/$GITHUB_BASE_REF`). The checkout must
include that history (`fetch-depth: 0`).

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- name: Secrets introduced by this PR
  run: greengate scan --new-since
```

`--changed-since <ref>` (formerly `--since`) is different: it scans only the
changed files but counts every finding in them, old or new. `--since` still
works as a deprecated alias of `--changed-since`.

## Baselines

```bash
greengate scan --update-baseline        # record today's findings; exits 0
git add .greengate-baseline.json        # commit it

greengate scan --since-baseline         # in CI: fail only on findings not in the baseline
```

`audit` and `ci-lint` take the same two flags. All three gates share one
`.greengate-baseline.json`: each entry records which gate wrote it, and
updating one gate's entries keeps the others'.

### How findings are recognised

Each finding gets a **fingerprint**:

```
gg1:HMAC-SHA256(salt, rule ‖ path ‖ H(match) ‖ H(context))
```

`match` is the text the rule matched (for a secret, the secret itself), and
`context` is the two non-blank lines on either side, with whitespace collapsed
and the match blanked out. A finding counts as already in the baseline when,
in order:

1. its fingerprint is in the baseline. The line can move freely, as long as the
   code around it is unchanged;
2. a baseline entry has the same rule, file and match. The nearest line wins.
   This covers edits around the finding;
3. exactly one entry anywhere has the same rule and match, and exactly one
   finding is left to claim it. This covers a renamed or moved file.

Each baseline entry can be claimed by one finding only, so a second copy of a
known secret is still reported. Entries that nothing claims are counted in the
output ("no longer found"), which usually means they were fixed. Refresh the
baseline with `--update-baseline` to drop them.

For `audit`, the match is the package rather than its version: upgrading a
package that is still affected by the same advisory is not a new finding.

### What the salt does, and what it does not

The baseline never stores a secret in plain text, only keyed hashes. The key
(`salt`) is random per repository and stored in the baseline file itself. As a
result:

- the hashes cannot be looked up in precomputed tables, and differ between
  repositories;
- anyone who can read the baseline can still test a **guess**: hash a
  candidate secret with the salt and compare. For a strong credential this is
  infeasible. For a short or predictable one (a weak password, a 6-digit PIN)
  it is not.

Treat the baseline like other repository metadata: it tells a reader which
files have findings, and lets them confirm guesses. It does not tell them the
secrets.

### Upgrading a 0.3 baseline

A baseline written by greengate 0.3 (a JSON array of path, rule and line) still
works, but it matches exact lines only, and greengate says so. Convert it:

```bash
greengate baseline migrate
```

This re-scans, keeps the findings the old baseline matched, and rewrites the
file as version 2. Old entries that no longer match any finding are dropped,
and the command reports how many.

## Governed exceptions

An exception waives specific findings for a limited time, and records who
decided and why. Exceptions live in `.greengate/exceptions.toml`:

```toml
[[exception]]
id = "EX-12"
match = { advisory = "GHSA-35jh-r3h4-6jhm", package = "lodash" }
reason = "Not reachable: we never call _.template with user input"
owner = "@payments-team"
expires = "2026-12-31"
ticket = "SEC-481"          # optional

[[exception]]
id = "EX-13"
match = { rule = "CI/UnpinnedAction", path = ".github/workflows/release.yml" }
reason = "Org-internal action, pinned by branch protection"
owner = "@platform"
expires = "2026-11-30"

[[exception]]
id = "EX-14"
match = { fingerprint = "gg1:4e6a3e3823389d4f5be47988a349f655" }
reason = "Revoked test key, history rewrite scheduled"
owner = "alice@example.com"
expires = "2026-10-31"
```

`id`, `match`, `reason`, `owner` and `expires` are required. `match` takes
exactly one of:

| Match | Waives | Optional narrowing |
|---|---|---|
| `fingerprint = "gg1:…"` | one finding | none |
| `rule = "…"` | a rule's findings | `path` (a glob) and/or `package` |
| `advisory = "GHSA-…"` | one advisory | `package` (`name` or `name@version`) |

A finding's fingerprint is shown in the JSON report (`--report out.json`).
Fingerprints are keyed with the baseline's salt, so they exist only once the
repository has a `.greengate-baseline.json`.

### Policy

- No exception may run more than `[policy] max_exception_days` (default **90**)
  from today. A longer one makes the file invalid.
- When an exception expires, its findings **count again**. The finding's
  message names the exception and its owner, for example `(exception EX-12
  expired 2026-12-31, owner @payments-team)`.
- An exception that expires within 14 days produces a warning, both in the
  output and in the report's `warnings`.
- An invalid file (a missing field, a bad date, an unknown key, a duplicate
  `id`) stops every gate with exit code `2`, the same as an invalid
  `.greengate.toml`. `greengate check-config` validates it and reports expired
  and expiring exceptions.

`greengate exceptions list` prints every exception with its owner and how long
it has left.

### Moving from `ignore_advisories`

`[audit] ignore_advisories` still works in 0.4, but it is deprecated: it has no
owner, reason or expiry. Convert it:

```bash
greengate exceptions migrate --owner @security
```

This appends one exception per advisory, expiring `max_exception_days` from
today. `--owner` defaults to your `git config user.email`. Replace each
placeholder reason with the real one, then delete `ignore_advisories` from
`.greengate.toml`.

## Inline comments

```python
password = "hunter2"  # greengate: ignore reason="fixture for the login test"

# greengate: ignore — documented example key
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
```

A comment on a line covers that line. A comment on a line of its own also
covers the line below it. In JS, TS, Python, Go and Rust files (with SAST on,
the default), a comment on the line *after* a finding also counts, because
formatters often move it there. The reason is optional: give it as `reason="…"`, or as any text after
the marker. The report lists every covered finding with its reason.

## In the report

Every suppressed finding appears under `suppressed` with a `suppression`
object:

```json
{
  "rule": "OSV/GHSA-35jh-r3h4-6jhm",
  "location": { "kind": "package", "ecosystem": "npm", "name": "lodash", "version": "4.17.20" },
  "message": "Command Injection in lodash",
  "suppression": {
    "kind": "exception",
    "id": "EX-12",
    "reason": "Not reachable: we never call _.template with user input",
    "owner": "@payments-team",
    "expires": "2026-12-31"
  }
}
```

`kind` is `inline`, `exception`, `baseline`, `config` (`ignore_advisories`) or
`triage` (`scan --triage`). The text output ends with a tally by kind, and
names every exception that was used.
