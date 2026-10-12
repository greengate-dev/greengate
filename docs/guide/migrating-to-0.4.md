---
title: 'Migrating to 0.4 — GreenGate'
description: 'What changes when you upgrade greengate from 0.3 to 0.4: exit codes, incomplete runs, run continuing past failures, greengate install replacing the install wrappers, baselines v2, exceptions, and renamed flags — with what to change in CI.'
---

# Migrating to 0.4

0.4 makes the gate stricter about one thing above all: **a check that could
not run is no longer a pass.** Most of the upgrade is about that, plus moving
from the install wrappers to `greengate install`. Work through the list below
in order; most projects need only the first two items.

## 1. Exit codes

| Code | 0.3 | 0.4 |
|---|---|---|
| `0` | passed, *or could not check* | passed |
| `1` | findings, *or any error* | findings |
| `2` | — | usage or configuration error (including an invalid `.greengate.toml`) |
| `3` | — | **incomplete**: some checks could not run, and nothing that ran found a problem |
| `4` | — | error: the gate or a tool it wraps failed |

**What to change:** CI steps that only check for success need nothing. A
script that tests `$? -eq 1` to mean "failed" should test `$? -ne 0`, or
handle `3` and `4` separately. See [exit codes](/reference/exit-codes).

## 2. Incomplete runs fail by default

In 0.3, `audit` with an unreachable OSV API printed a warning and exited `0`.
In 0.4 it exits `3`. The same applies to:

- a lockfile that could not be read;
- `requirements.txt` entries that are not `==` pinned;
- a Kubernetes manifest that did not parse;
- an unreadable workflow file in `ci-lint`;
- PageSpeed Insights being unreachable in `lighthouse`;
- `sbom --verify` without an expected signer identity;
- `image-scan` finding no layers;
- install wrappers whose registry lookups failed.

**What to change**, pick one:

- Keep it strict (recommended) and make the data available: in air-gapped or
  flaky-network CI, add `greengate db update` to a cached step and set
  `[audit] source = "auto"` (the default), so `audit` falls back to the
  offline snapshot.
- Accept incomplete runs: `[policy] on_incomplete = "warn"` in
  `.greengate.toml`, or `--allow-incomplete` per command. The exit code is `0`
  and the output still says *incomplete*.

## 3. `run` runs every step

`greengate run` used to stop at the first failing step. It now runs every
step and exits with the worst result, so one run shows everything that needs
fixing, and `--report` writes one merged report.

**What to change:** nothing, unless later steps must not run after a failure
(e.g. a deploy step). Then set:

```toml
[pipeline]
fail_fast = true
```

## 4. Install wrappers → `greengate install`

`watch-install`, `pip-install` and `cargo-add` are deprecated and **removed in
0.5**. When they wrap npm, pnpm, Yarn, Bun, pip ≥ 22.2 or a Cargo project,
they already run through [`greengate install`](/commands/install) in 0.4. That
changes how install scripts run:

- They run one package at a time, in bubblewrap where available: **no
  network**, the system read-only, a private home directory and `/tmp`, and
  the project's `.env*`, `.npmrc` and `.git/config` masked.
- Install scripts see an **allowlisted environment** (`PATH`, compilers,
  proxies, package-manager settings, …); everything else, `DATABASE_URL`
  and credential-like variables included, is removed.
- `--ignore-scripts` now also skips dependencies' scripts, and an unfinished
  check (unreachable registry, no OSV snapshot) stops the install before any
  package code runs.
- Packages the install adds or changes are checked for known advisories and
  release risk before anything runs.

**What to change:**

| 0.3 | 0.4 |
|---|---|
| `greengate watch-install npm ci` | `greengate install npm ci` |
| `greengate watch-install pnpm install --frozen-lockfile` | `greengate install pnpm install --frozen-lockfile` |
| `greengate pip-install -r requirements.txt` | `greengate install pip install -r requirements.txt` |
| `greengate cargo-add serde` | `greengate install cargo add serde` |

A package whose install script legitimately needs the network (it downloads a
prebuilt binary) needs `script_network = ["its-name"]` under `[supply_chain]`.
Variables an install script really needs go in `env_allow` (exact names or
`PREFIX_*`). To see what an
install would do without changing anything, use `greengate install --plan …`.

## 5. Advisory suppressions → exceptions

`[audit] ignore_advisories` still works, with a deprecation warning. It has
no owner, reason or expiry. Convert it:

```bash
greengate exceptions migrate --owner @your-team
```

Then give each new entry in `.greengate/exceptions.toml` its real reason, and
remove `ignore_advisories` from `.greengate.toml`. Exceptions expire, at most
`[policy] max_exception_days` (90) out, and their findings count again when
they do. See [Baselines & Exceptions](/guide/baselines-and-exceptions).

## 6. Baselines

A 0.3 `.greengate-baseline.json` still works, matching exact lines as before,
and greengate says so on every run. Upgrade it so findings stay known when
code moves:

```bash
greengate baseline migrate
git add .greengate-baseline.json
```

## 7. Renamed and new flags

| 0.3 | 0.4 |
|---|---|
| `scan --since <ref>` | `scan --changed-since <ref>`: same meaning; `--since` still works, with a warning |
| — | `scan --new-since <ref>`: only findings that are new since the merge base, no baseline file needed |

## 8. Smaller changes

- `sbom` stops with an error when one directory holds two lockfiles for the
  same ecosystem (e.g. `package-lock.json` and `yarn.lock`), instead of
  silently picking one. Remove the stale one, or pass `--lockfile`.
- `scan` no longer reads `.git/`, so committer emails in `.git/config` and
  the reflogs stop appearing as PII findings.
- `ci-lint` rule ids are `CI/UnpinnedAction`, `CI/ExpressionInjection` and
  `CI/PullRequestTargetWithCheckout`; earlier docs used `CILINT/…` names that
  never matched anything.
- The GitHub Action takes `report` and `dependency-review` inputs and sets
  `status`, `findings`, `incomplete` and `report-path` outputs. Pin it to a
  release: `greengate-dev/greengate@v0.4.0`.

## New in 0.4, worth turning on

- [`greengate deps review`](/commands/deps#deps-review-what-a-change-does-to-the-dependency-tree)
  on pull requests (`dependency-review: true` in the Action).
- [`greengate hook claude-code`](/guide/agents) if your team uses coding agents.
- `greengate db update` for offline vulnerability data.
