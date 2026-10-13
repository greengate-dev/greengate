---
title: 'deps — Dependency Graph'
description: 'List every package greengate reads from your lockfiles, show the chain that pulls a transitive dependency in, gate new releases on supply-chain risk, and review what a pull request does to the dependency tree — with the smallest fix for each new advisory. npm, Yarn, pnpm, Bun, uv, Poetry, pylock, pip, Cargo and Go.'
---

# deps — Dependency Graph

Shows the dependency graph greengate reads from the project's lockfiles — the
same one `audit` and `sbom` use.

## Usage

```
greengate deps list [--path <DIR>] [--format text|json]
greengate deps why <PACKAGE[@VERSION]> [--path <DIR>]
greengate deps check [--base <REV> | --all] [--path <DIR>]
greengate deps review [--base <REF>] [--format text|json|markdown] [--annotate] [--path <DIR>]
```

`deps list` prints every package in every dependency file under the
directory: version, whether it is a direct dependency, its scope (`prod`,
`dev`, `optional`) and its source (registry, git, URL or path).

`deps why` prints the shortest chain from the project to a package:

```
$ greengate deps why ms@2.0.0
pnpm-lock.yaml — my-app → debug@2.6.9 → ms@2.0.0
```

It exits `4` when no dependency file contains the package.

## deps check — supply-chain policy

`deps check` is a gate (exit codes `0`/`1`/`3`, `--report`) that answers
"is it safe to install what this change pins?" without installing anything.

**Release risk** — for each package that is new or upgraded since the base,
greengate asks the registry about that exact release and the one before it:

| Signal | Default | Fires when |
|---|---|---|
| `RELEASE/YoungRelease` | warn | the release is younger than `min_release_age_hours` (24) |
| `RELEASE/NewInstallScript` | fail | it runs code at install (npm lifecycle scripts / node-gyp; a PyPI release with no wheels) and its predecessor did not |
| `RELEASE/ProvenanceRegression` | fail | its predecessor had publish provenance (npm attestations, PEP 740, crates.io trusted publishing) and it has none |
| `RELEASE/PublisherChange` | warn | it was published, without provenance, by an account that never published an earlier version |
| `RELEASE/Withdrawn` | warn | it is yanked, deprecated, or not on the registry |

These are suspicion signals, not proof: maintainers hand over, and fresh
releases are usually fine. A release inside the cooldown that fixes an
advisory affecting the version it replaces is reported as a warning, not a
block, so security patches are not held back. Signals that a registry does
not expose (crates.io install scripts, PyPI publishers) never fire. Packages
from private registries are skipped; their own controls govern them.

The base is `--base <rev>`; in GitHub Actions without one, the merge base
with the PR's target branch; otherwise `HEAD` (your uncommitted lockfile
changes). `--all` checks every package, e.g. on a schedule. Outside a git
repository every package is checked.

**Lockfile policy** — offline, every package:

| Rule | Fires when |
|---|---|
| `REGISTRY/Mismatch` | a package matching a `[[supply_chain.registries]]` pattern resolves from another registry |
| `REGISTRY/DependencyConfusion` | a package matching `internal_packages` resolves from the public registry |
| `SOURCE/UnpinnedGit`, `SOURCE/Url`, `SOURCE/Path` | per `[supply_chain.sources]` |
| `LOCKFILE/MissingIntegrity` | registry packages without an integrity hash, in formats that normally record one |

pnpm, Bun and Yarn Berry do not record which registry served a package, so
a registry rule covering one of their packages makes the run *incomplete*
rather than passing it unverified.

Configure everything under `[supply_chain]` — see the
[configuration reference](../reference/config.md). In a pipeline, add the
step `deps-check` (`[pipeline] steps = ["deps-check", "audit", …]`).

## deps review — what a change does to the dependency tree

`deps review` compares every lockfile with its version at the merge base of
`--base` and `HEAD`, and lists each package that was **added**, **removed**,
**upgraded** or **downgraded**, with:

- whether it is a direct dependency, and the chain that pulls it in if not;
- its license, as an SPDX expression (from the registry);
- the advisories the change **introduces** (the new version is affected, the
  old one was not) and **fixes**;
- the release-risk signals of [`deps check`](#deps-check-supply-chain-policy)
  and the registry and source rules, for the packages the change brings in;
- for each introduced advisory, **how to fix it**.

```
$ greengate deps review --base origin/main

Dependency review: 3 added since merge base with origin/main (7e923c53)

  package-lock.json
    + lodash 4.17.20  direct · MIT · introduces GHSA-35jh-r3h4-6jhm, …
    + minimist 0.0.8  transitive · MIT · introduces GHSA-xvch-5gv4-984h, …
        via app@1.0.0 → mkdirp@0.5.1
    + mkdirp 0.5.1  direct · MIT

Blocking (3):
  [HIGH] OSV/GHSA-35jh-r3h4-6jhm lodash@4.17.20 — Command Injection in lodash (added, direct)
      fix: npm install lodash@^4.18.0
  [CRITICAL] OSV/GHSA-xvch-5gv4-984h minimist@0.0.8 — Prototype Pollution in minimist (added, transitive)
      fix: npm install mkdirp@^0.5.5  (mkdirp 0.5.1 → 0.5.5, outside your current requirement)
  …
```

Without `--base`, the merge base with the pull request's target branch is
used in GitHub Actions (`GITHUB_BASE_REF`), and `HEAD` elsewhere — so locally
it reviews your uncommitted lockfile changes.

### How fixes are worked out

For a vulnerable `X@v`, greengate takes the versions that none of its new
advisories affect (on any release line) and checks what everything that
depends on X requires of it — the project's own manifest (`package.json`,
`Cargo.toml`, `pyproject.toml`) or, for a dependency, its registry metadata:

1. **Every dependent already allows a fixed version** → refresh X:
   `npm update X`, `pnpm update X`, `yarn up -R X` (Yarn 2+), `bun update X`,
   `cargo update -p X@v --precise F`, `uv lock -P X`, `poetry update X`,
   `go get X@F`. Yarn 1's `yarn upgrade` only moves direct dependencies, so
   for Yarn 1 the advice is to delete X's entries from `yarn.lock` and run
   `yarn install`.
2. **The project's own requirement excludes it** → raise it
   (`npm install X@^F`, `cargo add X@F`, `uv add 'X>=F'`, …).
3. **A direct dependency D pins an older X** → the lowest release of D whose
   requirement allows a fixed X, and whether it is within your current
   requirement on D (`npm update D`) or needs a new one (`npm install D@^V`).
   Deprecated and yanked releases are skipped.
4. **Nothing allows it yet** (or the blocker is deeper in the tree) → the
   package manager's override, scoped to the blocking parent where the
   manager supports that: npm `overrides`, pnpm `pnpm.overrides` (`"P>X"`),
   Yarn `resolutions` (`"P/X"`), Bun `overrides`, uv
   `override-dependencies`. Cargo and Poetry have no way to force a version
   past a dependency's requirement; the review says so.

### Policy

```toml
[dependency_review]
fail_on_severity = "high"     # introduced advisories at or above this fail; below, warn
fail_on = ["new-advisory", "release-risk", "denied-license", "source-policy"]
deny_licenses = ["AGPL-3.0-only", "GPL-3.0-only"]
allow_licenses = []           # when set, only these are acceptable
unknown_license = "warn"      # off | warn | fail
```

- Advisories without a severity count as meeting `fail_on_severity`.
- Release-risk and source rules fail only at level `fail` (see
  `[supply_chain]`), and only when their kind is in `fail_on`; everything
  else is a warning.
- A license expression is acceptable when any alternative of an `OR` is, and
  when every part of an `AND` is. Denying `GPL-3.0-only` also catches the
  ambiguous `GPL-3.0`.
- `--profile strict` fails on every introduced advisory and on unknown
  licenses.
- Exceptions in `.greengate/exceptions.toml` apply; advisories are rules
  named `OSV/<id>`, so `match = { advisory = "GHSA-…", package = "lodash" }`
  waives one.

Exit codes are the usual ones: `0` passed, `1` blocking findings, `3` when
something could not be checked (OSV or a registry unreachable, a lockfile
unreadable at the base).

### Output and GitHub

- `--format text` (default) — the review above, on stderr.
- `--format markdown` — the pull-request comment, on stdout.
- `--format json` — a `greengate.deps-review/v1` document: `base`, every
  change with its evidence and fix guidance, and the `greengate.report/v1`
  report.
- `--annotate` — posts the review to the pull request: one comment, found
  again by a hidden marker and **updated in place** on every push, and a
  check run with an annotation on each affected lockfile line. Needs
  `GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `GITHUB_SHA`, and the permissions
  `pull-requests: write` and `checks: write`.

Set `dependency-review: true` and pin both the action and binary versions; see [CI integration](/guide/ci-integration):

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0   # the merge base must be in the history
  - uses: greengate-dev/greengate@v0.4.0
    with:
      version: v0.4.0
      dependency-review: true
```

In a `[pipeline]`, the step is `deps-review` (it takes `--base` and
`--annotate`).

**Limits.** Licenses come from the registry; PyPI records one per project,
so a Python package's license is its latest release's. Packages from git, URL
or path sources and from private registries are listed but not looked up.
Go modules always get `go get X@F`: a `go.mod` requirement is a minimum.

## Supported files

| Ecosystem | Dependency files |
|---|---|
| Node.js | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (Yarn 1 and Berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` |
| Python | `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751), `requirements.txt` (`==` pins) |
| Rust | `Cargo.lock` |
| Go | `go.mod` (Go 1.17+, with `replace` directives), else `go.sum` |

Each file parses into packages, the edges between them, and the project's
own code (the root and workspace members). Some formats do not record edges —
`requirements.txt`, `go.sum`, and `pylock.toml` written without
`dependencies` — so `deps why` reports that rather than inventing a chain.
`go.mod` records which modules the main module imports, but not why an
`// indirect` module is needed.

Scopes come from the lockfile where it records them (npm's `dev` flag,
Poetry groups, uv dependency groups). Otherwise they are derived from the
edges: a package reachable only through dev dependencies is `dev`. Cargo.lock
has no dev marker, so greengate reads `[dev-dependencies]` from the
workspace's `Cargo.toml` files.

Skip files with `[deps] exclude_patterns` in `.greengate.toml`.
