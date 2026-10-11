---
title: 'deps — Dependency Graph'
description: 'List every package greengate reads from your lockfiles and show the chain that pulls a transitive dependency into the project. npm, Yarn, pnpm, Bun, uv, Poetry, pylock, pip, Cargo and Go.'
---

# deps — Dependency Graph

Shows the dependency graph greengate reads from the project's lockfiles — the
same one `audit` and `sbom` use.

## Usage

```
greengate deps list [--path <DIR>] [--format text|json]
greengate deps why <PACKAGE[@VERSION]> [--path <DIR>]
greengate deps check [--base <REV> | --all] [--path <DIR>]
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
