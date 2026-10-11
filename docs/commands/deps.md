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
