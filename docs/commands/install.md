---
title: 'install — Inspect Before Any Package Code Runs'
description: 'Install npm, pnpm, Yarn, Bun, pip, uv and Cargo dependencies with no package code running before greengate has checked the complete tree: plan, fetch with scripts off, inspect every install script, then run approved scripts in a bubblewrap sandbox with no network, confined writes and masked credentials.'
---

# install — Inspect Before Any Package Code Runs

`greengate install` installs dependencies so that **no package code runs
before greengate has looked at the complete dependency tree** — direct and
transitive, including `npm ci` installs that name no packages.

```bash
greengate install npm ci
greengate install pnpm install --frozen-lockfile
greengate install yarn install
greengate install bun install
greengate install pip install -r requirements.txt     # --pip venv/bin/pip
greengate install uv sync
greengate install cargo add serde
greengate install --plan npm install some-new-package   # look, change nothing
```

`watch-install`, `pip-install` and `cargo-add` are deprecated and run
through `greengate install` when they wrap one of these managers; they will
be removed in 0.5.

## Per package manager

| | Plan (no package code) | Fetch | What runs, and how |
|---|---|---|---|
| **npm** | `npm install --package-lock-only --ignore-scripts` in a scratch copy | `npm ci --ignore-scripts` | each approved package's install scripts via `npm rebuild <name>@<version>`, sandboxed |
| **pnpm** | `pnpm install/add --lockfile-only --ignore-scripts` in a scratch copy | `pnpm install --frozen-lockfile --ignore-scripts` | only builds pnpm itself allows (`onlyBuiltDependencies`; pnpm 10 builds nothing by default), via `pnpm rebuild <name>`, sandboxed: the project is writable for pnpm's own state, but the package store and `.git` are read-only except the running package |
| **Yarn 1** | an `--ignore-scripts` install in a scratch copy (Yarn 1 has no lockfile-only mode) | `yarn install --frozen-lockfile --ignore-scripts` | like npm: each package via `npm rebuild <name>@<version>`, sandboxed |
| **Yarn Berry** | `yarn install --mode=update-lockfile` in a scratch copy | `yarn install --immutable --mode=skip-build`, which unplugs the packages that need building | Berry builds every package in one step, so isolation keeps builds from the rest of the system but not from each other. A suspicious-looking build is therefore held back even when isolated — allowlist it, or set `dependenciesMeta.<name>.built: false` so Yarn never builds it — and then no builds run, since Berry would build it too. |
| **Bun** | `bun install/add --lockfile-only` in a scratch copy | `bun install --frozen-lockfile --ignore-scripts` | only packages Bun trusts (`trustedDependencies` and its built-in list; `bun pm untrusted` names the rest), each via `npm rebuild`, sandboxed |
| **pip** | `pip install --dry-run --report` — **in the sandbox**, because resolving an sdist runs its build backend | greengate downloads every artifact itself and checks its sha256 against the index | sdists are built into wheels in the sandbox (with network, for build requirements; writes confined to a scratch directory); then only wheels are installed, which runs no package code |
| **uv** | `uv lock` / `uv add --no-sync` — **in the sandbox**, because locking runs sdist build backends; manifests are backed up | `uv sync --frozen --no-install-project` in the sandbox (uv checks every hash; sdist builds run there) | new `.pth` startup files are checked before any Python starts and suspicious ones quarantined; then the project itself is installed |
| **Cargo** | `cargo add` / `update` (manifests are backed up) | `cargo fetch --locked` (cargo checks every checksum) | nothing: build scripts and proc-macros run at `cargo build`, after the gate. New crates' build scripts and proc-macro sources are inspected; networking, shell invocations or encoded payloads block (`allow_cargo_crates` to allowlist). A blocked plan restores `Cargo.toml` and `Cargo.lock`. |

pip wheels are also inspected for `.pth` files with executable lines — they
run at every Python start, so isolation at install time does not help;
suspicious ones block (`INSTALL/StartupCode`).

## Phases

| Phase | What happens | Package code runs? |
|---|---|---|
| **Plan** | npm resolves the full tree into a lockfile in a scratch copy of the project (`--package-lock-only --ignore-scripts`). greengate applies the [`deps check`](deps.md#deps-check-supply-chain-policy) policies to every package the install adds or changes — release cooldown, new install scripts, lost provenance, registry binding, sources — and the name guard to packages named on the command line. A violation stops here: nothing is downloaded. | No |
| **Fetch** | `npm ci --ignore-scripts` downloads and extracts the planned tree. | No |
| **Verify artifacts** | npm checks every tarball against the lockfile integrity; greengate checks nothing outside the plan was installed. | No |
| **Inspect** | Every installed package — nested copies included — that runs code at install: lifecycle scripts, the helper files they call (`node install.js`), and `binding.gyp` builds. Suspicious patterns (network, `eval`, shell, `process.env`, `../`, an embedded encoded payload) are reported. | No |
| **Execute** | Approved scripts run one package at a time, dependencies first (`npm rebuild <name>@<version>`). | Yes — see below |
| **Verify files** | Without a sandbox: the tree is compared before and after each script, and a filesystem watcher catches files that appear and vanish. | — |

`--plan` stops after **Inspect**, working entirely in the scratch copy: the
project is not modified and no package code runs.

## How scripts run

With **bubblewrap** (Linux, `--isolate auto` picks it when it works), each
package's scripts run in a sandbox where:

- the whole system is read-only except that package's own directory and a
  private temp directory,
- there is no network (unless the package is listed in
  `[supply_chain] script_network`),
- credential files are masked (`~/.ssh`, `~/.aws`, `~/.npmrc`, `~/.netrc`,
  `~/.config/gh`, a project `.npmrc`, …).

A package's own code will run at runtime anyway; the sandbox makes sure
install time grants it nothing more. So a script with suspicious patterns is
**reported and run isolated** rather than blocked — real installers such as
esbuild's use networking, `child_process` and `process.env`, and blocking them
would break ordinary installs. A script that tries to write outside its
package is refused by the sandbox and reported as `INSTALL/BlockedWrite`.

**Without isolation** (`--isolate none`, or no bubblewrap), suspicious
scripts are **not run** unless the package is in
`[supply_chain] allow_postinstall`, and writes outside the package are
detected afterwards (`INSTALL/ForeignWrite`, `INSTALL/PhantomFile`) rather
than prevented. Set `[supply_chain] require_isolation = true` to refuse to
run scripts at all without a sandbox (the run is then incomplete).

In both modes, environment variables that look like credentials
(`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `SSH_AUTH_SOCK`, …) are removed
from install scripts; keep specific ones with `[supply_chain] env_allow`.

The project's own `preinstall`/`install`/`postinstall`/`prepare` scripts run
afterwards as usual — they are the project's code.

## Findings

| Rule | Meaning |
|---|---|
| `INSTALL/SuspiciousScript` | An install script (or a file it runs) matches suspicious patterns. Warning when it runs isolated or allowlisted; violation when it is held back. |
| `INSTALL/BlockedWrite` | A script tried to write outside its package; the sandbox refused. |
| `INSTALL/ForeignWrite` | Unisolated, a script created, modified or deleted files outside its package. |
| `INSTALL/PhantomFile` | Unisolated, a script created and deleted files outside its package. |
| `INSTALL/UnplannedPackage` | A package was installed that the plan did not contain. |
| `INSTALL/BuildNotAllowed` | pnpm will not run this package's install scripts (not in `onlyBuiltDependencies`), so greengate does not either. |
| `INSTALL/SuspiciousBuildScript` | A new crate's build script or proc-macro uses networking, shells out, or embeds an encoded payload. |
| `INSTALL/StartupCode` | A wheel adds a `.pth` file whose code runs at every Python start and looks suspicious. |
| `INSTALL/HashMismatch` | A downloaded pip artifact does not match the sha256 the index published. |

Plus every `deps check` rule from the plan phase.

## Options

```
greengate install [--plan] [--isolate auto|bwrap|none] [--no-fail] [--pip PIP] <npm|pnpm|yarn|bun|pip|uv|cargo> <COMMAND> [ARGS…]
```

```toml
[supply_chain]
require_isolation = false         # no sandbox → do not run scripts (incomplete)
script_network = ["puppeteer"]    # packages whose scripts may use the network
env_allow = ["NODE_EXTRA_CA_CERTS"]
allow_postinstall = ["sharp"]     # run unisolated even with suspicious patterns
```
