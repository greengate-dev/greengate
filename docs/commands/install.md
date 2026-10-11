---
title: 'install — Inspect Before Any Package Code Runs'
description: 'Install npm dependencies with no package code running before greengate has checked the complete tree: plan, fetch with scripts off, inspect every install script, then run approved scripts in a bubblewrap sandbox with no network, confined writes and masked credentials.'
---

# install — Inspect Before Any Package Code Runs

`greengate install` installs dependencies so that **no package code runs
before greengate has looked at the complete dependency tree** — direct and
transitive, including `npm ci` installs that name no packages.

```bash
greengate install npm ci
greengate install npm install left-pad
greengate install --plan npm install some-new-package   # look, change nothing
```

npm is supported so far; pnpm, pip and Cargo come next. Until then
[`watch-install`](watch-install.md), [`pip-install`](pip-install.md) and
[`cargo-add`](cargo-add.md) cover those.

## Phases

| Phase | What happens | Package code runs? |
|---|---|---|
| **Plan** | npm resolves the full tree into a lockfile in a scratch copy of the project (`--package-lock-only --ignore-scripts`). greengate applies the [`deps check`](deps.md#deps-check-supply-chain-policy) policies to every package the install adds or changes — release cooldown, new install scripts, lost provenance, registry binding, sources — and the name guard to packages named on the command line. A violation stops here: nothing is downloaded. | No |
| **Fetch** | `npm ci --ignore-scripts` downloads and extracts the planned tree. | No |
| **Verify artifacts** | npm checks every tarball against the lockfile integrity; greengate checks nothing outside the plan was installed. | No |
| **Inspect** | Every installed package — nested copies included — that runs code at install: lifecycle scripts, the helper files they call (`node install.js`), and `binding.gyp` builds. Suspicious patterns (network, `eval`, shell, `process.env`, `../`, high entropy) are reported. | No |
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

Plus every `deps check` rule from the plan phase.

## Options

```
greengate install [--plan] [--isolate auto|bwrap|none] [--no-fail] npm <install|ci> [ARGS…]
```

```toml
[supply_chain]
require_isolation = false         # no sandbox → do not run scripts (incomplete)
script_network = ["puppeteer"]    # packages whose scripts may use the network
env_allow = ["NODE_EXTRA_CA_CERTS"]
allow_postinstall = ["sharp"]     # run unisolated even with suspicious patterns
```
