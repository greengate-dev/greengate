---
title: 'install: inspect dependencies and restrict install scripts'
description: 'Plan supported dependency installs, apply policy, inspect artifacts, and run supported script phases with Linux bubblewrap isolation when available.'
---

# install

`greengate install` combines dependency policy with install-script inspection and execution controls. It supports npm, pnpm, Yarn, Bun, pip, uv, and Cargo. The phases and protection boundaries depend on the package manager.

```bash
greengate install npm ci
greengate install pnpm install --frozen-lockfile
greengate install yarn install
greengate install bun install
greengate install --pip .venv/bin/pip pip install -r requirements.txt
greengate install uv sync
greengate install cargo add serde
```

The package manager and its build tools must already be installed. The compatibility commands `watch-install`, `pip-install`, and `cargo-add` are deprecated and scheduled for removal in 0.5.

## Planning and policy

```bash
greengate install --plan npm install some-package
```

`--plan` avoids applying the requested install. For JavaScript managers it resolves, fetches, and inspects in a scratch project with lifecycle scripts disabled. Cargo restores its manifests and lockfile after inspecting fetched crates. uv restores its manifests and lockfile and stops before dependency sync; its plan does not inspect installed artifacts or `.pth` files.

**Python planning can execute package code.** pip and uv may run source-build backends to obtain metadata. With bubblewrap, those phases run isolated with network access for build requirements. Without isolation, they can run unconfined. `--plan` does not promise code-free resolution or unchanged package-manager caches.

The gate applies [`deps check`](deps.md) policy to the plan and checks known advisories for registry packages added or changed. The name guard scores explicitly requested package names; it does not score every transitive name. An unchanged lockfile does not trigger a full advisory re-audit: run [`audit`](audit.md) for that coverage.

Blocking plan findings and unfinished checks normally stop later phases. `[policy] on_incomplete = "warn"` or `--allow-incomplete` permits incomplete checks; it does not waive runtime errors. `--no-fail` permits findings and can continue the install, although an unplanned JavaScript package's scripts remain excluded. A later execution failure can still make the run fail after package code has run.

## Package-manager behavior

| Manager | Planning and inspection | Execution boundary |
|---|---|---|
| npm | Resolve a lockfile and fetch with lifecycle scripts disabled; inspect installed hooks, selected helper files, and native-build definitions | Approved dependency scripts run per package through `npm rebuild` |
| pnpm | Resolve and fetch with scripts disabled; respect supported build-approval settings | `pnpm rebuild` runs approved names; the project is writable for bookkeeping, with root changes checked afterward |
| Yarn 1 | Plan with a scripts-disabled install in a scratch project, then fetch the frozen tree | Dependency scripts run through npm; npm is also required |
| Yarn Berry | Update the lockfile without builds, then fetch with builds skipped | Approved builds share one `yarn rebuild` sandbox; held-back suspicious or unplanned packages block the combined build step |
| Bun | Resolve and fetch with scripts disabled; respect Bun's trust decisions | Trusted dependency scripts run through npm; npm is also required |
| pip | Resolve from a pip report, verify downloads, inspect wheels, and prepare source requirements | Source builds run in a sandbox when available; downloaded and built wheels are checked for suspicious `.pth` startup code before installation |
| uv | Lock in the sandbox when available, apply policy, then sync dependencies separately from the project | Dependency source builds run during sync; new or changed `.pth` files are inspected and suspicious files are quarantined afterward |
| Cargo | Add or update dependencies, fetch them, and inspect new build scripts and proc-macro sources | No crate compilation occurs here; later `cargo build` runs outside this gate |

pip local-directory sources build from copies, and git requirements are checked out at the planned commit. Editable and `--target` pip installs are unsupported. pip report support requires pip 22.2 or later. Cargo accepts `add`, `update`, and `fetch`; `cargo install` is unsupported.

The JavaScript inspection pass uses static signals, not complete program analysis. pip follows recognized imports into Python source files shipped in the same wheel; uv reads modules from the `.pth` file's site-packages directory. These are bounded checks and do not resolve every possible runtime import or native extension.

## Require Linux isolation

```bash
greengate install --isolate bwrap npm ci
```

`--isolate auto` is the default: it uses working bubblewrap on Linux and otherwise permits the unisolated fallback. `--isolate bwrap` requires bubblewrap; `--isolate none` explicitly disables OS isolation.

To refuse supported dependency script and Python build phases without isolation:

```toml
[supply_chain]
require_isolation = true
```

This includes pip metadata resolution and uv locking and syncing. It does not sandbox a later Cargo build, the project's own JavaScript lifecycle scripts, or uv's final project installation.

## Filesystem, network, and environment

With bubblewrap, supported dependency phases use a read-only system, private home and temporary directories, and writable package or scratch directories. Toolchains remain readable. pnpm and Yarn Berry also need project write access for manager state, so those paths combine restrictions with post-execution checks.

Known credential files are masked in the project, nested directories, and linked directories: `.env`, `.env.*`, `.npmrc`, `.yarnrc.yml`, `.pypirc`, `.netrc`, `.git-credentials`, and the root `.git/config`. The search skips dependency/build trees and virtual environments and warns if its directory limit is reached. It does not discover secrets in every arbitrary file.

JavaScript dependency scripts have networking disabled unless their package is listed in `script_network`. pip and uv resolution and source-build phases have networking enabled to obtain build requirements. Allowing network access is a policy decision, not proof that a build is safe.

The environment is reduced to build-related variables, with recognized credential names removed and userinfo stripped from kept URLs. `env_allow` passes matching names or prefixes unchanged, including credentials:

```toml
[supply_chain]
require_isolation = true
script_network = ["puppeteer"]
env_allow = ["SHARP_*", "ELECTRON_MIRROR"]
```

Without isolation, eligible scripts run with the reduced environment; suspicious JavaScript scripts are held back unless allowlisted. Filesystem monitoring detects some foreign writes after execution and cannot prevent reads or network access. A script running under OS isolation can still use its writable area and any readable data exposed to it.

The project's own JavaScript lifecycle scripts run normally after dependency handling. uv's final project installation also runs normally, unless `--no-install-project` is requested. Treat the project and package-manager configuration as trusted inputs.

## Script flags and allowlists

`--ignore-scripts`, including `=true` and `=1`, suppresses JavaScript dependency and project lifecycle scripts. Flags that would undo greengate's phase controls are rejected. `--prefix`, `--dir`, and `--cwd` are unsupported for the JavaScript install wrappers; run from the intended directory.

`allow_postinstall` permits selected JavaScript scripts that would otherwise be held back. It does **not** grant network access; use `script_network` separately. `allow_pip_packages` and `allow_cargo_crates` waive selected package checks. Keep allowlists narrow and review their effects.

## Findings

| Rule | Meaning |
|---|---|
| `INSTALL/SuspiciousScript` | A script or inspected helper matches suspicious patterns |
| `INSTALL/BlockedWrite` | A supported build or script attempted a write refused by the sandbox |
| `INSTALL/ForeignWrite` | A monitored phase changed files outside its permitted package scope |
| `INSTALL/PhantomFile` | Monitored files appeared and disappeared outside the package scope |
| `INSTALL/UnplannedPackage` | An installed JavaScript package was absent from the plan; its scripts stay excluded |
| `INSTALL/BuildNotAllowed` | pnpm's build policy does not allow the package |
| `INSTALL/SuspiciousBuildScript` | A new Cargo build script or proc-macro source matches suspicious signals |
| `INSTALL/StartupCode` | Python startup code or a recognized imported helper looks suspicious |
| `INSTALL/HashMismatch` | A downloaded pip artifact does not match its reported hash |

Dependency policy and advisory findings also appear in the report. See [limitations](/reference/limitations) and [exit codes](/reference/exit-codes).

## Options

```text
greengate install [--plan] [--isolate auto|bwrap|none] [--no-fail] [--pip PIP] <MANAGER> <COMMAND> [ARGS…]
```
