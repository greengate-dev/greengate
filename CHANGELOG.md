# Changelog

All notable changes to greengate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - Unreleased

### Breaking

See [Migrating to 0.4](docs/guide/migrating-to-0.4.md).

- `audit` exits `3` when it could not check every dependency, instead of warning and exiting `0`. That covers an unreachable or short OSV response, a truncated advisory list, an unreadable lockfile, and `requirements.txt` entries that are not `==` pinned (ranges, `-r` includes, editable installs). Findings still exit `1`; set `on_incomplete = "warn"` to keep exiting `0`.
- Exit codes are now `0` passed, `1` findings, `2` usage or config error, `3` incomplete, `4` error. Previously runtime errors and an invalid `.greengate.toml` exited `1`, the same as findings.
- These runs are now incomplete (exit `3`) instead of passing: `lint` with a manifest that did not parse (un-rendered templates are still skipped); `ci-lint` with a workflow that could not be read; `lighthouse` when PageSpeed Insights cannot be reached or returns an error (previously exit `1`); `sbom --verify` without an expected signer identity; install wrappers whose registry lookups failed; `cargo-add` when `cargo fetch` fails or a new crate's source cannot be found; `image-scan` when no layers are found or a layer cannot be extracted.
- `run` runs every step by default and reports the worst result, instead of stopping at the first failing step; set `[pipeline] fail_fast = true` for the old behaviour. Steps not run under `fail_fast` are reported as incomplete. It prints why a step could not run, and a step given a flag it does not take fails instead of ignoring it.
- `watch-install`, `pip-install` and `cargo-add` are deprecated and run through `greengate install` when they wrap npm, pnpm, Yarn, Bun, pip ≥ 22.2 or a Cargo project — install scripts then run sandboxed without network; list packages that need it in `[supply_chain] script_network`. Other commands keep the old behaviour with a notice. All three are removed in 0.5.
- `sbom` stops with an error when one directory holds two lockfiles for the same ecosystem, instead of using whichever it found first.
- `[audit] ignore_advisories` is deprecated in favour of `.greengate/exceptions.toml` (`greengate exceptions migrate`); 0.3 baselines still work but only match exact lines (`greengate baseline migrate`); `scan --since` is renamed `--changed-since` (alias kept).

### Added
- `greengate.report/v1` — one result model for every gate: `passed`, `findings`, `incomplete`, or `error`, with each check and its reason. `audit --format json` emits it.
- `[policy] on_incomplete = "fail" | "warn"` and a global `--allow-incomplete` flag.
- Global `--report <path>` on every gate: SARIF 2.1.0 for `*.sarif`, otherwise `greengate.report/v1` JSON. Written even when the gate errors. Incomplete checks appear in SARIF as tool-execution notifications with `executionSuccessful: false`. JSON Schema published at `/schema/report-v1.json`.
- `GREENGATE_OSV_URL` to point `audit` at an OSV mirror.
- Offline vulnerability data: `greengate db update` downloads and indexes OSV snapshots (ETag-revalidated); `greengate db status` shows their age. `audit --offline` / `[audit] source = "offline"` match locally; the default `source = "auto"` falls back to a snapshot no older than `max_db_age_hours` (24) when the API fails. Matching follows the OSV schema with SemVer and PEP 440 ordering, and returned the same 464 findings as the API on 11 real npm, pnpm, Cargo, Go and PyPI lockfiles.
- One dependency model for `audit`, `sbom`, `cargo-add` and `watch-install`, with new formats: `bun.lock`, `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751), `npm-shrinkwrap.json`, `package-lock.json` v1, Yarn Berry, pnpm v5–v9 and `go.mod` (with `replace`). It records direct vs transitive, dev/optional scope, source (registry, git, URL, path), integrity and workspace members. Checked against 17 real lockfiles (5,650 packages): every count matches, no orphaned packages.
- `greengate deps list` and `greengate deps why <pkg>`.
- `greengate deps check` (also a `deps-check` pipeline step): release-risk policy for packages new or upgraded since a base revision — release younger than a cooldown (24 h), a new install script, provenance regression (npm attestations, PEP 740, crates.io trusted publishing), a publisher who never published the package before, yanked/deprecated releases — plus offline lockfile policy on every package: `[[supply_chain.registries]]` binding, dependency confusion from `internal_packages`, unpinned git / URL / path sources, missing integrity. Each signal is `off`/`warn`/`fail` under `[supply_chain.release]` and `[supply_chain.sources]`; `--profile strict` turns warnings into failures. A cooldown hit that fixes an advisory in the replaced version is a warning, not a block. Registry metadata is cached for 6 hours.
- `[deps] exclude_patterns` to skip dependency files such as test fixtures.
- `sbom` covers every dependency file (or `--lockfile <file>`), with the dependency graph, scopes (dev → `excluded`), hashes, and `repository_url`/`vcs_url`/`download_url` purl qualifiers.
- `greengate install <npm|pnpm|yarn|bun|pip|uv|cargo> …`: no package code runs before the complete tree is checked. It plans the install without running code and applies `deps check` policy, fetches with scripts off, inspects every install script, build script and `.pth` file, then runs approved scripts one package at a time. `--plan` stops after inspection and changes nothing.
  - With bubblewrap, each script runs with the system read-only except its own package, a private home directory, `/tmp` and `/run` (toolchains stay readable), the project's `.env*`, `.npmrc`, `.git/config` and other secret files masked, its own namespaces and terminal session, and no network (unless listed in `script_network`). Suspicious-looking scripts run there with a warning instead of being blocked, so ordinary installers such as esbuild's still work; a write outside the package is refused and reported.
  - Without isolation, suspicious scripts are held back unless allowlisted, and writes outside a package are caught by before/after comparison and a filesystem watcher. `require_isolation = true` refuses to run package code without a sandbox — for pip and uv, planning too.
  - Install scripts get an allowlisted environment (`PATH`, compilers, proxies, package-manager settings, …); everything else, credential-like variables included, is removed. `env_allow` adds names or `PREFIX_*`.
  - A check that fails or does not finish (unreachable registry, no OSV snapshot) stops the install before any package code runs, unless `on_incomplete = "warn"`.
  - `--ignore-scripts` skips dependencies' scripts too. Flags that would undo a phase's own (`--ignore-scripts=false`, `--no-package-lock-only`, `--`) are refused, so `--plan` never runs package code.
  - pnpm: only builds pnpm itself allows (`onlyBuiltDependencies`) run.
  - pip: planning runs in the sandbox, because resolving an sdist runs its build backend. greengate downloads and sha256-checks every artifact, builds sdists in the sandbox and installs wheels only; a wheel whose `.pth` startup code looks suspicious is blocked.
  - Cargo: new crates' build scripts and proc-macros are inspected before anything builds; a blocked plan restores `Cargo.toml` and `Cargo.lock`.
  - Yarn 1 and Bun: npm-shaped trees, scripts run per package; Bun's trust list (`trustedDependencies`) is respected.
  - Yarn Berry: builds run together in one sandboxed step, so a suspicious-looking build is held back even when isolated (allowlist it or set `dependenciesMeta.<name>.built: false`).
  - uv: locking and `uv sync` run in the sandbox because both run sdist build backends; new `.pth` startup files are quarantined before any Python starts if they look suspicious.
- Checks in the report can carry a `source` — e.g. which snapshot answered and how old it was.
- `GREENGATE_CACHE_DIR` relocates greengate's cache.
- Gating on what a change introduces:
  - `scan --new-since [<ref>]` reports only findings absent at the merge base with `<ref>` (default in a pull request: its base branch). Changed files are scanned as they are and as they were; renames are followed; uncommitted and untracked files count. It works the same as a `run` step (`"scan --new-since origin/main"`).
  - Baselines identify findings by fingerprint (`gg1:` HMAC-SHA256 over rule, path, matched text and surrounding lines, with a per-repository salt), so a known finding stays known when lines move, nearby code changes or its file is renamed. A second copy of a known secret is still new. Secrets are never stored in the baseline.
  - `audit` and `ci-lint` take `--update-baseline` / `--since-baseline`; all three gates share `.greengate-baseline.json`. For `audit`, a version bump still affected by the same advisory stays known.
  - `greengate baseline migrate` upgrades a 0.3 baseline, which still works meanwhile (exact lines only).
- Governed exceptions in `.greengate/exceptions.toml`: each waives one finding (`fingerprint`), a rule (optionally by `path` glob or `package`) or an advisory (optionally by `package`), and needs a `reason`, `owner` and `expires` date no more than `[policy] max_exception_days` (90) away. An expired exception's findings count again, naming the exception and its owner; ones expiring within 14 days are warned about. An invalid file exits `2`; `check-config` validates it. `greengate exceptions list` shows them all.
- `greengate: ignore reason="…"` (or any text after the marker). Every suppressed finding — inline, exception, baseline, `ignore_advisories`, triage — is listed in the report's `suppressed` with a `suppression` object saying why, and the text output tallies them.
- `ci-lint` honours `# greengate: ignore` on the flagged line or the line above.
- `greengate deps review` (also a `deps-review` pipeline step): every package a change adds, removes, upgrades or downgrades since the merge base, with how it gets in (direct, or the chain), its SPDX license, the advisories it introduces or fixes, release-risk signals and registry/source rules.
  - For each introduced advisory, the smallest fix: refresh the package when every dependent already allows a fixed version; raise the project's own requirement; upgrade the direct dependency that pins it (the lowest release that allows a fix, and whether that is within the current requirement); or an override (npm `overrides`, pnpm `pnpm.overrides`, Yarn `resolutions`, Bun `overrides`, uv `override-dependencies`). Fixes count on any release line.
  - `[dependency_review]`: `fail_on_severity`, `fail_on`, `deny_licenses` / `allow_licenses` (SPDX `AND`/`OR` aware), `unknown_license`. Exceptions apply.
  - `--format text|json|markdown`; `--annotate` posts one PR comment, updated in place, and a check run annotating lockfile lines. GitHub Action input `dependency-review: true`; its result is merged into the action's report and `status`/`findings`/`incomplete` outputs.
- GitHub API calls honour `GITHUB_API_URL` (GitHub Enterprise Server).
- Checking what AI agents install:
  - `greengate check-command -- "<shell command>"` finds the dependency installs in a command (`npm i`, `pnpm add`, `yarn`, `bun add`, `pip install`, `uv add`/`sync`, `cargo add`; through `&&`, `cd`, `sudo -u …`, `env -C …`, `nice`, `timeout`, `bash -c`, and options such as `npm --prefix dir`), plans each with `install --plan`, and prints a `greengate.report/v1` document. Installs it cannot plan (Poetry, `cargo install`, global installs, `$(…)` arguments, an option it cannot tell from the subcommand) make it incomplete.
  - `greengate hook claude-code`: a Claude Code `PreToolUse` hook. Blocking findings deny the command, with the version to use instead; warnings, unfinished checks and unplannable installs ask you; a clean result stays silent so your permissions still apply (`--allow-on-pass` to approve). It always exits `0`, so a broken config cannot block every command. About a second per install with warm caches; `--budget-secs` caps it, and running out asks.
- `install` checks the packages it adds or changes for known advisories, blocking at or above `[dependency_review] fail_on_severity` and naming one version that clears them all.
- `[pipeline] fail_fast` and `run --fail-fast`; the run ends with a per-step summary.
- `GREENGATE_NPM_REGISTRY` can name a mirror of the public npm registry (an Artifactory or Verdaccio proxy): packages resolved from it are checked like registry.npmjs.org's instead of being skipped as private.
- `bench/install/gate.py`: `greengate install` driving real npm, pip and cargo against a local fixture registry, scored by whether each payload's effect happened. With bubblewrap, 24/24 attack trials had no effect and 21/21 benign installs worked, at a median 0.3 s over a plain install. Results in `bench/INSTALL_GATE_RESULTS.md`.
- Docs: [AI Agents](docs/guide/agents.md) guide and a [report schema](docs/reference/report-schema.md) reference.

### Changed
- A wrapped package manager that fails is an error (exit `4`).
- `watch-install` reports every post-install layer (scripts, phantom files, executable drops) together instead of stopping at the first, and no longer reports a pre-existing script threat twice.
- GitHub Action: new `report` input and `status`, `incomplete` and `report-path` outputs; the existing `findings` output, which was never set, now is. Inputs reach the script through environment variables instead of `${{ }}` interpolation.
- Telemetry records `greengate_command_*` metrics for every gate, not only `audit`, `coverage` and `ci-lint`.
- `audit` only reads files whose names it supports, rather than every file in the repository.
- PyPI package names are normalized (PEP 503, lowercase) in audit queries and SBOM purls.
- In JS, TS, Python, Go and Rust files, a `greengate: ignore` comment on its own line now also covers the line below, as it already did in other files and as documented.

### Security
- Replaced the deprecated `serde_yaml` with its maintained, API-compatible fork `serde_norway`: `serde_yaml`'s libyaml port, `unsafe-libyaml`, is unmaintained (RUSTSEC-2024-0449) and failed `cargo audit --deny warnings`.

### Fixed
- `audit` never checked scoped packages in pnpm lockfiles that quote their keys (`'@babel/core@7.29.0':`, as pnpm 9 writes them): the name was read as `'`. In one real lockfile that was 502 of 781 packages.
- `audit` queried nested npm copies (`node_modules/a/node_modules/b`) under the name `a/node_modules/b`, so advisories for them never matched.
- `sbom` wrote a `serialNumber` that is not a UUID (`urn:uuid:greengate-<timestamp>`), failing the CycloneDX schema; it also read only the first lockfile in the current directory.
- `image-scan` found no layers in archives written by Docker 25+ (OCI layout), scanned nothing, and passed. Layers are now read from `manifest.json`, which both layouts include.
- `cargo-add` matched build scripts by name prefix, so adding `serde` could scan `serde_json`'s `build.rs`, or another cached version; it now scans exactly the added `name-version`, and honours a custom `build = "…"` path.
- `image-scan --no-fail` still exited `1` on findings.
- `ci-lint --format json` and `image-scan --format json` printed a text line instead of JSON when nothing was found.
- `reassure` panicked on component names with multi-byte characters near the 40-character column.
- `requirements.txt` pins with extras (`pkg[extra]==1.0`), environment markers, `--hash` options, line continuations or `===` were mis-parsed into wrong names or versions.
- `audit` suggested the first fixed version an advisory lists, which can belong to another release line (e.g. `minimist@0.0.8` → `1.2.6` instead of `0.2.4`); it now suggests the fix for the installed version's line.
- `.pth` startup files: one that writes or deletes files now blocks the wheel (previously only network, subprocess, eval and similar did), and setuptools' `distutils-precedence.pth`, editable-install finders and namespace-package stubs are recognised as benign — installing setuptools itself was blocked.
- `scan` read files inside `.git/`, so every repository reported the committer emails in `.git/config` and the reflogs as PII.
- The `ci-lint` docs listed rule ids (`CILINT/…`), severities and a rule (`SecretsInEnv`) that do not exist, and a suppression setting that had no effect.

## [0.3.4] - 2026-10-11

### Added
- Slopsquat / hallucinated-package guard on every install wrapper, scoring registry existence, age, adoption and source repo. HIGH blocks, MEDIUM warns.
- Dependency-confusion detection via `[supply_chain] internal_packages`.
- `greengate provenance` — AI vs human authorship split for a commit range, with `--max-ai-lines-pct` and `--format text|json|sarif`.
- CI `advisories` job running `cargo audit --deny warnings`.
- Lint policy in `Cargo.toml` (`[lints]`) and `overflow-checks` in the release profile.
- Offline install-protection benchmark with labeled attack simulations and real C native-build fixtures, reporting preflight blocks, post-execution detections, misses, and benign-build false positives separately.

### Security
- Patched RUSTSEC-2026-0285 — `rustls` 0.23.37 → 0.23.45, `rustls-webpki` 0.103.13 → 0.103.15.
- An unparseable `.greengate.toml` is now a hard error instead of a silent fall back to defaults. A missing config still yields defaults.
- Unknown config keys are rejected (`deny_unknown_fields`) rather than ignored.
- Supply-chain signals that could not be verified now report MEDIUM instead of passing as LOW.
- Package names are validated and percent-encoded before reaching a registry URL.
- Response bodies capped at 8 MB; all outbound requests now have timeouts (10 s connect, 30 s read/write, 60 s overall).
- Crate contains no `unsafe`, enforced by `unsafe_code = "forbid"`.

### Fixed
- Two panics in `scan --triage` — source-context slicing past end of file, and LLM response parsing with reversed braces. Both covered by regression tests.
- Mutex poisoning in `watch-install` no longer aborts the run.
- `watch-install`, `pip-install` and `cargo-add` exited 0 when the wrapped package manager failed, so a broken install passed CI. They now fail, and `--no-fail` no longer masks it; post-install checks still run and report first.
- `pip-install` ran `pip <args>` instead of `pip install <args>`, so the documented `greengate pip-install requests` never installed anything — the failure was hidden by the exit-0 bug above. A leading `install` is still accepted.
- README install commands for Linux and macOS failed silently for non-root users — `curl -sL` into root-owned `/usr/local/bin` hid the permission error. They now download with `curl -fsSL` and install with `sudo install`, with a no-root `~/.local/bin` alternative.
- Corrected README and website audit support to match the six implemented dependency-file formats; documented existing Rust AST rules and install-watcher boundaries.

### Changed
- All outbound HTTP goes through one shared, pooled agent (`src/utils/http.rs`).
- `config::load` / `config::load_silent` return `Result<Config>`. Internal only; no CLI change.

## [0.3.3] - 2026-07-25

### Fixed
- Broken install — release asset names in the README and composite action did not match published binaries, so every documented install path 404'd.
- Vulnerable dependencies — `anyhow` 1.0.104 and `crossbeam-epoch` 0.9.20, resolving RUSTSEC-2026-0190 and RUSTSEC-2026-0204.

### Added
- `--version` / `-V` flag.
- Three secret-scan precision filters (example-credential allowlist, entropy-noise recognizers, PEM key-body suppression): precision 55.6% → 90.9%, recall held at 100%.
- Signed releases — keyless Sigstore `cosign sign-blob` bundles alongside each asset.
- Benchmark suite (`bench/`) scoring secret-detection precision/recall/F1.

### Changed
- README leads with the install-time supply-chain gate rather than breadth.
- `scan --fix` de-emphasized in favour of suppression and baselines.

[0.4.0]: https://github.com/greengate-dev/greengate/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/greengate-dev/greengate/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/greengate-dev/greengate/releases/tag/v0.3.3
