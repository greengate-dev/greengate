# Changelog

All notable changes to greengate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - Unreleased

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
  - With bubblewrap, each script runs with the system read-only except its own package, no network (unless listed in `script_network`) and credential files masked. Suspicious-looking scripts run there with a warning instead of being blocked, so ordinary installers such as esbuild's still work; a write outside the package is refused and reported.
  - Without isolation, suspicious scripts are held back unless allowlisted, and writes outside a package are caught by before/after comparison and a filesystem watcher. `require_isolation = true` refuses to run scripts without a sandbox.
  - Credential-like environment variables (`*_TOKEN`, `*_SECRET`, `AWS_*`, …) are removed from install scripts; keep specific ones with `env_allow`.
  - pnpm: only builds pnpm itself allows (`onlyBuiltDependencies`) run.
  - pip: planning runs in the sandbox, because resolving an sdist runs its build backend. greengate downloads and sha256-checks every artifact, builds sdists in the sandbox and installs wheels only; a wheel whose `.pth` startup code looks suspicious is blocked.
  - Cargo: new crates' build scripts and proc-macros are inspected before anything builds; a blocked plan restores `Cargo.toml` and `Cargo.lock`.
  - Yarn 1 and Bun: npm-shaped trees, scripts run per package; Bun's trust list (`trustedDependencies`) is respected.
  - Yarn Berry: builds run together in one sandboxed step, so a suspicious-looking build is held back even when isolated (allowlist it or set `dependenciesMeta.<name>.built: false`).
  - uv: locking and `uv sync` run in the sandbox because both run sdist build backends; new `.pth` startup files are quarantined before any Python starts if they look suspicious.
- Checks in the report can carry a `source` — e.g. which snapshot answered and how old it was.
- `GREENGATE_CACHE_DIR` relocates greengate's cache.
- Gating on what a change introduces:
  - `scan --new-since [<ref>]` reports only findings absent at the merge base with `<ref>` (default in a pull request: its base branch). Changed files are scanned as they are and as they were; renames are followed; uncommitted and untracked files count.
  - Baselines identify findings by fingerprint (`gg1:` HMAC-SHA256 over rule, path, matched text and surrounding lines, with a per-repository salt), so a known finding stays known when lines move, nearby code changes or its file is renamed. A second copy of a known secret is still new. Secrets are never stored in the baseline.
  - `audit` and `ci-lint` take `--update-baseline` / `--since-baseline`; all three gates share `.greengate-baseline.json`. For `audit`, a version bump still affected by the same advisory stays known.
  - `greengate baseline migrate` upgrades a 0.3 baseline, which still works meanwhile (exact lines only).
- Governed exceptions in `.greengate/exceptions.toml`: each waives one finding (`fingerprint`), a rule (optionally by `path` glob or `package`) or an advisory (optionally by `package`), and needs a `reason`, `owner` and `expires` date no more than `[policy] max_exception_days` (90) away. An expired exception's findings count again, naming the exception and its owner; ones expiring within 14 days are warned about. An invalid file exits `2`; `check-config` validates it. `greengate exceptions list` shows them all.
- `greengate: ignore reason="…"` (or any text after the marker). Every suppressed finding — inline, exception, baseline, `ignore_advisories`, triage — is listed in the report's `suppressed` with a `suppression` object saying why, and the text output tallies them.
- `ci-lint` honours `# greengate: ignore` on the flagged line or the line above.

### Changed
- **Breaking:** `audit` exits `3` when it could not check every dependency, instead of warning and exiting `0`. That covers an unreachable or short OSV response, a truncated advisory list, an unreadable lockfile, and `requirements.txt` entries that are not `==` pinned (ranges, `-r` includes, editable installs). Findings still exit `1`; set `on_incomplete = "warn"` to keep exiting `0`.
- **Breaking:** exit codes are now `0` passed, `1` findings, `2` usage or config error, `3` incomplete, `4` error. Previously runtime errors and an invalid `.greengate.toml` exited `1`, the same as findings.
- **Breaking:** these runs are now incomplete (exit `3`) instead of passing: `lint` with a manifest that did not parse (un-rendered templates are still skipped); `ci-lint` with a workflow that could not be read; `lighthouse` when PageSpeed Insights cannot be reached or returns an error (previously exit `1`); `sbom --verify` without an expected signer identity; install wrappers whose registry lookups failed; `cargo-add` when `cargo fetch` fails or a new crate's source cannot be found; `image-scan` when no layers are found or a layer cannot be extracted.
- A wrapped package manager that fails is an error (exit `4`).
- `run` reports the worst result among the steps that ran, and prints why a step could not run.
- `watch-install` reports every post-install layer (scripts, phantom files, executable drops) together instead of stopping at the first, and no longer reports a pre-existing script threat twice.
- GitHub Action: new `report` input and `status`, `incomplete` and `report-path` outputs; the existing `findings` output, which was never set, now is. Inputs reach the script through environment variables instead of `${{ }}` interpolation.
- Telemetry records `greengate_command_*` metrics for every gate, not only `audit`, `coverage` and `ci-lint`.
- `audit` only reads files whose names it supports, rather than every file in the repository.
- **Breaking:** `watch-install`, `pip-install` and `cargo-add` are deprecated and run through `greengate install` when they wrap npm, pnpm, Yarn, Bun, pip ≥ 22.2 or a Cargo project — install scripts then run sandboxed without network; list packages that need it in `[supply_chain] script_network`. Other commands keep the old behaviour with a notice. All three are removed in 0.5.
- **Breaking:** `sbom` stops with an error when one directory holds two lockfiles for the same ecosystem, instead of using whichever it found first.
- PyPI package names are normalized (PEP 503, lowercase) in audit queries and SBOM purls.
- `scan --since` is renamed `--changed-since`; `--since` remains as a deprecated alias.
- `[audit] ignore_advisories` is deprecated in favour of exceptions; `greengate exceptions migrate` converts it.
- In JS, TS, Python, Go and Rust files, a `greengate: ignore` comment on its own line now also covers the line below, as it already did in other files and as documented.

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

[0.3.4]: https://github.com/greengate-dev/greengate/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/greengate-dev/greengate/releases/tag/v0.3.3
