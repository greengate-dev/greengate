# Changelog

All notable changes to greengate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.4] - Unreleased

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
