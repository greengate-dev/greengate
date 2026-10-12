# greengate

**Stop the supply-chain attacks your CVE scanner can't see — one static binary, no Docker.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/greengate-dev/greengate/ci.yml?branch=main)](https://github.com/greengate-dev/greengate/actions)
[![GitHub release](https://img.shields.io/github/v/release/greengate-dev/greengate)](https://github.com/greengate-dev/greengate/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/greengate)](https://crates.io/crates/greengate)
[![Downloads](https://img.shields.io/crates/d/greengate)](https://crates.io/crates/greengate)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)](https://www.rust-lang.org)

**[Docs](https://greengate-dev.github.io/greengate)** · [Config Reference](https://greengate-dev.github.io/greengate/reference/config) · [CI Integration](https://greengate-dev.github.io/greengate/guide/ci-integration) · [SAST Rules](https://greengate-dev.github.io/greengate/reference/sast-rules)

---

CVE scanners match dependencies against known advisories; lock-file diffs show dependency changes. Those checks alone do not observe what install scripts do. greengate adds script checks and filesystem observation: **npm, yarn, pnpm, and bun** installs can be watched for files created then deleted, while **pip and Cargo** wrappers provide separate package/script checks. These signals can fail the gate, but do not isolate the installer or guarantee that malicious code never executes. No Docker or daemon is required for these checks.

**Built for the AI-coding era.** When an agent writes your code, it also *picks your dependencies* — and LLMs can hallucinate package names. Attackers can register those names ("**slopsquatting**"). Edit-distance checks may miss invented names that are not close to real ones. greengate's [slopsquat guard](#slopsquat--hallucinated-package-guard) scores registry metadata for explicitly requested package names and can block high-suspicion requests before installation. It does not inspect every transitive dependency or expand lockfile/requirements-only installs.

The same binary also runs secret scanning, AST-based SAST, dependency CVE audit, SBOM attestation, coverage, and CI-config hygiene. Its focus is combining local install signals with security and quality gates in one portable CLI.

No Node. No Python. No JVM. The core gates need no Docker either — just copy the binary and run. (A few opt-in features add a dependency: image scanning needs Docker, SBOM signing needs cosign, and the registry/CVE checks need network access.)

---

## Contents

- [Why greengate?](#why-greengate)
- [What it does](#what-it-does)
- [Supported languages](#supported-languages)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Suppressing false positives](#suppressing-false-positives)
- [AI triage](#ai-triage)
- [SBOM attestation](#sbom-attestation)
- [Container image scanning](#container-image-scanning)
- [GitHub Actions](#github-actions)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Contributing](#contributing)

---

## Why greengate?

**Beyond known-advisory checks.** A package without a known advisory may still have a suspicious install script. greengate adds local script checks and filesystem signals to dependency audits. Other tools, including [Socket Firewall](https://docs.socket.dev/docs/safe-npm-faq), also offer install-time protection; greengate's approach is a portable CLI combining these signals with other repository gates.

**How the supply-chain gate works:** `watch-install` scans existing lifecycle script strings before starting the package manager, polls `node_modules` for created-then-deleted files, then checks installed script strings and executable drops directly in the project root. New-package checks and runtime findings can fail the gate **after installer execution**. `pip-install` checks requested names before installation and installed source/artifacts afterward; `cargo-add` checks names before adding dependencies and scans fetched `build.rs` files afterward.

**Then it replaces the rest of your stack too.** A typical pipeline also strings together `gitleaks`, `semgrep`, `trivy`, `jest --coverage`, and a CI-config linter — each installed separately, version-pinned separately, and emitting a different output format. greengate runs all of those gates from the same binary, one config file, one exit code. Breadth is what keeps it in your pipeline; the supply-chain gate is why it earns a place there.

**Key properties:**
- **Adds install-time signals** — lifecycle script checks, polled phantom-file detection for npm-family installs, and separate pip/Cargo package and artifact checks. See the [install benchmark](bench/INSTALL_RESULTS.md) for detection timing, misses, and native-build false positives.
- **Single static binary** — ships as a single musl-linked executable for Linux, macOS, and Windows. Copy it to `/usr/local/bin` and it works. Every release binary is keyless-signed with Sigstore ([verify it](#verifying-a-release-binary)).
- **AST-accurate SAST** — uses tree-sitter to parse real ASTs instead of fragile regex over source text. No false positives from comments or string literals.
- **CI-native output** — emits SARIF, JUnit XML, GitLab SAST JSON, and GitHub Check Run annotations with per-line findings. Plugs into Code Scanning, GitLab Security Dashboard, and SonarQube out of the box.
- **Zero configuration required** — sensible defaults work on any repo; `.greengate.toml` is optional.

> **Where greengate is intentionally not the strongest tool:** on any single classic axis in isolation — raw secret-pattern count, deep inter-procedural taint, or a rules marketplace — a dedicated incumbent (gitleaks, Semgrep Pro) will go deeper. Our own reproducible [secret-detection benchmark](bench/) publishes the numbers honestly, false positives included. See [Known Limitations](https://greengate-dev.github.io/greengate/reference/limitations) for exactly where the boundaries are. greengate's bet is the supply-chain gate plus good-enough coverage of everything else in a single self-contained binary (a few features — image scanning, SBOM signing, registry checks — additionally need Docker, cosign, or network access).

---

## What it does

Commands are grouped by concern. Each runs standalone or as a step in `greengate run`. Install protection is listed first as the project's primary focus.

### Supply Chain Protection

| Command | What it does |
|---|---|
| `greengate install <npm\|pnpm\|yarn\|bun\|pip\|uv\|cargo> …` | Install with **no package code running before the complete tree is checked**: plan (resolve + `deps check` policy), fetch with scripts off, inspect every install script, build script and `.pth` file, then run approved scripts one by one in a bubblewrap sandbox — no network, writes confined, credentials masked. `--plan` looks without changing anything. |
| `greengate watch-install <pm> <args>` | Wrap any npm/yarn/pnpm/bun install. **Slopsquat guard** on every requested package, pre-flight lifecycle script scan (entropy + network/eval patterns), runtime phantom-file detection (files created then deleted by postinstall), and post-install exec-drop detection. |
| `greengate pip-install <args>` | Wrap `pip install`. Requested-name **slopsquat guard** + typosquat checks can halt before pip runs; `.dist-info/RECORD` Python source and executable-drop checks run after installation. |
| `greengate cargo-add <args>` | Wrap `cargo add`. **Slopsquat guard** + typosquat detection against the 60 most-downloaded crates.io crates, `build.rs` static analysis for every newly added crate (network access, subprocess spawning, env exfiltration), transitive dependency explosion guard (> 50 new transitive deps triggers a warning). |

> **What is the slopsquat guard?** See [Slopsquat / hallucinated-package guard](#slopsquat--hallucinated-package-guard) below — the AI-era defense that catches invented package names typosquat detection can't.

> **Scope of the runtime check:** phantom-file detection polls `node_modules` every 250 ms. Files created and deleted between polls can be missed; executable-drop checks inspect only files directly in the project root. This layer does not inspect network traffic or prevent installer execution. Full network isolation is on the [roadmap](https://greengate-dev.github.io/greengate/reference/roadmap) as `sandbox-install`. The [install benchmark](bench/INSTALL_RESULTS.md) reports these gaps and legitimate native-build behavior.

### Secrets & Code Security

| Command | What it does |
|---|---|
| `greengate scan` | Scan for hardcoded secrets, PII, and SAST issues. 26 built-in secret patterns (AWS keys, GitHub tokens, private keys, JWTs, etc.) plus Shannon entropy detection for unrecognised credentials. AST-based SAST for unsafe patterns in JS/TS/Python/Go/Rust. |
| `greengate scan --history` | Scan the full git commit history for secrets (catches credentials that were committed then deleted). |
| `greengate scan --staged` | Scan only staged files — ideal as a pre-commit hook. |
| `greengate scan --format sarif` | Emit SARIF 2.1.0 for GitHub Code Scanning / SonarQube upload. Also supports `json`, `junit`, `gitlab`. |
| `greengate scan --triage` | Call an LLM to classify each finding as likely-real, likely-false-positive, or uncertain. Shows confidence % and a one-sentence reason. Supports Claude (default), any OpenAI-compatible API, or a local model via Ollama. |
| `greengate scan --dry-run` / `--fix` | Preview (`--dry-run`), then optionally auto-redact detected secrets in-place, replacing matched values with `<REDACTED>`. Always run `--dry-run` first — `--fix` rewrites your source. See [Auto-redact](#auto-redact). |

### Dependencies

| Command | What it does |
|---|---|
| `greengate audit` | Query the [OSV database](https://osv.dev) for known vulnerabilities in your project's dependencies. Recursively discovers npm, Yarn, pnpm and Bun lockfiles, `uv.lock`, `poetry.lock`, `pylock.toml`, pinned `requirements.txt`, `Cargo.lock`, and `go.mod`/`go.sum`. Works offline from snapshots downloaded by `greengate db update`, and falls back to them when the API is down. |
| `greengate sbom` | Generate a [CycloneDX 1.5](https://cyclonedx.org) SBOM from the project's dependency files, with the dependency graph, scopes and hashes. |
| `greengate deps list` / `deps why <pkg>` | Show every package greengate reads from the lockfiles, and the chain that pulls a package in. |
| `greengate deps check` | Gate new or upgraded packages on release risk — cooldown, new install scripts, lost provenance, unfamiliar publishers, withdrawn releases — and every package on registry binding, dependency confusion and git/URL sources. |
| `greengate deps review` | Review what a pull request does to the dependency tree — every package added, removed, upgraded or downgraded, with its license, the advisories it introduces or fixes, release risk, and **the smallest fix for each new advisory** (refresh, upgrade the direct parent, or override). One PR comment, updated in place, with `--annotate` or the action's `dependency-review: true`. |
| `greengate sbom --attest` | Generate a SBOM and sign it with [Sigstore](https://sigstore.dev) keyless signing. Produces a bundle file anchored in the Rekor public transparency log. No private key required. |
| `greengate sbom --verify <file>` | Verify a SBOM against a cosign bundle. Fails if the signature is invalid or the bundle is missing from the Rekor log. |

### Code Quality & Review

| Command | What it does |
|---|---|
| `greengate review` | Analyse a PR diff: Complexity Score (cyclomatic + cognitive) and new-code coverage gaps. Posts a GitHub Check Run with per-line annotations. Fails if complexity exceeds `complexity_budget` or new code coverage falls below `min_new_code_coverage`. |
| `greengate coverage` | Parse LCOV or Cobertura XML and fail if total coverage is below a configurable threshold. |
| `greengate tia` | Test Impact Analysis — use AST import parsing to determine exactly which test files are affected by a diff. Pipe the output directly into pytest, jest, or go test to skip unaffected tests. |
| `greengate reassure` | Parse a [Reassure](https://github.com/callstack/reassure) performance report and fail if any React component's mean render time regresses beyond a threshold. |
| `greengate provenance` | Report the AI-authored vs human-authored split of a commit range (from commit trailers + author identity) and optionally fail when AI-generated code exceeds a share of new lines (`--max-ai-lines-pct`). Emits `--format text\|json\|sarif`. Differentiated governance for the AI-coding era. |

### Infrastructure & CI

| Command | What it does |
|---|---|
| `greengate ci-lint` | Lint GitHub Actions workflow files for security misconfigurations: unpinned action refs (`actions/checkout@v4` instead of a commit SHA), `pull_request_target` + PR checkout (script injection), and expression injection in `run:` steps. Emits SARIF for Code Scanning. |
| `greengate image-scan <image>` | Scan a Docker/OCI image for secrets baked into its layers. Calls `docker save`, unpacks every layer tar, and runs the full regex + entropy scan on all text files — including `.env`, `/etc/environment`, `.ssh/`, `.pem`, and `docker-compose` files. Findings include layer digest and path inside the layer. |
| `greengate lint` | Kubernetes manifest linting — validates resource limits, security contexts, `latest` image tags, and missing probes. |
| `greengate docker-lint` | Dockerfile best-practice checks — `latest` base images, running as root, missing `HEALTHCHECK`, `ADD` instead of `COPY`, etc. |
| `greengate lighthouse` | Gate on Google PageSpeed Insights scores (Performance, Accessibility, Best Practices, SEO). |

### Workflow

| Command | What it does |
|---|---|
| `greengate run` | Run every pipeline step defined in `[pipeline]` of `.greengate.toml` — all of them, unless `fail_fast` — with one merged report and the worst result as the exit code. |
| `greengate hook claude-code` / `greengate check-command` | Check the dependency installs an AI agent is about to run: each is planned with `install --plan` (nothing installed, no package code run); blocking findings deny the command with the fix, uncertain results ask you. See [AI Agents](https://greengate-dev.github.io/greengate/guide/agents). |
| `greengate init` | Interactive wizard that generates `.greengate.toml`. Pass `--ci github-actions` to also scaffold a ready-to-use workflow and `dependabot.yml`. |
| `greengate install-hooks` | Install greengate as a git pre-commit hook (runs `scan --staged` on every commit). |
| `greengate watch` | Re-run `scan` automatically whenever source files change (file-watcher mode for local development). |
| `greengate check-config` | Validate `.greengate.toml` and print all resolved configuration values. |

### Observability

| Feature | How it works |
|---|---|
| **OTLP metrics export** | After each command, greengate POSTs structured metrics to any OpenTelemetry-compatible collector (Grafana, Datadog, Honeycomb, etc.) via OTLP HTTP/JSON. Configure `otlp_endpoint` in `[telemetry]`. |
| **Prometheus text format** | Writes a `.prom` file after each command. Point `node_exporter --collector.textfile.directory` at the same directory and metrics are scraped automatically. Configure `metrics_file` in `[telemetry]`. |

---

## Supported languages

### Secret scanning

Secret scanning uses regex patterns and Shannon entropy — it is **language-agnostic** and runs on any file type, including config files, `.env` files, shell scripts, and binary-adjacent formats.

### SAST (AST-based)

SAST uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to parse a real AST, so findings are accurate even when the pattern appears inside a comment or a string in another language.

| Language | File extensions | SAST rules |
|---|---|---|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `eval()`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `setTimeout(string)`, `child_process.exec` |
| TypeScript | `.ts`, `.tsx` | Same as JavaScript |
| Python | `.py` | `exec()`, `eval()`, `subprocess` with shell=True, `pickle.loads`, `yaml.load` (unsafe), `os.system` |
| Go | `.go` | `os/exec` command injection, `fmt.Sprintf` in SQL, `http.ListenAndServe` without TLS |
| Rust | `.rs` | `unsafe {}` blocks, `std::process::Command`, `.unwrap()` and `.expect()` in library code |

### Test Impact Analysis

TIA walks the import graph using AST parsing to find which test files transitively import a changed source file.

| Language | Import resolution |
|---|---|
| JavaScript / TypeScript | `import` / `require` (relative paths, bare specifiers) |
| Python | `import` / `from … import` |
| Go | `import "…"` (full package path) |

### Dependency audit (OSV)

| Ecosystem | Dependency files |
|---|---|
| Node.js | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (Yarn 1 and Berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` |
| Python | `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751), `requirements.txt` (`==` pins) |
| Rust | `Cargo.lock` |
| Go | `go.mod` (Go 1.17+, with `replace` directives), else `go.sum` |

`audit`, `sbom` and `greengate deps` read these through one dependency model,
so they agree on what is direct, transitive, dev-only, and where each package
came from. Maven, .NET/NuGet, Ruby, `Pipfile.lock` and the binary `bun.lockb`
are not supported.

### Supply chain wrapping

| Package manager | Command | Typosquat detection | Script scanning | Exec-drop detection |
|---|---|---|---|---|
| npm / yarn / pnpm / bun | `greengate watch-install` | — | postinstall scripts | |
| pip | `greengate pip-install` | 60 popular PyPI packages | `.py` files via RECORD | venv `bin/` |
| Cargo | `greengate cargo-add` | 60 popular crates.io crates | `build.rs` | — |

### CI config linting

| Platform | File pattern |
|---|---|
| GitHub Actions | `.github/workflows/*.yml` |

---

## Installation

**macOS (Apple Silicon):**
```bash
curl -fsSL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-macos-arm64 -o greengate
sudo install -m 755 greengate /usr/local/bin/greengate
```

**macOS (Intel):**
```bash
curl -fsSL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-macos-amd64 -o greengate
sudo install -m 755 greengate /usr/local/bin/greengate
```

**Linux (x64, musl — works in Alpine/Docker):**
```bash
curl -fsSL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 -o greengate
sudo install -m 755 greengate /usr/local/bin/greengate
```

`/usr/local/bin` is root-owned on most Linux distributions and on macOS, hence the `sudo`. To install without root, use `install -m 755 greengate ~/.local/bin/greengate` instead and make sure `~/.local/bin` is on your `PATH`.

**Windows (x64) — PowerShell:**
```powershell
Invoke-WebRequest `
  -Uri "https://github.com/greengate-dev/greengate/releases/latest/download/greengate-windows-amd64.exe" `
  -OutFile "$env:USERPROFILE\.local\bin\greengate.exe"
```

**Build from source (Rust 1.85+):**
```bash
cargo install --git https://github.com/greengate-dev/greengate
```

### Verifying a release binary

Every release binary is signed with [Sigstore](https://sigstore.dev) keyless signing in the release workflow — the same mechanism `greengate sbom --attest` gives your own artifacts. Each asset ships with a `.sig` (signature) and `.pem` (signing certificate) alongside it. Verify a download before trusting it:

```bash
VERSION=v0.3.2   # the release you downloaded
BASE="https://github.com/greengate-dev/greengate/releases/download/${VERSION}"

# Fetch the signature and certificate for your platform's asset
curl -sLO "${BASE}/greengate-linux-amd64.sig"
curl -sLO "${BASE}/greengate-linux-amd64.pem"

cosign verify-blob \
  --certificate greengate-linux-amd64.pem \
  --signature   greengate-linux-amd64.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/[Tt]hink[Gg]rid-[Ll]abs/greengate/.github/workflows/release.yml@refs/tags/' \
  greengate-linux-amd64
```

A successful verification proves the binary was produced by greengate's own tagged release workflow and has not been modified since.

---

## Quick start

```bash
# Generate a .greengate.toml and a GitHub Actions workflow in one step
greengate init --ci github-actions

# Scan the current directory for secrets, PII, and SAST issues
greengate scan

# Preview what --fix would change (no files written) — always do this first
greengate scan --dry-run

# Auto-redact detected secrets in-place (rewrites source; review the diff after)
greengate scan --fix && git diff

# Audit dependencies for known CVEs (reads any supported lock file)
greengate audit

# Zero-trust npm install (static scan + runtime phantom-file watcher)
greengate watch-install npm ci

# Zero-trust pip install with typosquat detection
greengate pip-install -r requirements.txt

# Zero-trust cargo add with build.rs analysis
greengate cargo-add serde tokio

# Lint GitHub Actions workflows for security misconfigurations
greengate ci-lint

# Test impact analysis — run only affected tests
pytest $(greengate tia --base main)
npx jest $(greengate tia --base main --format newline)

# PR complexity score + coverage gaps (posts GitHub Check Run annotations)
greengate review --base main --coverage-file coverage/lcov.info --annotate

# Gate on 80% minimum coverage
greengate coverage --file coverage/lcov.info --min 80

# Lint Kubernetes manifests
greengate lint --dir ./k8s

# Triage findings with an LLM (requires ANTHROPIC_API_KEY)
greengate scan --triage

# Generate a CycloneDX SBOM
greengate sbom --output sbom.json

# Generate a SBOM and sign it with Sigstore keyless signing
greengate sbom --attest --output sbom.json

# Verify a SBOM against its cosign bundle
greengate sbom --verify sbom.json --bundle sbom.json.bundle.json

# Scan a Docker image for secrets baked into its layers (requires Docker)
greengate image-scan nginx:latest
greengate image-scan ghcr.io/my-org/my-app:sha-abc123

# Run all configured gates in order
greengate run

# Install as a git pre-commit hook
greengate install-hooks
```

---

## Suppressing false positives

### Inline suppression

Add `// greengate: ignore` on the same line as a finding to suppress it:

```javascript
const TEST_KEY = "AKIAIOSFODNN7EXAMPLE"; // greengate: ignore
```

### Next-line suppression

Put the comment on the line above to suppress the next line:

```python
# greengate: ignore
AWS_KEY = load_from_env("AWS_ACCESS_KEY_ID")
```

### Auto-redact

`--fix` rewrites your working tree, replacing each detected secret with `<REDACTED>` in place. It is a convenience for cleaning up an accidental commit, **not** a gate to run unattended in CI — a false positive means real source gets overwritten. Always preview with `--dry-run`, run it on a clean tree, and review `git diff` before committing:

```bash
greengate scan --dry-run   # preview changes — no files written
greengate scan --fix       # apply redactions (rewrites source)
git diff                   # review every change before committing
```

For most workflows, prefer [inline suppression](#inline-suppression) or a [baseline](#baseline) over `--fix`: they leave the (often still-needed) value in place and simply stop it failing the build.

### Baseline

Save current findings as an accepted baseline and only fail on *new* findings. Findings are fingerprinted, so they stay known when code moves around them or their file is renamed; `audit` and `ci-lint` take the same flags:

```bash
greengate scan --update-baseline   # save current state
greengate scan --since-baseline    # fail only on new findings
```

Or skip the baseline file and fail a pull request only on what it introduces:

```bash
greengate scan --new-since origin/main
```

To waive a finding for a limited time with an owner and a reason, use `.greengate/exceptions.toml`. See [Baselines & Exceptions](https://greengate-dev.github.io/greengate/guide/baselines-and-exceptions).

---

## AI triage

False positives are the #1 reason developers disable security tools. `--triage` sends each finding to an LLM along with its surrounding source code and asks: *"Is this a real issue or a false positive, and why?"*

```
⚠️  Found 3 potential issue(s) — 1 triaged as false positive(s) and auto-suppressed, 2 require attention:

  - [HIGH] [SAST/CommandInjection] ./src/admin/shell.rs:88
    → Triage: LIKELY REAL (94%) — User-controlled cmd flows into Command::new with no sanitization.

  - [HIGH] [Secret/AwsAccessKey] ./tests/fixtures/creds.rs:12 [AUTO-SUPPRESSED]
    → Triage: LIKELY FALSE POSITIVE (91%) — Matches canonical AWS example key in test fixture.

  - [MEDIUM] [SAST/EvalUsage] ./src/utils/eval.rs:44
    → Triage: UNCERTAIN (55%) — eval() usage but surrounding context does not clarify intent.

  Triage summary: 1 likely real · 1 uncertain · 1 false positive (suppressed: 1) · 0 unavailable
```

### Setup

Set the API key for your chosen model:

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (default)
export OPENAI_API_KEY=sk-...          # OpenAI-compatible
```

Then run:

```bash
greengate scan --triage
```

No additional dependencies — greengate calls the API directly using its built-in HTTP client.

### Configuration

```toml
[triage]
model                   = "claude-haiku-4-5-20251001"  # fast and cheap; accurate enough for triage
api_key_env             = "ANTHROPIC_API_KEY"           # env var that holds the key
auto_suppress_threshold = 0.0                           # 0 = annotate only; 0.9 = auto-suppress high-confidence FPs
context_lines           = 10                            # source lines before/after the finding sent as context
# endpoint = "http://localhost:11434/v1/chat/completions"  # Ollama or any OpenAI-compatible API
```

### `auto_suppress_threshold`

When set above `0.0`, findings where the LLM is at least that confident they are false positives are automatically suppressed — they appear in output tagged `[AUTO-SUPPRESSED]` but do not cause a non-zero exit code.

| Value | Behaviour |
|---|---|
| `0.0` (default) | Annotate all findings; never suppress. Safe for first use. |
| `0.90` | Suppress findings the LLM is ≥ 90% confident are false positives. |
| `1.0` | Only suppress when the LLM is 100% confident — effectively off. |

Start at `0.0` to see the triage output, then raise the threshold once you trust the results for your codebase.

### Local models via Ollama

Run triage entirely offline — no data leaves your machine:

```bash
ollama pull mistral
```

```toml
[triage]
model       = "mistral"
api_key_env = "UNUSED"                                           # Ollama doesn't require a key
endpoint    = "http://localhost:11434/v1/chat/completions"
```

Any model that supports the OpenAI `/v1/chat/completions` format works: Mistral, Llama 3, Phi-3, Gemma, etc.

### How triage errors are handled

- **API key missing** — prints a warning and falls through to normal scan output. Findings are never silently swallowed.
- **API call fails for one finding** — that finding shows `Triage: unavailable` and is counted as non-suppressed. The scan continues.
- **Triage errors never affect the scan exit code** — if LLM calls all fail, the exit code is determined entirely by the raw findings.

---

## Slopsquat / hallucinated-package guard

AI coding assistants confidently suggest packages that **don't exist**. Attackers harvest these hallucinated names from public prompts and model outputs, register them on npm / PyPI / crates.io, and ship malware to whoever installs them next — a supply-chain attack class known as **slopsquatting**. Because the invented name isn't a near-miss of any real package, classic edit-distance typosquat detection can't see it.

greengate's install wrappers score **registry metadata** for explicitly requested
package names. The npm wrapper skips scoring names already present in
`node_modules`, and the Cargo wrapper skips names already pinned in `Cargo.lock`.
The guard does not expand the full dependency tree, `npm ci`, or pip requirements
files. Package registration age is a signal, not the age or safety of a specific
release:

| Signal | Why it matters |
|---|---|
| **Does it exist?** | A name that 404s on the registry is very likely a pure hallucination. |
| **How new is it?** | Slopsquat packages are registered *after* the model starts suggesting the name — a package a few days old is suspect. |
| **How adopted is it?** | Near-zero downloads on a package your agent just reached for is a red flag. |
| **Any source repo?** | Legitimate packages almost always declare one. |

Signals combine into a suspicion level: **HIGH blocks the install, MEDIUM warns.** These are suspicion signals, not proof that a package is malicious. If the registry is unreachable, the package is reported as **not screened** and the run is incomplete (exit `3`) rather than passing; set `[policy] on_incomplete = "warn"` or pass `--allow-incomplete` for offline or air-gapped builds.

```bash
# An agent suggested a plausible-but-invented crate:
$ greengate cargo-add fast-json-parser-turbo
  [SLOPSQUAT] 'fast-json-parser-turbo' — High suspicion
       · does not exist on the registry (possible hallucinated name)
  If an AI assistant suggested this name, verify the exact crate at https://crates.io before adding.
Error: 1 high-suspicion slopsquat(s) — halting before add.
```

Works across all three install wrappers:

```bash
greengate watch-install npm install <pkg>   # npm / yarn / pnpm / bun
greengate pip-install <pkg>                  # PyPI
greengate cargo-add <pkg>                    # crates.io
```

### Dependency confusion

The same pre-flight also catches **dependency-confusion** attacks — where an attacker publishes a package to a *public* registry using the name of one of your *private/internal* packages, hoping a misconfigured install resolves the public (malicious) one. Declare what's yours and greengate flags any internal name that unexpectedly resolves on the public registry:

```toml
[supply_chain]
internal_packages = ["@mycorp", "acme-internal-*", "acme-secret-db"]
```

Patterns may be an npm scope (`@mycorp` → matches `@mycorp/anything`), an exact name, or a `prefix-*` wildcard. Empty (default) disables the check.

```
[DEP-CONFUSION] '@mycorp/auth' — High suspicion
     · declared internal, but '@mycorp/auth' also resolves on the public npm registry — dependency-confusion risk
```

### Configuration

```toml
[supply_chain]
slopsquat_check         = true    # enable the guard (default: true)
slopsquat_min_age_days  = 90      # registered more recently than this = suspicious
slopsquat_min_downloads = 1000    # fewer total downloads than this = suspicious
internal_packages       = []      # your private names/scopes/prefixes (dependency-confusion)
```

Add known-good internal package names to the relevant `allow_*` list (`allow_cargo_crates`, `allow_pip_packages`, `allow_postinstall`) to exempt them from the guard.

---

## SBOM attestation

Software Bill of Materials attestation lets you prove to customers, auditors, and your own security team that a published SBOM was generated by a specific, unmodified build — and that it hasn't been tampered with since.

greengate uses [Sigstore](https://sigstore.dev) **keyless signing** via the `cosign` CLI. There is no private key to manage or rotate: in CI the signing identity comes from the OIDC token issued by your CI provider (GitHub Actions, GitLab CI, etc.). The resulting signature is anchored in the [Rekor](https://rekor.sigstore.dev) public transparency log, making it auditable by anyone.

### Requirements

Install `cosign` once:

```bash
# macOS
brew install sigstore/tap/cosign

# GitHub Actions (add before the greengate step)
- uses: sigstore/cosign-installer@v3
```

### Sign a SBOM

```bash
# Generates sbom.json then signs it → writes sbom.json.bundle.json
greengate sbom --attest

# Custom paths
greengate sbom --attest --output dist/sbom.json --bundle dist/sbom.bundle.json
```

In GitHub Actions with `id-token: write` permission this runs fully non-interactively. Locally it opens a browser for a one-time OAuth flow.

The bundle file (`sbom.json.bundle.json`) contains:
- The signing certificate (your CI identity, e.g. `https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main`)
- The ECDSA signature over the SBOM content
- The Rekor transparency log entry ID and inclusion proof

Distribute both `sbom.json` and `sbom.json.bundle.json` alongside your release artifacts.

### Verify a SBOM

```bash
# Basic verification — validates the certificate chain and Rekor log entry
greengate sbom --verify sbom.json --bundle sbom.json.bundle.json

# Strict: require the SBOM to have been signed by your GitHub Actions workflow
greengate sbom --verify sbom.json \
  --bundle sbom.json.bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

Without `--certificate-oidc-issuer` / `--certificate-identity`, greengate accepts any valid Sigstore identity. For production pipelines, always pin both to your specific workflow URL.

### GitHub Actions — full release example

```yaml
permissions:
  contents: read
  id-token: write   # required for keyless Sigstore signing

steps:
  - uses: actions/checkout@v4

  - uses: sigstore/cosign-installer@v3

  - name: Install greengate
    run: |
      curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
        -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

  - name: Generate and attest SBOM
    run: greengate sbom --attest --output sbom.json

  - name: Upload SBOM and bundle as release assets
    uses: softprops/action-gh-release@v2
    with:
      files: |
        sbom.json
        sbom.json.bundle.json
```

Any consumer can then verify the SBOM without trusting you:

```bash
greengate sbom --verify sbom.json \
  --bundle sbom.json.bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

### Config defaults

Set your expected issuer and identity once in `.greengate.toml` to avoid repeating them on every `--verify` call:

```toml
[sbom]
default_output    = "sbom.json"
expected_issuer   = "https://token.actions.githubusercontent.com"
expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
```

---

## Telemetry

greengate emits metrics after every command run. Both backends are **opt-in, optional, and independent** — telemetry errors are printed as warnings and never cause a command to fail.

### OTLP (OpenTelemetry)

```toml
[telemetry]
enabled       = true
otlp_endpoint = "http://localhost:4318"   # OTLP HTTP/JSON (port 4318, not gRPC 4317)
service_name  = "my-api"                  # attached as service.name resource attribute
```

Metrics are posted to `{otlp_endpoint}/v1/metrics` after each run. Compatible with:

| Backend | How to connect |
|---|---|
| **OpenTelemetry Collector** | Set `otlp_endpoint` to the collector's OTLP HTTP receiver |
| **Grafana Cloud** | Use the Grafana Agent OTLP endpoint, or the Cloud OTLP gateway URL |
| **Datadog** | Enable OTLP intake in the Datadog Agent (`otlp_config.receiver.protocols.http`) |
| **Honeycomb** | `https://api.honeycomb.io` with `api-key` header (set via collector) |
| **Self-hosted Grafana + Prometheus** | Use the Prometheus text format below instead |

### Prometheus text format

```toml
[telemetry]
enabled      = true
service_name = "my-api"
metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

Writes a `.prom` file with standard `# HELP` / `# TYPE` headers after each command. Add the containing directory to `node_exporter --collector.textfile.directory` and Prometheus will scrape it automatically.

### Metrics reference

| Metric | Type | Labels | Emitted by |
|---|---|---|---|
| `greengate_scan_findings_total` | counter | `severity`, `service` | `scan` |
| `greengate_scan_duration_ms` | gauge | `service` | `scan` |
| `greengate_command_duration_ms` | gauge | `command`, `success`, `service` | all commands |
| `greengate_command_success` | gauge | `command`, `service` | all commands |

**Example Grafana queries:**

```promql
# Finding rate over time
rate(greengate_scan_findings_total{severity="critical"}[7d])

# Commands failing in CI
greengate_command_success == 0

# Slowest commands
topk(5, greengate_command_duration_ms)
```

---

## Container image scanning

Most applications ship as Docker images. Secrets baked in at build time — via `COPY .env /app/`, `ARG` values written to config files, or leaked into the shell environment — don't appear in your source repo but live in every deployed container. `greengate image-scan` catches them.

### How it works

1. **`docker save <image> -o image.tar`** — exports the full image to a local tar archive. The image is pulled from the registry if not already cached.
2. **Unpack the outer tar** — extracts the OCI manifest and layer archives.
3. **Unpack each layer** — extracts every `layer.tar` individually. OCI images contain one tar per filesystem layer.
4. **Scan all text files** — runs the same 26 secret patterns and Shannon entropy scan used by `greengate scan` on every text file in every layer.
5. **Deduplicate** — files that are unchanged across layers (a common OCI pattern) are reported only once.

Findings are reported as `<image>::layer:<digest>::<path>`, e.g.:

```
nginx:latest::layer:a1b2c3d4e5f6::etc/environment:3  HIGH  AWS_ACCESS_KEY_ID
```

### Sensitive path promotion

Files in sensitive locations have their severity automatically promoted one level (medium → high) to surface credentials that are more likely to be exploitable:

| Promoted paths |
|---|
| `.env`, `*.env.*` |
| `.aws/credentials` |
| `.ssh/` directories |
| `etc/environment` |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| `docker-compose*.yml` |

### Usage

```bash
# Scan a public image
greengate image-scan nginx:latest

# Scan a private registry image (must be accessible via `docker pull`)
greengate image-scan ghcr.io/my-org/my-app:sha-abc123

# Output as JSON (for CI integration)
greengate image-scan my-app:v1.2.3 --format json

# Report findings but don't fail the build (audit mode)
greengate image-scan my-app:v1.2.3 --no-fail
```

### GitHub Actions — scan image before push

```yaml
- name: Build image
  run: docker build -t my-app:${{ github.sha }} .

- name: Scan image layers for secrets
  run: greengate image-scan my-app:${{ github.sha }}
```

### Requirements

- **Docker** must be running and `docker` must be in `PATH`. `greengate image-scan` will print a helpful error with installation instructions if Docker is not found.
- The image must be accessible locally (already pulled) or in a registry that the Docker daemon can pull from.

---

## GitHub Actions

The fastest setup: `greengate init --ci github-actions` writes a ready-to-use workflow. Or wire it in manually:

```yaml
name: greengate

on: [push, pull_request]

permissions:
  contents: read
  checks: write
  security-events: write

jobs:
  greengate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install greengate
        run: |
          curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
            -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

      # Scan for secrets/SAST and upload results to GitHub Code Scanning
      - name: Scan (SARIF)
        run: greengate scan --format sarif > greengate.sarif || true

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: greengate.sarif

      # Lint CI workflows for security misconfigurations
      - name: CI lint
        run: greengate ci-lint

      # Zero-trust install — catches supply chain attacks at install time
      - name: Zero-trust install
        run: greengate watch-install npm ci

      # Dependency CVE audit
      - name: Audit
        run: greengate audit

      # Coverage gate
      - name: Coverage
        run: greengate coverage --file coverage/lcov.info --min 80

      # PR complexity + coverage gaps (pull_request only)
      - name: Review
        if: github.event_name == 'pull_request'
        run: |
          greengate review \
            --base "${{ github.event.pull_request.base.sha }}" \
            --coverage-file coverage/lcov.info \
            --annotate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_SHA: ${{ github.sha }}
```

Or use the **composite action** (zero download boilerplate):

```yaml
- uses: greengate-dev/greengate@v0
  id: greengate
  with:
    profile: ci
    report: greengate.sarif        # optional; JSON in RUNNER_TEMP by default
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action exits with greengate's [exit code](https://greengate-dev.github.io/greengate/reference/exit-codes) and sets `status` (`passed`, `findings`, `incomplete` or `error`), `findings`, `incomplete` and `report-path` outputs. A `.sarif` report can go straight to `github/codeql-action/upload-sarif`.

> See [CI/CD Integration](https://greengate-dev.github.io/greengate/guide/ci-integration) for GitLab CI, Bitbucket Pipelines, and CircleCI examples.

---

## Configuration

Run `greengate init` for an interactive wizard, or create `.greengate.toml` manually. Every field is optional — greengate works with zero config.

```toml
[scan]
entropy             = true
entropy_threshold   = 4.5          # higher = fewer false positives
exclude_patterns    = ["tests/**", "*.test.ts", "fixtures/**"]

[sast]
enabled = true

[supply_chain]
block_phantom_scripts   = true
enforce_sandbox         = true
allow_postinstall       = ["esbuild", "prisma", "@swc/core"]  # npm
allow_pip_packages      = ["grpcio"]                           # pip
allow_cargo_crates      = ["openssl"]                          # cargo
slopsquat_check         = true    # hallucinated-package guard (all install wrappers)
slopsquat_min_age_days  = 90      # registered more recently than this = suspicious
slopsquat_min_downloads = 1000    # fewer total downloads than this = suspicious
internal_packages       = ["@mycorp", "acme-internal-*"]  # dependency-confusion guard

[coverage]
file = "coverage/lcov.info"
min  = 80.0

[review]
min_new_code_coverage = 80    # new lines must be covered at this % (PR gate)
complexity_budget     = 0     # 0 = warn only; > 0 = hard fail threshold

[tia]
test_patterns = [
  "**/*.test.ts",
  "**/*.test.js",
  "**/test_*.py",
  "**/*_test.go",
]

[pipeline]
steps = [
  "scan",
  "ci-lint",
  "audit",
  "coverage",
  "review --base main --coverage-file coverage/lcov.info",
]

[triage]
model                   = "claude-haiku-4-5-20251001"
api_key_env             = "ANTHROPIC_API_KEY"
auto_suppress_threshold = 0.0      # raise to 0.9 once you've reviewed triage output
context_lines           = 10
# endpoint = "http://localhost:11434/v1/chat/completions"  # Ollama

[sbom]
default_output    = "sbom.json"
# expected_issuer   = "https://token.actions.githubusercontent.com"
# expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"

[telemetry]
enabled       = true
otlp_endpoint = "http://localhost:4318"   # OTLP HTTP — remove if not using
# metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"  # Prometheus
service_name  = "my-service"
```

Full reference → [Configuration Reference](https://greengate-dev.github.io/greengate/reference/config)

---

## Documentation

- [Getting Started](https://greengate-dev.github.io/greengate/guide/getting-started)
- [CI/CD Integration](https://greengate-dev.github.io/greengate/guide/ci-integration)
- [Secret Patterns](https://greengate-dev.github.io/greengate/reference/secret-patterns)
- [SAST Rules](https://greengate-dev.github.io/greengate/reference/sast-rules)
- [Output Formats](https://greengate-dev.github.io/greengate/reference/output-formats) — SARIF, JUnit, GitLab, JSON
- [Exit Codes](https://greengate-dev.github.io/greengate/reference/exit-codes)
- [Roadmap](https://greengate-dev.github.io/greengate/reference/roadmap)
- [Benchmarks](bench/) — reproducible secret-detection precision/recall vs. other scanners

---

## Contributing

greengate is open source under the [MIT License](LICENSE). Contributions welcome — especially new secret patterns, SAST rules, and CI platform support.

```bash
cargo test          # 255 unit + integration tests
cargo clippy        # lint
cargo fmt --check   # formatting
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, SAST rules, and run the full test suite.
