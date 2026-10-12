---
title: 'Configuration Reference — .greengate.toml'
description: 'Full .greengate.toml reference: scan, sast, supply_chain (npm/pip/cargo), tia, triage (AI false-positive), sbom attestation, telemetry (OTLP/Prometheus), coverage, audit, review, and all default values.'
---

# Configuration File (.greengate.toml)

Place `.greengate.toml` in the root of your repository. CLI flags always override config file values. All fields are optional — omitted values fall back to built-in defaults.

## Full reference

```toml
[scan]
# Glob patterns for paths to exclude from scanning
exclude_patterns = [
  "tests/**",
  "*.test.ts",
  "fixtures/**",
  "vendor/**",
]

# Extra patterns added on top of the 26 built-ins
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
]

# Shannon entropy detection — flags high-entropy tokens not matched by named patterns
entropy = true
entropy_threshold = 4.5    # lower = more sensitive (default 4.5)
entropy_min_length = 20    # ignore tokens shorter than this (default 20)

[sast]
# Set to false to disable SAST entirely and fall back to regex for JS/TS files
enabled = true

# Suppress specific rule IDs
disabled_rules = [
  # "SAST/ChildProcessExec",
  # "SAST/EvalUsage",
  # "SMELL/LongFunction",
]

# Code smell thresholds
max_function_lines = 50   # flag functions longer than this many lines (default 50)
max_parameters     = 5    # flag functions with more parameters than this (default 5)
max_nesting_depth  = 4    # flag control-flow nesting deeper than this (default 4)

# Custom tree-sitter rules — each must include a @match capture
custom_rules = [
  # { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]

[coverage]
file = "coverage/lcov.info"    # default coverage file path
min  = 85.0                    # default minimum threshold %

[lint]
target_dir = "./infrastructure/k8s"    # default Kubernetes manifest directory

[lighthouse]
url              = "https://yourapp.com"
strategy         = "mobile"    # mobile or desktop
min_performance  = 80
min_accessibility = 90
min_best_practices = 80
min_seo          = 80
# api_key = ""                 # prefer PAGESPEED_API_KEY env var

[reassure]
current   = "output/current.perf"
baseline  = "output/baseline.perf"
threshold = 15.0               # maximum regression % before failing

[review]
# Minimum coverage required for newly added lines in a PR diff (default 80.0)
# Only enforced when --coverage-file is provided
min_new_code_coverage = 80.0

# Maximum Complexity Score before failing (default 0 = warn only)
# Set to a positive integer to fail the gate when the score exceeds this value
complexity_budget = 0

[policy]
# What a gate does when it could not check everything (e.g. the vulnerability
# database was unreachable): "fail" exits 3 (default), "warn" exits 0 but
# still reports the run as incomplete. See the exit codes reference.
on_incomplete = "fail"
# The longest an exception in .greengate/exceptions.toml may run, in days from
# today. See the Baselines & Exceptions guide.
max_exception_days = 90

[deps]
# Dependency files to ignore (globs relative to the scanned directory) — used
# by audit, sbom and `greengate deps`. Typical: test fixtures, examples.
exclude_patterns = ["tests/fixtures/**"]

[audit]
# Deprecated: advisory IDs to suppress, with no owner or expiry. Use
# .greengate/exceptions.toml instead (`greengate exceptions migrate`).
ignore_advisories = []
# Vulnerability data: "auto" (OSV API, falling back to an offline snapshot
# when it fails), "online", or "offline" (snapshots from `greengate db update`)
source = "auto"
# Oldest offline snapshot audit will use; older data makes the run incomplete
max_db_age_hours = 24

[dependency_review]
# `greengate deps review`: introduced advisories at or above this severity
# fail (low | medium | high | critical); below it, they are warnings.
fail_on_severity = "high"
# Which kinds of problem fail the review; the rest are warnings.
fail_on = ["new-advisory", "release-risk", "denied-license", "source-policy"]
# SPDX licenses no new or changed dependency may use.
deny_licenses = []
# When set, only these SPDX licenses are acceptable.
allow_licenses = []
# A dependency whose license is missing or unreadable: off | warn | fail.
unknown_license = "warn"

[supply_chain]
# Halt the install when any layer of the zero-trust gate detects a threat (default: true).
block_phantom_scripts = true

# Monitor the project root for new executable files after install (default: true).
enforce_sandbox = true

# Packages whose postinstall scripts legitimately make network calls or create
# temp files (e.g. native build tools that compile .node addons). Findings from
# these packages are downgraded to warnings — they still appear in output for
# audit trail but do not trigger a non-zero exit.
allow_postinstall = [
  # "esbuild",
  # "prisma",
  # "@swc/core",
]

# PyPI package names exempted from greengate pip-install typosquat and source scanning.
allow_pip_packages = [
  # "my-internal-requests-wrapper",
]

# Cargo crate names exempted from greengate cargo-add typosquat and build.rs scanning.
allow_cargo_crates = [
  # "openssl",   # legitimate complex build.rs for system lib detection
]

# Your private package names / scopes / prefixes. In `deps check`, a package
# matching one that resolves from the public registry fails as dependency
# confusion; the install wrappers also check the public registry for them.
internal_packages = [
  # "@acme", "acme-*",
]

# `greengate install`: refuse to run dependency install scripts without a
# sandbox (the run is then incomplete instead of running them unisolated).
require_isolation = false
# Packages whose install scripts may use the network inside the sandbox.
script_network = [
  # "puppeteer",
]
# Credential-looking environment variables still passed to install scripts.
env_allow = [
  # "NODE_EXTRA_CA_CERTS",
]

# Release-risk policy for new or upgraded packages (`greengate deps check`).
# Each signal is "off", "warn" or "fail". `--profile strict` turns every
# "warn" here (and in [supply_chain.sources]) into "fail".
[supply_chain.release]
min_release_age_hours = 24        # cooldown
young_release = "warn"            # published inside the cooldown
new_install_script = "fail"       # runs install code its predecessor did not
provenance_regression = "fail"    # predecessor had provenance, this one has none
publisher_change = "warn"         # publisher never published this package before
withdrawn = "warn"                # yanked, deprecated, or missing from the registry
missing_integrity = "warn"        # lockfile records no hash (formats that normally do)

# Packages that must come from a given registry (repeatable).
# [[supply_chain.registries]]
# pattern = "@acme/*"              # exact name, npm scope, or prefix-*
# url = "https://npm.acme.dev/"
# ecosystems = ["npm"]             # optional: npm, PyPI, crates.io

# Dependencies that do not come from a registry.
[supply_chain.sources]
git = "warn"    # git dependencies not pinned to a full commit hash
url = "warn"    # tarball / archive URLs
path = "off"    # local paths outside the workspace

[tia]
# Glob patterns that identify test files for Test Impact Analysis.
# Uses standard glob syntax with ** for recursive matching.
# Defaults cover TypeScript/JavaScript, Python, and Go conventions.
test_patterns = [
  "**/*.test.ts",
  "**/*.test.tsx",
  "**/*.test.js",
  "**/*.test.jsx",
  "**/*.spec.ts",
  "**/*.spec.tsx",
  "**/*.spec.js",
  "**/*.spec.jsx",
  "**/test_*.py",
  "**/*_test.py",
  "tests/**/*.py",
  "**/*_test.go",
]

[triage]
# Master switch — set to false to disable even when --triage is passed (default: true)
enabled = true

# LLM model. Default: claude-haiku-4-5-20251001 (fast, cheap, accurate for triage).
# For OpenAI-compatible endpoints use the model name expected by that API.
model = "claude-haiku-4-5-20251001"

# Environment variable that holds the API key (default: ANTHROPIC_API_KEY).
api_key_env = "ANTHROPIC_API_KEY"

# LLM API endpoint. Leave unset to use the Anthropic Messages API.
# Set to an OpenAI-compatible URL to use Ollama, OpenAI, or any compatible server.
# endpoint = "http://localhost:11434/v1/chat/completions"

# Automatically suppress findings where the LLM is >= this confident they are false
# positives. 0.0 = never auto-suppress (annotate only). Start here, raise once you
# trust the results for your codebase.
auto_suppress_threshold = 0.0

# Source lines before and after the flagged line to include as context (default: 10).
context_lines = 10

[sbom]
# Default output path for generated SBOMs (default: "sbom.json").
default_output = "sbom.json"

# For greengate sbom --verify: expected OIDC issuer of the signing certificate.
# Leave unset to accept any Sigstore identity (permissive but still validates Rekor).
# expected_issuer = "https://token.actions.githubusercontent.com"

# For greengate sbom --verify: expected signer identity (exact match).
# Typically the full workflow URL including ref, e.g.:
# expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"

[telemetry]
# Master switch (default: true — but nothing is sent unless an endpoint or file is set)
enabled = true

# Service name attached to every metric as the service.name resource attribute.
service_name = "my-service"

# OTLP HTTP/JSON endpoint (port 4318, not gRPC 4317). Leave unset to disable.
# otlp_endpoint = "http://localhost:4318"

# Prometheus text-format .prom file. Leave unset to disable.
# metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

## Precedence

CLI flag > `--profile` override > `.greengate.toml` > built-in default

## Profiles

Apply a named quality profile on top of your loaded config with the global `--profile` flag:

```bash
greengate --profile strict scan
greengate --profile ci scan --staged
```

| Profile | Effect |
|---|---|
| `strict` | Coverage ≥ 90%, entropy threshold 3.5 (more sensitive), Lighthouse performance ≥ 90, accessibility ≥ 95, SAST enabled |
| `relaxed` | Coverage ≥ 70%, entropy threshold 5.0 (fewer false positives) |
| `ci` | Coverage ≥ 80%, SAST enabled, code-smell rules (`SMELL/*`) disabled to reduce noise |

Profiles modify the in-memory config only — they never write to `.greengate.toml`.

## Inline suppression

Suppress a finding on a specific line using a comment, optionally with a reason:

```ts
const key = "AKIAIOSFODNN7EXAMPLE123"; // greengate: ignore reason="docs example"
el.innerHTML = sanitizedHtml;           // greengate: ignore
```

Works for secret/PII, SAST and `ci-lint` findings. Suppressed findings are listed in the report with their reason.

## Exceptions: `.greengate/exceptions.toml`

Time-limited waivers with an owner and a reason, for any gate that reports
findings by rule, advisory or fingerprint:

```toml
[[exception]]
id = "EX-12"
match = { advisory = "GHSA-35jh-r3h4-6jhm", package = "lodash" }
reason = "Not reachable: we never call _.template with user input"
owner = "@payments-team"
expires = "2026-12-31"
ticket = "SEC-481"   # optional
```

See [Baselines & Exceptions](/guide/baselines-and-exceptions#governed-exceptions)
for the match forms and the expiry policy.

## Pipeline

```toml
[pipeline]
# Steps for `greengate run`, each a command with optional flags.
steps = ["scan", "audit", "deps-review", "ci-lint", "coverage --min 80"]
# Stop at the first step that does not pass (default: run every step and
# report the worst result).
fail_fast = false
```

## Environment variables

| Variable | Effect |
|---|---|
| `GREENGATE_CACHE_DIR` | Where greengate caches OSV answers, registry metadata and offline snapshots (default: the user cache directory) |
| `GREENGATE_OSV_URL` | An OSV-compatible API to query instead of `https://api.osv.dev` |
| `GREENGATE_OSV_DB_URL` | Where `greengate db update` downloads OSV snapshots from |
| `GREENGATE_NPM_REGISTRY` | The npm registry to read release metadata from. Set it to a mirror of the public registry (Artifactory, Verdaccio): packages resolved from it are then checked like registry.npmjs.org's instead of being skipped as private |
| `GREENGATE_PYPI_URL` | The PyPI JSON API to read release metadata from |
| `GREENGATE_CRATES_URL` | The crates.io API to read release metadata from |
| `GREENGATE_CRATES_INDEX` | The crates.io sparse index `deps review` reads requirements from |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_SHA` | Enable `--annotate` (check runs and the pull-request comment) |
| `GITHUB_API_URL` | The GitHub API root (set by Actions; GitHub Enterprise Server) |
| `GITHUB_BASE_REF` | In a pull request, the default base for `deps check`, `deps review` and `scan --new-since` |

