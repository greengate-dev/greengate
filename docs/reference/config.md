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

[audit]
# GHSA/CVE advisory IDs to suppress — use for known-acceptable transitive
# dependency vulnerabilities that cannot be fixed by upgrading a direct dep.
# Always document WHY each entry is acceptable in a comment above the ID.
# Re-evaluate when upstream tools release new major versions.
ignore_advisories = [
  # "GHSA-xxxx-yyyy-zzzz",   # affected-package — reason suppressed
]

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

Suppress a finding on a specific line using a comment:

```ts
const key = "AKIAIOSFODNN7EXAMPLE123"; // greengate: ignore
el.innerHTML = sanitizedHtml;           // greengate: ignore
```

Works for both secret/PII and SAST findings.
