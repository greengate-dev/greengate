use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub coverage: CoverageConfig,
    #[serde(default)]
    pub lint: LintConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub lighthouse: LighthouseConfig,
    #[serde(default)]
    pub reassure: ReassureConfig,
    #[serde(default)]
    pub sast: SastConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub review: ReviewConfig,
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,
    #[serde(default)]
    pub tia: TiaConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub sbom: SbomConfig,
    #[serde(default)]
    pub triage: TriageConfig,
}

/// Audit settings loaded from `.greengate.toml` under `[audit]`.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// GHSA/CVE IDs to suppress — use for known-acceptable transitive dep
    /// vulnerabilities that cannot be fixed by upgrading a direct dependency.
    /// Document WHY each entry is acceptable in a comment above the list.
    #[serde(default)]
    pub ignore_advisories: Vec<String>,
}

/// A user-defined tree-sitter query rule from `.greengate.toml`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CustomSastRule {
    /// Unique rule ID reported in findings, e.g. "MY/NoConsoleLog"
    pub id: String,
    /// tree-sitter S-expression query. Must contain a @match capture.
    pub query: String,
}

/// SAST settings loaded from `.greengate.toml` under `[sast]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SastConfig {
    /// Master switch — set to false to disable all SAST checks (default: true)
    #[serde(default = "default_sast_enabled")]
    pub enabled: bool,
    /// Rule IDs to skip, e.g. ["SAST/EvalUsage", "SAST/SetTimeout"]
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Max lines in a function body before SMELL/LongFunction fires (default: 50)
    #[serde(default = "default_max_function_lines")]
    pub max_function_lines: usize,
    /// Max parameters before SMELL/TooManyParameters fires (default: 5)
    #[serde(default = "default_max_parameters")]
    pub max_parameters: usize,
    /// Max nesting depth before SMELL/DeepNesting fires (default: 4)
    #[serde(default = "default_max_nesting_depth")]
    pub max_nesting_depth: usize,
    /// User-defined tree-sitter query rules (default: [])
    #[serde(default)]
    pub custom_rules: Vec<CustomSastRule>,
}

impl Default for SastConfig {
    fn default() -> Self {
        Self {
            enabled: default_sast_enabled(),
            disabled_rules: Vec::new(),
            max_function_lines: default_max_function_lines(),
            max_parameters: default_max_parameters(),
            max_nesting_depth: default_max_nesting_depth(),
            custom_rules: Vec::new(),
        }
    }
}

fn default_sast_enabled() -> bool {
    true
}
fn default_max_function_lines() -> usize {
    50
}
fn default_max_parameters() -> usize {
    5
}
fn default_max_nesting_depth() -> usize {
    4
}

/// Per-scan settings loaded from `.greengate.toml`.
/// `#[derive(Default)]` is not used because the entropy fields require non-zero defaults
/// that cannot be expressed with Rust's `Default` trait directly; use helper fns instead.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub extra_patterns: Vec<ExtraPattern>,
    /// Enable Shannon entropy detection for high-entropy tokens (default: true)
    #[serde(default = "default_entropy_enabled")]
    pub entropy: bool,
    /// Minimum entropy score for base64-like tokens to be flagged (default: 4.5)
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Minimum token length (chars) before entropy is checked (default: 20)
    #[serde(default = "default_entropy_min_length")]
    pub entropy_min_length: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            exclude_patterns: Vec::new(),
            extra_patterns: Vec::new(),
            entropy: default_entropy_enabled(),
            entropy_threshold: default_entropy_threshold(),
            entropy_min_length: default_entropy_min_length(),
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExtraPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CoverageConfig {
    #[serde(default = "default_coverage_min")]
    pub min: f64,
    #[serde(default = "default_lcov_file")]
    pub file: String,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            min: default_coverage_min(),
            file: default_lcov_file(),
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LintConfig {
    #[serde(default = "default_target_dir")]
    pub target_dir: String,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            target_dir: default_target_dir(),
        }
    }
}

// ── Lighthouse config ─────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LighthouseConfig {
    /// URL to audit (required for `greengate lighthouse` unless passed via CLI)
    #[serde(default)]
    pub url: Option<String>,
    /// Device strategy: "mobile" (default) or "desktop"
    #[serde(default = "default_lighthouse_strategy")]
    pub strategy: String,
    #[serde(default = "default_lighthouse_perf")]
    pub min_performance: u8,
    #[serde(default = "default_lighthouse_a11y")]
    pub min_accessibility: u8,
    #[serde(default = "default_lighthouse_bp")]
    pub min_best_practices: u8,
    #[serde(default = "default_lighthouse_seo")]
    pub min_seo: u8,
    /// Google PageSpeed Insights API key (optional; can also set PAGESPEED_API_KEY env var)
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            url: None,
            strategy: default_lighthouse_strategy(),
            min_performance: default_lighthouse_perf(),
            min_accessibility: default_lighthouse_a11y(),
            min_best_practices: default_lighthouse_bp(),
            min_seo: default_lighthouse_seo(),
            api_key: None,
        }
    }
}

// ── Reassure config ───────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReassureConfig {
    /// Path to Reassure current.perf file
    #[serde(default = "default_reassure_current")]
    pub current: String,
    /// Path to Reassure baseline.perf file (optional)
    #[serde(default = "default_reassure_baseline")]
    pub baseline: String,
    /// Percentage mean-time increase allowed before flagging a regression
    #[serde(default = "default_reassure_threshold")]
    pub threshold: f64,
}

impl Default for ReassureConfig {
    fn default() -> Self {
        Self {
            current: default_reassure_current(),
            baseline: default_reassure_baseline(),
            threshold: default_reassure_threshold(),
        }
    }
}

// ── Default value fns ─────────────────────────────────────────────────────────

fn default_entropy_enabled() -> bool {
    true
}
fn default_entropy_threshold() -> f64 {
    4.5
}
fn default_entropy_min_length() -> usize {
    20
}
fn default_coverage_min() -> f64 {
    80.0
}
fn default_lcov_file() -> String {
    "coverage/lcov.info".to_string()
}
fn default_target_dir() -> String {
    ".".to_string()
}
fn default_lighthouse_strategy() -> String {
    "mobile".to_string()
}
fn default_lighthouse_perf() -> u8 {
    80
}
fn default_lighthouse_a11y() -> u8 {
    90
}
fn default_lighthouse_bp() -> u8 {
    80
}
fn default_lighthouse_seo() -> u8 {
    80
}
fn default_reassure_current() -> String {
    "output/current.perf".to_string()
}
fn default_reassure_baseline() -> String {
    "output/baseline.perf".to_string()
}
fn default_reassure_threshold() -> f64 {
    15.0
}

// ── Docker config ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DockerConfig {
    /// Path to the Dockerfile to lint (default: "Dockerfile")
    #[serde(default = "default_dockerfile")]
    pub dockerfile: String,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            dockerfile: default_dockerfile(),
        }
    }
}

fn default_dockerfile() -> String {
    "Dockerfile".to_string()
}

// ── Review config ─────────────────────────────────────────────────────────────

/// Settings for `greengate review` loaded from `.greengate.toml` under `[review]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReviewConfig {
    /// Minimum coverage percentage required for newly added lines (default: 80)
    #[serde(default = "default_review_min_coverage")]
    pub min_new_code_coverage: f64,
    /// Fail if Complexity Score exceeds this value; 0 = warn only (default: 0)
    #[serde(default)]
    pub complexity_budget: u32,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            min_new_code_coverage: default_review_min_coverage(),
            complexity_budget: 0,
        }
    }
}

fn default_review_min_coverage() -> f64 {
    80.0
}

// ── Pipeline config ───────────────────────────────────────────────────────────

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct PipelineConfig {
    /// Ordered list of steps to run with `greengate run`.
    /// Each entry is a command string, e.g. "scan", "coverage --min 80".
    #[serde(default)]
    pub steps: Vec<String>,
}

// ── Supply chain config ───────────────────────────────────────────────────────

/// Settings for supply-chain protection loaded from `.greengate.toml`
/// under `[supply_chain]`.  Currently drives `greengate watch-install`;
/// reserved for `greengate sandbox-install` in a future release.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainConfig {
    /// Fail the install if a phantom file (created-then-deleted postinstall
    /// binary) or unexpected executable drop is detected (default: true).
    #[serde(default = "default_supply_chain_block_phantom")]
    pub block_phantom_scripts: bool,
    /// Monitor the project root for new executables dropped during install.
    /// When false, only `node_modules/` phantom-file detection runs (default: true).
    #[serde(default = "default_supply_chain_sandbox")]
    pub enforce_sandbox: bool,
    /// Packages whose postinstall scripts may legitimately create temp files
    /// (e.g. native build tools).  Findings from these packages are reported
    /// as warnings and do not trigger a failure.
    #[serde(default)]
    pub allow_postinstall: Vec<String>,
    /// PyPI package names exempted from `greengate pip-install` checks.
    #[serde(default)]
    pub allow_pip_packages: Vec<String>,
    /// Cargo crate names exempted from `greengate cargo-add` checks.
    #[serde(default)]
    pub allow_cargo_crates: Vec<String>,
    /// Enable the slopsquat / hallucinated-package guard on install wrappers,
    /// which scores registry metadata of newly-introduced packages (default: true).
    #[serde(default = "default_slopsquat_check")]
    pub slopsquat_check: bool,
    /// A newly-introduced package registered fewer than this many days ago is
    /// treated as suspicious (default: 90).
    #[serde(default = "default_slopsquat_min_age_days")]
    pub slopsquat_min_age_days: u64,
    /// A newly-introduced package with fewer total downloads than this is
    /// treated as suspicious (default: 1000).
    #[serde(default = "default_slopsquat_min_downloads")]
    pub slopsquat_min_downloads: u64,
    /// Private/internal package names, npm scopes (`@myco`), or `prefix-*`
    /// patterns owned by the caller. If one of these also resolves on the public
    /// registry during an install, that's flagged as a dependency-confusion risk.
    /// Empty (default) disables the confusion check.
    #[serde(default)]
    pub internal_packages: Vec<String>,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            block_phantom_scripts: default_supply_chain_block_phantom(),
            enforce_sandbox: default_supply_chain_sandbox(),
            allow_postinstall: Vec::new(),
            allow_pip_packages: Vec::new(),
            allow_cargo_crates: Vec::new(),
            slopsquat_check: default_slopsquat_check(),
            slopsquat_min_age_days: default_slopsquat_min_age_days(),
            slopsquat_min_downloads: default_slopsquat_min_downloads(),
            internal_packages: Vec::new(),
        }
    }
}

fn default_supply_chain_block_phantom() -> bool {
    true
}
fn default_supply_chain_sandbox() -> bool {
    true
}
fn default_slopsquat_check() -> bool {
    true
}
fn default_slopsquat_min_age_days() -> u64 {
    90
}
fn default_slopsquat_min_downloads() -> u64 {
    1000
}

// ── TIA config ────────────────────────────────────────────────────────────────

/// Settings for `greengate tia` loaded from `.greengate.toml` under `[tia]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TiaConfig {
    /// Glob patterns that identify test files to consider for impact analysis.
    /// Patterns follow standard glob syntax with `**` for recursive matching.
    #[serde(default = "default_tia_test_patterns")]
    pub test_patterns: Vec<String>,
}

impl Default for TiaConfig {
    fn default() -> Self {
        Self {
            test_patterns: default_tia_test_patterns(),
        }
    }
}

fn default_tia_test_patterns() -> Vec<String> {
    vec![
        "**/*.test.ts".to_string(),
        "**/*.test.tsx".to_string(),
        "**/*.test.js".to_string(),
        "**/*.test.jsx".to_string(),
        "**/*.spec.ts".to_string(),
        "**/*.spec.tsx".to_string(),
        "**/*.spec.js".to_string(),
        "**/*.spec.jsx".to_string(),
        "**/test_*.py".to_string(),
        "**/*_test.py".to_string(),
        "tests/**/*.py".to_string(),
        "**/*_test.go".to_string(),
    ]
}

// ── Telemetry config ──────────────────────────────────────────────────────────

/// Settings for metrics export loaded from `.greengate.toml` under `[telemetry]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Master switch — set to false to disable all telemetry (default: true)
    #[serde(default = "default_telemetry_enabled")]
    pub enabled: bool,
    /// OTLP HTTP endpoint, e.g. "http://localhost:4318". Leave unset to disable.
    /// Accepts any OTLP-compatible collector: OpenTelemetry Collector, Grafana
    /// Agent, Datadog Agent OTLP intake, Honeycomb, etc.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Service name attached to every metric as the `service.name` resource
    /// attribute (default: "greengate").
    #[serde(default = "default_telemetry_service_name")]
    pub service_name: String,
    /// Path to write a Prometheus text-format `.prom` file after each command.
    /// Point Prometheus node_exporter's `--collector.textfile.directory` at the
    /// containing directory. Leave unset to disable.
    #[serde(default)]
    pub metrics_file: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: default_telemetry_enabled(),
            otlp_endpoint: None,
            service_name: default_telemetry_service_name(),
            metrics_file: None,
        }
    }
}

fn default_telemetry_enabled() -> bool {
    true
}

fn default_telemetry_service_name() -> String {
    "greengate".to_string()
}

// ── SBOM config ───────────────────────────────────────────────────────────────

/// Settings for `greengate sbom` loaded from `.greengate.toml` under `[sbom]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SbomConfig {
    /// Default output path for generated SBOMs (default: "sbom.json").
    #[serde(default = "default_sbom_output")]
    pub default_output: String,
    /// Expected OIDC issuer when verifying attestations, e.g.
    /// `https://token.actions.githubusercontent.com`. Leave empty to accept any.
    #[serde(default)]
    pub expected_issuer: Option<String>,
    /// Expected signer identity when verifying attestations, e.g.
    /// `https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main`.
    /// Leave empty to accept any. Treated as an exact match.
    #[serde(default)]
    pub expected_identity: Option<String>,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            default_output: default_sbom_output(),
            expected_issuer: None,
            expected_identity: None,
        }
    }
}

fn default_sbom_output() -> String {
    "sbom.json".to_string()
}

// ── Triage config ─────────────────────────────────────────────────────────────

/// Settings for `greengate scan --triage` loaded from `.greengate.toml` under `[triage]`.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TriageConfig {
    /// Master switch — set to false to disable triage even when --triage is passed (default: true)
    #[serde(default = "default_triage_enabled")]
    pub enabled: bool,
    /// LLM model to use. Default: claude-haiku-4-5-20251001 (fast, cheap, accurate enough).
    /// For OpenAI-compatible endpoints use the model name expected by that API.
    #[serde(default = "default_triage_model")]
    pub model: String,
    /// Name of the environment variable that holds the API key (default: ANTHROPIC_API_KEY).
    #[serde(default = "default_triage_api_key_env")]
    pub api_key_env: String,
    /// LLM API endpoint. Leave unset to use the Anthropic Messages API.
    /// Set to an OpenAI-compatible URL (e.g. http://localhost:11434/v1/chat/completions)
    /// to use a local model via Ollama or any other OpenAI-compatible server.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Automatically suppress findings where the LLM is ≥ this confident they are false
    /// positives. 0.0 = never auto-suppress (just annotate). 0.9 is a good starting point.
    #[serde(default)]
    pub auto_suppress_threshold: f64,
    /// Number of source lines before and after the flagged line to include as context
    /// in the LLM prompt (default: 10).
    #[serde(default = "default_triage_context_lines")]
    pub context_lines: usize,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            enabled: default_triage_enabled(),
            model: default_triage_model(),
            api_key_env: default_triage_api_key_env(),
            endpoint: None,
            auto_suppress_threshold: 0.0,
            context_lines: default_triage_context_lines(),
        }
    }
}

fn default_triage_enabled() -> bool {
    true
}

fn default_triage_model() -> String {
    "claude-haiku-4-5-20251001".to_string()
}

fn default_triage_api_key_env() -> String {
    "ANTHROPIC_API_KEY".to_string()
}

fn default_triage_context_lines() -> usize {
    10
}

/// Load `.greengate.toml` from the current directory, falling back to defaults.
/// Prints a status message to stderr (suitable for text/interactive output).
/// Use [`load_silent`] when emitting structured output (JSON, SARIF, JUnit).
///
/// # Errors
/// Returns an error if `.greengate.toml` exists but cannot be read or parsed.
/// A *missing* file is not an error — it yields the defaults.
pub fn load() -> Result<Config> {
    load_inner(true)
}

/// Like [`load`] but suppresses the "Loaded config" info message.
/// Use this when the caller is emitting machine-readable output so that the
/// info line does not pollute parsers that capture stderr alongside stdout.
///
/// # Errors
/// As [`load`].
pub fn load_silent() -> Result<Config> {
    load_inner(false)
}

fn load_inner(verbose: bool) -> Result<Config> {
    let path = std::path::Path::new(".greengate.toml");
    if !path.exists() {
        return Ok(Config::default());
    }

    // A config that exists but does not parse is a hard error. Falling back to
    // defaults here would silently discard every gate the user configured —
    // allowlists, thresholds, whether SAST runs at all — and the run would look
    // like a pass. With `deny_unknown_fields` on the structs above, a typo'd key
    // lands here too, which is the whole point: an unrecognised setting is not a
    // setting that is quietly off.
    let content = std::fs::read_to_string(path)
        .context("failed to read .greengate.toml (it exists but could not be opened)")?;
    let cfg = toml::from_str(&content).context(
        "failed to parse .greengate.toml — fix the file, or run `greengate check-config` for detail",
    )?;
    if verbose {
        eprintln!("ℹ️  Loaded config from .greengate.toml");
    }
    Ok(cfg)
}

/// Apply a named profile on top of an already-loaded config.
///
/// Profiles adjust thresholds without requiring a config file change:
///   `strict`  — tighter quality gates (higher coverage, lower entropy threshold)
///   `relaxed` — looser gates (lower coverage, higher entropy threshold)
///   `ci`      — CI-optimised: strict gates + SAST enabled, no interactive output
pub fn apply_profile(cfg: &mut Config, profile: &str) {
    match profile {
        "strict" => {
            // Raise coverage threshold to 90 % if not already higher
            if cfg.coverage.min < 90.0 {
                cfg.coverage.min = 90.0;
            }
            // Also tighten the review command's new-code coverage gate
            if cfg.review.min_new_code_coverage < 90.0 {
                cfg.review.min_new_code_coverage = 90.0;
            }
            // Lower entropy threshold → more sensitive secret detection
            if cfg.scan.entropy_threshold > 3.5 {
                cfg.scan.entropy_threshold = 3.5;
            }
            // Ensure SAST is on
            cfg.sast.enabled = true;
            // Stricter Lighthouse scores
            if cfg.lighthouse.min_performance < 90 {
                cfg.lighthouse.min_performance = 90;
            }
            if cfg.lighthouse.min_accessibility < 95 {
                cfg.lighthouse.min_accessibility = 95;
            }
        }
        "relaxed" => {
            // Lower coverage threshold to 70 % if not already lower
            if cfg.coverage.min > 70.0 {
                cfg.coverage.min = 70.0;
            }
            // Raise entropy threshold → fewer false positives
            if cfg.scan.entropy_threshold < 5.0 {
                cfg.scan.entropy_threshold = 5.0;
            }
        }
        "ci" => {
            // Same as strict, but also disable code-smell rules that produce noise in CI
            if cfg.coverage.min < 80.0 {
                cfg.coverage.min = 80.0;
            }
            cfg.sast.enabled = true;
            // Code smell rules are optional noise in CI — disable if not already set
            for rule in &[
                "SMELL/LongFunction",
                "SMELL/TooManyParameters",
                "SMELL/DeepNesting",
            ] {
                if !cfg.sast.disabled_rules.iter().any(|r| r == rule) {
                    cfg.sast.disabled_rules.push(rule.to_string());
                }
            }
        }
        other => {
            eprintln!(
                "⚠️  Unknown profile '{}'. Valid profiles: strict, relaxed, ci",
                other
            );
        }
    }
}
