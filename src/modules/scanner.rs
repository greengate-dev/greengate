use crate::utils::{
    config::{SastConfig, ScanConfig},
    files, terminal,
};
use anyhow::{Context, Result};
use ignore::overrides::OverrideBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Built-in secret and PII detection patterns.
/// Organised by cloud provider / service so new entries are easy to locate.
const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    // ── AWS ────────────────────────────────────────────────────────────────
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    (
        "AWS Secret Key",
        r"(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}",
    ),
    // ── Azure ──────────────────────────────────────────────────────────────
    // Full connection string (AccountName + AccountKey together)
    (
        "Azure Storage Connection String",
        r"DefaultEndpointsProtocol=(http|https);AccountName=[^;\n]+;AccountKey=[A-Za-z0-9+/]{86}==",
    ),
    // Shared Access Signature URL – look for the mandatory sv= and sig= params
    (
        "Azure SAS Token",
        r"(?i)sv=20\d{2}-\d{2}-\d{2}[^#\n]*[?&]sig=[A-Za-z0-9%+/]+=*",
    ),
    // ── GCP ────────────────────────────────────────────────────────────────
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    // Service-account JSON files always contain this literal field
    (
        "GCP Service Account Key",
        r#""type"\s*:\s*"service_account""#,
    ),
    // Short-lived OAuth2 access token issued by GCP
    ("GCP OAuth2 Token", r"ya29\.[0-9A-Za-z\-_]+"),
    // ── DigitalOcean ───────────────────────────────────────────────────────
    ("DigitalOcean PAT", r"dop_v1_[a-zA-Z0-9]{64}"),
    // ── Alibaba Cloud ──────────────────────────────────────────────────────
    ("Alibaba Cloud Access Key ID", r"LTAI[A-Za-z0-9]{14,20}"),
    // ── GitHub ─────────────────────────────────────────────────────────────
    ("GitHub PAT (classic)", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub PAT (fine-grained)", r"github_pat_[A-Za-z0-9_]{82}"),
    // ── Slack ──────────────────────────────────────────────────────────────
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    ),
    // ── Stripe ─────────────────────────────────────────────────────────────
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24}"),
    // ── SendGrid ───────────────────────────────────────────────────────────
    (
        "SendGrid API Key",
        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    ),
    // ── Mailgun ────────────────────────────────────────────────────────────
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
    // ── Twilio ─────────────────────────────────────────────────────────────
    // Account SIDs are 34 hex chars prefixed with AC
    ("Twilio Account SID", r"\bAC[a-f0-9]{32}\b"),
    // ── HashiCorp Vault ────────────────────────────────────────────────────
    // Service tokens (vault 1.10+) begin with hvs.
    ("HashiCorp Vault Token", r"hvs\.[A-Za-z0-9_\-]{90,}"),
    // ── Expo / EAS (React Native) ──────────────────────────────────────────
    // Personal Access Tokens and Robot Tokens used with EAS CLI
    ("Expo Access Token", r"expa_[A-Za-z0-9]{40,}"),
    // ── Sentry ─────────────────────────────────────────────────────────────
    // DSN: https://<key>@o<org>.ingest[.us].sentry.io/<project>
    // Leaking allows event flooding (quota exhaustion) and reading event data
    (
        "Sentry DSN",
        r"https://[a-f0-9]{16,32}@o[0-9]+\.ingest(?:\.us)?\.sentry\.io/[0-9]+",
    ),
    // ── Mapbox ─────────────────────────────────────────────────────────────
    // Secret tokens (sk.eyJ...) grant full account/billing access
    // Public tokens (pk.eyJ...) are intentionally client-side — not flagged
    ("Mapbox Secret Token", r"sk\.eyJ[A-Za-z0-9_\-]+"),
    // ── Private keys & generic tokens ─────────────────────────────────────
    (
        "PEM Private Key",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    ),
    // ── PII ────────────────────────────────────────────────────────────────
    ("Generic PII (SSN)", r"\b\d{3}-\d{2}-\d{4}\b"),
    (
        "Generic PII (Email)",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    ),
];

/// Map a rule ID to its severity level: "critical", "high", "medium", or "low".
pub fn severity_for_rule(rule_id: &str) -> &'static str {
    match rule_id {
        "AWS Access Key"
        | "AWS Secret Key"
        | "Azure Storage Connection String"
        | "GCP Service Account Key"
        | "PEM Private Key"
        | "HashiCorp Vault Token"
        | "Stripe Secret Key"
        | "SendGrid API Key"
        | "GitHub PAT (classic)"
        | "GitHub PAT (fine-grained)" => "critical",

        "Google API Key"
        | "GCP OAuth2 Token"
        | "Azure SAS Token"
        | "DigitalOcean PAT"
        | "Alibaba Cloud Access Key ID"
        | "Slack Webhook"
        | "Stripe Publishable Key"
        | "Mailgun API Key"
        | "Twilio Account SID"
        | "Expo Access Token"
        | "Mapbox Secret Token"
        | "JWT Token" => "high",

        "Sentry DSN" => "medium",

        "Generic PII (SSN)" | "Generic PII (Email)" => "low",

        r if r.starts_with("SAST/ChildProcess")
            || r == "SAST/EvalUsage"
            || r == "SAST/FunctionConstructor"
            || r == "SAST/PythonEval"
            || r == "SAST/PythonExec" =>
        {
            "critical"
        }
        r if r == "SAST/PythonPickle"
            || r == "SAST/PythonSubprocessShell"
            || r == "SAST/GoExecCommand"
            || r == "SAST/RustCommandNew" =>
        {
            "high"
        }
        "SAST/RustUnsafeBlock" => "medium",
        r if r == "SAST/RustUnwrap" || r == "SAST/RustExpect" => "low",
        r if r.starts_with("CI/ExpressionInjection")
            || r == "CI/PullRequestTargetWithCheckout" =>
        {
            "critical"
        }
        r if r.starts_with("CI/") => "medium",
        r if r.starts_with("SAST/") => "high",
        r if r.starts_with("SMELL/") => "low",

        _ => "medium", // High-entropy strings, custom patterns
    }
}

pub struct Finding {
    pub path: PathBuf,
    pub rule_id: String,
    pub line: usize,
    /// Set to the short commit hash when this finding came from a `--history` scan.
    pub commit: Option<String>,
    /// Severity level: "critical", "high", "medium", or "low"
    pub severity: String,
    /// Git blame info (author + commit), populated only with `--blame` flag
    pub blame: Option<String>,
}

/// Convenience constructor that auto-derives severity from the rule ID.
pub(crate) fn make_finding(
    path: PathBuf,
    rule_id: String,
    line: usize,
    commit: Option<String>,
) -> Finding {
    let severity = severity_for_rule(&rule_id).to_string();
    Finding {
        path,
        rule_id,
        line,
        commit,
        severity,
        blame: None,
    }
}

#[derive(Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    /// JUnit XML — consumed by most CI dashboards (Jenkins, GitLab, etc.)
    Junit,
    /// GitLab Security Scanner JSON — uploads to GitLab's vulnerability tab
    Gitlab,
}

pub enum DiffMode {
    Staged,
    Since(String),
    /// Scan the entire git commit history via `git log --all -p`.
    History,
}

pub struct ScanOpts<'a> {
    pub format: OutputFormat,
    pub diff: Option<DiffMode>,
    pub config: &'a ScanConfig,
    pub sast_config: &'a SastConfig,
}

/// Returns true for files handled by the SAST scanner (JS/TS, Python, Go, Rust).
pub(crate) fn is_sast_file(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ts" | "tsx" | "js" | "jsx" | "py" | "go" | "rs")
    )
}

// ── Entropy detection ─────────────────────────────────────────────────────────

enum CharsetKind {
    Base64Like,
    HexLike,
    Other,
}

/// Compute Shannon entropy H = -Σ p(x)·log₂(p(x)) for an ASCII/UTF-8 string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Classify a token as base64-like, hex-only, or neither.
fn classify_charset(token: &str) -> CharsetKind {
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return CharsetKind::HexLike;
    }
    if token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'))
    {
        return CharsetKind::Base64Like;
    }
    CharsetKind::Other
}

/// Substrings that mark a value as a documented example, a template placeholder,
/// or a test fixture rather than a live credential. Matched case-insensitively
/// against the secret value itself (not the surrounding line), so a real key that
/// merely sits near the word "example" is unaffected. Covers the canonical AWS
/// example key `AKIAIOSFODNN7EXAMPLE`, `YOUR_API_KEY_HERE`, `changeme`, etc.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "example",
    "changeme",
    "placeholder",
    "your_",
    "yourkey",
    "dummy",
    "sample",
    "notreal",
    "redacted",
    "xxxxxx",
];

/// Credential prefixes that are safe by construction — e.g. Stripe **test** keys,
/// which are explicitly non-live and safe to commit. Matched case-insensitively
/// against the start of the value.
const SAFE_PREFIXES: &[&str] = &["sk_test_", "pk_test_", "rk_test_"];

/// True when a matched secret value or high-entropy token is a known false
/// positive: a documented example, a template placeholder, or a by-construction
/// safe test key. Applied to BOTH regex and entropy findings so that, e.g., the
/// AWS example key in documentation is not reported.
pub(crate) fn is_known_false_positive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    SAFE_PREFIXES.iter().any(|p| lower.starts_with(p))
        || PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m))
}

/// True when a high-entropy token matches a well-known **non-secret** shape: a
/// content hash / git object id, a package integrity digest, or base64 asset data
/// from a data URI. These are high-entropy by nature but never credentials, and
/// are the dominant source of entropy false positives. Regex secret patterns are
/// unaffected — this only gates the entropy heuristic.
fn is_entropy_noise(token: &str, line: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    // Subresource / package-manager integrity digests: "sha512-…", "md5-…".
    if ["sha1-", "sha256-", "sha384-", "sha512-", "md5-"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return true;
    }
    // Content hashes / git object ids: pure hex of a canonical digest length
    // (SHA-1 = 40, SHA-256 = 64, SHA-512 = 128). Length 32 (md5-shaped) is left
    // detectable, since several API keys are 32 hex chars.
    if token.chars().all(|c| c.is_ascii_hexdigit()) && matches!(token.len(), 40 | 64 | 128) {
        return true;
    }
    // base64 payload of a data URI, e.g. `url(data:image/png;base64,iVBOR…)`.
    if line.contains("base64,") {
        return true;
    }
    false
}

/// True when a line opens or lies inside a PEM key block. Used to suppress the
/// entropy heuristic on wrapped base64 key bodies (public keys, and the body of a
/// private key whose `-----BEGIN … PRIVATE KEY-----` header the regex already
/// caught) — without suppressing the header match itself.
pub(crate) fn is_pem_boundary(line: &str) -> (bool, bool) {
    let t = line.trim_start();
    let begin = t.starts_with("-----BEGIN") && t.contains("KEY-----");
    let end = t.starts_with("-----END") && t.contains("KEY-----");
    (begin, end)
}

/// Check one source line for high-entropy tokens that may be unrecognised secrets.
/// Returns rule IDs for each flagged token (may be empty).
pub(crate) fn check_entropy(line: &str, config: &ScanConfig) -> Vec<String> {
    if !config.entropy {
        return Vec::new();
    }
    line.split(['=', ':', '"', '\'', ' ', '\t', ',', ';'])
        .filter(|s| s.len() >= config.entropy_min_length)
        .filter(|token| !is_entropy_noise(token, line) && !is_known_false_positive(token))
        .flat_map(|token| {
            let e = shannon_entropy(token);
            match classify_charset(token) {
                CharsetKind::Base64Like if e > config.entropy_threshold => {
                    vec!["High Entropy String (base64)".to_string()]
                }
                CharsetKind::HexLike if e > 3.5 && token.len() >= 32 => {
                    vec!["High Entropy String (hex)".to_string()]
                }
                _ => vec![],
            }
        })
        .collect()
}

// ── Git history scan ──────────────────────────────────────────────────────────

/// Parse the output of `git log --all -p --no-color` and return every *added* line
/// as a tuple of `(commit_hash, file_path, line_content, new_file_line_number)`.
///
/// Only `+` prefix lines are collected; context (` `) and removed (`-`) lines are
/// skipped. The new-file line counter advances on both added and context lines so
/// that line numbers are accurate relative to the post-commit file.
fn parse_git_log_patch(stdout: &str) -> Vec<(String, PathBuf, String, usize)> {
    let mut results: Vec<(String, PathBuf, String, usize)> = Vec::new();
    let mut current_commit = String::new();
    let mut current_path: Option<PathBuf> = None;
    let mut hunk_line_no: usize = 0;

    for raw_line in stdout.lines() {
        if let Some(hash) = raw_line.strip_prefix("commit ") {
            // Only take the first word (the actual hash, before any decorations)
            current_commit = hash.split_whitespace().next().unwrap_or("").to_string();
            current_path = None;
            hunk_line_no = 0;
            continue;
        }

        // "diff --git a/path/to/file b/path/to/file"
        if raw_line.starts_with("diff --git ") {
            if let Some(b_part) = raw_line.split(" b/").nth(1) {
                current_path = Some(PathBuf::from(b_part.trim()));
            }
            hunk_line_no = 0;
            continue;
        }

        // "@@ -old_start,count +new_start,count @@"
        if raw_line.starts_with("@@ ") {
            // Extract the "+new_start" portion
            if let Some(after_plus) = raw_line.split('+').nth(1) {
                let num_str = after_plus.split([',', ' ']).next().unwrap_or("1");
                hunk_line_no = num_str.parse().unwrap_or(1);
                // hunk_line_no now points to the first line of the hunk in the new file;
                // we'll increment BEFORE recording or after context lines.
                // Pre-decrement so the first line increments back to new_start.
                hunk_line_no = hunk_line_no.saturating_sub(1);
            }
            continue;
        }

        if let Some(ref path) = current_path {
            if raw_line.starts_with("+++") || raw_line.starts_with("---") {
                // Diff file header lines — skip, don't advance counter
                continue;
            }
            if let Some(stripped) = raw_line.strip_prefix('+') {
                hunk_line_no += 1;
                let content = stripped.to_string();
                results.push((current_commit.clone(), path.clone(), content, hunk_line_no));
            } else if raw_line.starts_with(' ') {
                // Context line — advance new-file counter but don't collect
                hunk_line_no += 1;
            }
            // '-' lines (removed) do not belong to the new file — don't advance counter
        }
    }

    results
}

/// Scan the full git commit history for secrets in added lines.
fn run_history_scan(
    opts: &ScanOpts<'_>,
    all_patterns: &[(String, Regex)],
) -> Result<Vec<Finding>> {
    let is_text = matches!(opts.format, OutputFormat::Text);

    if is_text {
        terminal::info("Scanning full git history (this may take a while on large repos)...");
    }

    let output = Command::new("git")
        .args(["log", "--all", "-p", "--no-color"])
        .output()
        .context("Failed to run git log — is this a git repository?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git log failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git log output is not valid UTF-8")?;

    let added_lines = parse_git_log_patch(&stdout);
    let total = added_lines.len() as u64;

    if is_text {
        terminal::info(&format!("Scanning {} added lines across history...", total));
    }

    let bar = if is_text {
        let b = terminal::create_progress_bar(total);
        b.set_message("Scanning history...");
        Some(b)
    } else {
        None
    };

    let findings: Vec<Finding> = added_lines
        .par_iter()
        .flat_map(|(commit, path, line, line_no)| {
            let mut hits: Vec<Finding> = Vec::new();

            // Feature 3: inline suppression
            if line.contains("greengate: ignore") {
                if let Some(b) = &bar {
                    b.inc(1);
                }
                return hits;
            }

            for (name, regex) in all_patterns {
                if let Some(m) = regex.find(line) {
                    if is_known_false_positive(m.as_str()) {
                        continue;
                    }
                    hits.push(make_finding(
                        path.clone(),
                        name.clone(),
                        *line_no,
                        Some(commit.clone()),
                    ));
                }
            }
            for rule_id in check_entropy(line, opts.config) {
                hits.push(make_finding(
                    path.clone(),
                    rule_id,
                    *line_no,
                    Some(commit.clone()),
                ));
            }

            if let Some(b) = &bar {
                b.inc(1);
            }
            hits
        })
        .collect();

    if let Some(b) = bar {
        b.finish_with_message("History scan complete.");
    }

    Ok(findings)
}

// ── Pattern compilation ───────────────────────────────────────────────────────

fn compile_patterns(opts: &ScanOpts<'_>) -> Result<Vec<(String, Regex)>> {
    let mut patterns: Vec<(String, Regex)> = BUILTIN_PATTERNS
        .iter()
        .map(|(name, pat)| {
            Regex::new(pat)
                .with_context(|| format!("Invalid built-in pattern for '{}'", name))
                .map(|re| (name.to_string(), re))
        })
        .collect::<Result<Vec<_>>>()?;

    for ep in &opts.config.extra_patterns {
        let re = Regex::new(&ep.regex)
            .with_context(|| format!("Invalid extra_pattern regex for '{}'", ep.name))?;
        patterns.push((ep.name.clone(), re));
    }

    Ok(patterns)
}

// ── Diff helpers ──────────────────────────────────────────────────────────────

fn get_changed_files(mode: &DiffMode) -> Result<Vec<PathBuf>> {
    let args: &[&str] = match mode {
        DiffMode::Staged => &["diff", "--cached", "--name-only"],
        DiffMode::Since(commit) => &["diff", commit.as_str(), "--name-only"],
        DiffMode::History => unreachable!("History mode is handled before get_changed_files"),
    };
    let output = Command::new("git")
        .args(args)
        .output()
        .context("Failed to run git — is this a git repository?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .collect())
}

// ── File scan ─────────────────────────────────────────────────────────────────

/// Collect all files to scan (honoring diff mode and exclusions) into a Vec.
fn collect_scan_files(
    opts: &ScanOpts<'_>,
    excludes: &Option<ignore::overrides::Override>,
    is_text: bool,
) -> Result<Vec<PathBuf>> {
    let files: Vec<PathBuf> = match &opts.diff {
        Some(mode @ (DiffMode::Staged | DiffMode::Since(_))) => {
            if is_text {
                terminal::info("Diff mode: scanning only changed files...");
            }
            get_changed_files(mode)?
        }
        None => {
            let walker = files::get_walker("./");
            walker
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
                .map(|e| e.into_path())
                .collect()
        }
        Some(DiffMode::History) => unreachable!("History mode handled before collect_scan_files"),
    };

    Ok(files
        .into_iter()
        .filter(|p| !is_excluded(p, excludes))
        .collect())
}

/// Regex + entropy scan over a pre-built file list.
/// When SAST is enabled, JS/TS files are skipped here — the SAST module handles them.
fn run_regex_scan(
    opts: &ScanOpts<'_>,
    all_patterns: &[(String, Regex)],
    files: &[PathBuf],
    is_text: bool,
) -> Vec<Finding> {
    // When SAST is enabled, skip JS/TS files (SAST Phase 1 handles them with
    // context-aware, string-literal-scoped detection — fewer false positives).
    let scan_files: Vec<&PathBuf> = if opts.sast_config.enabled {
        files.iter().filter(|p| !is_sast_file(p)).collect()
    } else {
        files.iter().collect()
    };

    let bar = if is_text {
        Some(terminal::create_progress_bar(scan_files.len() as u64))
    } else {
        None
    };

    let findings: Vec<Finding> = scan_files
        .par_iter()
        .flat_map(|path| {
            let mut file_findings: Vec<Finding> = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                let mut suppress_next = false;
                let mut in_pem_block = false;
                for (line_no, line) in content.lines().enumerate() {
                    if line.contains("greengate: ignore") {
                        // A standalone comment line (no other content) suppresses the NEXT
                        // line. An inline trailing comment suppresses only THIS line.
                        let is_standalone = line
                            .trim()
                            .trim_start_matches("//")
                            .trim_start_matches('#')
                            .trim()
                            .starts_with("greengate: ignore");
                        suppress_next = is_standalone;
                        continue;
                    }
                    if suppress_next {
                        suppress_next = false;
                        continue;
                    }
                    let (pem_begin, pem_end) = is_pem_boundary(line);
                    if pem_begin {
                        in_pem_block = true;
                    }
                    for (name, regex) in all_patterns {
                        if let Some(m) = regex.find(line) {
                            if is_known_false_positive(m.as_str()) {
                                continue;
                            }
                            file_findings.push(make_finding(
                                path.to_path_buf(),
                                name.clone(),
                                line_no + 1,
                                None,
                            ));
                        }
                    }
                    // Skip the entropy heuristic on PEM key bodies: the header (if a
                    // private key) is already caught by the regex above, and the wrapped
                    // base64 body is not an independent secret.
                    if !in_pem_block {
                        for rule_id in check_entropy(line, opts.config) {
                            file_findings.push(make_finding(
                                path.to_path_buf(),
                                rule_id,
                                line_no + 1,
                                None,
                            ));
                        }
                    }
                    if pem_end {
                        in_pem_block = false;
                    }
                }
            }
            if let Some(b) = &bar {
                b.inc(1);
            }
            file_findings
        })
        .collect();

    if let Some(b) = &bar {
        b.finish_with_message("Scan complete.");
    }

    findings
}

// ── Output helpers ────────────────────────────────────────────────────────────

fn output_json(findings: &[Finding]) -> Result<()> {
    let out = json!({
        "total": findings.len(),
        "findings": findings.iter().map(|f| {
            let mut entry = json!({
                "rule":     f.rule_id,
                "severity": f.severity,
                "file":     f.path.to_string_lossy(),
                "line":     f.line,
            });
            if let Some(ref hash) = f.commit {
                entry["commit"] = json!(hash);
            }
            if let Some(ref blame) = f.blame {
                entry["blame"] = json!(blame);
            }
            entry
        }).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

// ── Auto-fix: in-place secret redaction ──────────────────────────────────────

/// Redact secrets detected by the scan in the source files.
///
/// For each regex-matched finding the pattern is re-run on the flagged line and
/// the matched substring is replaced with `<REDACTED>`.  High-entropy token
/// findings are handled by re-running the entropy check and replacing the first
/// flagged token.  SAST / structural findings cannot be auto-redacted and are
/// reported as requiring manual attention.
///
/// When `dry_run` is true the changes are printed but not written to disk.
pub fn apply_scan_fixes(findings: &[Finding], opts: &ScanOpts<'_>, dry_run: bool) -> Result<()> {
    use std::collections::HashMap;

    // Recompile patterns so we can match the exact substring to replace.
    let all_patterns = compile_patterns(opts)?;

    // Only fix filesystem findings — history/commit findings cannot be rewritten.
    let fixable: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.commit.is_none() && !f.path.as_os_str().is_empty())
        .collect();

    if fixable.is_empty() {
        terminal::info(
            "No fixable findings (history findings cannot be auto-redacted; fix them with `git filter-repo`).",
        );
        return Ok(());
    }

    // Group by file path.
    let mut by_file: HashMap<std::path::PathBuf, Vec<&Finding>> = HashMap::new();
    for f in &fixable {
        by_file.entry(f.path.clone()).or_default().push(f);
    }

    let prefix = if dry_run { "[dry-run] " } else { "" };
    let mut total_redacted = 0usize;
    let mut total_skipped = 0usize;

    let mut paths: Vec<std::path::PathBuf> = by_file.keys().cloned().collect();
    paths.sort();

    eprintln!();
    for path in &paths {
        let file_findings = &by_file[path];
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ⚠️  Cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let trailing_newline = content.ends_with('\n');
        let mut file_redacted = 0usize;

        for f in file_findings.iter() {
            let idx = f.line.saturating_sub(1);
            if idx >= lines.len() {
                continue;
            }

            let original = lines[idx].clone();
            let mut redacted = original.clone();

            // Regex findings: find the exact matching pattern and replace the match.
            for (name, re) in &all_patterns {
                if *name == f.rule_id {
                    if let Some(m) = re.find(&redacted) {
                        redacted = format!(
                            "{}{}{}",
                            &redacted[..m.start()],
                            "<REDACTED>",
                            &redacted[m.end()..]
                        );
                    }
                    break;
                }
            }

            // Entropy findings: re-locate the high-entropy token and replace it.
            if redacted == original && f.rule_id.contains("High Entropy") {
                for token in original.split(['=', ':', '"', '\'', ' ', '\t', ',', ';']) {
                    if token.len() < opts.config.entropy_min_length {
                        continue;
                    }
                    let e = shannon_entropy(token);
                    let is_flagged = match classify_charset(token) {
                        CharsetKind::Base64Like => e > opts.config.entropy_threshold,
                        CharsetKind::HexLike => e > 3.5 && token.len() >= 32,
                        CharsetKind::Other => false,
                    };
                    if is_flagged {
                        redacted = original.replacen(token, "<REDACTED>", 1);
                        break;
                    }
                }
            }

            if redacted != original {
                eprintln!("  {}{}:{}  [{}]", prefix, path.display(), f.line, f.rule_id);
                eprintln!("    - {}", original.trim_start());
                eprintln!("    + {}", redacted.trim_start());
                lines[idx] = redacted;
                file_redacted += 1;
                total_redacted += 1;
            } else if f.rule_id.starts_with("SAST/") || f.rule_id.starts_with("SMELL/") {
                eprintln!(
                    "  ⚠️  {}:{} [{}] — requires manual fix (structural/code finding)",
                    path.display(),
                    f.line,
                    f.rule_id
                );
                total_skipped += 1;
            }
        }

        if !dry_run && file_redacted > 0 {
            let new_content = lines.join("\n");
            let final_content = if trailing_newline {
                format!("{}\n", new_content)
            } else {
                new_content
            };
            fs::write(path, final_content)?;
        }
    }

    eprintln!();
    if dry_run {
        terminal::info(&format!(
            "[dry-run] {} finding(s) would be redacted across {} file(s); {} require manual fixes. \
             Re-run without --dry-run to apply.",
            total_redacted,
            paths.len(),
            total_skipped,
        ));
    } else if total_redacted > 0 {
        terminal::success(&format!(
            "{} finding(s) redacted across {} file(s). Run `git diff` to review before committing.",
            total_redacted,
            paths.len(),
        ));
        if total_skipped > 0 {
            terminal::warn(&format!(
                "{} SAST/structural finding(s) still require manual remediation.",
                total_skipped
            ));
        }
    }

    Ok(())
}

fn output_sarif(findings: &[Finding]) -> Result<()> {
    let mut seen_rules = std::collections::BTreeSet::new();
    for f in findings {
        seen_rules.insert(f.rule_id.clone());
    }
    let rules: Vec<_> = seen_rules
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": format!("{} detected", id) },
                "helpUri": "https://github.com/greengate-dev/greengate"
            })
        })
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let msg = match &f.commit {
                Some(h) => format!("{} found (commit {})", f.rule_id, &h[..8.min(h.len())]),
                None => format!("{} found", f.rule_id),
            };
            json!({
                "ruleId": f.rule_id,
                "level": sarif_level(&f.severity),
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.path.to_string_lossy(),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "greengate",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/greengate-dev/greengate",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn output_junit(findings: &[Finding]) -> Result<()> {
    let n = findings.len();
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"greengate\" tests=\"{n}\" failures=\"{n}\" errors=\"0\" time=\"0\">\n"
    ));
    xml.push_str(&format!(
        "  <testsuite name=\"secret-and-sast-scan\" tests=\"{n}\" failures=\"{n}\" errors=\"0\" time=\"0\">\n"
    ));
    for f in findings {
        let file = f.path.to_string_lossy();
        let name = xml_escape(&format!("[{}] {}:{}", f.rule_id, file, f.line));
        let classname = xml_escape(&file);
        let msg = xml_escape(&format!(
            "{} detected at line {} [{}]",
            f.rule_id, f.line, f.severity
        ));
        let body = xml_escape(&format!(
            "[{}] {}:{} | severity: {}",
            f.rule_id, file, f.line, f.severity
        ));
        xml.push_str(&format!(
            "    <testcase name=\"{name}\" classname=\"{classname}\">\n"
        ));
        xml.push_str(&format!(
            "      <failure message=\"{msg}\" type=\"{sev}\">{body}</failure>\n",
            sev = f.severity
        ));
        xml.push_str("    </testcase>\n");
    }
    xml.push_str("  </testsuite>\n</testsuites>\n");
    println!("{}", xml);
    Ok(())
}

fn output_gitlab(findings: &[Finding]) -> Result<()> {
    let gitlab_severity = |s: &str| match s {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Info",
    };

    let vulns: Vec<_> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            json!({
                "id": format!("greengate-{}", i),
                "category": "sast",
                "name": f.rule_id,
                "description": format!("{} detected", f.rule_id),
                "severity": gitlab_severity(&f.severity),
                "confidence": "High",
                "scanner": { "id": "greengate", "name": "GreenGate" },
                "location": {
                    "file": f.path.to_string_lossy(),
                    "start_line": f.line,
                    "end_line": f.line
                },
                "identifiers": [{
                    "type": "greengate_rule",
                    "name": f.rule_id,
                    "value": f.rule_id
                }]
            })
        })
        .collect();

    let report = json!({
        "version": "15.0.6",
        "vulnerabilities": vulns,
        "scan": {
            "scanner": {
                "id": "greengate",
                "name": "GreenGate",
                "version": env!("CARGO_PKG_VERSION")
            },
            "type": "sast",
            "status": "success"
        }
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn emit_findings(findings: &[Finding], format: &OutputFormat) -> Result<()> {
    if findings.is_empty() {
        match format {
            OutputFormat::Text => terminal::success("No secrets or PII found."),
            OutputFormat::Json => output_json(findings)?,
            OutputFormat::Sarif => output_sarif(findings)?,
            OutputFormat::Junit => output_junit(findings)?,
            OutputFormat::Gitlab => output_gitlab(findings)?,
        }
        return Ok(());
    }

    match format {
        OutputFormat::Text => {
            terminal::warn(&format!("Found {} potential issue(s):", findings.len()));
            for f in findings {
                let commit_note = f
                    .commit
                    .as_deref()
                    .map(|h| format!(" (commit {})", &h[..8.min(h.len())]))
                    .unwrap_or_default();
                let blame_note = f
                    .blame
                    .as_deref()
                    .map(|b| format!(" — {}", b))
                    .unwrap_or_default();
                eprintln!(
                    "  - [{}] [{}] {}:{}{}{}",
                    f.severity.to_uppercase(),
                    f.rule_id,
                    f.path.display(),
                    f.line,
                    commit_note,
                    blame_note
                );
            }
        }
        OutputFormat::Json => output_json(findings)?,
        OutputFormat::Sarif => output_sarif(findings)?,
        OutputFormat::Junit => output_junit(findings)?,
        OutputFormat::Gitlab => output_gitlab(findings)?,
    }

    anyhow::bail!(
        "Scan failed: {} secret(s)/PII found. Review the findings above.",
        findings.len()
    );
}

// ── Git blame enrichment ──────────────────────────────────────────────────────

/// Run `git blame` for each finding and populate `finding.blame` with a short
/// summary: `"Author Name <email> @ abc12345"`. Findings for which blame cannot
/// be determined are left with `blame: None`.
pub fn enrich_with_blame(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        if f.path.as_os_str().is_empty() {
            continue;
        }
        let output = Command::new("git")
            .args([
                "blame",
                "-L",
                &format!("{},{}", f.line, f.line),
                "--porcelain",
                "--",
                &f.path.to_string_lossy(),
            ])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut commit = String::new();
            let mut author = String::new();
            let mut email = String::new();
            for line in text.lines() {
                if commit.is_empty()
                    && line.len() >= 8
                    && line.chars().next().is_some_and(|c| c.is_ascii_hexdigit())
                {
                    commit = line
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(8)
                        .collect();
                } else if let Some(rest) = line.strip_prefix("author ") {
                    author = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix("author-mail ") {
                    email = rest.trim().trim_matches(['<', '>']).to_string();
                }
            }
            if !author.is_empty() {
                f.blame = Some(format!("{} <{}> @ {}", author, email, commit));
            }
        }
    }
}

// ── Main entry ────────────────────────────────────────────────────────────────

/// Collect all findings without emitting output. Used by `run_scan` and
/// the GitHub annotation path in `main.rs`.
pub fn collect_findings(opts: &ScanOpts<'_>) -> Result<Vec<Finding>> {
    let is_text = matches!(opts.format, OutputFormat::Text);

    let all_patterns = compile_patterns(opts)?;
    let excludes = build_excludes(&opts.config.exclude_patterns)?;

    if let Some(DiffMode::History) = &opts.diff {
        return run_history_scan(opts, &all_patterns);
    }

    // Collect all files once — shared between regex scan and SAST scan.
    let files = collect_scan_files(opts, &excludes, is_text)?;

    // Regex + entropy scan (skips JS/TS files when SAST is enabled).
    let mut all_findings = run_regex_scan(opts, &all_patterns, &files, is_text);

    // SAST scan: string-literal-scoped secrets + dangerous patterns for JS/TS files.
    if opts.sast_config.enabled {
        if is_text {
            terminal::info("Running SAST checks...");
        }
        let sast_findings = crate::modules::sast::run_sast_scan(
            &files,
            opts.sast_config,
            &all_patterns,
            opts.config,
            is_text,
        )?;
        all_findings.extend(sast_findings);
    }

    Ok(all_findings)
}

// ── Image-scan helpers (public re-exports for image_scan module) ──────────────

/// Compile built-in + extra patterns without a full ScanOpts.
/// Used by `image_scan` to reuse the same pattern set.
pub fn compile_patterns_for_scan(cfg: &ScanConfig) -> Result<Vec<(String, Regex)>> {
    let mut patterns: Vec<(String, Regex)> = BUILTIN_PATTERNS
        .iter()
        .map(|(name, pat)| {
            Regex::new(pat)
                .with_context(|| format!("Invalid built-in pattern for '{}'", name))
                .map(|re| (name.to_string(), re))
        })
        .collect::<Result<Vec<_>>>()?;
    for ep in &cfg.extra_patterns {
        let re = Regex::new(&ep.regex)
            .with_context(|| format!("Invalid extra_pattern regex for '{}'", ep.name))?;
        patterns.push((ep.name.clone(), re));
    }
    Ok(patterns)
}

/// Scan a raw text string against pre-compiled patterns + entropy rules.
/// `path_label` is used as the `path` field on returned `Finding`s.
pub fn scan_text_content(
    path_label: &std::path::Path,
    content: &str,
    patterns: &[(String, Regex)],
    cfg: &ScanConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_pem_block = false;
    for (line_no, line) in content.lines().enumerate() {
        let (pem_begin, pem_end) = is_pem_boundary(line);
        if pem_begin {
            in_pem_block = true;
        }
        for (name, regex) in patterns {
            if let Some(m) = regex.find(line) {
                if is_known_false_positive(m.as_str()) {
                    continue;
                }
                findings.push(make_finding(
                    path_label.to_path_buf(),
                    name.clone(),
                    line_no + 1,
                    None,
                ));
            }
        }
        if !in_pem_block {
            for rule_id in check_entropy(line, cfg) {
                findings.push(make_finding(
                    path_label.to_path_buf(),
                    rule_id,
                    line_no + 1,
                    None,
                ));
            }
        }
        if pem_end {
            in_pem_block = false;
        }
    }
    findings
}

pub fn run_scan(opts: ScanOpts<'_>) -> Result<()> {
    let is_text = matches!(opts.format, OutputFormat::Text);
    if is_text {
        terminal::info("Starting secret and PII scan...");
    }
    let findings = collect_findings(&opts)?;
    emit_findings(&findings, &opts.format)
}

// ── Exclude helpers ───────────────────────────────────────────────────────────

fn build_excludes(patterns: &[String]) -> Result<Option<ignore::overrides::Override>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = OverrideBuilder::new(".");
    for pat in patterns {
        builder
            .add(&format!("!{}", pat))
            .with_context(|| format!("Invalid exclude pattern: {}", pat))?;
    }
    Ok(Some(builder.build()?))
}

fn is_excluded(path: &PathBuf, excludes: &Option<ignore::overrides::Override>) -> bool {
    if let Some(ov) = excludes {
        ov.matched(path, false).is_ignore()
    } else {
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_builtins() -> Vec<(String, Regex)> {
        BUILTIN_PATTERNS
            .iter()
            .map(|(name, pattern)| {
                let re = Regex::new(pattern)
                    .unwrap_or_else(|e| panic!("Pattern '{}' failed to compile: {}", name, e));
                (name.to_string(), re)
            })
            .collect()
    }

    fn default_scan_config() -> ScanConfig {
        ScanConfig::default()
    }

    // ── Pattern compilation ─────────────────────────────────────────────────

    #[test]
    fn test_all_patterns_compile() {
        compile_builtins();
    }

    #[test]
    fn test_aws_access_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "AWS Access Key")
            .unwrap();
        assert!(re.is_match("AKIAIOSFODNN7EXAMPLE123"));
        assert!(re.is_match("export KEY=AKIAIOSFODNN7EXAMPLEKEY1"));
    }

    #[test]
    fn test_aws_access_key_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "AWS Access Key")
            .unwrap();
        assert!(!re.is_match("some random text without keys"));
        assert!(!re.is_match("AKIA_SHORT"));
    }

    #[test]
    fn test_ssn_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("SSN")).unwrap();
        assert!(re.is_match("ssn: 123-45-6789"));
        assert!(re.is_match("SSN=987-65-4321"));
    }

    #[test]
    fn test_ssn_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("SSN")).unwrap();
        assert!(!re.is_match("123-456-7890")); // phone number
        assert!(!re.is_match("1234-56-789"));
    }

    #[test]
    fn test_email_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("Email")).unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("contact: admin@company.org"));
    }

    #[test]
    fn test_email_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("Email")).unwrap();
        assert!(!re.is_match("not-an-email"));
        assert!(!re.is_match("missing@tld"));
    }

    #[test]
    fn test_github_pat_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GitHub PAT (classic)")
            .unwrap();
        assert!(re.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"));
    }

    #[test]
    fn test_stripe_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Stripe Secret Key")
            .unwrap();
        // Split across concat so no single source literal triggers GitHub push-protection.
        assert!(re.is_match(&["sk_live_", "abcdefghijklmnopqrstuvwx"].concat()));
    }

    #[test]
    fn test_pem_private_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "PEM Private Key")
            .unwrap();
        assert!(re.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(re.is_match("-----BEGIN PRIVATE KEY-----"));
    }

    // ── Azure ──────────────────────────────────────────────────────────────

    #[test]
    fn test_azure_connection_string_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure Storage Connection String")
            .unwrap();
        let sample = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;\
            AccountKey=dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dA==";
        assert!(re.is_match(sample));
    }

    #[test]
    fn test_azure_connection_string_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure Storage Connection String")
            .unwrap();
        assert!(!re.is_match("some random string with no azure connection data"));
    }

    #[test]
    fn test_azure_sas_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure SAS Token")
            .unwrap();
        let sample = "https://account.blob.core.windows.net/container?sv=2023-01-03&ss=b&srt=sco\
             &sp=rwdlacupitfx&se=2025-01-01T00:00:00Z&st=2024-01-01T00:00:00Z\
             &spr=https&sig=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==";
        assert!(re.is_match(sample));
    }

    // ── GCP ────────────────────────────────────────────────────────────────

    #[test]
    fn test_gcp_service_account_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP Service Account Key")
            .unwrap();
        assert!(re.is_match(r#"{ "type": "service_account", "project_id": "myproj" }"#));
        assert!(re.is_match(r#""type":"service_account""#));
    }

    #[test]
    fn test_gcp_service_account_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP Service Account Key")
            .unwrap();
        assert!(!re.is_match(r#""type": "user""#));
        assert!(!re.is_match("some unrelated JSON"));
    }

    #[test]
    fn test_gcp_oauth2_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP OAuth2 Token")
            .unwrap();
        assert!(re.is_match("ya29.A0ARrdaM-validlookingtokenfortest1234567890abc"));
    }

    // ── DigitalOcean ───────────────────────────────────────────────────────

    #[test]
    fn test_digitalocean_pat_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "DigitalOcean PAT")
            .unwrap();
        let token = format!("dop_v1_{}", "a".repeat(64));
        assert!(re.is_match(&token));
    }

    #[test]
    fn test_digitalocean_pat_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "DigitalOcean PAT")
            .unwrap();
        assert!(!re.is_match("dop_v1_tooshort"));
    }

    // ── Alibaba Cloud ──────────────────────────────────────────────────────

    #[test]
    fn test_alibaba_access_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Alibaba Cloud Access Key ID")
            .unwrap();
        assert!(re.is_match("LTAI5tFakeAlibaba1234567"));
        assert!(re.is_match("access_key=LTAIAnotherFakeKey12345"));
    }

    // ── SendGrid ───────────────────────────────────────────────────────────

    #[test]
    fn test_sendgrid_api_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "SendGrid API Key")
            .unwrap();
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
        assert!(re.is_match(&key));
    }

    // ── Twilio ─────────────────────────────────────────────────────────────

    #[test]
    fn test_twilio_sid_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Twilio Account SID")
            .unwrap();
        // Twilio SIDs are AC + exactly 32 lowercase hex chars = 34 chars total.
        // Split across concat so no single source literal triggers GitHub push-protection.
        assert!(re.is_match(&["AC", "abcdef1234567890abcdef1234567890"].concat()));
    }

    #[test]
    fn test_twilio_sid_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Twilio Account SID")
            .unwrap();
        assert!(!re.is_match("ACXYZ_not_a_real_sid_because_not_hex"));
    }

    // ── HashiCorp Vault ────────────────────────────────────────────────────

    #[test]
    fn test_vault_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "HashiCorp Vault Token")
            .unwrap();
        let token = format!("hvs.{}", "A".repeat(92));
        assert!(re.is_match(&token));
    }

    #[test]
    fn test_vault_token_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "HashiCorp Vault Token")
            .unwrap();
        assert!(!re.is_match("hvs.tooshort"));
    }

    // ── Feature 3: Inline suppression ──────────────────────────────────────

    #[test]
    fn test_suppression_marker_detected() {
        let line = "AWS_KEY=AKIAIOSFODNN7EXAMPLEKEY1  # greengate: ignore";
        assert!(line.contains("greengate: ignore"));
    }

    // ── Feature 1: Shannon entropy ─────────────────────────────────────────

    #[test]
    fn test_shannon_entropy_high() {
        // Mixed-case alphanumeric has high entropy
        let s = "aB3dEfGhIjKlMnOpQrSt";
        assert!(shannon_entropy(s) > 3.5);
    }

    #[test]
    fn test_shannon_entropy_low() {
        // Repeated character → near-zero entropy
        let s = "aaaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(s) < 0.1);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_check_entropy_base64_flagged() {
        let config = default_scan_config();
        // 32-char token composed of base64-like chars with high variance
        let line = "SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345";
        let hits = check_entropy(line, &config);
        assert!(
            hits.iter().any(|r| r.contains("base64")),
            "expected base64 entropy hit, got: {:?}",
            hits
        );
    }

    #[test]
    fn test_check_entropy_hex_flagged() {
        let config = default_scan_config();
        // 32-char hex string with good entropy
        let line = "hash=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let hits = check_entropy(line, &config);
        assert!(
            hits.iter().any(|r| r.contains("hex")),
            "expected hex entropy hit, got: {:?}",
            hits
        );
    }

    // ── Precision: known false positives & entropy noise ───────────────────

    #[test]
    fn test_allowlist_documented_example_key() {
        // The canonical AWS example key must not be reported, even though it
        // matches the AWS Access Key regex shape.
        assert!(is_known_false_positive("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_allowlist_placeholders_and_test_keys() {
        assert!(is_known_false_positive("YOUR_API_KEY_HERE"));
        assert!(is_known_false_positive("changeme"));
        // Literals are split so the source never contains a contiguous
        // provider-format key (avoids GitHub push-protection false positives).
        assert!(is_known_false_positive(
            &["sk_", "test_abcdefghij0123456789ABCD"].concat()
        ));
        // A real-looking live key is NOT allowlisted.
        assert!(!is_known_false_positive(
            &["sk_", "live_abcdefghij0123456789ABCD"].concat()
        ));
        assert!(!is_known_false_positive("AKIA3KGXQW7ZP2MTV9CD"));
    }

    #[test]
    fn test_entropy_noise_skips_git_sha_and_integrity() {
        let config = default_scan_config();
        // 40-char git object id — high-entropy hex, but not a secret.
        assert!(check_entropy("2eed506f9c3b1a4d7e8f0a1b2c3d4e5f6a7b8c9d", &config).is_empty());
        // npm integrity digest.
        assert!(
            check_entropy(
                "lodash sha512-abcdefghij0123456789ABCDEFGHIJ0123456789xyzAaBb==",
                &config
            )
            .is_empty()
        );
    }

    #[test]
    fn test_entropy_noise_skips_data_uri() {
        let config = default_scan_config();
        let line =
            ".logo{background:url(\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB\")}";
        assert!(check_entropy(line, &config).is_empty());
    }

    #[test]
    fn test_pem_boundary_detection() {
        assert_eq!(is_pem_boundary("-----BEGIN PUBLIC KEY-----"), (true, false));
        assert_eq!(
            is_pem_boundary("-----END RSA PRIVATE KEY-----"),
            (false, true)
        );
        assert_eq!(is_pem_boundary("const x = 1;"), (false, false));
    }

    #[test]
    fn test_real_secret_still_flagged_by_entropy() {
        // Guardrail: the precision filters must not suppress a genuine unknown
        // high-entropy secret that isn't hash/placeholder/test-shaped.
        let config = default_scan_config();
        let hits = check_entropy("API_TOKEN=aB3dEfGhIjKlMnOpQrStUvWxYz012345", &config);
        assert!(
            !hits.is_empty(),
            "genuine high-entropy token should still flag"
        );
    }

    #[test]
    fn test_check_entropy_disabled() {
        let config = ScanConfig {
            entropy: false,
            ..Default::default()
        };
        let line = "SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345";
        assert!(check_entropy(line, &config).is_empty());
    }

    #[test]
    fn test_check_entropy_too_short() {
        let config = default_scan_config(); // min_length = 20
        // 10-char token — below min
        let line = "tok=aBcDeFgHiJ";
        assert!(check_entropy(line, &config).is_empty());
    }

    // ── Feature 2: parse_git_log_patch ─────────────────────────────────────

    #[test]
    fn test_parse_git_log_patch_extracts_added_lines() {
        let patch = "\
commit abc123def456abc123def456abc123def456abc1\n\
diff --git a/src/config.rs b/src/config.rs\n\
@@ -1,3 +1,4 @@\n\
 fn main() {}\n\
+    let key = \"some value here\";\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "abc123def456abc123def456abc123def456abc1");
        assert_eq!(lines[0].1, PathBuf::from("src/config.rs"));
        assert!(lines[0].2.contains("key"));
    }

    #[test]
    fn test_parse_git_log_patch_skips_removed_lines() {
        let patch = "\
commit deadbeef00000000000000000000000000000000\n\
diff --git a/foo.txt b/foo.txt\n\
@@ -1,1 +1,1 @@\n\
-old line\n\
+new line\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 1, "only added line should be collected");
        assert!(lines[0].2.contains("new line"));
    }

    #[test]
    fn test_parse_git_log_patch_multiple_commits() {
        let patch = "\
commit aaa0000000000000000000000000000000000000\n\
diff --git a/a.txt b/a.txt\n\
@@ -1,1 +1,1 @@\n\
+line_in_aaa\n\
commit bbb0000000000000000000000000000000000000\n\
diff --git a/b.txt b/b.txt\n\
@@ -1,1 +1,1 @@\n\
+line_in_bbb\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, "aaa0000000000000000000000000000000000000");
        assert_eq!(lines[1].0, "bbb0000000000000000000000000000000000000");
    }

    #[test]
    fn test_parse_git_log_patch_line_numbers() {
        // @@ -5,3 +10,4 @@ means new file starts at line 10.
        // Use concat!() so leading spaces in context lines are NOT stripped
        // (Rust's `\` line-continuation strips leading whitespace, which would
        // break context-line detection and produce wrong line numbers).
        let patch = concat!(
            "commit ccc0000000000000000000000000000000000000\n",
            "diff --git a/x.txt b/x.txt\n",
            "@@ -5,3 +10,4 @@\n",
            " context at 10\n",
            "+added at 11\n",
            " context at 12\n",
            "+added at 13\n",
        );
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].3, 11, "first added line should be at line 11");
        assert_eq!(lines[1].3, 13, "second added line should be at line 13");
    }
}
