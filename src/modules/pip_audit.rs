//! `greengate pip-install` — Zero-Trust pip wrapper.
//!
//! **Layer 1 — Pre-flight typosquat check**
//! Package names are compared against a curated list of the 60 most-downloaded
//! PyPI packages using Levenshtein distance.  Any name within edit-distance 2
//! of a popular package (but not identical to it) is flagged as a potential
//! typosquat.
//!
//! **Layer 2 — Static script analysis (post-install)**
//! After the install completes, newly installed `.dist-info/RECORD` files are
//! discovered by diffing the dist-info directories that existed before and after
//! the install.  Every `.py` source file listed in those RECORDs is scanned for
//! suspicious signals: network access, dynamic code execution, process spawning,
//! credential exfiltration, and high Shannon entropy.
//!
//! **Layer 3 — Executable drop detection**
//! Any new executable that appears in the Python scripts directory (e.g.
//! `~/.local/bin`, `venv/bin`) between the before/after snapshots is flagged.

use crate::report::{Check, Finding, Report, Severity};
use crate::utils::terminal;
use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ── Public API ────────────────────────────────────────────────────────────────

pub struct PipInstallOpts {
    /// pip / pip3 / python -m pip binary to invoke
    pub pip: String,
    /// Arguments forwarded verbatim to pip
    pub args: Vec<String>,
    /// Exit non-zero on any finding (default: true)
    pub no_fail: bool,
    /// Package names whose findings are reported as warnings only
    pub allow_packages: Vec<String>,
    /// Run the slopsquat / hallucinated-package guard (registry-metadata check)
    pub slopsquat_check: bool,
    /// Age threshold (days) below which a requested package is suspicious
    pub slopsquat_min_age_days: u64,
    /// Download threshold below which a requested package is suspicious
    pub slopsquat_min_downloads: u64,
    /// Internal package patterns for the dependency-confusion check
    pub internal_packages: Vec<String>,
}

// ── Popular PyPI package list for typosquat detection ────────────────────────

/// The 60 most-downloaded PyPI packages.  Used as the typosquat reference set.
const PYPI_POPULAR: &[&str] = &[
    "numpy",
    "pandas",
    "requests",
    "scipy",
    "matplotlib",
    "tensorflow",
    "torch",
    "flask",
    "django",
    "fastapi",
    "boto3",
    "botocore",
    "setuptools",
    "certifi",
    "urllib3",
    "idna",
    "chardet",
    "six",
    "python-dateutil",
    "pytz",
    "cryptography",
    "pydantic",
    "aiohttp",
    "click",
    "colorama",
    "tqdm",
    "pillow",
    "sqlalchemy",
    "pyyaml",
    "jinja2",
    "paramiko",
    "pytest",
    "black",
    "mypy",
    "pylint",
    "sphinx",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "httpx",
    "anyio",
    "starlette",
    "uvicorn",
    "gunicorn",
    "werkzeug",
    "itsdangerous",
    "markupsafe",
    "packaging",
    "toml",
    "attrs",
    "typing-extensions",
    "filelock",
    "platformdirs",
    "rich",
    "loguru",
    "pydantic-core",
    "grpcio",
    "protobuf",
    "lxml",
];

// ── Suspicious Python patterns ────────────────────────────────────────────────

/// (signal_name, substring) pairs checked in every installed .py file.
const PY_SIGNALS: &[(&str, &str)] = &[
    // Dynamic code execution
    ("eval()", "eval("),
    ("exec()", "exec("),
    ("compile()", "compile("),
    ("__import__()", "__import__("),
    // Subprocess / shell
    ("subprocess", "subprocess"),
    ("os.system()", "os.system("),
    ("os.popen()", "os.popen("),
    ("os.execv()", "os.execv("),
    ("popen()", "popen("),
    // Networking
    ("socket.connect", "socket.connect"),
    ("urllib.request", "urllib.request"),
    ("http.client", "http.client"),
    ("requests.get", "requests.get"),
    ("requests.post", "requests.post"),
    ("httplib", "httplib"),
    ("ftplib", "ftplib"),
    // Base64 / obfuscation
    ("base64.b64decode", "base64.b64decode"),
    ("codecs.decode", "codecs.decode"),
    ("binascii.unhexlify", "binascii.unhexlify"),
    ("zlib.decompress", "zlib.decompress"),
    // Credential exfiltration
    ("os.environ", "os.environ"),
    ("open('/etc/passwd')", "open('/etc/passwd')"),
    ("open(\"/etc/passwd\")", "open(\"/etc/passwd\")"),
    ("open('/etc/shadow')", "open('/etc/shadow')"),
    // Shell commands
    ("curl ", "curl "),
    ("wget ", "wget "),
];

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_pip_install(opts: PipInstallOpts) -> Result<Report> {
    let install_args = install_args(&opts.args);
    let mut report = Report::new("pip-install");
    report.no_fail = opts.no_fail;
    terminal::info(&format!(
        "Zero-Trust Supply Chain Gate (pip): intercepting `{} install {}`",
        opts.pip,
        install_args.join(" ")
    ));

    // ── Layer 1: Typosquat pre-flight ─────────────────────────────────────────
    let packages_to_install = extract_package_names(install_args);
    let mut typosquats: Vec<(String, String)> = Vec::new(); // (requested, closest_match)
    for pkg in &packages_to_install {
        if let Some(candidate) = check_typosquat(pkg) {
            typosquats.push((pkg.clone(), candidate));
        }
    }
    if !typosquats.is_empty() {
        eprintln!();
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (pip): {} potential typosquat(s) detected:",
            typosquats.len()
        );
        eprintln!();
        for (requested, closest) in &typosquats {
            eprintln!(
                "  [TYPOSQUAT] '{}' is suspiciously close to popular package '{}'",
                requested, closest
            );
        }
        eprintln!();
        eprintln!("  Verify the exact package name at https://pypi.org before installing.");
        eprintln!();

        for (requested, closest) in &typosquats {
            let finding = Finding::package(
                "SUPPLY-CHAIN/TYPOSQUAT",
                Severity::High,
                "pip",
                requested,
                format!("suspiciously close to popular package '{closest}'"),
            );
            if is_allowlisted(requested, &opts.allow_packages) {
                report.warnings.push(finding);
            } else {
                report.findings.push(finding);
            }
        }
        if !report.findings.is_empty() && !opts.no_fail {
            eprintln!(
                "Zero-Trust Supply Chain Gate: {} potential typosquat(s) — halting before install.",
                report.findings.len()
            );
            return Ok(report);
        }
    }

    // ── Layer 1.5: Slopsquat / hallucinated-package guard ─────────────────────
    // Catches plausible-but-invented names an AI assistant may have suggested,
    // which edit-distance typosquat detection misses. Only explicitly-named
    // packages are checked (`-r requirements.txt` deps are not expanded here).
    if opts.slopsquat_check {
        use crate::modules::slopsquat::{self, Ecosystem};
        let policy = slopsquat::GuardPolicy {
            slop: slopsquat::SlopConfig {
                min_age_days: opts.slopsquat_min_age_days,
                min_downloads: opts.slopsquat_min_downloads,
            },
            internal_patterns: opts.internal_packages.clone(),
        };
        let reports = slopsquat::guard(
            Ecosystem::Pypi,
            &packages_to_install,
            &opts.allow_packages,
            &|_| false,
            &policy,
            &mut report.checks,
        );
        let blocking = slopsquat::print_reports(Ecosystem::Pypi, &reports);
        slopsquat::record(Ecosystem::Pypi, &reports, &mut report);
        if blocking > 0 && !opts.no_fail {
            eprintln!(
                "Zero-Trust Supply Chain Gate (pip): {blocking} high-suspicion slopsquat(s) — halting before install."
            );
            return Ok(report);
        }
    }

    // ── Pre-install snapshot of dist-info dirs ────────────────────────────────
    let site_packages_dirs = discover_site_packages(&opts.pip);
    let pre_dist_info = snapshot_dist_info_dirs(&site_packages_dirs);
    let pre_scripts = snapshot_scripts_dir(&site_packages_dirs);

    // ── Run pip ───────────────────────────────────────────────────────────────
    let status = std::process::Command::new(&opts.pip) // greengate: ignore — intentionally wrapping pip to intercept the install
        .arg("install")
        .args(install_args)
        .status();

    // A failed install still gets the post-install checks below — whatever it
    // left behind is evidence — but it can never be reported as a pass.
    let pip_failure = match &status {
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to launch `{}`: {}. Is pip installed and on PATH?",
                opts.pip,
                e
            ));
        }
        Ok(s) if !s.success() => Some(format!(
            "`{}` failed ({s}) — the install did not complete.",
            opts.pip
        )),
        _ => None,
    };

    // ── Layer 2: RECORD-driven static analysis ────────────────────────────────
    let post_dist_info = snapshot_dist_info_dirs(&site_packages_dirs);
    let new_dist_info: Vec<PathBuf> = post_dist_info.difference(&pre_dist_info).cloned().collect();

    let mut script_threats: Vec<PipThreat> = Vec::new();
    for dist_info_dir in &new_dist_info {
        let record_path = dist_info_dir.join("RECORD");
        if let Ok(record) = std::fs::read_to_string(&record_path) {
            let pkg_name = dist_info_dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.split('-').next())
                .unwrap_or("<unknown>")
                .to_string();

            // RECORD lines: path,hash,size — path is relative to site-packages
            for line in record.lines() {
                let file_path_str = line.split(',').next().unwrap_or("").trim();
                if !file_path_str.ends_with(".py") {
                    continue;
                }
                // Resolve relative to the parent of the dist-info dir (site-packages)
                let base = dist_info_dir.parent().unwrap_or(Path::new("."));
                let full_path = base.join(file_path_str);
                if let Ok(src) = std::fs::read_to_string(&full_path) {
                    let signals = scan_python_signals(&src);
                    let max_entropy = max_script_entropy(&src);
                    const ENTROPY_THRESHOLD: f64 = 4.8;
                    if !signals.is_empty() || max_entropy > ENTROPY_THRESHOLD {
                        script_threats.push(PipThreat {
                            package: pkg_name.clone(),
                            file: full_path,
                            signals,
                            max_entropy,
                        });
                    }
                }
            }
        }
    }

    // ── Layer 3: Executable drop detection ───────────────────────────────────
    let post_scripts = snapshot_scripts_dir(&site_packages_dirs);
    let new_executables: Vec<PathBuf> = post_scripts
        .difference(&pre_scripts)
        .filter(|&p| is_executable(p))
        .cloned()
        .collect();

    // ── Report ─────────────────────────────────────────────────────────────────
    let mut any_blocking = false;

    if !script_threats.is_empty() {
        eprintln!();
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (pip): {} file(s) with suspicious patterns in newly installed package(s):",
            script_threats.len()
        );
        eprintln!();
        for t in &script_threats {
            let allowed = is_allowlisted(&t.package, &opts.allow_packages);
            let tag = if allowed { " [allowlisted]" } else { "" };
            eprintln!(
                "  [SCRIPT_THREAT] {} — {}{}",
                t.package,
                t.file.display(),
                tag
            );
            if !t.signals.is_empty() {
                eprintln!("    Signals  : {}", t.signals.join(", "));
            }
            if t.max_entropy > 4.8 {
                eprintln!(
                    "    Entropy  : {:.2}  (threshold 4.80 — likely obfuscated)",
                    t.max_entropy
                );
            }
            let finding = Finding::package(
                "SUPPLY-CHAIN/SCRIPT_THREAT",
                Severity::High,
                "pip",
                &t.package,
                format!(
                    "{}: {}",
                    t.file.display(),
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
            "  Tip: inspect the flagged file(s) manually. \
             Add the package to [supply_chain] allow_pip_packages to suppress."
        );
        eprintln!();
    }

    if !new_executables.is_empty() {
        eprintln!(
            "⚠️  Zero-Trust Supply Chain Gate (pip): {} new executable(s) dropped into scripts directory:",
            new_executables.len()
        );
        for exe in &new_executables {
            eprintln!("  [EXEC_DROP] {}", exe.display());
            any_blocking = true;
            report.findings.push(Finding::in_file(
                "SUPPLY-CHAIN/EXEC_DROP",
                Severity::High,
                exe,
                0,
                "new executable dropped into the scripts directory",
            ));
        }
        eprintln!();
    }

    if any_blocking && !opts.no_fail {
        eprintln!("Zero-Trust Supply Chain Gate (pip): blocking finding(s) detected — halting.");
    }

    if let Some(failure) = pip_failure {
        eprintln!("{failure}");
        report.checks.push(Check::error("pip", failure));
        return Ok(report);
    }

    if script_threats.is_empty()
        && new_executables.is_empty()
        && typosquats.is_empty()
        && report.unfinished().next().is_none()
    {
        terminal::success(
            "Zero-Trust Supply Chain Gate (pip): clean — no typosquats, suspicious scripts, \
             or unexpected executables detected.",
        );
    }

    report.print_unfinished();
    Ok(report)
}

// ── Internal types ────────────────────────────────────────────────────────────

struct PipThreat {
    package: String,
    file: PathBuf,
    signals: Vec<String>,
    max_entropy: f64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract plain package names from pip args (skip flags and version specs).
/// The arguments to pass after `pip install`. The command takes them without
/// the subcommand (`greengate pip-install requests`), but a leading `install`
/// is tolerated so it is neither sent twice nor checked as a package name.
fn install_args(args: &[String]) -> &[String] {
    match args.split_first() {
        Some((first, rest)) if first == "install" => rest,
        _ => args,
    }
}

pub(crate) fn extract_package_names(args: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Skip flags that take a value
        if matches!(
            arg.as_str(),
            "-r" | "--requirement"
                | "-t"
                | "--target"
                | "-d"
                | "--dest"
                | "--index-url"
                | "-i"
                | "--extra-index-url"
                | "--trusted-host"
                | "--constraint"
                | "-c"
        ) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        // Strip version specifiers: requests>=2.0 → requests
        let name = arg
            .split(&['>', '<', '=', '!', '[', ';', '@'][..])
            .next()
            .unwrap_or(arg)
            .trim()
            .to_lowercase();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Returns the closest popular package name if `pkg` looks like a typosquat,
/// i.e. Levenshtein distance 1–2 from a popular name of length ≥ 5.
fn check_typosquat(pkg: &str) -> Option<String> {
    // Normalise: lowercase, replace hyphens/underscores
    let norm = pkg.to_lowercase().replace('-', "_");

    for &popular in PYPI_POPULAR {
        let pop_norm = popular.to_lowercase().replace('-', "_");
        if norm == pop_norm {
            return None; // exact match — not a typosquat
        }
        // Only flag if both names are >= 5 chars (avoids noise on short names)
        if norm.len() < 5 || pop_norm.len() < 5 {
            continue;
        }
        let dist = levenshtein(&norm, &pop_norm);
        if dist <= 2 {
            return Some(popular.to_string());
        }
    }
    None
}

/// Levenshtein distance (edit distance) between two strings.
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

    // Early exit: if length difference alone exceeds threshold, skip.
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

/// Discover Python site-packages directories by running `pip show pip`.
fn discover_site_packages(pip: &str) -> Vec<PathBuf> {
    let out = std::process::Command::new(pip) // greengate: ignore — querying pip to locate site-packages
        .args(["show", "--files", "pip"])
        .output();

    let Ok(output) = out else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Location: ") {
            let location = PathBuf::from(rest.trim());
            if location.is_dir() {
                return vec![location];
            }
        }
    }
    Vec::new()
}

/// Snapshot all `.dist-info` directory paths inside the given site-packages dirs.
fn snapshot_dist_info_dirs(site_packages: &[PathBuf]) -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    for sp in site_packages {
        let Ok(entries) = std::fs::read_dir(sp) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".dist-info"))
                    .unwrap_or(false)
            {
                set.insert(path);
            }
        }
    }
    set
}

/// Snapshot all files in the `bin` / `Scripts` sibling of site-packages.
fn snapshot_scripts_dir(site_packages: &[PathBuf]) -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    for sp in site_packages {
        // venv: site-packages/../bin (Unix) or ../Scripts (Windows)
        let bin = sp.parent().map(|p| p.join("bin")).unwrap_or_default();
        let scripts = sp.parent().map(|p| p.join("Scripts")).unwrap_or_default();
        for dir in &[bin, scripts] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                set.insert(entry.path());
            }
        }
    }
    set
}

pub(crate) fn scan_python_signals(source: &str) -> Vec<String> {
    PY_SIGNALS
        .iter()
        .filter(|(_, needle)| source.contains(needle))
        .map(|(name, _)| name.to_string())
        .collect()
}

fn max_script_entropy(text: &str) -> f64 {
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

fn is_allowlisted(pkg: &str, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|a| a.to_lowercase() == pkg.to_lowercase())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("exe") | Some("bat") | Some("cmd") | Some("ps1")
    )
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typosquat_detects_numpy_variant() {
        // "numpi" is edit-distance 1 from "numpy"
        let result = check_typosquat("numpi");
        assert_eq!(result.as_deref(), Some("numpy"));
    }

    #[test]
    fn typosquat_exact_match_not_flagged() {
        assert!(check_typosquat("numpy").is_none());
        assert!(check_typosquat("requests").is_none());
        assert!(check_typosquat("flask").is_none());
    }

    #[test]
    fn typosquat_short_names_not_flagged() {
        // "pip" is too short (< 5 chars), shouldn't match
        assert!(check_typosquat("pip").is_none());
    }

    #[test]
    fn typosquat_clearly_different_not_flagged() {
        assert!(check_typosquat("my_totally_unique_package_xyz").is_none());
    }

    #[test]
    fn typosquat_requests_variant() {
        // "requets" — missing 's' — edit distance 1
        let result = check_typosquat("requets");
        assert_eq!(result.as_deref(), Some("requests"));
    }

    #[test]
    fn typosquat_hyphen_underscore_normalised() {
        // "python_dateutil" vs "python-dateutil" should NOT be a typosquat
        assert!(check_typosquat("python_dateutil").is_none());
    }

    #[test]
    fn extract_names_strips_version_specifiers() {
        let args: Vec<String> = ["requests>=2.28", "flask==2.3.0", "numpy"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let names = extract_package_names(&args);
        assert_eq!(names, vec!["requests", "flask", "numpy"]);
    }

    #[test]
    fn install_args_drops_a_leading_install_only() {
        let to_vec = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(install_args(&to_vec(&["requests"])), to_vec(&["requests"]));
        assert_eq!(
            install_args(&to_vec(&["install", "requests"])),
            to_vec(&["requests"])
        );
        // A package literally named `install` later in the list is kept.
        assert_eq!(
            install_args(&to_vec(&["-U", "install"])),
            to_vec(&["-U", "install"])
        );
    }

    #[test]
    fn extract_names_skips_flags() {
        let args: Vec<String> = ["-r", "requirements.txt", "--upgrade", "flask"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let names = extract_package_names(&args);
        assert_eq!(names, vec!["flask"]);
    }

    #[test]
    fn scan_python_detects_subprocess() {
        let src = "import subprocess\nsubprocess.run(['ls', '-la'])";
        let signals = scan_python_signals(src);
        assert!(signals.iter().any(|s| s.contains("subprocess")));
    }

    #[test]
    fn scan_python_detects_eval() {
        let src = "data = eval(encoded_payload)";
        let signals = scan_python_signals(src);
        assert!(signals.iter().any(|s| s == "eval()"));
    }

    #[test]
    fn scan_python_clean_file_no_signals() {
        let src = "def add(a, b):\n    return a + b\n";
        let signals = scan_python_signals(src);
        assert!(signals.is_empty());
    }

    #[test]
    fn levenshtein_identical() {
        assert_eq!(levenshtein("hello", "hello"), 0);
    }

    #[test]
    fn levenshtein_one_insert() {
        assert_eq!(levenshtein("numpy", "numpi"), 1);
    }

    #[test]
    fn levenshtein_empty() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn allowlist_case_insensitive() {
        let allow = vec!["NumPy".to_string()];
        assert!(is_allowlisted("numpy", &allow));
        assert!(is_allowlisted("NUMPY", &allow));
    }
}
