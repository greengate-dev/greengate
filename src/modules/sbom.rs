use crate::report::{Check, Finding, Report, Severity};
use anyhow::{Context, Result};
use serde_json::json;

/// A parsed package entry used for SBOM generation.
struct SbomPackage {
    name: String,
    version: String,
    #[allow(dead_code)]
    ecosystem: &'static str,
    purl: String,
}

// ── Lock-file parsers ─────────────────────────────────────────────────────────

fn parse_cargo_lock(content: &str) -> Vec<SbomPackage> {
    let Ok(value) = content.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?.to_string();
            let version = pkg.get("version")?.as_str()?.to_string();
            let purl = format!("pkg:cargo/{}@{}", name, version);
            Some(SbomPackage {
                name,
                version,
                ecosystem: "crates.io",
                purl,
            })
        })
        .collect()
}

fn parse_package_lock(content: &str) -> Vec<SbomPackage> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let Some(packages) = root.get("packages").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    packages
        .iter()
        .filter_map(|(key, val)| {
            if key.is_empty() {
                return None;
            }
            let name = key.trim_start_matches("node_modules/").to_string();
            let version = val.get("version")?.as_str()?.to_string();
            let purl = format!("pkg:npm/{}@{}", name, version);
            Some(SbomPackage {
                name,
                version,
                ecosystem: "npm",
                purl,
            })
        })
        .collect()
}

fn parse_requirements_txt(content: &str) -> Vec<SbomPackage> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            if let Some(idx) = line.find("==") {
                let name = line[..idx].trim().to_string();
                let version = line[idx + 2..].trim().to_string();
                let purl = format!("pkg:pypi/{}@{}", name.to_lowercase(), version);
                Some(SbomPackage {
                    name,
                    version,
                    ecosystem: "PyPI",
                    purl,
                })
            } else {
                None
            }
        })
        .collect()
}

fn parse_go_sum(content: &str) -> Vec<SbomPackage> {
    let mut seen = std::collections::HashSet::new();
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            let module = parts[0];
            let ver_raw = parts[1];
            // go.sum entries may have "/go.mod" suffix — skip those, keep the plain version
            if ver_raw.ends_with("/go.mod") {
                return None;
            }
            let version = ver_raw.trim_start_matches('v').to_string();
            if !seen.insert(format!("{}@{}", module, version)) {
                return None;
            }
            let purl = format!("pkg:golang/{}@{}", module, version);
            Some(SbomPackage {
                name: module.to_string(),
                version,
                ecosystem: "Go",
                purl,
            })
        })
        .collect()
}

// ── Lock-file detection ───────────────────────────────────────────────────────

const LOCK_FILES: &[(&str, &str)] = &[
    ("Cargo.lock", "cargo"),
    ("package-lock.json", "npm"),
    ("requirements.txt", "pypi"),
    ("go.sum", "go"),
];

fn detect_and_parse() -> Result<(Vec<SbomPackage>, String)> {
    for (filename, kind) in LOCK_FILES {
        if std::path::Path::new(filename).exists() {
            let content = std::fs::read_to_string(filename)
                .with_context(|| format!("Failed to read {}", filename))?;
            let packages = match *kind {
                "cargo" => parse_cargo_lock(&content),
                "npm" => parse_package_lock(&content),
                "pypi" => parse_requirements_txt(&content),
                "go" => parse_go_sum(&content),
                _ => Vec::new(),
            };
            return Ok((packages, filename.to_string()));
        }
    }
    anyhow::bail!(
        "No supported lock file found. Supported: Cargo.lock, package-lock.json, requirements.txt, go.sum"
    )
}

// ── Sigstore / cosign attestation ─────────────────────────────────────────────

/// Verify cosign is in PATH. Returns a helpful installation hint if not found.
fn require_cosign() -> Result<()> {
    let result = std::process::Command::new("cosign") // greengate: ignore
        .arg("version")
        .output();
    if result.is_err() {
        anyhow::bail!(
            "cosign not found in PATH.\n\
             \n\
             Install it:\n\
               macOS:   brew install sigstore/tap/cosign\n\
               Linux:   https://github.com/sigstore/cosign/releases (download cosign-linux-amd64)\n\
             \n\
             In GitHub Actions, add a step before greengate:\n\
               - uses: sigstore/cosign-installer@v3"
        );
    }
    Ok(())
}

/// Sign `sbom_path` with Sigstore keyless signing and write the bundle to `bundle_path`.
///
/// Uses `cosign sign-blob`. In CI with OIDC ambient credentials (GitHub Actions with
/// `id-token: write`) this is fully non-interactive. Locally it opens a browser for OAuth.
pub fn run_sbom_attest(sbom_path: &str, bundle_path: &str) -> Result<()> {
    require_cosign()?;

    crate::utils::terminal::info(&format!(
        "Signing {} with Sigstore keyless signing...",
        sbom_path
    ));

    let status = std::process::Command::new("cosign") // greengate: ignore
        .args(["sign-blob", "--yes", "--bundle", bundle_path, sbom_path])
        .status()
        .context("Failed to spawn cosign sign-blob")?;

    if !status.success() {
        anyhow::bail!(
            "cosign sign-blob exited with code {}",
            status.code().unwrap_or(-1)
        );
    }

    crate::utils::terminal::success(&format!("Bundle written to {}", bundle_path));
    crate::utils::terminal::info(
        "The bundle contains the certificate chain and Rekor transparency log entry.",
    );
    crate::utils::terminal::info(&format!(
        "Distribute both {} and {} — verifiers need both files.",
        sbom_path, bundle_path
    ));
    Ok(())
}

/// Verify `sbom_path` against a cosign bundle. Returns an error if verification fails.
///
/// When `issuer` / `identity` are `None` the check uses regexp wildcards, which is
/// permissive but still validates the Rekor log entry and certificate chain. For
/// production use always set both to tighten the policy.
pub fn run_sbom_verify(
    sbom_path: &str,
    bundle_path: &str,
    issuer: Option<&str>,
    identity: Option<&str>,
) -> Result<Report> {
    require_cosign()?;

    crate::utils::terminal::info(&format!(
        "Verifying {} against bundle {}...",
        sbom_path, bundle_path
    ));

    let mut cmd = std::process::Command::new("cosign"); // greengate: ignore
    cmd.args(["verify-blob", "--bundle", bundle_path]);

    match (issuer, identity) {
        (Some(iss), Some(id)) => {
            cmd.args([
                "--certificate-oidc-issuer",
                iss,
                "--certificate-identity",
                id,
            ]);
        }
        (Some(iss), None) => {
            cmd.args([
                "--certificate-oidc-issuer",
                iss,
                "--certificate-identity-regexp",
                ".*",
            ]);
        }
        (None, Some(id)) => {
            cmd.args([
                "--certificate-oidc-issuer-regexp",
                ".*",
                "--certificate-identity",
                id,
            ]);
        }
        (None, None) => {
            cmd.args([
                "--certificate-oidc-issuer-regexp",
                ".*",
                "--certificate-identity-regexp",
                ".*",
            ]);
        }
    }

    cmd.arg(sbom_path);

    let status = cmd.status().context("Failed to spawn cosign verify-blob")?;

    let mut report = Report::new("sbom-verify");
    if !status.success() {
        let message = "SBOM attestation FAILED — the SBOM may have been tampered with or the \
                       signing identity does not match the expected policy.";
        eprintln!("{message}");
        report.findings.push(Finding::in_file(
            "SBOM/AttestationInvalid",
            Severity::High,
            sbom_path,
            0,
            message,
        ));
        return Ok(report);
    }

    // Without an expected identity, cosign accepts a valid signature from
    // anyone: the file is intact, but who signed it was never checked.
    if identity.is_none() {
        report.checks.push(Check::incomplete(
            "sbom:signer",
            "signature is valid, but no expected signer identity is set \
             (--certificate-identity or [sbom] expected_identity), so the signer was not checked",
        ));
        crate::utils::terminal::warn(
            "Signature is valid and anchored in Rekor, but the signer identity was NOT checked.",
        );
        report.print_unfinished();
        return Ok(report);
    }

    crate::utils::terminal::success(
        "Attestation verified. Signature is valid and anchored in the Rekor transparency log.",
    );
    Ok(report)
}

// ── CycloneDX output ──────────────────────────────────────────────────────────

pub fn run_sbom(output_file: Option<&str>) -> Result<()> {
    let (packages, source) = detect_and_parse()?;
    crate::utils::terminal::info(&format!(
        "Generating SBOM from {} ({} package(s))...",
        source,
        packages.len()
    ));

    let components: Vec<_> = packages
        .iter()
        .map(|p| {
            json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                "scope": "required"
            })
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:greengate-{}", now),
        "version": 1,
        "metadata": {
            "timestamp": format_timestamp(now),
            "tools": [{
                "vendor": "greengate-dev",
                "name": "greengate",
                "version": env!("CARGO_PKG_VERSION")
            }]
        },
        "components": components
    });

    let json_str = serde_json::to_string_pretty(&sbom)?;

    if let Some(path) = output_file {
        std::fs::write(path, &json_str)
            .with_context(|| format!("Failed to write SBOM to {}", path))?;
        crate::utils::terminal::success(&format!(
            "SBOM written to {} ({} components, CycloneDX 1.5).",
            path,
            packages.len()
        ));
    } else {
        println!("{}", json_str);
    }

    Ok(())
}

fn format_timestamp(unix: u64) -> String {
    // Simple ISO-8601 approximation without chrono dependency.
    // Computes YYYY-MM-DDTHH:MM:SSZ from a Unix timestamp.
    let secs = unix % 60;
    let mins = (unix / 60) % 60;
    let hours = (unix / 3600) % 24;
    let days_since_epoch = unix / 86400;

    // Days since Unix epoch → rough Gregorian date (good until 2100)
    let mut year: u64 = 1970;
    let mut days = days_since_epoch;
    loop {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month: u64 = 1;
    for md in &month_days {
        if days < *md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_cosign_fails_gracefully_when_not_found() {
        // If cosign happens to be installed the function succeeds; that's fine.
        // What we're testing is that it doesn't panic on either path.
        let _ = require_cosign();
    }

    #[test]
    fn attest_errors_when_sbom_file_missing() {
        // cosign sign-blob will fail if the file doesn't exist.
        // We only run this if cosign is actually present.
        if require_cosign().is_err() {
            return; // cosign not installed — skip
        }
        let result = run_sbom_attest("/tmp/__nonexistent_sbom_xyz.json", "/tmp/out.bundle.json");
        assert!(result.is_err());
    }

    #[test]
    fn verify_errors_when_bundle_file_missing() {
        // cosign verify-blob will fail if the bundle doesn't exist.
        if require_cosign().is_err() {
            return;
        }
        let result = run_sbom_verify(
            "/tmp/__nonexistent_sbom_xyz.json",
            "/tmp/__nonexistent.bundle.json",
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn format_timestamp_epoch() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2024-01-15T12:00:00Z = 1705320000
        let ts = format_timestamp(1705320000);
        assert!(ts.starts_with("2024-01-15T"), "got: {}", ts);
    }

    #[test]
    fn parse_cargo_lock_basic() {
        let input = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let pkgs = parse_cargo_lock(input);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].purl, "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn parse_requirements_txt_basic() {
        let input = "requests==2.31.0\nflask==3.0.0\n# comment\n";
        let pkgs = parse_requirements_txt(input);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(pkgs[1].purl, "pkg:pypi/flask@3.0.0");
    }
}
