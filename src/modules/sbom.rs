use crate::deps::{Ecosystem, Lockfile, Package, Scope, Source};
use crate::report::{Check, Finding, Report, Severity};
use anyhow::{Context, Result};
use serde_json::json;

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

/// Which dependency files the SBOM covers.
pub struct SbomOpts<'a> {
    pub output: Option<&'a str>,
    /// Use only this file instead of discovering every one under `.`.
    pub lockfile: Option<&'a str>,
    pub exclude: &'a [String],
}

pub fn run_sbom(opts: SbomOpts<'_>) -> Result<()> {
    let lockfiles = match opts.lockfile {
        Some(path) => vec![crate::deps::load(std::path::Path::new(path))?],
        None => {
            let found = crate::deps::discover(std::path::Path::new("."), opts.exclude);
            if let Some((path, err)) = found.failed.first() {
                anyhow::bail!("could not read {}: {err}", path.display());
            }
            // An SBOM states what the product contains; with two lockfiles for
            // one ecosystem, which one is installed is a guess.
            if let Some((dir, files)) = found.ambiguous().into_iter().next() {
                let names: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
                anyhow::bail!(
                    "{} has several lockfiles for one ecosystem ({}). Choose one with --lockfile, \
                     or exclude the others with [deps] exclude_patterns.",
                    dir.display(),
                    names.join(", ")
                );
            }
            found.lockfiles
        }
    };
    anyhow::ensure!(
        !lockfiles.is_empty(),
        "No supported dependency files found. Supported: package-lock.json, npm-shrinkwrap.json, \
         yarn.lock, pnpm-lock.yaml, bun.lock, Cargo.lock, uv.lock, poetry.lock, pylock.toml, \
         requirements.txt, go.mod, go.sum"
    );
    for lock in &lockfiles {
        for u in &lock.unresolved {
            crate::utils::terminal::warn(&format!(
                "{}: not in the SBOM — {u}",
                lock.path.display()
            ));
        }
    }

    let sbom = cyclonedx(&lockfiles, now_secs());
    let components = sbom["components"].as_array().map_or(0, Vec::len);
    let sources: Vec<String> = lockfiles
        .iter()
        .map(|l| l.path.display().to_string())
        .collect();
    crate::utils::terminal::info(&format!(
        "Generating SBOM from {} ({components} component(s))...",
        sources.join(", ")
    ));
    let json_str = serde_json::to_string_pretty(&sbom)?;

    if let Some(path) = opts.output {
        std::fs::write(path, &json_str)
            .with_context(|| format!("Failed to write SBOM to {}", path))?;
        crate::utils::terminal::success(&format!(
            "SBOM written to {} ({components} components, CycloneDX 1.5).",
            path
        ));
    } else {
        println!("{}", json_str);
    }

    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A CycloneDX 1.5 BOM for `lockfiles`: one component per distinct package
/// URL, the dependency graph, scopes and hashes as the lockfiles record them.
fn cyclonedx(lockfiles: &[Lockfile], now: u64) -> serde_json::Value {
    use std::collections::{BTreeMap, BTreeSet};

    let mut components: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut depends: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut root_depends: BTreeSet<String> = BTreeSet::new();

    for lock in lockfiles {
        let refs: Vec<Option<String>> = lock
            .packages
            .iter()
            .map(|p| (!p.member).then(|| purl(lock.ecosystem, p)))
            .collect();
        for (i, p) in lock.packages.iter().enumerate() {
            let Some(r) = &refs[i] else { continue };
            components
                .entry(r.clone())
                .or_insert_with(|| component(r, p));
            let entry = depends.entry(r.clone()).or_default();
            for (t, _) in &lock.edges[i] {
                if let Some(Some(tr)) = refs.get(*t) {
                    entry.insert(tr.clone());
                }
            }
        }
        for i in lock.direct() {
            if let Some(Some(r)) = refs.get(i) {
                root_depends.insert(r.clone());
            }
        }
    }

    let root_name = std::env::current_dir()
        .ok()
        .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "project".to_string());
    let mut dependencies = vec![json!({
        "ref": "root",
        "dependsOn": root_depends,
    })];
    dependencies.extend(
        depends
            .into_iter()
            .map(|(r, on)| json!({ "ref": r, "dependsOn": on })),
    );

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", uuid_v4()),
        "version": 1,
        "metadata": {
            "timestamp": format_timestamp(now),
            "tools": [{
                "vendor": "greengate-dev",
                "name": "greengate",
                "version": env!("CARGO_PKG_VERSION")
            }],
            "component": { "type": "application", "bom-ref": "root", "name": root_name }
        },
        "components": components.into_values().collect::<Vec<_>>(),
        "dependencies": dependencies,
    })
}

fn component(bom_ref: &str, p: &Package) -> serde_json::Value {
    let mut c = json!({
        "type": "library",
        "bom-ref": bom_ref,
        "name": p.name,
        "purl": bom_ref,
    });
    if !p.version.is_empty() {
        c["version"] = json!(p.version);
    }
    let scope = match p.scope {
        Scope::Prod => Some("required"),
        Scope::Optional => Some("optional"),
        // Development-only: not part of what ships.
        Scope::Dev => Some("excluded"),
        Scope::Unknown => None,
    };
    if let Some(scope) = scope {
        c["scope"] = json!(scope);
    }
    if let Some(hash) = p.integrity.as_deref().and_then(cyclonedx_hash) {
        c["hashes"] = json!([hash]);
    }
    c
}

/// Percent-encode everything outside the purl-safe set.
fn pct(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'-' | b'_' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Package URL (https://github.com/package-url/purl-spec), with a qualifier
/// naming where the package came from when that is not the default registry.
fn purl(eco: Ecosystem, p: &Package) -> String {
    let name = match eco {
        // `@scope/name`: the scope is the namespace, its `@` encoded.
        Ecosystem::Npm => pct(&p.name, true),
        Ecosystem::PyPI => pct(&crate::deps::normalize_python(&p.name), false),
        Ecosystem::Go => pct(&p.name, true),
        Ecosystem::Cargo => pct(&p.name, false),
    };
    let mut out = format!("pkg:{}/{name}", eco.purl_type());
    if !p.version.is_empty() {
        out.push('@');
        out.push_str(&pct(&p.version, false));
    }
    let qualifier = match &p.source {
        Source::Registry { url: Some(u) } => Some(("repository_url", u.clone())),
        Source::Git { url, rev } => Some((
            "vcs_url",
            match rev {
                Some(r) => format!("{url}@{r}"),
                None => url.clone(),
            },
        )),
        Source::Url { url } => Some(("download_url", url.clone())),
        _ => None,
    };
    if let Some((key, value)) = qualifier {
        out.push_str(&format!("?{key}={}", pct(&value, false)));
    }
    out
}

/// A CycloneDX hash from a lockfile integrity value: SRI (`sha512-<base64>`)
/// or `<alg>:<hex>`.
fn cyclonedx_hash(integrity: &str) -> Option<serde_json::Value> {
    let first = integrity.split_whitespace().next()?;
    let (alg, hex) = if let Some((alg, hex)) = first.split_once(':') {
        (alg.to_ascii_lowercase(), hex.to_ascii_lowercase())
    } else {
        let (alg, b64) = first.split_once('-')?;
        let bytes = base64_decode(b64)?;
        (
            alg.to_ascii_lowercase(),
            bytes.iter().map(|b| format!("{b:02x}")).collect(),
        )
    };
    let alg = match alg.as_str() {
        "sha1" => "SHA-1",
        "sha256" => "SHA-256",
        "sha384" => "SHA-384",
        "sha512" => "SHA-512",
        _ => return None,
    };
    Some(json!({ "alg": alg, "content": hex }))
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for c in input.bytes().filter(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// A random (version 4) UUID, as CycloneDX requires for `serialNumber`.
/// `RandomState` is seeded from OS randomness per instance.
fn uuid_v4() -> String {
    use std::hash::BuildHasher;
    let rand = |n: u64| std::collections::hash_map::RandomState::new().hash_one(n);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&rand(1).to_le_bytes());
    b[8..].copy_from_slice(&rand(2).to_le_bytes());
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
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
    fn purls_follow_the_spec() {
        use crate::deps::{Ecosystem, Package, Source};
        let p = |name: &str, version: &str, source: Source| Package::new(name, version, source);
        assert_eq!(
            purl(
                Ecosystem::Npm,
                &p("@sindresorhus/is", "4.6.0", Source::registry())
            ),
            "pkg:npm/%40sindresorhus/is@4.6.0"
        );
        assert_eq!(
            purl(
                Ecosystem::PyPI,
                &p("Django_Rest", "3.0+local", Source::registry())
            ),
            "pkg:pypi/django-rest@3.0%2Blocal"
        );
        assert_eq!(
            purl(
                Ecosystem::Go,
                &p("github.com/gin-gonic/gin", "v1.9.0", Source::registry())
            ),
            "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
        );
        assert_eq!(
            purl(
                Ecosystem::Npm,
                &p(
                    "x",
                    "1.0.0",
                    Source::Registry {
                        url: Some("https://npm.acme.dev/".into())
                    }
                )
            ),
            "pkg:npm/x@1.0.0?repository_url=https%3A%2F%2Fnpm.acme.dev%2F"
        );
    }

    #[test]
    fn integrity_values_become_cyclonedx_hashes() {
        // sha512 of the empty string, SRI-encoded.
        let sri = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==";
        let h = cyclonedx_hash(sri).unwrap();
        assert_eq!(h["alg"], "SHA-512");
        assert!(
            h["content"]
                .as_str()
                .unwrap()
                .starts_with("cf83e1357eefb8bd")
        );
        let h = cyclonedx_hash("sha256:ABCDEF").unwrap();
        assert_eq!(
            (h["alg"].as_str(), h["content"].as_str()),
            (Some("SHA-256"), Some("abcdef"))
        );
        assert!(cyclonedx_hash("md5-xyz").is_none());
    }

    #[test]
    fn serial_number_is_a_v4_uuid() {
        let u = uuid_v4();
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(
            parts[3].chars().next(),
            Some('8' | '9' | 'a' | 'b')
        ));
        assert_ne!(u, uuid_v4());
    }

    #[test]
    fn bom_has_graph_scopes_and_root() {
        let lock = crate::deps::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/deps/npm/package-lock.json"),
        )
        .unwrap();
        let bom = cyclonedx(std::slice::from_ref(&lock), 0);
        let comps = bom["components"].as_array().unwrap();
        assert_eq!(comps.len(), 5);
        let scope = |purl: &str| {
            comps
                .iter()
                .find(|c| c["purl"] == purl)
                .map(|c| c["scope"].clone())
                .unwrap()
        };
        assert_eq!(scope("pkg:npm/is-number@7.0.0"), "excluded");
        assert_eq!(scope("pkg:npm/ms@2.0.0"), "required");
        let deps = bom["dependencies"].as_array().unwrap();
        let of = |r: &str| deps.iter().find(|d| d["ref"] == r).unwrap()["dependsOn"].clone();
        assert_eq!(
            of("pkg:npm/debug@2.6.9"),
            serde_json::json!(["pkg:npm/ms@2.0.0"])
        );
        assert_eq!(of("root").as_array().unwrap().len(), 4);
    }
}
