use crate::report::{Check, Finding, Format, Location, Report, Severity};
use crate::utils::http;
use crate::utils::{config, files, terminal};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// OSV API root. `GREENGATE_OSV_URL` points the audit at a mirror (or, in
/// tests, at a local fake) without changing anything else.
fn osv_base() -> String {
    std::env::var("GREENGATE_OSV_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .map_or_else(
            || "https://api.osv.dev".to_string(),
            |u| u.trim_end_matches('/').to_string(),
        )
}
/// OSV cache lives for 24 hours — enough to avoid repeated CI queries.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    ecosystem: &'static str,
    /// Which lock file this package was parsed from.
    source_file: PathBuf,
}

#[derive(Debug)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub vuln_id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub fixed_in: Option<String>,
    pub reference_url: Option<String>,
    pub source_file: PathBuf,
    pub ecosystem: &'static str,
}

impl Vulnerability {
    fn to_finding(&self) -> Finding {
        Finding {
            rule: format!("OSV/{}", self.vuln_id),
            severity: self
                .severity
                .as_deref()
                .map_or(Severity::Unknown, Severity::parse),
            location: Location::Package {
                ecosystem: self.ecosystem.to_string(),
                name: self.package.clone(),
                version: Some(self.version.clone()),
                source: Some(self.source_file.clone()),
            },
            message: self.summary.clone(),
            remediation: self
                .fixed_in
                .as_ref()
                .map(|fix| format!("upgrade to >= {fix}")),
            reference: self.reference_url.clone(),
        }
    }
}

// ── Lock-file parsers ─────────────────────────────────────────────────────────

/// Parse `Cargo.lock` (TOML) and return crates.io packages.
fn parse_cargo_lock(content: &str, source: PathBuf) -> Vec<Package> {
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
            // Only include packages from crates.io registry; skip local path/workspace deps
            // (they have empty source in Cargo.lock but are not published to crates.io).
            let src = pkg.get("source").and_then(|s| s.as_str()).unwrap_or("");
            if src.contains("crates.io-index") {
                Some(Package {
                    name,
                    version,
                    ecosystem: "crates.io",
                    source_file: source.clone(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `package-lock.json` (npm v2/v3) and return npm packages.
fn parse_package_lock(content: &str, source: PathBuf) -> Vec<Package> {
    let Ok(root) = serde_json::from_str::<Value>(content) else {
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
            Some(Package {
                name,
                version,
                ecosystem: "npm",
                source_file: source.clone(),
            })
        })
        .collect()
}

/// Parse `requirements.txt` — only `==` / `===` pinned versions are auditable.
///
/// Returns the pinned packages and every other requirement line (ranges,
/// includes, editable installs, URLs). Those were *not* checked, and the caller
/// must say so rather than let them pass unseen.
fn parse_requirements_txt(content: &str, source: PathBuf) -> Parsed {
    let mut packages = Vec::new();
    let mut unchecked = Vec::new();
    // pip-compile writes `pkg==1.0 \` with `--hash` continuation lines.
    let joined = content.replace("\\\r\n", " ").replace("\\\n", " ");
    for raw in joined.lines() {
        // Inline comments need preceding whitespace (`#` can appear in URLs).
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            // Includes and editable installs pull in packages we do not see;
            // everything else (`--index-url`, `-c`, `--require-hashes`…) is a
            // pip option, not a requirement.
            let first = line.split([' ', '=']).next().unwrap_or("");
            if matches!(first, "-r" | "--requirement" | "-e" | "--editable") {
                unchecked.push(line.to_string());
            }
            continue;
        }
        // Drop environment markers and per-requirement options (`--hash=…`).
        let spec = line.split(';').next().unwrap_or("");
        let spec = spec.split(" --").next().unwrap_or("").trim();
        let pinned = spec
            .split_once("==")
            .map(|(name, version)| (name, version.trim_start_matches('=')));
        match pinned {
            Some((name, version)) if !name.contains("://") => {
                // `requests[security]` → `requests`
                let name = name.split('[').next().unwrap_or("").trim();
                let version = version.trim();
                if name.is_empty() || version.is_empty() {
                    unchecked.push(line.to_string());
                    continue;
                }
                packages.push(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: "PyPI",
                    source_file: source.clone(),
                });
            }
            _ => unchecked.push(line.to_string()),
        }
    }
    (packages, unchecked)
}

/// Parse `go.sum` and return Go packages.
///
/// Format per line: `<module> <version>[/go.mod] <hash>`
///
/// Lines whose version field ends with `/go.mod` are module verification records
/// (not actual dependencies) and are skipped. Only one entry per module@version
/// is returned (the non-/go.mod line).
fn parse_go_sum(content: &str, source: PathBuf) -> Vec<Package> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                return None;
            }
            let mut fields = line.splitn(3, ' ');
            let module = fields.next()?.trim();
            let version = fields.next()?.trim();
            // Skip the /go.mod verification lines — they reference module metadata, not the module itself
            if version.ends_with("/go.mod") || module.is_empty() {
                return None;
            }
            Some(Package {
                name: module.to_string(),
                version: version.to_string(),
                ecosystem: "Go",
                source_file: source.clone(),
            })
        })
        .collect()
}

/// Parse `yarn.lock` (v1 classic and v2/v3 berry) and return npm packages.
///
/// v1 format: non-indented header lines followed by `  version "x.y.z"`
/// v2 format: non-indented header lines followed by `  version: x.y.z`
fn parse_yarn_lock(content: &str, source: PathBuf) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Comment lines and __metadata block reset state
        if trimmed.starts_with('#') || trimmed.starts_with("__metadata") {
            current_name = None;
            continue;
        }

        // Non-indented line ending with ':' → package header
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':');
            // Take the first comma-separated specifier
            let first = header.split(',').next().unwrap_or(header).trim();
            // Strip surrounding quotes
            let first = first.trim_matches('"');
            // Skip workspace / local / link dependencies — no OSV entries
            if first.contains("workspace:") || first.contains("link:") || first.contains("file:") {
                current_name = None;
                continue;
            }
            // Find the '@' separating name from version specifier.
            // Scoped packages start with '@', so skip the first character when searching.
            let search_from = if first.starts_with('@') { 1 } else { 0 };
            current_name = first[search_from..]
                .find('@')
                .map(|i| first[..i + search_from].to_string());
        }
        // Indented version line (we have a pending package name)
        else if let Some(ref name) = current_name.clone() {
            // v1: version "4.17.21"
            if let Some(v) = trimmed
                .strip_prefix("version \"")
                .and_then(|s| s.strip_suffix('"'))
            {
                packages.push(Package {
                    name: name.clone(),
                    version: v.to_string(),
                    ecosystem: "npm",
                    source_file: source.clone(),
                });
                current_name = None;
            }
            // v2/v3 berry: version: 4.17.21
            else if let Some(v) = trimmed.strip_prefix("version: ") {
                let v = v.trim().trim_matches('"');
                packages.push(Package {
                    name: name.clone(),
                    version: v.to_string(),
                    ecosystem: "npm",
                    source_file: source.clone(),
                });
                current_name = None;
            }
        }
    }

    packages
}

/// Parse `pnpm-lock.yaml` and return npm packages.
///
/// Only the `packages:` section is parsed (canonical resolved package list).
/// Handles pnpm v5–v9: v5–v8 use `/name@version:` keys; v9 uses `name@version:`.
fn parse_pnpm_lock(content: &str, source: PathBuf) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Top-level (non-indented) key transitions between sections
        if !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            in_packages = trimmed == "packages:";
            continue;
        }

        if !in_packages || trimmed.is_empty() {
            continue;
        }

        // 2-space indented package entries (not 4-space sub-fields)
        if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
            let key = trimmed.trim_end_matches(':');
            // Strip leading slash present in pnpm v5–v8 format
            let key = key.trim_start_matches('/');
            // Find the '@' separating name from version (handle scoped packages)
            let search_from = if key.starts_with('@') { 1 } else { 0 };
            if let Some(at_idx) = key[search_from..].find('@').map(|i| i + search_from) {
                let name = &key[..at_idx];
                let version_str = &key[at_idx + 1..];
                // Strip peer-dep suffix like "4.17.21(react@18.0.0)"
                let version = version_str.split('(').next().unwrap_or(version_str).trim();
                if !name.is_empty() && !version.is_empty() {
                    packages.push(Package {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: "npm",
                        source_file: source.clone(),
                    });
                }
            }
        }
    }

    packages
}

// ── Lock-file discovery ───────────────────────────────────────────────────────

/// Packages read from a dependency file, plus the entries that could not be.
type Parsed = (Vec<Package>, Vec<String>);

/// Walk the entire directory tree and collect packages from ALL supported lock files.
///
/// Supported: `Cargo.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
/// `requirements.txt`, `go.sum`
///
/// Unlike the old single-file detection, this walks the whole repo so monorepos
/// with multiple sub-projects are fully covered. Every dependency file found
/// gets a check, so a file that could not be read is reported, not skipped.
fn collect_all_lockfiles(root: &Path, checks: &mut Vec<Check>) -> Vec<Package> {
    let mut all: Vec<Package> = Vec::new();

    for entry in files::get_walker(root).filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        let parse: fn(&str, PathBuf) -> Parsed = match file_name {
            "Cargo.lock" => |c, p| (parse_cargo_lock(c, p), Vec::new()),
            "package-lock.json" => |c, p| (parse_package_lock(c, p), Vec::new()),
            "yarn.lock" => |c, p| (parse_yarn_lock(c, p), Vec::new()),
            "pnpm-lock.yaml" => |c, p| (parse_pnpm_lock(c, p), Vec::new()),
            "requirements.txt" => parse_requirements_txt,
            "go.sum" => |c, p| (parse_go_sum(c, p), Vec::new()),
            _ => continue,
        };

        let check_id = format!("lockfile:{}", path.display());
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                checks.push(Check::incomplete(
                    check_id,
                    format!("could not be read: {e}"),
                ));
                continue;
            }
        };

        let (pkgs, unchecked) = parse(&content, path.clone());
        if unchecked.is_empty() {
            checks.push(Check::passed(check_id));
        } else {
            let shown: Vec<&str> = unchecked.iter().take(3).map(String::as_str).collect();
            let more = unchecked.len().saturating_sub(shown.len());
            checks.push(Check::incomplete(
                check_id,
                format!(
                    "{} requirement(s) are not pinned with `==` and were not checked: {}{}",
                    unchecked.len(),
                    shown.join(", "),
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                ),
            ));
        }

        if !pkgs.is_empty() {
            terminal::info(&format!(
                "Found {} package(s) in {}",
                pkgs.len(),
                path.display()
            ));
        }
        all.extend(pkgs);
    }

    all
}

// ── OSV disk cache ────────────────────────────────────────────────────────────

/// A simple djb2-style hash to build a cache filename from the query body.
fn cache_key(body: &str) -> String {
    let mut h: u64 = 5381;
    for b in body.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    format!("{:016x}", h)
}

fn cache_dir() -> Option<PathBuf> {
    let dir = files::cache_root()?.join("osv");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn cache_read(key: &str) -> Option<Value> {
    let path = cache_dir()?.join(format!("{}.json", key));
    let metadata = std::fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok()?;
    if SystemTime::now().duration_since(modified).ok()? > CACHE_TTL {
        return None; // expired
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn cache_write(key: &str, value: &Value) {
    if let Some(dir) = cache_dir() {
        let path = dir.join(format!("{}.json", key));
        if let Ok(s) = serde_json::to_string(value) {
            let _ = std::fs::write(path, s);
        }
    }
}

// ── OSV API ───────────────────────────────────────────────────────────────────

struct VulnDetails {
    /// False when the full record could not be fetched; the advisory itself is
    /// still real, only its summary/severity/fix are missing.
    complete: bool,
    summary: String,
    severity: Option<String>,
    fixed_in: Option<String>,
    reference_url: Option<String>,
}

/// Fetch full vulnerability details from `/v1/vulns/{id}`.
///
/// The batch querybatch API only returns `id`, `modified`, and `aliases` — not
/// `summary`, `severity`, `affected`, or `references`. This fetches and caches
/// the full record so the displayed output shows meaningful context.
fn fetch_vuln_details(id: &str) -> VulnDetails {
    let cache_key_str = format!("vuln-{}", id);

    let parsed: Value = if let Some(cached) = cache_read(&cache_key_str) {
        cached
    } else {
        let url = format!("{}/v1/vulns/{}", osv_base(), id);
        let Ok(response) = http::agent().get(&url).call() else {
            return VulnDetails {
                complete: false,
                summary: "No summary available".to_string(),
                severity: None,
                fixed_in: None,
                reference_url: None,
            };
        };
        let Ok(v) = http::read_json::<Value>(response) else {
            return VulnDetails {
                complete: false,
                summary: "No summary available".to_string(),
                severity: None,
                fixed_in: None,
                reference_url: None,
            };
        };
        cache_write(&cache_key_str, &v);
        v
    };

    let summary = parsed
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("No summary available")
        .to_string();

    // Severity: prefer database_specific.severity (e.g. "CRITICAL"), fall back to CVSS score
    let severity = parsed
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Fixed version: first `fixed` event across all affected ranges
    let fixed_in = parsed
        .get("affected")
        .and_then(|a| a.as_array())
        .and_then(|affected| {
            affected.iter().find_map(|entry| {
                entry
                    .get("ranges")
                    .and_then(|r| r.as_array())
                    .and_then(|ranges| {
                        ranges.iter().find_map(|range| {
                            range
                                .get("events")
                                .and_then(|ev| ev.as_array())
                                .and_then(|events| {
                                    events.iter().find_map(|e| {
                                        e.get("fixed")
                                            .and_then(|f| f.as_str())
                                            .map(|s| s.to_string())
                                    })
                                })
                        })
                    })
            })
        });

    // Reference: prefer ADVISORY type, then first URL
    let reference_url = parsed
        .get("references")
        .and_then(|r| r.as_array())
        .and_then(|refs| {
            refs.iter()
                .find(|r| r.get("type").and_then(|t| t.as_str()) == Some("ADVISORY"))
                .or_else(|| refs.first())
        })
        .and_then(|r| r.get("url"))
        .and_then(|u| u.as_str())
        .map(|s| s.to_string());

    VulnDetails {
        complete: true,
        summary,
        severity,
        fixed_in,
        reference_url,
    }
}

/// Query OSV for `packages`. A transport failure is an `Err`; a response that
/// does not cover every package is reported through `checks`.
fn query_osv(packages: &[Package], checks: &mut Vec<Check>) -> Result<Vec<Vulnerability>> {
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "version": p.version,
                "package": {
                    "name": p.name,
                    "ecosystem": p.ecosystem
                }
            })
        })
        .collect();

    let body = json!({ "queries": queries });
    let body_str = serde_json::to_string(&body)?;
    let key = cache_key(&body_str);

    // Return cached result if it exists and is not expired.
    let result: Value = if let Some(cached) = cache_read(&key) {
        cached
    } else {
        let response = http::agent()
            .post(&format!("{}/v1/querybatch", osv_base()))
            .set("Content-Type", "application/json")
            .send_string(&body_str)
            .context("Failed to reach OSV API — check your network connection")?;

        let parsed: Value =
            http::read_json(response).context("Failed to parse OSV API response")?;

        cache_write(&key, &parsed);
        parsed
    };

    let empty = vec![];
    let results: &Vec<Value> = result
        .get("results")
        .and_then(|r: &Value| r.as_array())
        .unwrap_or(&empty);

    // OSV answers each query positionally. Any package past the end of the
    // results was never checked.
    if results.len() < packages.len() {
        checks.push(Check::incomplete(
            "osv:coverage",
            format!(
                "OSV returned {} result(s) for {} package(s); the rest were not checked",
                results.len(),
                packages.len()
            ),
        ));
    }

    let mut vulns = Vec::new();
    let mut paged: Vec<String> = Vec::new();
    let mut without_details: Vec<String> = Vec::new();
    for (result_entry, pkg) in results.iter().zip(packages.iter()) {
        // More advisories than fit in one batch page: the ones listed are
        // real, but the list is not exhaustive.
        if result_entry
            .get("next_page_token")
            .and_then(Value::as_str)
            .is_some_and(|t| !t.is_empty())
        {
            paged.push(format!("{}@{}", pkg.name, pkg.version));
        }
        let vuln_array: &Vec<Value> =
            match result_entry.get("vulns").and_then(|v: &Value| v.as_array()) {
                Some(a) => a,
                None => continue,
            };
        for vuln in vuln_array {
            let id = vuln
                .get("id")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            // OSV querybatch only returns id/modified/aliases — fetch full record for details.
            let details = fetch_vuln_details(&id);
            if !details.complete {
                without_details.push(id.clone());
            }
            vulns.push(Vulnerability {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                vuln_id: id,
                summary: details.summary,
                severity: details.severity,
                fixed_in: details.fixed_in,
                reference_url: details.reference_url,
                source_file: pkg.source_file.clone(),
                ecosystem: pkg.ecosystem,
            });
        }
    }

    if !paged.is_empty() {
        checks.push(Check::incomplete(
            "osv:pagination",
            format!("advisory list truncated by OSV for: {}", paged.join(", ")),
        ));
    }
    if !without_details.is_empty() {
        checks.push(Check::incomplete(
            "osv:details",
            format!(
                "could not fetch severity/fix details for: {}",
                without_details.join(", ")
            ),
        ));
    }

    Ok(vulns)
}

/// Match `packages` against the offline OSV snapshots. Every ecosystem gets a
/// check: passed with the snapshot's age as its source, or incomplete when the
/// snapshot is missing or too old, or a version could not be evaluated.
/// `online_error` is set when this is a fallback for a failed API query.
fn query_offline(
    packages: &[Package],
    max_age: Duration,
    online_error: Option<&str>,
    checks: &mut Vec<Check>,
) -> Vec<Vulnerability> {
    use crate::modules::osv_db::{Snapshot, Unavailable};

    let fallback_note = online_error
        .map(|e| format!(" — used because the OSV API failed: {e}"))
        .unwrap_or_default();
    let mut ecosystems: Vec<&'static str> = packages.iter().map(|p| p.ecosystem).collect();
    ecosystems.sort_unstable();
    ecosystems.dedup();

    let mut vulns = Vec::new();
    for eco in ecosystems {
        let id = format!("osv-db:{eco}");
        let in_eco: Vec<&Package> = packages.iter().filter(|p| p.ecosystem == eco).collect();
        let mut snapshot = match Snapshot::open(eco, max_age) {
            Ok(s) => s,
            Err(why) => {
                let why = match why {
                    Unavailable::Missing => "no offline snapshot".to_string(),
                    Unavailable::Stale(age) => format!(
                        "offline snapshot is {} h old (limit {} h)",
                        age.as_secs() / 3600,
                        max_age.as_secs() / 3600
                    ),
                };
                let online = online_error
                    .map(|e| format!("OSV API failed ({e}) and "))
                    .unwrap_or_default();
                checks.push(Check::incomplete(
                    id,
                    format!(
                        "{online}{why} — {} package(s) not checked; run `greengate db update`",
                        in_eco.len()
                    ),
                ));
                continue;
            }
        };
        let source = format!(
            "offline OSV snapshot, checked {} h ago{fallback_note}",
            snapshot.meta.age().as_secs() / 3600
        );
        let mut unknown: Vec<String> = Vec::new();
        for pkg in in_eco {
            match snapshot.lookup(&pkg.name, &pkg.version) {
                Ok(entries) => vulns.extend(entries.into_iter().map(|e| Vulnerability {
                    package: pkg.name.clone(),
                    version: pkg.version.clone(),
                    fixed_in: e.fixed_in().map(str::to_string),
                    vuln_id: e.id,
                    summary: if e.summary.is_empty() {
                        "No summary available".to_string()
                    } else {
                        e.summary
                    },
                    severity: e.severity,
                    reference_url: e.reference,
                    source_file: pkg.source_file.clone(),
                    ecosystem: pkg.ecosystem,
                })),
                Err(reason) => unknown.push(reason),
            }
        }
        if unknown.is_empty() {
            checks.push(Check::passed(id).with_source(source));
        } else {
            checks.push(
                Check::incomplete(
                    id,
                    format!(
                        "{} package(s) not evaluated: {}",
                        unknown.len(),
                        unknown.join("; ")
                    ),
                )
                .with_source(source),
            );
        }
    }
    vulns
}

/// The OSV ecosystems of the dependency files under `root`, without parsing
/// them — what `greengate db update` downloads by default.
pub fn project_ecosystems(root: &Path) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = files::get_walker(root)
        .filter_map(|e| e.ok())
        .filter_map(|e| match e.file_name().to_str()? {
            "Cargo.lock" => Some("crates.io"),
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => Some("npm"),
            "requirements.txt" => Some("PyPI"),
            "go.sum" => Some("Go"),
            _ => None,
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_audit(cfg: &config::AuditConfig, format: Format, offline: bool) -> Result<Report> {
    let source = if offline {
        config::AuditSource::Offline
    } else {
        cfg.source
    };
    let max_age = Duration::from_secs(cfg.max_db_age_hours.saturating_mul(3600));
    let text = format == Format::Text;
    let ignored: HashSet<String> = cfg
        .ignore_advisories
        .iter()
        .map(|id| id.to_uppercase())
        .collect();

    if !ignored.is_empty() {
        terminal::info(&format!(
            "Ignoring {} suppressed advisory/-ies from .greengate.toml",
            ignored.len()
        ));
    }

    let mut report = Report::new("audit");
    let root = std::path::Path::new(".");

    // Walk the entire repo for all supported lock files
    let all_packages = collect_all_lockfiles(root, &mut report.checks);

    if all_packages.is_empty() && report.checks.is_empty() {
        anyhow::bail!(
            "No supported lock files found. Supported: Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, go.sum"
        );
    }

    terminal::info(&format!(
        "Found {} package entries across all lock files. Deduplicating...",
        all_packages.len()
    ));

    // Deduplicate by (name, version, ecosystem) — keeps first occurrence for source_file display
    let mut seen: HashSet<(&str, &str, &'static str)> = HashSet::new();
    let unique: Vec<&Package> = all_packages
        .iter()
        .filter(|p| seen.insert((&p.name, &p.version, p.ecosystem)))
        .collect();

    terminal::info(&format!(
        "Auditing {} unique package(s) via OSV...",
        unique.len()
    ));

    // Clone into owned Vec for chunked queries (query_osv takes &[Package])
    let to_query: Vec<Package> = unique
        .iter()
        .map(|p| Package {
            name: p.name.clone(),
            version: p.version.clone(),
            ecosystem: p.ecosystem,
            source_file: p.source_file.clone(),
        })
        .collect();

    let mut all_vulns: Vec<Vulnerability> = Vec::new();
    if source == config::AuditSource::Offline {
        all_vulns = query_offline(&to_query, max_age, None, &mut report.checks);
    } else {
        // OSV batch API supports up to 1000 queries; chunk if needed
        let bar = terminal::create_progress_bar(1);
        bar.set_message("Querying OSV API...");
        let chunks = to_query.chunks(1000).count();
        for (i, chunk) in to_query.chunks(1000).enumerate() {
            match query_osv(chunk, &mut report.checks) {
                Ok(vulns) => all_vulns.extend(vulns),
                Err(e) if source == config::AuditSource::Auto => {
                    // The API failed; a fresh offline snapshot can still
                    // answer. If none can, query_offline says so.
                    let reason = format!("{e:#}");
                    all_vulns.extend(query_offline(
                        chunk,
                        max_age,
                        Some(&reason),
                        &mut report.checks,
                    ));
                }
                Err(e) => {
                    // A failed query leaves its packages unchecked — that is not a
                    // pass. Keep going: other chunks may still answer.
                    let id = if chunks > 1 {
                        format!("osv:batch-{}", i + 1)
                    } else {
                        "osv".to_string()
                    };
                    report.checks.push(Check::incomplete(
                        id,
                        format!("{} package(s) not checked: {e:#}", chunk.len()),
                    ));
                }
            }
        }
        bar.finish_and_clear();
    }

    // Split into suppressed vs. actionable
    let (suppressed, actionable): (Vec<_>, Vec<_>) = all_vulns
        .into_iter()
        .partition(|v| ignored.contains(&v.vuln_id.to_uppercase()));

    report.suppressed = suppressed.iter().map(Vulnerability::to_finding).collect();
    report.findings = actionable.iter().map(Vulnerability::to_finding).collect();

    if !text {
        return Ok(report);
    }

    if !suppressed.is_empty() {
        terminal::warn(&format!(
            "Suppressed {} advisory/-ies (listed in .greengate.toml [audit] ignore_advisories):",
            suppressed.len()
        ));
        for v in &suppressed {
            let sev = v.severity.as_deref().unwrap_or("?");
            eprintln!(
                "  [suppressed] [{}] [{}] {}@{} — {}",
                v.vuln_id, sev, v.package, v.version, v.summary
            );
        }
    }

    if actionable.is_empty() {
        if report.unfinished().next().is_none() {
            terminal::success(&format!(
                "No actionable vulnerabilities found in {} unique package(s).",
                unique.len()
            ));
        }
    } else {
        terminal::warn(&format!(
            "Found {} vulnerability/-ies across {} unique package(s):",
            actionable.len(),
            unique.len()
        ));
        for v in &actionable {
            let sev = v.severity.as_deref().unwrap_or("UNKNOWN");
            eprintln!("  [{}] [{}] {}@{}", v.vuln_id, sev, v.package, v.version);
            eprintln!("    {}", v.summary);
            if let Some(fix) = &v.fixed_in {
                eprintln!("    Fix: upgrade to >= {}", fix);
            }
            if let Some(url) = &v.reference_url {
                eprintln!("    Ref: {}", url);
            }
            eprintln!("    Source: {}", v.source_file.display());
        }
    }

    report.print_unfinished();
    if !actionable.is_empty() {
        eprintln!(
            "Audit failed: {} known vulnerability/-ies found.",
            actionable.len()
        );
    }
    Ok(report)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cargo.lock ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_cargo_lock_basic() {
        let content = r#"
version = 3

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"
"#;
        let pkgs = parse_cargo_lock(content, PathBuf::from("Cargo.lock"));
        assert!(
            pkgs.iter()
                .any(|p| p.name == "anyhow" && p.version == "1.0.86")
        );
    }

    #[test]
    fn test_parse_cargo_lock_source_file_preserved() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let source = PathBuf::from("sub/project/Cargo.lock");
        let pkgs = parse_cargo_lock(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── package-lock.json ──────────────────────────────────────────────────

    #[test]
    fn test_parse_package_lock_basic() {
        let content = r#"
{
  "packages": {
    "": { "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.0" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#;
        let pkgs = parse_package_lock(content, PathBuf::from("package-lock.json"));
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.version == "4.18.0")
        );
    }

    // ── requirements.txt ──────────────────────────────────────────────────

    #[test]
    fn test_parse_requirements_txt_pinned_only() {
        let content = "Django==4.2.0\nrequests>=2.28.0\nflask==2.3.2\n# comment\n";
        let (pkgs, unchecked) = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        assert_eq!(pkgs.len(), 2);
        assert_eq!(unchecked, vec!["requests>=2.28.0"]);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Django" && p.version == "4.2.0")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "flask" && p.version == "2.3.2")
        );
    }

    #[test]
    fn test_parse_requirements_txt_skips_comments() {
        let content = "# this is a comment\n\nrequests==2.28.2\n";
        let (pkgs, unchecked) = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        assert_eq!(pkgs.len(), 1);
        assert!(unchecked.is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_pip_compile_output() {
        // Hash continuations, markers, extras and pip options are all normal
        // in a compiled requirements file; none of them is an unchecked dep.
        let content = "--index-url https://pypi.org/simple\n\
                       --require-hashes\n\
                       requests[security]==2.31.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n\
                       pywin32==306 ; sys_platform == \"win32\"  # via foo\n\
                       black===23.1.0\n";
        let (pkgs, unchecked) = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        let got: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("requests", "2.31.0"),
                ("pywin32", "306"),
                ("black", "23.1.0")
            ]
        );
        assert!(unchecked.is_empty(), "unexpected: {unchecked:?}");
    }

    #[test]
    fn test_parse_requirements_txt_reports_what_it_cannot_check() {
        let content = "-r base.txt\n-e .\ngit+https://github.com/a/b.git==1.0\nflask>=2\n";
        let (pkgs, unchecked) = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        assert!(pkgs.is_empty());
        assert_eq!(unchecked.len(), 4);
    }

    #[test]
    fn test_parse_requirements_txt_source_file_preserved() {
        let content = "Django==4.2.0\n";
        let source = PathBuf::from("services/api/requirements.txt");
        let (pkgs, _) = parse_requirements_txt(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── go.sum ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_go_sum_basic() {
        let content = "\
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnzf3MoPlaT00ZchkJ6MB6SBSJ0+CY0s3f5E=\n\
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPGd8YAYS9Oks18D/DM3wRJQ9R0T2tZP4f+qSmfHfX4=\n\
golang.org/x/net v0.12.0 h1:something=\n\
";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        // /go.mod line must be skipped → 2 packages, not 3
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/gin-gonic/gin" && p.version == "v1.9.1")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "golang.org/x/net" && p.version == "v0.12.0")
        );
    }

    #[test]
    fn test_parse_go_sum_skips_go_mod_lines() {
        let content = "mod.example.com/foo v1.0.0/go.mod h1:abc=\n";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        assert!(
            pkgs.is_empty(),
            "version ending with /go.mod must be skipped"
        );
    }

    #[test]
    fn test_parse_go_sum_ecosystem_is_go() {
        let content = "example.com/bar v2.1.0 h1:xyz=\n";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        assert!(!pkgs.is_empty());
        assert_eq!(pkgs[0].ecosystem, "Go");
    }

    #[test]
    fn test_parse_go_sum_empty() {
        let pkgs = parse_go_sum("", PathBuf::from("go.sum"));
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_go_sum_source_file_preserved() {
        let content = "github.com/foo/bar v1.0.0 h1:abc=\n";
        let source = PathBuf::from("subdir/go.sum");
        let pkgs = parse_go_sum(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── yarn.lock ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_yarn_lock_v1_basic() {
        let content = concat!(
            "# yarn lockfile v1\n",
            "\n",
            "lodash@^4.17.21:\n",
            "  version \"4.17.21\"\n",
            "  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
            "  integrity sha512-xxx\n",
        );
        let pkgs = parse_yarn_lock(content, PathBuf::from("yarn.lock"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
        assert_eq!(pkgs[0].ecosystem, "npm");
    }

    #[test]
    fn test_parse_yarn_lock_v2_berry() {
        let content = concat!(
            "__metadata:\n",
            "  version: 6\n",
            "  cacheKey: 8\n",
            "\n",
            "\"lodash@npm:^4.17.21\":\n",
            "  version: 4.17.21\n",
            "  resolution: \"lodash@npm:4.17.21\"\n",
        );
        let pkgs = parse_yarn_lock(content, PathBuf::from("yarn.lock"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
    }

    #[test]
    fn test_parse_yarn_lock_scoped_package() {
        let content = concat!(
            "\"@babel/core@^7.0.0\":\n",
            "  version \"7.21.0\"\n",
            "  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.21.0.tgz\"\n",
        );
        let pkgs = parse_yarn_lock(content, PathBuf::from("yarn.lock"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@babel/core");
        assert_eq!(pkgs[0].version, "7.21.0");
    }

    #[test]
    fn test_parse_yarn_lock_multiple_specifiers_same_line() {
        // Yarn v1 often merges multiple specifiers into one block
        let content = concat!(
            "lodash@^4.17.0, lodash@^4.17.21:\n",
            "  version \"4.17.21\"\n",
        );
        let pkgs = parse_yarn_lock(content, PathBuf::from("yarn.lock"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
    }

    #[test]
    fn test_parse_yarn_lock_skips_workspace_deps() {
        let content = concat!("\"my-app@workspace:.\":\n", "  version: 0.0.0-use.local\n",);
        let pkgs = parse_yarn_lock(content, PathBuf::from("yarn.lock"));
        assert!(pkgs.is_empty(), "workspace deps should be skipped");
    }

    #[test]
    fn test_parse_yarn_lock_empty() {
        let pkgs = parse_yarn_lock("# yarn lockfile v1\n", PathBuf::from("yarn.lock"));
        assert!(pkgs.is_empty());
    }

    // ── pnpm-lock.yaml ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_pnpm_lock_v5_v8_with_slash() {
        let content = concat!(
            "lockfileVersion: '6.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  /lodash@4.17.21:\n",
            "    resolution: {integrity: sha512-xxx}\n",
            "    dev: false\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
        assert_eq!(pkgs[0].ecosystem, "npm");
    }

    #[test]
    fn test_parse_pnpm_lock_v9_no_slash() {
        let content = concat!(
            "lockfileVersion: '9.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  lodash@4.17.21:\n",
            "    resolution: {integrity: sha512-xxx}\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
    }

    #[test]
    fn test_parse_pnpm_lock_scoped_package() {
        let content = concat!(
            "lockfileVersion: '6.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  /@babel/core@7.21.0:\n",
            "    resolution: {integrity: sha512-xxx}\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@babel/core");
        assert_eq!(pkgs[0].version, "7.21.0");
    }

    #[test]
    fn test_parse_pnpm_lock_peer_dep_suffix_stripped() {
        // pnpm encodes peer deps as version(peer@ver)
        let content = concat!(
            "lockfileVersion: '9.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  react-dom@18.2.0(react@18.2.0):\n",
            "    resolution: {integrity: sha512-xxx}\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "react-dom");
        assert_eq!(pkgs[0].version, "18.2.0");
    }

    #[test]
    fn test_parse_pnpm_lock_ignores_importers_section() {
        let content = concat!(
            "lockfileVersion: '9.0'\n",
            "\n",
            "importers:\n",
            "  .:\n",
            "    dependencies:\n",
            "      lodash:\n",
            "        specifier: ^4.17.21\n",
            "        version: 4.17.21\n",
            "\n",
            "packages:\n",
            "\n",
            "  lodash@4.17.21:\n",
            "    resolution: {integrity: sha512-xxx}\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        // importers section must not produce extra entries
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
    }

    #[test]
    fn test_parse_pnpm_lock_stops_at_snapshots_section() {
        let content = concat!(
            "lockfileVersion: '9.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  lodash@4.17.21:\n",
            "    resolution: {integrity: sha512-xxx}\n",
            "\n",
            "snapshots:\n",
            "\n",
            "  lodash@4.17.21: {}\n",
        );
        let pkgs = parse_pnpm_lock(content, PathBuf::from("pnpm-lock.yaml"));
        // snapshots section must not double-count
        assert_eq!(pkgs.len(), 1);
    }

    // ── Deduplication ──────────────────────────────────────────────────────

    #[test]
    fn test_deduplication_across_lockfiles() {
        // Same package appearing in two different lock files
        let pkgs = [
            Package {
                name: "anyhow".into(),
                version: "1.0.86".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("Cargo.lock"),
            },
            Package {
                name: "anyhow".into(),
                version: "1.0.86".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("subdir/Cargo.lock"),
            },
            Package {
                name: "serde".into(),
                version: "1.0.0".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("Cargo.lock"),
            },
        ];

        let mut seen: HashSet<(String, String, &'static str)> = HashSet::new();
        let unique: Vec<_> = pkgs
            .iter()
            .filter(|p| seen.insert((p.name.clone(), p.version.clone(), p.ecosystem)))
            .collect();

        assert_eq!(
            unique.len(),
            2,
            "anyhow should be deduplicated to one entry"
        );
    }
}
