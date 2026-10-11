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

// ── Dependency discovery ──────────────────────────────────────────────────────

/// Collect every registry package from the dependency files under `root`,
/// via the shared dependency model. Every file gets a check: a file that
/// could not be parsed, or whose entries could not all be pinned, is reported
/// rather than skipped.
fn collect_all_lockfiles(root: &Path, exclude: &[String], report: &mut Report) -> Vec<Package> {
    let found = crate::deps::discover(root, exclude);
    for (path, err) in &found.failed {
        report.checks.push(Check::incomplete(
            format!("lockfile:{}", path.display()),
            format!("could not be read: {err}"),
        ));
    }
    for (dir, files) in found.ambiguous() {
        let names: Vec<String> = files
            .iter()
            .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        report.warnings.push(Finding::project(
            "DEPS/AmbiguousLockfiles",
            Severity::Low,
            format!(
                "{} has several lockfiles for one ecosystem ({}); all were audited, but which one is installed is ambiguous",
                dir.display(),
                names.join(", ")
            ),
        ));
    }

    let mut all: Vec<Package> = Vec::new();
    for lock in &found.lockfiles {
        let check_id = format!("lockfile:{}", lock.path.display());
        if lock.unresolved.is_empty() {
            report.checks.push(Check::passed(check_id));
        } else {
            let shown: Vec<&str> = lock.unresolved.iter().take(3).map(String::as_str).collect();
            let more = lock.unresolved.len().saturating_sub(shown.len());
            report.checks.push(Check::incomplete(
                check_id,
                format!(
                    "{} entr(y/ies) could not be pinned to a version and were not checked: {}{}",
                    lock.unresolved.len(),
                    shown.join(", "),
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                ),
            ));
        }

        // OSV advisories are keyed by registry package and version; git, URL
        // and path dependencies have no registry version to match.
        let mut registry = 0usize;
        let mut other = 0usize;
        for p in lock.dependencies() {
            if p.source.is_registry() && !p.version.is_empty() {
                registry += 1;
                all.push(Package {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    ecosystem: lock.ecosystem.osv(),
                    source_file: lock.path.clone(),
                });
            } else {
                other += 1;
            }
        }
        if registry > 0 {
            terminal::info(&format!(
                "Found {registry} package(s) in {}",
                lock.path.display()
            ));
        }
        if other > 0 {
            terminal::info(&format!(
                "  {other} git/URL/path package(s) in {} have no registry version to audit",
                lock.path.display()
            ));
        }
    }
    all
}

/// The OSV ecosystems of the dependency files under `root` — what
/// `greengate db update` downloads by default.
pub fn project_ecosystems(root: &Path, exclude: &[String]) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = crate::deps::discover(root, exclude)
        .lockfiles
        .iter()
        .map(|l| l.ecosystem.osv())
        .collect();
    found.sort_unstable();
    found.dedup();
    found
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

/// Advisory IDs affecting each `(ecosystem, name, version)` — no details,
/// one batch query (cached like the audit's). `None` when OSV cannot be
/// asked. Used to tell whether a new release fixes its predecessor.
pub fn advisory_ids(queries: &[(&str, &str, &str)]) -> Option<Vec<Vec<String>>> {
    if queries.is_empty() {
        return Some(Vec::new());
    }
    let body = json!({
        "queries": queries.iter().map(|(eco, name, version)| json!({
            "version": version,
            "package": { "name": name, "ecosystem": eco }
        })).collect::<Vec<_>>()
    });
    let body_str = serde_json::to_string(&body).ok()?;
    let key = cache_key(&body_str);
    let result: Value = match cache_read(&key) {
        Some(cached) => cached,
        None => {
            let response = http::agent()
                .post(&format!("{}/v1/querybatch", osv_base()))
                .set("Content-Type", "application/json")
                .send_string(&body_str)
                .ok()?;
            let parsed: Value = http::read_json(response).ok()?;
            cache_write(&key, &parsed);
            parsed
        }
    };
    let results = result.get("results")?.as_array()?;
    if results.len() != queries.len() {
        return None;
    }
    Some(
        results
            .iter()
            .map(|r| {
                r.get("vulns")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .collect(),
    )
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_audit(
    cfg: &config::AuditConfig,
    exclude: &[String],
    format: Format,
    offline: bool,
) -> Result<Report> {
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
    let all_packages = collect_all_lockfiles(root, exclude, &mut report);

    if all_packages.is_empty() && report.checks.is_empty() {
        anyhow::bail!(
            "No supported dependency files found. Supported: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, Cargo.lock, uv.lock, poetry.lock, pylock.toml, requirements.txt, go.mod, go.sum"
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
