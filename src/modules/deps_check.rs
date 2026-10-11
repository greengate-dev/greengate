//! `greengate deps check` — supply-chain policy for the dependencies a change
//! introduces, before anything is installed.
//!
//! Two kinds of checks:
//!
//! * **Lockfile policies** (offline, every package): registry binding,
//!   dependency confusion, git/URL/path sources, missing integrity hashes.
//! * **Release risk** (registry metadata, only packages that are new or
//!   changed since a base revision): a release younger than the cooldown, a
//!   new install script, lost provenance, a different publisher, a yanked or
//!   deprecated version.
//!
//! Registry signals are suspicion, not proof: a new maintainer or a fresh
//! release is usually legitimate. The policy levels decide what blocks.

use crate::deps::{self, Ecosystem, Format, Lockfile, Package, Source};
use crate::modules::slopsquat::matches_internal;
use crate::registry::{self, History, Lookup};
use crate::report::{Check, Finding, Location, Report, Severity};
use crate::utils::config::{Level, ReleasePolicy, SupplyChainConfig};
use crate::utils::terminal;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

pub struct CheckOpts<'a> {
    pub root: &'a Path,
    /// Compare against this git revision instead of the default.
    pub base: Option<&'a str>,
    /// Check every package, not just changed ones.
    pub all: bool,
    pub exclude: &'a [String],
    pub policy: &'a SupplyChainConfig,
    /// Current time, unix seconds (a parameter so tests can fix it).
    pub now: u64,
}

/// What "changed" is measured against.
enum Base {
    All(String),
    Rev { rev: String, label: String },
}

// ── Signals ───────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct Signal {
    pub rule: &'static str,
    pub level: Level,
    pub message: String,
}

/// Release-risk signals for one release, under `policy`, at time `now`.
pub fn release_signals(h: &History, policy: &ReleasePolicy, now: u64) -> Vec<Signal> {
    let mut out = Vec::new();
    let mut push = |rule, level, message: String| {
        if level != Level::Off {
            out.push(Signal {
                rule,
                level,
                message,
            });
        }
    };
    if let Some(published) = h.this.published {
        let age_h = now.saturating_sub(published) / 3600;
        if age_h < policy.min_release_age_hours {
            push(
                "RELEASE/YoungRelease",
                policy.young_release,
                format!(
                    "published {age_h} h ago, inside the {} h cooldown",
                    policy.min_release_age_hours
                ),
            );
        }
    }
    if let Some((prev_v, prev)) = &h.previous {
        if h.this.install_script == Some(true) && prev.install_script == Some(false) {
            push(
                "RELEASE/NewInstallScript",
                policy.new_install_script,
                format!("runs code at install time; {prev_v} did not"),
            );
        }
        if prev.provenance == Some(true) && h.this.provenance == Some(false) {
            push(
                "RELEASE/ProvenanceRegression",
                policy.provenance_regression,
                format!("has no publish provenance; {prev_v} did"),
            );
        }
    }
    // With provenance, the release is tied to a source repository and build
    // — stronger evidence than any account name. That includes npm's trusted
    // publishing, which publishes as the account "GitHub Actions".
    if let Some(by) = &h.this.publisher
        && h.this.provenance != Some(true)
        && !h.earlier_publishers.is_empty()
        && !h.earlier_publishers.contains(by)
    {
        push(
            "RELEASE/PublisherChange",
            policy.publisher_change,
            format!(
                "published by {by}, who never published an earlier version (earlier: {})",
                h.earlier_publishers.join(", ")
            ),
        );
    }
    if let Some(why) = &h.this.withdrawn {
        push(
            "RELEASE/Withdrawn",
            policy.withdrawn,
            format!("withdrawn by the registry: {why}"),
        );
    }
    out
}

fn record(report: &mut Report, level: Level, finding: Finding) {
    match level {
        Level::Fail => report.findings.push(finding),
        Level::Warn => report.warnings.push(finding),
        Level::Off => {}
    }
}

fn severity(level: Level) -> Severity {
    if level == Level::Fail {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn package_finding(
    rule: &str,
    level: Level,
    lock: &Lockfile,
    p: &Package,
    message: String,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity: severity(level),
        location: Location::Package {
            ecosystem: lock.ecosystem.osv().to_string(),
            name: p.name.clone(),
            version: (!p.version.is_empty()).then(|| p.version.clone()),
            source: Some(lock.path.clone()),
        },
        message,
        remediation: None,
        reference: None,
    }
}

// ── Lockfile policies ─────────────────────────────────────────────────────────

/// The registry a format means when it records none.
fn default_registry(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "https://registry.npmjs.org",
        Ecosystem::PyPI => "https://pypi.org/simple",
        Ecosystem::Cargo => "https://github.com/rust-lang/crates.io-index",
        Ecosystem::Go => "https://proxy.golang.org",
    }
}

fn norm_url(u: &str) -> String {
    u.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Formats that record an integrity hash for each registry package, so a
/// missing one means something. (Berry's checksum covers its own cache
/// archive; go.sum's hashes are not per-package here.)
fn records_integrity(lock: &Lockfile) -> bool {
    match lock.format {
        Format::YarnBerry | Format::GoMod | Format::GoSum => false,
        // Hashes are optional in requirements files: only expect them once
        // the file uses them.
        Format::Requirements => lock.dependencies().any(|p| p.integrity.is_some()),
        _ => true,
    }
}

fn lockfile_policies(lock: &Lockfile, policy: &SupplyChainConfig, report: &mut Report) {
    let mut unbound: Vec<String> = Vec::new();
    for p in lock.dependencies() {
        // Registry binding and dependency confusion.
        if let Source::Registry { url } = &p.source {
            let rules: Vec<_> = policy
                .registries
                .iter()
                .filter(|r| {
                    r.ecosystems.is_empty()
                        || r.ecosystems.iter().any(|e| e == lock.ecosystem.osv())
                })
                .filter(|r| matches_internal(&p.name, std::slice::from_ref(&r.pattern)))
                .collect();
            let internal = matches_internal(&p.name, &policy.internal_packages);
            if (!rules.is_empty() || internal) && !lock.registry_recorded && url.is_none() {
                unbound.push(p.id());
            } else {
                let effective =
                    norm_url(url.as_deref().unwrap_or(default_registry(lock.ecosystem)));
                for rule in rules {
                    if effective != norm_url(&rule.url) {
                        record(
                            report,
                            Level::Fail,
                            package_finding(
                                "REGISTRY/Mismatch",
                                Level::Fail,
                                lock,
                                p,
                                format!(
                                    "must come from {}, but resolves from {effective}",
                                    rule.url
                                ),
                            ),
                        );
                    }
                }
                if internal && url.is_none() {
                    record(
                        report,
                        Level::Fail,
                        package_finding(
                            "REGISTRY/DependencyConfusion",
                            Level::Fail,
                            lock,
                            p,
                            format!(
                                "declared internal, but resolves from the public registry {effective}"
                            ),
                        ),
                    );
                }
            }
        }

        // Non-registry sources.
        let (rule, level, message) = match &p.source {
            Source::Git { url, rev } => {
                let pinned = rev
                    .as_deref()
                    .is_some_and(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()));
                if pinned {
                    continue;
                }
                (
                    "SOURCE/UnpinnedGit",
                    policy.sources.git,
                    format!("git dependency {url} is not pinned to a full commit hash"),
                )
            }
            Source::Url { url } => (
                "SOURCE/Url",
                policy.sources.url,
                format!("downloaded from {url}, outside any registry"),
            ),
            Source::Path { path } => (
                "SOURCE/Path",
                policy.sources.path,
                format!("local path dependency {path}"),
            ),
            Source::Registry { .. } => continue,
        };
        record(
            report,
            level,
            package_finding(rule, level, lock, p, message),
        );
    }

    if !unbound.is_empty() {
        report.checks.push(Check::incomplete(
            format!("registry-binding:{}", lock.path.display()),
            format!(
                "{:?} does not record which registry served {} package(s) covered by registry rules: {}",
                lock.format,
                unbound.len(),
                unbound.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }

    let level = policy.release.missing_integrity;
    if level != Level::Off && records_integrity(lock) {
        let missing: Vec<String> = lock
            .dependencies()
            .filter(|p| p.source.is_registry() && p.integrity.is_none())
            .map(Package::id)
            .collect();
        if !missing.is_empty() {
            record(
                report,
                level,
                Finding::in_file(
                    "LOCKFILE/MissingIntegrity",
                    severity(level),
                    &lock.path,
                    0,
                    format!(
                        "{} registry package(s) have no integrity hash: {}{}",
                        missing.len(),
                        missing
                            .iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", "),
                        if missing.len() > 5 { " …" } else { "" }
                    ),
                ),
            );
        }
    }
}

// ── Change detection ──────────────────────────────────────────────────────────

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git") // greengate: ignore — reading repository history
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn resolve_base(opts: &CheckOpts<'_>) -> Base {
    if opts.all {
        return Base::All("--all".to_string());
    }
    if git(opts.root, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        return Base::All("not a git repository".to_string());
    }
    if let Some(rev) = opts.base {
        return Base::Rev {
            rev: rev.to_string(),
            label: rev.to_string(),
        };
    }
    if let Ok(target) = std::env::var("GITHUB_BASE_REF")
        && !target.is_empty()
        && let Some(mb) = git(
            opts.root,
            &["merge-base", "HEAD", &format!("origin/{target}")],
        )
    {
        return Base::Rev {
            rev: mb,
            label: format!("merge base with origin/{target}"),
        };
    }
    Base::Rev {
        rev: "HEAD".to_string(),
        label: "HEAD (uncommitted changes)".to_string(),
    }
}

/// `lock` as it was at `rev`, or `None` if the file did not exist there.
fn at_revision(lock: &Lockfile, rev: &str) -> Option<Lockfile> {
    let dir = lock
        .path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = lock.path.file_name()?.to_string_lossy();
    let content = git(dir, &["show", &format!("{rev}:./{name}")])?;
    deps::parse(&lock.path, &content).ok()
}

// ── Gate ──────────────────────────────────────────────────────────────────────

struct Candidate {
    lock: usize,
    pkg: usize,
    /// The version this one replaces, when a base had the package.
    replaces: Option<String>,
}

pub fn run_deps_check(opts: CheckOpts<'_>) -> Result<Report> {
    let mut report = Report::new("deps-check");
    let found = deps::discover(opts.root, opts.exclude);
    for (path, err) in &found.failed {
        report.checks.push(Check::incomplete(
            format!("lockfile:{}", path.display()),
            format!("could not be read: {err}"),
        ));
    }
    if found.lockfiles.is_empty() && found.failed.is_empty() {
        anyhow::bail!(
            "No supported dependency files found under {}",
            opts.root.display()
        );
    }

    let base = resolve_base(&opts);
    let base_label = match &base {
        Base::All(why) => format!("every package ({why})"),
        Base::Rev { label, .. } => format!("packages changed since {label}"),
    };
    terminal::info(&format!("Release-risk checks cover {base_label}."));

    let previous: Vec<Option<HashMap<String, Vec<String>>>> = found
        .lockfiles
        .iter()
        .map(|lock| match &base {
            Base::All(_) => None,
            Base::Rev { rev, .. } => Some(
                at_revision(lock, rev)
                    .as_ref()
                    .map_or_else(HashMap::new, versions_by_name),
            ),
        })
        .collect();
    let checked = evaluate(
        &found.lockfiles,
        &previous,
        &base_label,
        opts.policy,
        opts.now,
        &mut report,
    )?;
    print_report(&report, checked);
    Ok(report)
}

/// Evaluate supply-chain policy on `lockfiles`. `previous[i]` holds the
/// versions each package name had at the base for `lockfiles[i]`; `None`
/// checks every package's release against the registry. Returns how many
/// releases were looked up.
pub fn evaluate(
    lockfiles: &[Lockfile],
    previous: &[Option<HashMap<String, Vec<String>>>],
    base_label: &str,
    policy: &SupplyChainConfig,
    now: u64,
    report: &mut Report,
) -> Result<usize> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut private: usize = 0;
    for (li, lock) in lockfiles.iter().enumerate() {
        if !lock.unresolved.is_empty() {
            report.checks.push(Check::incomplete(
                format!("lockfile:{}", lock.path.display()),
                format!(
                    "{} entr(y/ies) could not be pinned and were not checked",
                    lock.unresolved.len()
                ),
            ));
        }
        lockfile_policies(lock, policy, report);

        let previous = previous.get(li).and_then(Option::as_ref);
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut changed = 0usize;
        for (pi, p) in lock.packages.iter().enumerate() {
            if p.member
                || p.version.is_empty()
                || !seen.insert((p.name.clone(), p.version.clone()))
            {
                continue;
            }
            let replaces = match previous {
                Some(prev) => match prev.get(&p.name) {
                    Some(versions) if versions.contains(&p.version) => continue,
                    Some(versions) => registry::highest(lock.ecosystem, versions),
                    None => None,
                },
                None => None,
            };
            changed += 1;
            match &p.source {
                Source::Registry { url: None } if lock.ecosystem != Ecosystem::Go => candidates
                    .push(Candidate {
                        lock: li,
                        pkg: pi,
                        replaces,
                    }),
                // Your own registry's packages are governed by its controls,
                // and their metadata is usually behind authentication.
                Source::Registry { url: Some(_) } => private += 1,
                _ => {}
            }
        }
        report.checks.push(
            Check::passed(format!("release-scope:{}", lock.path.display()))
                .with_source(format!("{changed} package(s) checked: {base_label}")),
        );
    }
    if private > 0 {
        terminal::info(&format!(
            "{private} package(s) from private registries: release metadata not checked."
        ));
    }

    // Registry lookups, a few at a time.
    let pool = rayon::ThreadPoolBuilder::new().num_threads(8).build()?;
    let lookups: Vec<Lookup> = pool.install(|| {
        candidates
            .par_iter()
            .map(|c| {
                let lock = &lockfiles[c.lock];
                let p = &lock.packages[c.pkg];
                registry::lookup(lock.ecosystem, &p.name, &p.version, None)
            })
            .collect()
    });

    let mut unavailable: Vec<String> = Vec::new();
    // (finding index into report.findings or warnings, candidate) for cooldown exemptions
    let mut young: Vec<(usize, Level, Finding)> = Vec::new();
    for (ci, (c, lookup)) in candidates.iter().zip(lookups).enumerate() {
        let lock = &lockfiles[c.lock];
        let p = &lock.packages[c.pkg];
        match lookup {
            Lookup::Found(h) => {
                for s in release_signals(&h, &policy.release, now) {
                    let mut finding = package_finding(s.rule, s.level, lock, p, s.message);
                    if let Some(from) = &c.replaces {
                        finding
                            .message
                            .push_str(&format!(" (upgraded from {from})"));
                    }
                    if s.rule == "RELEASE/YoungRelease" && c.replaces.is_some() {
                        young.push((ci, s.level, finding));
                    } else {
                        record(report, s.level, finding);
                    }
                }
            }
            Lookup::Missing => record(
                report,
                policy.release.withdrawn,
                package_finding(
                    "RELEASE/Withdrawn",
                    policy.release.withdrawn,
                    lock,
                    p,
                    "this version is not on the registry (unpublished or never published there)"
                        .into(),
                ),
            ),
            Lookup::Unavailable(why) => unavailable.push(format!("{}: {why}", p.id())),
        }
    }

    // Cooldown exemption: a young upgrade that fixes an advisory affecting
    // the version it replaces should not be held back.
    if !young.is_empty() {
        let pairs: Vec<(&str, &str, &str)> = young
            .iter()
            .flat_map(|(ci, _, _)| {
                let c = &candidates[*ci];
                let lock = &lockfiles[c.lock];
                let p = &lock.packages[c.pkg];
                let eco = lock.ecosystem.osv();
                [
                    (eco, p.name.as_str(), c.replaces.as_deref().unwrap_or("")),
                    (eco, p.name.as_str(), p.version.as_str()),
                ]
            })
            .collect();
        let ids = crate::modules::audit::advisory_ids(&pairs);
        for (i, (_, level, mut finding)) in young.into_iter().enumerate() {
            let fixed: Vec<String> = ids
                .as_ref()
                .map(|ids| {
                    let (old, new) = (&ids[2 * i], &ids[2 * i + 1]);
                    old.iter().filter(|id| !new.contains(id)).cloned().collect()
                })
                .unwrap_or_default();
            if fixed.is_empty() {
                record(report, level, finding);
            } else {
                finding.message.push_str(&format!(
                    " — exempt from the cooldown: it fixes {} affecting the version it replaces",
                    fixed.join(", ")
                ));
                record(report, Level::Warn, finding);
            }
        }
    }

    if !unavailable.is_empty() {
        report.checks.push(Check::incomplete(
            "registry-metadata",
            format!(
                "{} release(s) not checked: {}{}",
                unavailable.len(),
                unavailable
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; "),
                if unavailable.len() > 3 { " …" } else { "" }
            ),
        ));
    } else if !candidates.is_empty() {
        report.checks.push(Check::passed("registry-metadata"));
    }

    Ok(candidates.len())
}

/// Package name → versions, for comparing a lockfile against an older one.
pub fn versions_by_name(lock: &Lockfile) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for p in lock.dependencies() {
        m.entry(p.name.clone()).or_default().push(p.version.clone());
    }
    m
}

pub(crate) fn print_report(report: &Report, checked: usize) {
    let line = |f: &Finding| {
        let what = match &f.location {
            Location::Package {
                name,
                version,
                source,
                ..
            } => format!(
                "{name}{} ({})",
                version
                    .as_deref()
                    .map(|v| format!("@{v}"))
                    .unwrap_or_default(),
                source
                    .as_deref()
                    .map(Path::display)
                    .map(|d| d.to_string())
                    .unwrap_or_default()
            ),
            Location::File { path, .. } => path.display().to_string(),
            _ => String::new(),
        };
        format!("  [{}] {what} — {}", f.rule, f.message)
    };
    if !report.warnings.is_empty() {
        terminal::warn(&format!("{} warning(s):", report.warnings.len()));
        for f in &report.warnings {
            eprintln!("{}", line(f));
        }
    }
    if !report.findings.is_empty() {
        eprintln!("\n🚨 {} policy violation(s):", report.findings.len());
        for f in &report.findings {
            eprintln!("{}", line(f));
        }
    }
    report.print_unfinished();
    if report.findings.is_empty() && report.unfinished().next().is_none() {
        terminal::success(&format!(
            "deps check: no policy violations ({checked} release(s) checked against the registry)."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Release;

    const DAY: u64 = 86_400;

    fn rel(published: u64, script: bool, by: &str, prov: bool) -> Release {
        Release {
            published: Some(published),
            install_script: Some(script),
            publisher: Some(by.into()),
            provenance: Some(prov),
            withdrawn: None,
        }
    }

    fn rules(signals: &[Signal]) -> Vec<(&str, Level)> {
        signals.iter().map(|s| (s.rule, s.level)).collect()
    }

    #[test]
    fn a_compromised_looking_update_trips_every_signal() {
        let now = 100 * DAY;
        let h = History {
            this: Release {
                withdrawn: Some("do not use".into()),
                ..rel(now - 3600, true, "mallory", false)
            },
            previous: Some(("1.0.0".into(), rel(now - 30 * DAY, false, "alice", true))),
            earlier_publishers: vec!["alice".into()],
        };
        assert_eq!(
            rules(&release_signals(&h, &ReleasePolicy::default(), now)),
            [
                ("RELEASE/YoungRelease", Level::Warn),
                ("RELEASE/NewInstallScript", Level::Fail),
                ("RELEASE/ProvenanceRegression", Level::Fail),
                ("RELEASE/PublisherChange", Level::Warn),
                ("RELEASE/Withdrawn", Level::Warn),
            ]
        );
    }

    #[test]
    fn an_ordinary_update_is_quiet() {
        let now = 100 * DAY;
        let h = History {
            this: rel(now - 10 * DAY, false, "bob", true),
            previous: Some(("1.0.0".into(), rel(now - 30 * DAY, false, "alice", true))),
            // A co-maintainer who has published before: routine rotation.
            earlier_publishers: vec!["alice".into(), "bob".into()],
        };
        assert!(release_signals(&h, &ReleasePolicy::default(), now).is_empty());
    }

    #[test]
    fn a_new_publisher_with_provenance_is_not_flagged() {
        // e.g. a move to npm trusted publishing ("GitHub Actions").
        let now = 100 * DAY;
        let h = History {
            this: rel(now - 10 * DAY, false, "GitHub Actions", true),
            previous: Some(("1.0.0".into(), rel(now - 30 * DAY, false, "alice", false))),
            earlier_publishers: vec!["alice".into()],
        };
        assert!(release_signals(&h, &ReleasePolicy::default(), now).is_empty());
    }

    #[test]
    fn unknown_facts_never_trigger_signals() {
        // crates.io does not expose install scripts; PyPI no publisher.
        let now = 100 * DAY;
        let unknown = Release {
            published: Some(now - 10 * DAY),
            ..Release::default()
        };
        let h = History {
            this: unknown.clone(),
            previous: Some(("1.0.0".into(), unknown)),
            earlier_publishers: Vec::new(),
        };
        assert!(release_signals(&h, &ReleasePolicy::default(), now).is_empty());
    }

    #[test]
    fn off_levels_are_silent() {
        let now = 100 * DAY;
        let h = History {
            this: rel(now, true, "b", false),
            previous: Some(("1.0.0".into(), rel(0, false, "a", true))),
            earlier_publishers: vec!["a".into()],
        };
        let off = ReleasePolicy {
            young_release: Level::Off,
            new_install_script: Level::Off,
            provenance_regression: Level::Off,
            publisher_change: Level::Off,
            ..ReleasePolicy::default()
        };
        assert!(release_signals(&h, &off, now).is_empty());
    }
}
