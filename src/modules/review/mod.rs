//! `greengate deps review` — what a change does to the dependency tree, and
//! whether that is acceptable.
//!
//! Every lockfile is compared with its version at the merge base. Each
//! package that was added, removed, upgraded or downgraded is listed with
//! the evidence a reviewer needs: how it gets into the project, its license,
//! the advisories the change introduces or fixes, release-risk signals and
//! registry/source policy. Each introduced advisory comes with the smallest
//! change that fixes it (see [`fix`]).
//!
//! `[dependency_review]` decides what fails the review; the rest is shown as
//! warnings. Exceptions in `.greengate/exceptions.toml` apply.

pub mod fix;
mod license;
mod manifest;
mod ranges;
mod render;

use crate::deps::{self, Ecosystem, Lockfile, Scope, Source};
use crate::modules::audit::{self, Advisory};
use crate::modules::deps_check::{lockfile_policies, release_signals};
use crate::modules::suppress;
use crate::registry::{self, Lookup, requirements};
use crate::report::{Check, Finding, Location, Report, Severity};
use crate::utils::config::{Config, Level, ReviewFailOn};
use crate::utils::terminal;
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum ReviewFormat {
    Text,
    /// A `greengate.deps-review/v1` document on stdout.
    Json,
    /// The pull-request comment, on stdout.
    Markdown,
}

pub struct ReviewOpts<'a> {
    pub root: &'a Path,
    /// Compare with the merge base of this ref and HEAD.
    pub base: Option<&'a str>,
    pub cfg: &'a Config,
    pub format: ReviewFormat,
    /// Post the review to the pull request (comment and check run).
    pub annotate: bool,
    pub policy: suppress::Policy,
    /// Current time, unix seconds.
    pub now: u64,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Added,
    Upgraded,
    Downgraded,
    Removed,
}

#[derive(Serialize, Debug, Clone)]
pub struct Signal {
    pub rule: &'static str,
    pub level: &'static str,
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct Change {
    pub lockfile: PathBuf,
    pub ecosystem: Ecosystem,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub kind: Kind,
    pub direct: bool,
    pub scope: Scope,
    /// How it gets into the project: member first, the package last.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub why: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Advisories affecting the new version but not the old one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub introduced: Vec<Advisory>,
    /// Advisories affecting the old version but not the new one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixed: Vec<Advisory>,
    /// Advisories affecting both.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub release: Vec<Signal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<fix::Guidance>,
    /// Index of the lockfile pair and of the package on the new side.
    #[serde(skip)]
    pair: usize,
    #[serde(skip)]
    head_index: Option<usize>,
}

impl Change {
    /// `1.0.0 → 1.1.0`, `+1.0.0`, `-1.0.0`.
    pub fn versions(&self) -> String {
        match (&self.from, &self.to) {
            (Some(f), Some(t)) => format!("{f} → {t}"),
            (None, Some(t)) => t.clone(),
            (Some(f), None) => f.clone(),
            (None, None) => String::new(),
        }
    }

    fn how(&self) -> String {
        match self.kind {
            Kind::Added => "added".to_string(),
            Kind::Removed => "removed".to_string(),
            Kind::Upgraded => format!("upgraded from {}", self.from.as_deref().unwrap_or("?")),
            Kind::Downgraded => format!("downgraded from {}", self.from.as_deref().unwrap_or("?")),
        }
    }
}

pub struct Review {
    pub base_rev: String,
    pub base_label: String,
    pub changes: Vec<Change>,
}

// ── Base revision ─────────────────────────────────────────────────────────────

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git") // greengate: ignore — fixed program, args from greengate
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The merge base with `base` (or the pull request's base branch); without
/// either, `HEAD`, so uncommitted changes are reviewed.
fn resolve_base(root: &Path, base: Option<&str>) -> Result<(String, String)> {
    if git(root, &["rev-parse", "--is-inside-work-tree"])
        .as_deref()
        .map(str::trim)
        != Some("true")
    {
        bail!(
            "deps review compares against git history; {} is not in a git repository",
            root.display()
        );
    }
    let target = base.map(str::to_string).or_else(|| {
        std::env::var("GITHUB_BASE_REF")
            .ok()
            .filter(|b| !b.is_empty())
            .map(|b| format!("origin/{b}"))
    });
    let Some(target) = target else {
        return Ok(("HEAD".into(), "HEAD (uncommitted changes)".into()));
    };
    let short = |s: &str| s.chars().take(8).collect::<String>();
    if let Some(mb) = git(root, &["merge-base", &target, "HEAD"]) {
        let mb = mb.trim().to_string();
        return Ok((
            mb.clone(),
            format!("merge base with {target} ({})", short(&mb)),
        ));
    }
    // No common history (or a bare commit): compare with the ref itself.
    match git(
        root,
        &["rev-parse", "--verify", &format!("{target}^{{commit}}")],
    ) {
        Some(rev) => Ok((rev.trim().to_string(), target)),
        None => bail!("{target} is not a git revision here"),
    }
}

/// `path` as it was at `rev`: `Ok(None)` when it did not exist.
fn at_revision(root: &Path, rev: &str, path: &Path) -> Result<Option<Lockfile>, String> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(root);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some(content) = git(dir, &["show", &format!("{rev}:./{name}")]) else {
        return Ok(None);
    };
    deps::parse(path, &content)
        .map(Some)
        .map_err(|e| format!("{e:#}"))
}

/// Lockfiles deleted since `rev`, as they were there.
fn deleted_lockfiles(
    root: &Path,
    rev: &str,
    exclude: &[String],
    report: &mut Report,
) -> Vec<Lockfile> {
    let mut excluded = globset::GlobSetBuilder::new();
    for p in exclude {
        if let Ok(g) = globset::Glob::new(p) {
            excluded.add(g);
        }
    }
    let excluded = excluded
        .build()
        .unwrap_or_else(|_| globset::GlobSet::empty());
    let Some(diff) = git(
        root,
        &["diff", "--name-status", "--relative", "--no-renames", rev],
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in diff.lines() {
        let Some(rel) = line.strip_prefix("D\t") else {
            continue;
        };
        let rel = Path::new(rel);
        if deps::format_of(rel).is_none() || excluded.is_match(rel) {
            continue;
        }
        match at_revision(root, rev, &root.join(rel)) {
            Ok(Some(lock)) => out.push(lock),
            Ok(None) => {}
            Err(e) => report.checks.push(Check::incomplete(
                format!("lockfile:{}", root.join(rel).display()),
                format!("could not be read at the base: {e}"),
            )),
        }
    }
    out
}

// ── Diff ──────────────────────────────────────────────────────────────────────

fn name_key(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::PyPI => deps::normalize_python(name),
        _ => name.to_string(),
    }
}

fn by_name(lock: &Lockfile) -> BTreeMap<String, Vec<usize>> {
    let mut m: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, p) in lock.packages.iter().enumerate() {
        if !p.member && !p.version.is_empty() {
            m.entry(name_key(lock.ecosystem, &p.name))
                .or_default()
                .push(i);
        }
    }
    m
}

fn chain(lock: &Lockfile, idx: usize) -> Vec<String> {
    lock.why(idx)
        .map(|path| path.iter().map(|&i| lock.packages[i].id()).collect())
        .unwrap_or_default()
}

/// The changes between `base` and `head` (the same lockfile at two points).
fn diff(pair: usize, base: Option<&Lockfile>, head: Option<&Lockfile>) -> Vec<Change> {
    let Some(any) = head.or(base) else {
        return Vec::new();
    };
    let eco = any.ecosystem;
    let empty = BTreeMap::new();
    let b = base.map(by_name);
    let h = head.map(by_name);
    let (b, h) = (b.as_ref().unwrap_or(&empty), h.as_ref().unwrap_or(&empty));
    let head_direct: HashSet<usize> = head
        .map(|l| l.direct().into_iter().collect())
        .unwrap_or_default();
    let base_direct: HashSet<usize> = base
        .map(|l| l.direct().into_iter().collect())
        .unwrap_or_default();
    let order = |l: &Lockfile, v: &mut Vec<usize>| {
        v.sort_by(|&x, &y| {
            let (a, c) = (&l.packages[x].version, &l.packages[y].version);
            if requirements::less(eco, a, c) == Some(true) {
                std::cmp::Ordering::Less
            } else if requirements::less(eco, c, a) == Some(true) {
                std::cmp::Ordering::Greater
            } else {
                a.cmp(c)
            }
        });
        v.dedup_by(|x, y| l.packages[*x].version == l.packages[*y].version);
    };
    let mut out = Vec::new();
    let names: std::collections::BTreeSet<&String> = b.keys().chain(h.keys()).collect();
    for name in names {
        let mut old: Vec<usize> = b.get(name).cloned().unwrap_or_default();
        let mut new: Vec<usize> = h.get(name).cloned().unwrap_or_default();
        if let Some(base) = base {
            order(base, &mut old);
        }
        if let Some(head) = head {
            order(head, &mut new);
        }
        // Versions on both sides did not change.
        let (Some(base_l), Some(head_l)) = (base.or(head), head.or(base)) else {
            continue;
        };
        let old_v: HashSet<&str> = old
            .iter()
            .map(|&i| base_l.packages[i].version.as_str())
            .collect();
        let new_v: HashSet<&str> = new
            .iter()
            .map(|&i| head_l.packages[i].version.as_str())
            .collect();
        old.retain(|&i| !new_v.contains(base_l.packages[i].version.as_str()));
        new.retain(|&i| !old_v.contains(head_l.packages[i].version.as_str()));

        let make = |kind: Kind, o: Option<usize>, n: Option<usize>| {
            let (lock, idx, direct) = match n {
                Some(n) => (head_l, n, head_direct.contains(&n)),
                None => (
                    base_l,
                    o.unwrap_or(0),
                    base_direct.contains(&o.unwrap_or(0)),
                ),
            };
            let p = &lock.packages[idx];
            Change {
                lockfile: any.path.clone(),
                ecosystem: eco,
                name: p.name.clone(),
                from: o.map(|i| base_l.packages[i].version.clone()),
                to: n.map(|i| head_l.packages[i].version.clone()),
                kind,
                direct,
                scope: p.scope,
                why: chain(lock, idx),
                license: None,
                introduced: Vec::new(),
                fixed: Vec::new(),
                remaining: Vec::new(),
                release: Vec::new(),
                fix: None,
                pair,
                head_index: n,
            }
        };
        let paired = old.len().min(new.len());
        for k in 0..paired {
            let (o, n) = (old[k], new[k]);
            let up = requirements::less(
                eco,
                &base_l.packages[o].version,
                &head_l.packages[n].version,
            ) != Some(false);
            out.push(make(
                if up { Kind::Upgraded } else { Kind::Downgraded },
                Some(o),
                Some(n),
            ));
        }
        for &n in &new[paired..] {
            out.push(make(Kind::Added, None, Some(n)));
        }
        for &o in &old[paired..] {
            out.push(make(Kind::Removed, Some(o), None));
        }
    }
    out
}

// ── Gate ──────────────────────────────────────────────────────────────────────

fn level_str(level: Level) -> &'static str {
    match level {
        Level::Fail => "fail",
        Level::Warn => "warn",
        Level::Off => "off",
    }
}

fn change_finding(c: &Change, rule: &str, severity: Severity, message: String) -> Finding {
    let mut f = Finding::package(rule, severity, c.ecosystem.osv(), &c.name, message);
    if let Location::Package {
        version, source, ..
    } = &mut f.location
    {
        *version = c.to.clone().or_else(|| c.from.clone());
        *source = Some(c.lockfile.clone());
    }
    f
}

pub fn run_review(opts: ReviewOpts<'_>) -> Result<Report> {
    let cfg = opts.cfg;
    let policy = &cfg.dependency_review;
    let fails = |k: ReviewFailOn| policy.fail_on.contains(&k);
    let mut report = Report::new("deps-review");
    let text = opts.format == ReviewFormat::Text;

    let (rev, label) = resolve_base(opts.root, opts.base)?;
    report
        .checks
        .push(Check::passed("review:base").with_source(label.clone()));
    if text {
        terminal::info(&format!("Reviewing dependency changes since {label}..."));
    }

    // Lockfile pairs: (base, head).
    let found = deps::discover(opts.root, &cfg.deps.exclude_patterns);
    for (path, err) in &found.failed {
        report.checks.push(Check::incomplete(
            format!("lockfile:{}", path.display()),
            format!("could not be read: {err}"),
        ));
    }
    let mut pairs: Vec<(Option<Lockfile>, Option<Lockfile>)> = Vec::new();
    for head in found.lockfiles {
        if !head.unresolved.is_empty() {
            report.checks.push(Check::incomplete(
                format!("lockfile:{}", head.path.display()),
                format!(
                    "{} entr(y/ies) could not be pinned and were not reviewed",
                    head.unresolved.len()
                ),
            ));
        }
        let base = match at_revision(opts.root, &rev, &head.path) {
            Ok(b) => b,
            Err(e) => {
                report.checks.push(Check::incomplete(
                    format!("lockfile:{}", head.path.display()),
                    format!("could not be read at the base: {e}"),
                ));
                continue;
            }
        };
        pairs.push((base, Some(head)));
    }
    for gone in deleted_lockfiles(opts.root, &rev, &cfg.deps.exclude_patterns, &mut report) {
        pairs.push((Some(gone), None));
    }

    let mut changes: Vec<Change> = pairs
        .iter()
        .enumerate()
        .flat_map(|(i, (b, h))| diff(i, b.as_ref(), h.as_ref()))
        .collect();
    let head_of = |c: &Change| pairs[c.pair].1.as_ref().zip(c.head_index);

    // ── Advisories, old and new side ─────────────────────────────────────────
    let mut queries: Vec<(Ecosystem, String, String)> = Vec::new();
    for c in &changes {
        if let Some(to) = &c.to {
            queries.push((c.ecosystem, c.name.clone(), to.clone()));
        }
        if let Some(from) = &c.from {
            queries.push((c.ecosystem, c.name.clone(), from.clone()));
        }
    }
    queries.sort();
    queries.dedup();
    let answers = audit::advisories(&queries, &cfg.audit, &mut report.checks);
    let advisories: HashMap<&(Ecosystem, String, String), &Vec<Advisory>> =
        queries.iter().zip(&answers).collect();
    let none: Vec<Advisory> = Vec::new();
    for c in &mut changes {
        let get = |v: &Option<String>| {
            v.as_ref()
                .and_then(|v| {
                    advisories
                        .get(&(c.ecosystem, c.name.clone(), v.clone()))
                        .copied()
                })
                .unwrap_or(&none)
        };
        let (old, new) = (get(&c.from), get(&c.to));
        let ids = |list: &Vec<Advisory>| list.iter().map(|a| a.id.clone()).collect::<HashSet<_>>();
        let (old_ids, new_ids) = (ids(old), ids(new));
        c.introduced = new
            .iter()
            .filter(|a| !old_ids.contains(&a.id))
            .cloned()
            .collect();
        c.fixed = old
            .iter()
            .filter(|a| !new_ids.contains(&a.id))
            .cloned()
            .collect();
        c.remaining = new
            .iter()
            .filter(|a| old_ids.contains(&a.id))
            .map(|a| a.id.clone())
            .collect();
    }

    // ── Registry metadata: release risk and license ──────────────────────────
    let lookups_for: Vec<usize> = changes
        .iter()
        .enumerate()
        .filter(|(_, c)| c.to.is_some() && c.ecosystem != Ecosystem::Go)
        .filter(|(_, c)| {
            head_of(c).is_some_and(|(l, i)| {
                matches!(l.packages[i].source, Source::Registry { url: None })
            })
        })
        .map(|(i, _)| i)
        .collect();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(8).build()?;
    let lookups: Vec<Lookup> = pool.install(|| {
        lookups_for
            .par_iter()
            .map(|&i| {
                let c = &changes[i];
                registry::lookup(c.ecosystem, &c.name, c.to.as_deref().unwrap_or(""), None)
            })
            .collect()
    });
    let mut unavailable: Vec<String> = Vec::new();
    for (&i, lookup) in lookups_for.iter().zip(lookups) {
        let c = &mut changes[i];
        match lookup {
            Lookup::Found(h) => {
                c.license = h
                    .this
                    .license
                    .as_deref()
                    .and_then(license::normalize)
                    .or(h.this.license.clone());
                for s in release_signals(&h, &cfg.supply_chain.release, opts.now) {
                    let mut level = s.level;
                    let mut message = s.message;
                    // A young release that fixes advisories in the version it
                    // replaces should not be held back.
                    if s.rule == "RELEASE/YoungRelease" && !c.fixed.is_empty() {
                        level = Level::Warn;
                        message.push_str(&format!(
                            " — exempt from the cooldown: it fixes {}",
                            c.fixed
                                .iter()
                                .map(|a| a.id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    c.release.push(Signal {
                        rule: s.rule,
                        level: level_str(level),
                        message,
                    });
                }
            }
            Lookup::Missing => c.release.push(Signal {
                rule: "RELEASE/Withdrawn",
                level: level_str(cfg.supply_chain.release.withdrawn),
                message:
                    "this version is not on the registry (unpublished or never published there)"
                        .into(),
            }),
            Lookup::Unavailable(why) => unavailable.push(format!(
                "{}@{}: {why}",
                c.name,
                c.to.as_deref().unwrap_or("")
            )),
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
    } else if !lookups_for.is_empty() {
        report.checks.push(Check::passed("registry-metadata"));
    }

    // ── Fix guidance for introduced advisories ───────────────────────────────
    let mut ctx = fix::Ctx::default();
    for c in &mut changes {
        if c.introduced.is_empty() {
            continue;
        }
        if let Some((lock, idx)) = pairs[c.pair].1.as_ref().zip(c.head_index) {
            c.fix = Some(fix::guidance(lock, idx, &c.introduced, &mut ctx));
        }
    }
    if !ctx.unavailable.is_empty() {
        report.checks.push(Check::incomplete(
            "fix-guidance",
            format!(
                "registry metadata for fix guidance unavailable: {}",
                ctx.unavailable
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ));
    }

    // ── Policy ───────────────────────────────────────────────────────────────
    let push = |report: &mut Report, fail: bool, f: Finding| {
        if fail {
            report.findings.push(f);
        } else {
            report.warnings.push(f);
        }
    };
    for c in &changes {
        if c.to.is_none() {
            continue;
        }
        for a in &c.introduced {
            let mut f = change_finding(
                c,
                &format!("OSV/{}", a.id),
                a.severity,
                format!(
                    "{} ({}, {})",
                    a.summary,
                    c.how(),
                    if c.direct { "direct" } else { "transitive" }
                ),
            );
            f.reference = a.reference.clone();
            f.remediation = c.fix.as_ref().and_then(render::first_step);
            let blocking =
                fails(ReviewFailOn::NewAdvisory) && policy.fail_on_severity.met_by(a.severity);
            push(&mut report, blocking, f);
        }
        for s in &c.release {
            let level = if s.level == "fail" {
                Level::Fail
            } else {
                Level::Warn
            };
            let f = change_finding(
                c,
                s.rule,
                if level == Level::Fail {
                    Severity::High
                } else {
                    Severity::Medium
                },
                s.message.clone(),
            );
            push(
                &mut report,
                level == Level::Fail && fails(ReviewFailOn::ReleaseRisk),
                f,
            );
        }
        let looked_up = head_of(c)
            .is_some_and(|(l, i)| matches!(l.packages[i].source, Source::Registry { url: None }))
            && c.ecosystem != Ecosystem::Go;
        if looked_up {
            match license::verdict(
                c.license.as_deref(),
                &policy.deny_licenses,
                &policy.allow_licenses,
            ) {
                license::Verdict::Allowed => {}
                license::Verdict::Denied(ids) => push(
                    &mut report,
                    fails(ReviewFailOn::DeniedLicense),
                    change_finding(
                        c,
                        "LICENSE/Denied",
                        Severity::High,
                        format!(
                            "license {} is not allowed ({})",
                            c.license.as_deref().unwrap_or("?"),
                            ids.join(", ")
                        ),
                    ),
                ),
                license::Verdict::Unknown if policy.unknown_license != Level::Off => push(
                    &mut report,
                    policy.unknown_license == Level::Fail,
                    change_finding(
                        c,
                        "LICENSE/Unknown",
                        Severity::Medium,
                        match &c.license {
                            Some(l) => format!("license {l:?} is not an SPDX expression"),
                            None => "the registry records no license".to_string(),
                        },
                    ),
                ),
                license::Verdict::Unknown => {}
            }
        }
    }
    // Registry and source rules, for the packages this change brings in.
    for (b, h) in &pairs {
        let (Some(head), _) = (h, b) else { continue };
        let changed: HashSet<(String, String)> = changes
            .iter()
            .filter(|c| c.lockfile == head.path)
            .filter_map(|c| Some((c.name.clone(), c.to.clone()?)))
            .collect();
        if changed.is_empty() {
            continue;
        }
        let mut tmp = Report::new("deps-review");
        lockfile_policies(head, &cfg.supply_chain, &mut tmp);
        let ours = |f: &Finding| match &f.location {
            Location::Package { name, version, .. } => {
                changed.contains(&(name.clone(), version.clone().unwrap_or_default()))
            }
            _ => false,
        };
        for f in tmp.findings.into_iter().filter(ours) {
            push(&mut report, fails(ReviewFailOn::SourcePolicy), f);
        }
        report
            .warnings
            .extend(tmp.warnings.into_iter().filter(ours));
    }

    // Exceptions apply to review findings too.
    let outcome = suppress::apply(
        &mut report.findings,
        &suppress::Options {
            tool: "deps-review",
            policy: suppress::Policy {
                baseline: suppress::BaselineMode::Off,
                ..opts.policy
            },
            matcher: None,
            base: None,
        },
    )?;
    let findings = std::mem::take(&mut report.findings);
    let (kept, gone) = suppress::partition(findings, &outcome.verdicts);
    report.findings = kept;
    report.suppressed = gone
        .into_iter()
        .map(|(mut f, s)| {
            f.suppression = Some(s);
            f
        })
        .collect();
    report.warnings.extend(outcome.warnings);

    changes.sort_by(|a, b| (&a.lockfile, a.kind, &a.name).cmp(&(&b.lockfile, b.kind, &b.name)));
    let review = Review {
        base_rev: rev,
        base_label: label,
        changes,
    };

    match opts.format {
        ReviewFormat::Text => {
            render::text(&review, &report);
            suppress::print_summary(&outcome.notes, &report.suppressed);
            report.print_unfinished();
        }
        ReviewFormat::Markdown => println!("{}", render::markdown(&review, &report)),
        ReviewFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&render::json(&review, &report))?
        ),
    }
    if opts.annotate {
        match crate::modules::github::detect_github_env() {
            Some(env) => {
                let annotations = render::annotations(&report);
                let body = render::markdown(&review, &report);
                if let Err(e) =
                    crate::modules::github::post_review(&env, &body, &annotations, report.status())
                        .context("could not post the review to GitHub")
                {
                    terminal::warn(&format!("{e:#}"));
                }
            }
            None => terminal::warn(
                "--annotate needs GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_SHA; nothing was posted",
            ),
        }
    }
    Ok(report)
}

/// The marker in greengate's review comment.
pub fn render_marker() -> &'static str {
    render::MARKER
}

/// The line of `lockfile` that records `name@version`, for annotations.
pub fn lockfile_line(lockfile: &Path, name: &str, version: Option<&str>) -> Option<usize> {
    let text = std::fs::read_to_string(lockfile).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let names = |l: &str| {
        l.contains(&format!("\"{name}\""))
            || l.contains(&format!("/{name}\""))
            || l.contains(&format!("{name}@"))
            || l.contains(&format!("'{name}"))
            || l.trim_start().starts_with(&format!("name = \"{name}\""))
            || l.trim_start().starts_with(&format!("{name}=="))
            || l.trim_start().starts_with(&format!("{name} "))
    };
    let mut first = None;
    for (i, l) in lines.iter().enumerate() {
        if !names(l) {
            continue;
        }
        first.get_or_insert(i + 1);
        let Some(v) = version else {
            return Some(i + 1);
        };
        // The entry runs until the next line that names the package again.
        let end = (i + 1..lines.len().min(i + 5))
            .find(|&k| names(lines[k]))
            .unwrap_or(lines.len().min(i + 5));
        if lines[i..end].iter().any(|n| n.contains(v)) {
            return Some(i + 1);
        }
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Package;

    fn lock(pkgs: &[(&str, &str)]) -> Lockfile {
        let mut l = Lockfile::new_for_tests();
        let app = l.add(Package::member("app", "1.0.0", "."));
        for (n, v) in pkgs {
            let i = l.add(Package::new(*n, *v, Source::registry()));
            l.link(app, i);
        }
        l
    }

    fn kinds(changes: &[Change]) -> Vec<(String, Kind, String)> {
        let mut v: Vec<_> = changes
            .iter()
            .map(|c| (c.name.clone(), c.kind, c.versions()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn classifies_changes() {
        let base = lock(&[
            ("a", "1.0.0"),
            ("b", "2.0.0"),
            ("c", "1.0.0"),
            ("same", "1.0.0"),
        ]);
        let head = lock(&[
            ("a", "1.1.0"),
            ("b", "1.9.0"),
            ("d", "0.1.0"),
            ("same", "1.0.0"),
        ]);
        assert_eq!(
            kinds(&diff(0, Some(&base), Some(&head))),
            [
                ("a".into(), Kind::Upgraded, "1.0.0 → 1.1.0".into()),
                ("b".into(), Kind::Downgraded, "2.0.0 → 1.9.0".into()),
                ("c".into(), Kind::Removed, "1.0.0".into()),
                ("d".into(), Kind::Added, "0.1.0".into()),
            ]
        );
    }

    #[test]
    fn multiple_versions_pair_in_order() {
        // npm can hold two copies; one moved, one stayed.
        let base = lock(&[("x", "1.0.0"), ("x", "2.0.0")]);
        let head = lock(&[("x", "2.0.0"), ("x", "1.0.5"), ("x", "3.0.0")]);
        assert_eq!(
            kinds(&diff(0, Some(&base), Some(&head))),
            [
                ("x".into(), Kind::Added, "3.0.0".into()),
                ("x".into(), Kind::Upgraded, "1.0.0 → 1.0.5".into()),
            ]
        );
    }

    #[test]
    fn a_new_lockfile_is_all_additions() {
        let head = lock(&[("a", "1.0.0")]);
        let c = diff(0, None, Some(&head));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, Kind::Added);
        assert!(c[0].direct);
        assert_eq!(c[0].why, ["app@1.0.0", "a@1.0.0"]);
    }

    #[test]
    fn finds_lockfile_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("package-lock.json");
        std::fs::write(
            &p,
            "{\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"version\": \"4.17.20\"\n    },\n    \"node_modules/x/node_modules/lodash\": {\n      \"version\": \"3.0.0\"\n    }\n  }\n}\n",
        )
        .unwrap();
        assert_eq!(lockfile_line(&p, "lodash", Some("4.17.20")), Some(3));
        assert_eq!(lockfile_line(&p, "lodash", Some("3.0.0")), Some(6));
        let c = dir.path().join("Cargo.lock");
        std::fs::write(&c, "[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n").unwrap();
        assert_eq!(lockfile_line(&c, "serde", Some("1.0.1")), Some(2));
    }
}
