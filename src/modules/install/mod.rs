//! `greengate install` — install dependencies with no package code running
//! before greengate has looked at the complete tree.
//!
//! Phases (each is a check in the report):
//!
//! 1. **Plan** — resolve the full tree into a lockfile in a scratch copy of
//!    the project (no downloads of package code, no scripts) and apply the
//!    `deps check` policies to everything it adds or changes.
//! 2. **Fetch** — download and extract the planned tree with scripts off.
//! 3. **Verify artifacts** — the package manager checks each tarball against
//!    the lockfile's integrity; greengate checks nothing unplanned arrived.
//! 4. **Inspect** — every package that wants to run code at install time,
//!    including the helper files its scripts call.
//! 5. **Execute** — run approved scripts one package at a time, dependencies
//!    first: in a sandbox when available (no network, writes confined to the
//!    package, credentials masked), always with a scrubbed environment.
//! 6. **Verify files** — unisolated, compare the tree before and after each
//!    script and watch for files that appear and vanish.
//!
//! `--plan` stops after phase 4 and changes nothing in the project.

mod cargo;
mod inspect;
mod js;
mod npm;
mod pip;
mod pnpm;
pub mod sandbox;

use crate::deps::Lockfile;
use crate::modules::{deps_check, slopsquat};
use crate::report::{Check, Finding, Report, Severity};
use crate::utils::config::SupplyChainConfig;
use crate::utils::terminal;
use anyhow::{Result, bail};
use sandbox::IsolateMode;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct InstallOpts<'a> {
    pub manager: String,
    pub args: Vec<String>,
    pub plan_only: bool,
    pub isolate: IsolateMode,
    pub no_fail: bool,
    pub policy: &'a SupplyChainConfig,
    pub now: u64,
    /// pip / pip3 binary for pip installs.
    pub pip: String,
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("greengate-install-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn package_finding(
    rule: &str,
    severity: Severity,
    name: &str,
    version: &str,
    dir: &Path,
    message: String,
) -> Finding {
    let mut f = Finding::package(rule, severity, "", name, message);
    if let crate::report::Location::Package {
        ecosystem,
        version: v,
        source,
        ..
    } = &mut f.location
    {
        ecosystem.clear();
        *v = (!version.is_empty()).then(|| version.to_string());
        *source = Some(dir.to_path_buf());
    }
    f
}

/// Phase 1 policy: `deps check` on everything the planned lockfile adds or
/// changes relative to `current`, plus the name guard on packages named on
/// the command line.
fn plan_policy(
    report: &mut Report,
    planned: &Lockfile,
    current: Option<&Lockfile>,
    named: Option<(slopsquat::Ecosystem, &Vec<String>, &Vec<String>)>,
    opts: &InstallOpts<'_>,
) -> Result<()> {
    let label = if current.is_some() {
        "packages this install adds or changes"
    } else {
        "every package (nothing installed before)"
    };
    report
        .checks
        .push(Check::passed("install:plan").with_source(format!(
            "{} package(s) planned; release checks cover {label}",
            planned.dependencies().count()
        )));
    let previous = vec![current.map(deps_check::versions_by_name)];
    let checked = deps_check::evaluate(
        std::slice::from_ref(planned),
        &previous,
        label,
        opts.policy,
        opts.now,
        report,
    )?;
    if let Some((eco, names, allow)) = named
        && opts.policy.slopsquat_check
        && !names.is_empty()
    {
        let known: HashSet<String> = current
            .map(|c| c.dependencies().map(|p| p.name.clone()).collect())
            .unwrap_or_default();
        let policy = slopsquat::GuardPolicy {
            slop: slopsquat::SlopConfig {
                min_age_days: opts.policy.slopsquat_min_age_days,
                min_downloads: opts.policy.slopsquat_min_downloads,
            },
            internal_patterns: opts.policy.internal_packages.clone(),
        };
        let reports = slopsquat::guard(
            eco,
            names,
            allow,
            &|n| known.contains(n),
            &policy,
            &mut report.checks,
        );
        slopsquat::print_reports(eco, &reports);
        slopsquat::record(eco, &reports, report);
    }
    deps_check::print_report(report, checked);
    Ok(())
}

pub fn run_install(opts: InstallOpts<'_>) -> Result<Report> {
    match opts.manager.as_str() {
        "npm" => js::run(js::Js::Npm, opts),
        "pnpm" => js::run(js::Js::Pnpm, opts),
        "pip" | "pip3" => pip::run(opts),
        "cargo" => cargo::run(opts),
        other => bail!(
            "greengate install supports npm, pnpm, pip and cargo; for `{other}`, use `greengate watch-install {other}`"
        ),
    }
}

fn rel(p: &Path, base: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).display().to_string()
}

fn print_install(report: &Report, note: &str) {
    let tail_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.rule.starts_with("INSTALL/"))
        .collect();
    let tail_warnings: Vec<&Finding> = report
        .warnings
        .iter()
        .filter(|f| f.rule.starts_with("INSTALL/"))
        .collect();
    let show = |f: &Finding| {
        let who = match &f.location {
            crate::report::Location::Package { name, version, .. } => {
                format!(
                    "{name}{}",
                    version
                        .as_deref()
                        .map(|v| format!("@{v}"))
                        .unwrap_or_default()
                )
            }
            _ => String::new(),
        };
        eprintln!("  [{}] {who} — {}", f.rule, f.message);
    };
    if !tail_warnings.is_empty() {
        terminal::warn("Install-time warnings:");
        tail_warnings.into_iter().for_each(show);
    }
    if !tail_findings.is_empty() {
        eprintln!("\n🚨 Install-time violations:");
        tail_findings.into_iter().for_each(show);
    }
    report.print_unfinished();
    if !note.is_empty() {
        terminal::info(note);
    }
    if report.findings.is_empty() && report.unfinished().next().is_none() {
        for c in report
            .checks
            .iter()
            .filter(|c| c.id.starts_with("install:"))
        {
            if let Some(s) = &c.source {
                eprintln!("  {} — {s}", c.id);
            }
        }
        terminal::success("greengate install: done.");
    }
}
