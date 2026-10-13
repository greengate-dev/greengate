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
//!    package, private home, project secrets masked), always with an
//!    allowlisted environment. Unfinished checks stop the install before
//!    this phase (and before fetching) unless `on_incomplete = "warn"`.
//! 6. **Verify files** — unisolated, compare the tree before and after each
//!    script and watch for files that appear and vanish.
//!
//! `--plan` stops after phase 4 and changes nothing in the project.

mod bun;
mod cargo;
mod inspect;
mod js;
mod npm;
mod pip;
mod pnpm;
pub mod sandbox;
mod uv;
mod yarn;

use crate::deps::Lockfile;
use crate::modules::{deps_check, slopsquat};
use crate::report::{Check, Finding, OnIncomplete, Report, Severity, Status};
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
    /// `[policy] on_incomplete` (or `--allow-incomplete`): whether an
    /// unfinished check stops the install before package code runs.
    pub on_incomplete: OnIncomplete,
    pub policy: &'a SupplyChainConfig,
    /// Where advisories come from (`[audit] source`).
    pub audit: &'a crate::utils::config::AuditConfig,
    /// Which advisories block (`[dependency_review] fail_on_severity`).
    pub review: &'a crate::utils::config::DependencyReviewConfig,
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

/// Copies of files a plan step edits in place, restored when the install
/// is halted or only planned.
struct Backup(Vec<(PathBuf, Option<Vec<u8>>)>);

impl Backup {
    /// Back up `files`; each of `must_not_exist` that is absent now is
    /// removed again on restore.
    fn take(files: Vec<PathBuf>, must_not_exist: &[PathBuf]) -> Backup {
        let mut saved: Vec<(PathBuf, Option<Vec<u8>>)> = files
            .into_iter()
            .map(|p| {
                let bytes = std::fs::read(&p).ok();
                (p, bytes)
            })
            .collect();
        for p in must_not_exist {
            if !p.exists() && !saved.iter().any(|(s, _)| s == p) {
                saved.push((p.clone(), None));
            }
        }
        Backup(saved)
    }

    fn restore(&self) -> Result<()> {
        for (path, bytes) in &self.0 {
            match bytes {
                Some(b) => std::fs::write(path, b)?,
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        Ok(())
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

/// The gate between phases: whether the install stops here, before the next
/// phase downloads or runs package code. It stops on a blocking finding, on
/// a check that failed to run, and on one left incomplete unless
/// `on_incomplete` is `warn` — so a run that will exit non-zero never runs
/// package code first. The caller says what was (not) done.
fn must_halt(report: &Report, opts: &InstallOpts<'_>) -> bool {
    (!report.findings.is_empty() && !opts.no_fail) || unfinished(report, opts)
}

/// Whether a check failed to run or (under `on_incomplete = "fail"`) did
/// not finish — either way the run will not pass, so no package code may
/// run after it.
fn unfinished(report: &Report, opts: &InstallOpts<'_>) -> bool {
    let blocking = report
        .unfinished()
        .any(|c| c.status == Status::Error || opts.on_incomplete == OnIncomplete::Fail);
    if blocking {
        terminal::warn(
            "Not every check finished, and an unchecked dependency is not a safe one \
             (`--allow-incomplete` or [policy] on_incomplete = \"warn\" continues anyway).",
        );
    }
    blocking
}

/// `[supply_chain] require_isolation` with no sandbox: records that `what`
/// was not run and returns true, so the caller stops before running it.
fn isolation_missing(
    report: &mut Report,
    opts: &InstallOpts<'_>,
    isolation: sandbox::Isolation,
    what: &str,
) -> bool {
    if isolation != sandbox::Isolation::None || !opts.policy.require_isolation {
        return false;
    }
    report.checks.push(Check::incomplete(
        "install:execute",
        format!("no sandbox is available and [supply_chain] require_isolation is set — {what}"),
    ));
    print_install(report, "");
    true
}

/// Refuse caller arguments that would undo a flag greengate sets for a phase
/// (`--ignore-scripts=false`, `--no-package-lock-only`, `--mode skip-build`…),
/// and `--`, after which greengate's own flags would stop being flags. Each
/// of `owned` (without dashes) may only appear in its affirmative form; a
/// `name=value` entry allows exactly that value too.
fn reject_overrides(manager: &str, args: &[String], owned: &[&str]) -> Result<()> {
    for (i, a) in args.iter().enumerate() {
        if a == "--" {
            bail!(
                "`--` is not supported by greengate install: greengate adds its own {manager} flags after yours"
            );
        }
        let Some(flag) = a.strip_prefix("--") else {
            continue;
        };
        let (name, value) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (flag, None),
        };
        let negated = name.strip_prefix("no-");
        for o in owned {
            let (o_name, o_value) = match o.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (*o, None),
            };
            let next = args.get(i + 1).map(String::as_str);
            let affirmative = match (o_value, value) {
                (None, None) => !matches!(next, Some("false" | "0")),
                (None, Some(v)) => affirms(v),
                (Some(want), Some(v)) => want == v,
                (Some(want), None) => next == Some(want),
            };
            if negated == Some(o_name) || (name == o_name && !affirmative) {
                bail!(
                    "`{a}` conflicts with how greengate install runs {manager}: it sets `--{o_name}` itself so no package code runs before the checks"
                );
            }
        }
    }
    Ok(())
}

/// Whether a boolean flag's value turns it on, as npm, pnpm, Yarn and Bun
/// read it (`--flag=1` is `--flag=true`). [`reject_overrides`] and
/// [`ignore_scripts`] share it, so a value one accepts the other honours.
fn affirms(value: &str) -> bool {
    matches!(value, "true" | "1")
}

/// Whether the caller asked that no install scripts run at all. Negated
/// forms never get here: [`reject_overrides`] refuses them first.
fn ignore_scripts(args: &[String]) -> bool {
    args.iter().any(|a| {
        a == "--ignore-scripts" || a.strip_prefix("--ignore-scripts=").is_some_and(affirms)
    })
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
    advisories(report, planned, current, opts);
    deps_check::print_report(report, checked);
    Ok(())
}

/// Known advisories in the packages the plan adds or changes. They block at
/// or above `[dependency_review] fail_on_severity`, like a review of the
/// same change would, and warn below it.
fn advisories(
    report: &mut Report,
    planned: &Lockfile,
    current: Option<&Lockfile>,
    opts: &InstallOpts<'_>,
) {
    use crate::utils::config::ReviewFailOn;
    let before = current
        .map(deps_check::versions_by_name)
        .unwrap_or_default();
    let mut queries: Vec<(crate::deps::Ecosystem, String, String)> = planned
        .dependencies()
        // A local or git package of the same name is not the registry's.
        .filter(|p| !p.version.is_empty() && p.source.is_registry())
        .filter(|p| !before.get(&p.name).is_some_and(|v| v.contains(&p.version)))
        .map(|p| (planned.ecosystem, p.name.clone(), p.version.clone()))
        .collect();
    queries.sort();
    queries.dedup();
    if queries.is_empty() {
        return;
    }
    let answers = crate::modules::audit::advisories(&queries, opts.audit, &mut report.checks);
    let dir = std::env::current_dir().unwrap_or_default();
    let blocking = opts.review.fail_on.contains(&ReviewFailOn::NewAdvisory);
    for ((eco, name, version), list) in queries.iter().zip(answers) {
        // One version that clears every advisory, not each one's own fix.
        let target = list
            .iter()
            .filter_map(|a| a.fixed_in.clone())
            .reduce(|a, b| {
                if crate::registry::requirements::less(*eco, &a, &b) == Some(true) {
                    b
                } else {
                    a
                }
            });
        for a in list {
            let mut f = package_finding(
                &format!("OSV/{}", a.id),
                a.severity,
                name,
                version,
                &dir,
                a.summary.clone(),
            );
            f.remediation = target.as_ref().map(|v| format!("use {name} {v} or later"));
            f.reference = a.reference.clone();
            if blocking && opts.review.fail_on_severity.met_by(a.severity) {
                report.findings.push(f);
            } else {
                report.warnings.push(f);
            }
        }
    }
}

/// Whether `greengate install <manager> <args…>` can take over a legacy
/// wrapper's command line (`watch-install`, `pip-install`, `cargo-add`).
pub fn accepts(manager: &str, args: &[String]) -> bool {
    match manager {
        "npm" => npm::parse_args(args).is_ok(),
        "pnpm" => pnpm::parse_args(args).is_ok(),
        "yarn" => yarn::parse_args(args).is_ok(),
        "bun" => bun::parse_args(args).is_ok(),
        _ => false,
    }
}

/// pip 22.2+ writes the `--report` that `install pip` plans from.
pub fn pip_supports_report(pip: &str) -> bool {
    std::process::Command::new(pip) // greengate: ignore — reading pip's version
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            let out = String::from_utf8_lossy(&o.stdout).into_owned();
            let version = out
                .strip_prefix("pip ")?
                .split_whitespace()
                .next()?
                .to_string();
            let mut parts = version.split('.').filter_map(|p| p.parse::<u32>().ok());
            Some((parts.next()?, parts.next().unwrap_or(0)))
        })
        .is_some_and(|v| v >= (22, 2))
}

/// The one-line notice the legacy wrappers print.
pub fn deprecation(old: &str, routed: Option<&str>) {
    match routed {
        Some(new) => terminal::warn(&format!(
            "`greengate {old}` is deprecated and will be removed in 0.5 — running `greengate install {new}` \
             (install scripts run sandboxed; see `greengate install --help`)."
        )),
        None => terminal::warn(&format!(
            "`greengate {old}` is deprecated and will be removed in 0.5; use `greengate install` \
             (npm, pnpm, yarn, bun, pip, uv, cargo)."
        )),
    }
}

pub fn run_install(opts: InstallOpts<'_>) -> Result<Report> {
    match opts.manager.as_str() {
        "npm" => js::run(js::Js::Npm, opts),
        "pnpm" => js::run(js::Js::Pnpm, opts),
        "bun" => js::run(js::Js::Bun, opts),
        "yarn" => {
            let berry = yarn::is_berry(&std::env::current_dir()?);
            js::run(if berry { js::Js::Berry } else { js::Js::Yarn1 }, opts)
        }
        "pip" | "pip3" => pip::run(opts),
        "cargo" => cargo::run(opts),
        "uv" => uv::run(opts),
        other => bail!(
            "greengate install supports npm, pnpm, yarn, bun, pip, uv and cargo, not `{other}`"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::Config;

    fn opts(cfg: &Config, on_incomplete: OnIncomplete, no_fail: bool) -> InstallOpts<'_> {
        InstallOpts {
            manager: "npm".into(),
            args: Vec::new(),
            plan_only: false,
            isolate: IsolateMode::None,
            no_fail,
            on_incomplete,
            policy: &cfg.supply_chain,
            audit: &cfg.audit,
            review: &cfg.dependency_review,
            now: 0,
            pip: "pip".into(),
        }
    }

    #[test]
    fn unfinished_checks_halt_before_package_code_runs() {
        let cfg: Config = toml::from_str("").unwrap();
        let mut r = Report::new("install");
        r.checks.push(Check::passed("install:plan"));
        assert!(!must_halt(&r, &opts(&cfg, OnIncomplete::Fail, false)));

        r.checks
            .push(Check::incomplete("osv", "offline snapshot missing"));
        assert!(must_halt(&r, &opts(&cfg, OnIncomplete::Fail, false)));
        // `--no-fail` waives findings, not unchecked dependencies.
        assert!(must_halt(&r, &opts(&cfg, OnIncomplete::Fail, true)));
        assert!(!must_halt(&r, &opts(&cfg, OnIncomplete::Warn, false)));

        r.checks.push(Check::error("registry", "unreachable"));
        assert!(must_halt(&r, &opts(&cfg, OnIncomplete::Warn, false)));
    }

    #[test]
    fn require_isolation_stops_unisolated_runs() {
        let cfg: Config = toml::from_str("[supply_chain]\nrequire_isolation = true\n").unwrap();
        let o = opts(&cfg, OnIncomplete::Fail, false);
        let mut r = Report::new("install");
        assert!(!isolation_missing(
            &mut r,
            &o,
            sandbox::Isolation::Bwrap,
            "x"
        ));
        assert!(isolation_missing(&mut r, &o, sandbox::Isolation::None, "x"));
        assert_eq!(r.exit_code(OnIncomplete::Fail), 3);
    }

    #[test]
    fn overrides_of_phase_flags_are_refused() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let owned = &["ignore-scripts", "mode=skip-build"];
        assert!(reject_overrides("x", &a(&["--ignore-scripts"]), owned).is_ok());
        assert!(reject_overrides("x", &a(&["--mode=skip-build"]), owned).is_ok());
        assert!(reject_overrides("x", &a(&["--mode", "skip-build"]), owned).is_ok());
        for bad in [
            &["--ignore-scripts=false"][..],
            &["--no-ignore-scripts"],
            &["--ignore-scripts", "false"],
            &["--mode=update-lockfile"],
            &["--mode", "skip-cache"],
            &["--"],
        ] {
            assert!(reject_overrides("x", &a(bad), owned).is_err(), "{bad:?}");
        }
        // Every form the validator lets through as affirmative is honoured.
        for on in [
            "--ignore-scripts",
            "--ignore-scripts=true",
            "--ignore-scripts=1",
        ] {
            assert!(reject_overrides("x", &a(&[on]), owned).is_ok(), "{on}");
            assert!(ignore_scripts(&a(&["ci", on])), "{on}");
        }
        assert!(!ignore_scripts(&a(&["ci"])));
    }
}
