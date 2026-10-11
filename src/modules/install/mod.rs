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

mod inspect;
mod npm;
pub mod sandbox;

use crate::deps::{self, Lockfile};
use crate::modules::{deps_check, slopsquat};
use crate::report::{Check, Finding, Report, Severity};
use crate::utils::config::SupplyChainConfig;
use crate::utils::terminal;
use anyhow::{Context, Result, bail};
use inspect::ScriptPackage;
use sandbox::{IsolateMode, Isolation, Sandbox};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct InstallOpts<'a> {
    pub manager: String,
    pub args: Vec<String>,
    pub plan_only: bool,
    pub isolate: IsolateMode,
    pub no_fail: bool,
    pub policy: &'a SupplyChainConfig,
    pub now: u64,
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

fn lockfile_in(dir: &Path) -> Option<PathBuf> {
    ["package-lock.json", "npm-shrinkwrap.json"]
        .iter()
        .map(|f| dir.join(f))
        .find(|p| p.is_file())
}

fn package_finding(
    rule: &str,
    severity: Severity,
    pkg: &inspect::Installed,
    message: String,
) -> Finding {
    let mut f = Finding::package(rule, severity, "npm", &pkg.name, message);
    if let crate::report::Location::Package {
        version, source, ..
    } = &mut f.location
    {
        *version = Some(pkg.version.clone());
        *source = Some(pkg.dir.clone());
    }
    f
}

/// Script packages in dependency order: a package's dependencies run first,
/// as npm orders them.
fn execution_order(planned: &Lockfile, scripts: Vec<ScriptPackage>) -> Vec<ScriptPackage> {
    let index: HashMap<(String, String), usize> = planned
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.name.clone(), p.version.clone()), i))
        .collect();
    let mut rank: HashMap<usize, usize> = HashMap::new();
    let mut visited = vec![false; planned.packages.len()];
    fn visit(i: usize, lock: &Lockfile, visited: &mut [bool], rank: &mut HashMap<usize, usize>) {
        if visited[i] {
            return;
        }
        visited[i] = true;
        for &(t, _) in &lock.edges[i] {
            visit(t, lock, visited, rank);
        }
        let next = rank.len();
        rank.insert(i, next);
    }
    for i in 0..planned.packages.len() {
        visit(i, planned, &mut visited, &mut rank);
    }
    let mut keyed: Vec<(usize, ScriptPackage)> = scripts
        .into_iter()
        .map(|s| {
            let r = index
                .get(&(s.pkg.name.clone(), s.pkg.version.clone()))
                .and_then(|i| rank.get(i))
                .copied()
                .unwrap_or(usize::MAX);
            (r, s)
        })
        .collect();
    keyed.sort_by_key(|(r, s)| (*r, s.pkg.dir.clone()));
    keyed.into_iter().map(|(_, s)| s).collect()
}

/// Copy every manifest `npm` changed while planning back into the project.
fn apply_plan(work: &Path, project: &Path) -> Result<()> {
    let mut stack = vec![work.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let path = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if e.file_name() != "node_modules" && e.file_name() != "tmp" {
                    stack.push(path);
                }
                continue;
            }
            let name = e.file_name();
            if !matches!(
                name.to_str(),
                Some("package.json" | "package-lock.json" | "npm-shrinkwrap.json")
            ) {
                continue;
            }
            let dest = project.join(path.strip_prefix(work).unwrap_or(&path));
            if std::fs::read(&dest).ok() != std::fs::read(&path).ok() {
                std::fs::copy(&path, &dest)
                    .with_context(|| format!("updating {}", dest.display()))?;
            }
        }
    }
    Ok(())
}

pub fn run_install(opts: InstallOpts<'_>) -> Result<Report> {
    if opts.manager != "npm" {
        bail!(
            "greengate install supports npm so far; for `{}`, use `greengate watch-install {}`",
            opts.manager,
            opts.manager
        );
    }
    let sub = npm::parse_args(&opts.args)?;
    let project = std::env::current_dir()?;
    let mut report = Report::new("install");
    report.no_fail = opts.no_fail;
    let scratch = Scratch::new()?;
    let work = scratch.0.join("project");
    std::fs::create_dir_all(&work)?;

    // ── 1. Plan ──────────────────────────────────────────────────────────────
    terminal::info("Plan: resolving the full dependency tree (no package code runs)...");
    npm::stage(&project, &work)?;
    npm::link_local_specs(&project, &work, &opts.args)?;
    npm::plan(&work, &sub)?;
    let planned_path = lockfile_in(&work).context("planning produced no lockfile")?;
    let planned = deps::load(&planned_path)?;
    let current = lockfile_in(&project).and_then(|p| deps::load(&p).ok());
    let label = if current.is_some() {
        "packages this install adds or changes"
    } else {
        "every package (no existing lockfile)"
    };
    report
        .checks
        .push(Check::passed("install:plan").with_source(format!(
            "{} package(s) planned; release checks cover {label}",
            planned.dependencies().count()
        )));
    let previous = vec![current.as_ref().map(deps_check::versions_by_name)];
    let checked = deps_check::evaluate(
        std::slice::from_ref(&planned),
        &previous,
        label,
        opts.policy,
        opts.now,
        &mut report,
    )?;
    // Named packages also get the name guard (hallucinated / typo names).
    let named = slopsquat::npm_packages_from_args(&opts.args);
    if opts.policy.slopsquat_check && !named.is_empty() {
        let known: HashSet<String> = current
            .as_ref()
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
            slopsquat::Ecosystem::Npm,
            &named,
            &opts.policy.allow_postinstall,
            &|n| known.contains(n),
            &policy,
            &mut report.checks,
        );
        slopsquat::print_reports(slopsquat::Ecosystem::Npm, &reports);
        slopsquat::record(slopsquat::Ecosystem::Npm, &reports, &mut report);
    }
    deps_check::print_report(&report, checked);
    if !report.findings.is_empty() && !opts.no_fail {
        eprintln!("Install halted at the plan: nothing was downloaded and no package code ran.");
        return Ok(report);
    }

    // ── 2. Fetch ─────────────────────────────────────────────────────────────
    let target = if opts.plan_only {
        work.clone()
    } else {
        apply_plan(&work, &project)?;
        project.clone()
    };
    terminal::info("Fetch: downloading and extracting with every install script off...");
    npm::fetch(&target, &sub)?;
    report.checks.push(Check::passed("install:fetch"));

    // ── 3. Verify artifacts ──────────────────────────────────────────────────
    let installed = inspect::installed_packages(&target.join("node_modules"));
    let planned_ids: HashSet<(String, String)> = planned
        .dependencies()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    for pkg in &installed {
        if !planned_ids.contains(&(pkg.name.clone(), pkg.version.clone())) {
            report.findings.push(package_finding(
                "INSTALL/UnplannedPackage",
                Severity::High,
                pkg,
                "installed, but not in the planned lockfile".into(),
            ));
        }
    }
    report.checks.push(Check::passed("install:verify-artifacts").with_source(format!(
        "npm verified every tarball against the lockfile integrity; {} installed package(s) checked against the plan",
        installed.len()
    )));

    // ── 4. Inspect ───────────────────────────────────────────────────────────
    let isolation = sandbox::detect(opts.isolate)?;
    let scripts = inspect::script_packages(&installed);
    let mut approved: Vec<ScriptPackage> = Vec::new();
    for sp in scripts {
        let allowlisted = opts
            .policy
            .allow_postinstall
            .iter()
            .any(|a| a == &sp.pkg.name);
        if !sp.suspicious() {
            approved.push(sp);
        } else if allowlisted || isolation == Isolation::Bwrap {
            // Isolated, a script can reach nothing its package's own code
            // could not reach at runtime; report it and let it run there.
            report.warnings.push(package_finding(
                "INSTALL/SuspiciousScript",
                Severity::Medium,
                &sp.pkg,
                format!(
                    "{} — {} {}",
                    sp.evidence(),
                    if opts.plan_only { "would run" } else { "runs" },
                    if allowlisted {
                        "because it is allowlisted"
                    } else {
                        "isolated"
                    }
                ),
            ));
            approved.push(sp);
        } else {
            report.findings.push(package_finding(
                "INSTALL/SuspiciousScript",
                Severity::High,
                &sp.pkg,
                format!(
                    "{} — {} (no isolation available; allowlist it to run it)",
                    sp.evidence(),
                    if opts.plan_only {
                        "would not run"
                    } else {
                        "not run"
                    }
                ),
            ));
        }
    }
    let names: Vec<String> = approved
        .iter()
        .map(|s| format!("{}@{}", s.pkg.name, s.pkg.version))
        .collect();
    report
        .checks
        .push(Check::passed("install:inspect").with_source(format!(
            "{} package(s) run install scripts{}",
            names.len(),
            if names.is_empty() {
                String::new()
            } else {
                format!(": {}", names.join(", "))
            }
        )));

    if opts.plan_only {
        print_install(
            &report,
            "Plan only: nothing in the project was changed and no package code ran.",
        );
        return Ok(report);
    }
    if isolation == Isolation::None && opts.policy.require_isolation {
        report.checks.push(Check::incomplete(
            "install:execute",
            "no sandbox is available and [supply_chain] require_isolation is set — install scripts were not run",
        ));
        print_install(&report, "");
        return Ok(report);
    }

    // ── 5–6. Execute and verify ──────────────────────────────────────────────
    let tmp = scratch.0.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let order = execution_order(&planned, approved);
    let mut monitoring_gaps: Vec<String> = Vec::new();
    let any_network = order
        .iter()
        .any(|s| opts.policy.script_network.contains(&s.pkg.name));
    for sp in &order {
        let network = opts.policy.script_network.contains(&sp.pkg.name);
        let id = format!("{}@{}", sp.pkg.name, sp.pkg.version);
        terminal::info(&format!("Running install scripts of {id}..."));
        let sandbox = Sandbox {
            isolation,
            project: &target,
            tmp: &tmp,
            writable: vec![sp.pkg.dir.clone()],
            network,
            env_allow: &opts.policy.env_allow,
        };
        let unisolated = isolation == Isolation::None;
        let before = unisolated.then(|| inspect::snapshot(&target, &[".git"]));
        let watch = if unisolated {
            inspect::Watch::start(&[&target])
        } else {
            None
        };
        if unisolated && watch.is_none() {
            monitoring_gaps.push(format!("{id}: filesystem watcher unavailable"));
        }
        let program = if cfg!(windows) { "npm.cmd" } else { "npm" };
        let output = sandbox
            .command(program, &npm::rebuild_args(&sp.pkg.name, &sp.pkg.version))
            .output()
            .with_context(|| format!("could not run install scripts of {id}"))?;

        if !output.status.success() {
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let tail: Vec<&str> = log
                .lines()
                .rev()
                .take(6)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if log.contains("EROFS") || log.contains("read-only file system") {
                report.findings.push(package_finding(
                    "INSTALL/BlockedWrite",
                    Severity::High,
                    &sp.pkg,
                    "its install script tried to write outside its own package directory; the sandbox refused".into(),
                ));
            } else {
                let hint = if ["ENETUNREACH", "ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED"]
                    .iter()
                    .any(|e| log.contains(e))
                {
                    format!(
                        " — it needs the network; if that is expected, add \"{}\" to [supply_chain] script_network",
                        sp.pkg.name
                    )
                } else {
                    String::new()
                };
                report.checks.push(Check::error(
                    format!("install:script:{id}"),
                    format!(
                        "install script failed ({}){hint}: {}",
                        output.status,
                        tail.join(" | ")
                    ),
                ));
            }
        }

        if let Some(before) = before {
            let after = inspect::snapshot(&target, &[".git"]);
            let c = inspect::changes(&before, &after);
            let outside = |p: &PathBuf| !p.starts_with(&sp.pkg.dir);
            for (what, paths) in [
                ("created", &c.created),
                ("modified", &c.modified),
                ("deleted", &c.deleted),
            ] {
                let foreign: Vec<&PathBuf> = paths.iter().filter(|p| outside(p)).collect();
                if !foreign.is_empty() {
                    let shown: Vec<String> =
                        foreign.iter().take(5).map(|p| rel(p, &target)).collect();
                    report.findings.push(package_finding(
                        "INSTALL/ForeignWrite",
                        Severity::High,
                        &sp.pkg,
                        format!(
                            "its install script {what} {} file(s) outside its package: {}",
                            foreign.len(),
                            shown.join(", ")
                        ),
                    ));
                }
            }
            if let Some(w) = watch {
                match w.vanished() {
                    Ok(gone) => {
                        let foreign: Vec<String> = gone
                            .iter()
                            .filter(|p| outside(p))
                            .take(5)
                            .map(|p| rel(p, &target))
                            .collect();
                        if !foreign.is_empty() {
                            report.findings.push(package_finding(
                                "INSTALL/PhantomFile",
                                Severity::High,
                                &sp.pkg,
                                format!("created and deleted files outside its package while running: {}", foreign.join(", ")),
                            ));
                        }
                    }
                    Err(e) => monitoring_gaps.push(format!("{id}: {e}")),
                }
            }
        }
    }
    if !monitoring_gaps.is_empty() {
        report.checks.push(Check::incomplete(
            "install:monitoring",
            monitoring_gaps.join("; "),
        ));
    }

    // The project's own lifecycle scripts, which `npm ci --ignore-scripts`
    // skipped. They are the project's code, so they run normally.
    if !opts.args.iter().any(|a| a == "--ignore-scripts") {
        let manifest: serde_json::Value = std::fs::read_to_string(project.join("package.json"))
            .ok()
            .and_then(|m| serde_json::from_str(&m).ok())
            .unwrap_or_default();
        for hook in npm::root_hooks(&manifest) {
            if let Err(e) = npm::run_root_hook(&project, &hook) {
                report.checks.push(Check::error(
                    format!("install:root:{hook}"),
                    format!("{e:#}"),
                ));
            }
        }
    }
    report
        .checks
        .push(Check::passed("install:execute").with_source(format!(
            "{} package(s) ran install scripts; {}",
            order.len(),
            isolation.describe(any_network)
        )));
    print_install(&report, "");
    Ok(report)
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

    #[test]
    fn dependencies_run_before_dependents() {
        let mut lock = Lockfile::new_for_tests();
        let root = lock.add(deps::Package::member("app", "", "."));
        let a = lock.add(deps::Package::new("a", "1.0.0", deps::Source::registry()));
        let b = lock.add(deps::Package::new("b", "1.0.0", deps::Source::registry()));
        lock.link(root, a);
        lock.link(a, b); // a depends on b: b's scripts first
        let sp = |name: &str| ScriptPackage {
            pkg: inspect::Installed {
                dir: PathBuf::from(format!("node_modules/{name}")),
                name: name.into(),
                version: "1.0.0".into(),
                manifest: serde_json::Value::Null,
            },
            hooks: vec![],
            signals: vec![],
            max_entropy: 0.0,
            helpers: vec![],
        };
        let order = execution_order(&lock, vec![sp("a"), sp("b")]);
        let names: Vec<&str> = order.iter().map(|s| s.pkg.name.as_str()).collect();
        assert_eq!(names, ["b", "a"]);
    }
}
