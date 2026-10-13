//! uv: `uv lock` (or `uv add --no-sync`) and `uv sync` both run sdist build
//! backends, so both run in the sandbox. Then greengate checks every `.pth`
//! file the sync added — code that runs at every Python start — before any
//! Python has started, and installs the project itself last.

use super::sandbox::{self, Isolation, Sandbox};
use super::{
    Backup, InstallOpts, Scratch, inspect, isolation_missing, must_halt, package_finding,
    plan_policy, print_install, rel,
};
use crate::deps;
use crate::modules::pip_audit::extract_package_names;
use crate::report::{Check, Report, Severity};
use crate::utils::terminal;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every `pyproject.toml` in the project (workspace members included).
fn pyprojects(project: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![project.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = e.file_name();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if !matches!(
                    name.to_str(),
                    Some(".git" | ".venv" | "node_modules" | "target")
                ) {
                    stack.push(e.path());
                }
            } else if name == "pyproject.toml" {
                out.push(e.path());
            }
        }
    }
    out
}

/// `.pth` files in the project's virtual environment, with their contents.
fn pth_files(project: &Path) -> HashMap<PathBuf, String> {
    let mut out = HashMap::new();
    let venv = project.join(".venv");
    let site_dirs: Vec<PathBuf> = std::fs::read_dir(venv.join("lib"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("site-packages"))
        .chain([venv.join("Lib/site-packages")])
        .filter(|p| p.is_dir())
        .collect();
    for site in site_dirs {
        for e in std::fs::read_dir(&site).into_iter().flatten().flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "pth")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                out.insert(p, text);
            }
        }
    }
    out
}

/// Flags that shape what `uv sync` installs.
fn sync_flags(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        let takes_value = matches!(
            a.as_str(),
            "--extra" | "--group" | "--only-group" | "--no-group" | "--package"
        );
        let flag = matches!(
            a.as_str(),
            "--no-dev"
                | "--all-extras"
                | "--all-groups"
                | "--only-dev"
                | "--all-packages"
                | "--no-default-groups"
        ) || takes_value
            || ["--extra=", "--group=", "--package="]
                .iter()
                .any(|p| a.starts_with(p));
        if flag {
            out.push(a.clone());
            if takes_value && let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

fn blocked_write(log: &str) -> bool {
    log.contains("Read-only file system") || log.contains("EROFS")
}

pub fn run(opts: InstallOpts<'_>) -> Result<Report> {
    let Some((sub, rest)) = opts.args.split_first() else {
        bail!("expected a uv command, e.g. `greengate install uv sync`");
    };
    if !matches!(sub.as_str(), "sync" | "add") {
        bail!("`uv {sub}` is not supported; greengate install wraps `uv sync` and `uv add`");
    }
    let project = std::env::current_dir()?;
    if !project.join("pyproject.toml").is_file() {
        bail!("no pyproject.toml in the current directory");
    }
    let mut report = Report::new("install");
    report.no_fail = opts.no_fail;
    let scratch = Scratch::new()?;
    let tmp = scratch.0.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let cache = tmp.join("uv-cache");
    let isolation = sandbox::detect(opts.isolate)?;
    let lock_path = project.join("uv.lock");

    // A sandbox over the project: writable, but `.git` read-only. Build
    // backends may run in here, so project changes are checked afterwards.
    let sandbox = |writable_venv: bool| Sandbox {
        isolation,
        project: &project,
        tmp: &tmp,
        writable: vec![project.clone()],
        read_only: if writable_venv {
            vec![project.join(".git")]
        } else {
            vec![project.join(".git"), project.join(".venv")]
        },
        inner: Vec::new(),
        network: true,
        env_allow: &opts.policy.env_allow,
        project_copy: None,
    };
    let run_uv = |args: Vec<String>, writable_venv: bool| -> Result<(bool, String)> {
        let out = sandbox(writable_venv)
            .command("uv", &args)
            .env("UV_CACHE_DIR", &cache)
            .output()
            .context("could not run uv")?;
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok((out.status.success(), log))
    };
    let skip: &[&str] = &[".git", ".venv"];
    let foreign = |before: &inspect::Snapshot, report: &mut Report, what: &str| {
        let c = inspect::changes(before, &inspect::snapshot(&project, skip));
        let changed: Vec<String> = c
            .created
            .iter()
            .chain(&c.modified)
            .chain(&c.deleted)
            .filter(|p| {
                !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("uv.lock" | "pyproject.toml")
                )
            })
            .take(5)
            .map(|p| rel(p, &project))
            .collect();
        if !changed.is_empty() {
            report.findings.push(package_finding(
                "INSTALL/ForeignWrite",
                Severity::High,
                what,
                "",
                &project,
                format!(
                    "build code changed files in the project: {}",
                    changed.join(", ")
                ),
            ));
        }
    };

    // ── 1. Plan (sandboxed: resolving runs sdist build backends) ─────────────
    terminal::info("Plan: locking (sdist metadata builds run isolated)...");
    let backup = Backup::take(
        pyprojects(&project)
            .into_iter()
            .chain([lock_path.clone()])
            .collect(),
        std::slice::from_ref(&lock_path),
    );
    let current = std::fs::read_to_string(&lock_path)
        .ok()
        .and_then(|c| deps::parse(&lock_path, &c).ok());
    let mut plan_args: Vec<String> = if sub == "add" {
        let mut a = vec!["add".to_string(), "--no-sync".to_string()];
        a.extend(rest.iter().cloned());
        a
    } else {
        vec!["lock".to_string()]
    };
    if sub == "sync"
        && rest.iter().any(|a| a == "--frozen" || a == "--locked")
        && current.is_some()
    {
        plan_args.clear(); // install exactly the committed lockfile
    }
    // Locking and syncing both run sdist build backends.
    if (!plan_args.is_empty() || !opts.plan_only)
        && isolation_missing(
            &mut report,
            &opts,
            isolation,
            "uv runs sdist build code while locking and syncing, so nothing was run",
        )
    {
        backup.restore()?;
        return Ok(report);
    }
    let before = inspect::snapshot(&project, skip);
    if !plan_args.is_empty() {
        let (ok, log) = run_uv(plan_args.clone(), false)?;
        if !ok {
            backup.restore()?;
            eprint!("{log}");
            if blocked_write(&log) {
                report.findings.push(package_finding(
                    "INSTALL/BlockedWrite",
                    Severity::High,
                    "build backend",
                    "",
                    &project,
                    "an sdist's build code, run while locking, tried to write outside the sandbox; it was refused".into(),
                ));
                print_install(
                    &report,
                    "Install halted at the plan; pyproject.toml and uv.lock were restored.",
                );
                return Ok(report);
            }
            bail!("`uv {}` failed", plan_args.join(" "));
        }
    }
    foreign(&before, &mut report, "lock step");
    let planned = deps::load(&lock_path).context("the plan produced no uv.lock")?;
    let named = if sub == "add" {
        extract_package_names(rest)
    } else {
        Vec::new()
    };
    plan_policy(
        &mut report,
        &planned,
        current.as_ref(),
        Some((
            crate::modules::slopsquat::Ecosystem::Pypi,
            &named,
            &opts.policy.allow_pip_packages,
        )),
        &opts,
    )?;
    if opts.plan_only || must_halt(&report, &opts) {
        backup.restore()?;
        print_install(
            &report,
            if opts.plan_only {
                "Plan only: pyproject.toml and uv.lock were restored; nothing was installed."
            } else {
                "Install halted at the plan; pyproject.toml and uv.lock were restored."
            },
        );
        return Ok(report);
    }

    // ── 2–4. Sync dependencies (sandboxed), then inspect startup code ────────
    terminal::info("Sync: installing dependencies; sdist builds run isolated...");
    let pth_before = pth_files(&project);
    let before = inspect::snapshot(&project, skip);
    let mut sync_args: Vec<String> = vec![
        "sync".into(),
        "--frozen".into(),
        "--no-install-project".into(),
    ];
    sync_args.extend(sync_flags(rest));
    let (ok, log) = run_uv(sync_args, true)?;
    if !ok {
        eprint!("{log}");
        if blocked_write(&log) {
            report.findings.push(package_finding(
                "INSTALL/BlockedWrite",
                Severity::High,
                "build backend",
                "",
                &project,
                "an sdist's build code tried to write outside the sandbox; it was refused".into(),
            ));
            print_install(&report, "");
            return Ok(report);
        }
        bail!("`uv sync --frozen --no-install-project` failed");
    }
    foreign(&before, &mut report, "sync step");
    report
        .checks
        .push(Check::passed("install:fetch").with_source(format!(
            "uv verified every artifact against uv.lock; builds ran {}",
            if isolation == Isolation::Bwrap {
                "in bubblewrap"
            } else {
                "without isolation"
            }
        )));

    let mut startup: Vec<String> = Vec::new();
    for (path, text) in pth_files(&project) {
        if pth_before.get(&path) == Some(&text) {
            continue;
        }
        let code: String = text
            .lines()
            .filter(|l| l.starts_with("import"))
            .collect::<Vec<_>>()
            .join("\n");
        if code.is_empty() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // The modules it imports are read from its own directory.
        let dir = path.parent().unwrap_or(Path::new(""));
        let signals = inspect::pth_signals(&code, &|m| {
            inspect::module_source(m, |f| std::fs::read_to_string(dir.join(f)).ok())
        });
        // uv's own virtualenv bootstrap, inspected like the rest, is not a
        // package's startup code.
        if name != "_virtualenv.pth" || !signals.is_empty() {
            startup.push(name.clone());
        }
        if !signals.is_empty() {
            // It has not run yet: no Python has started since the sync.
            let quarantined = path.with_extension("pth.greengate-blocked");
            std::fs::rename(&path, &quarantined)?;
            report.findings.push(package_finding(
                "INSTALL/StartupCode",
                Severity::High,
                &name,
                "",
                &quarantined,
                format!(
                    "runs at every Python start: {} — quarantined as {}",
                    signals.join(", "),
                    quarantined
                        .file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default()
                ),
            ));
        }
    }
    report
        .checks
        .push(Check::passed("install:inspect").with_source(format!(
            "{} new startup (.pth) file(s){}",
            startup.len(),
            if startup.is_empty() {
                String::new()
            } else {
                format!(": {}", startup.join(", "))
            }
        )));

    // ── 5. The project itself: its own code, installed normally ──────────────
    if !rest.iter().any(|a| a == "--no-install-project") {
        let status = Command::new("uv") // greengate: ignore — installing the project's own code
            .args(["sync", "--frozen"])
            .args(sync_flags(rest))
            .status()?;
        if !status.success() {
            report.checks.push(Check::error(
                "install:project",
                format!("`uv sync --frozen` failed ({status})"),
            ));
        }
    }
    report
        .checks
        .push(Check::passed("install:execute").with_source(isolation.describe(true)));
    print_install(&report, "");
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_flags_pass_through() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            sync_flags(&a(&[
                "--frozen",
                "--no-dev",
                "--extra",
                "web",
                "--group=lint"
            ])),
            a(&["--no-dev", "--extra", "web", "--group=lint"])
        );
    }
}
