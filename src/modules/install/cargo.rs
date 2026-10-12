//! Cargo: nothing a dependency ships runs until `cargo build`, where build
//! scripts and proc-macros execute. So the gate is: plan the lockfile change
//! (`cargo add` / `update`), apply policy, `cargo fetch --locked`, and inspect
//! every new crate's build script and proc-macro source before anyone builds.

use super::{
    Backup, InstallOpts, Scratch, must_halt, package_finding, plan_policy, print_install,
};
use crate::deps::{self, Source};
use crate::modules::cargo_audit::{
    self, CrateSource, extract_crate_names, find_build_script, locate_cargo_registry_src,
};
use crate::report::{Check, Report, Severity};
use crate::utils::terminal;
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Build-script signals that ordinary build scripts do not need. Spawning a
/// compiler, writing to `OUT_DIR` and reading `CARGO_*` variables are what
/// build scripts are for, so they do not block.
const STRONG: &[&str] = &[
    "TcpStream::connect",
    "UdpSocket::bind",
    "reqwest",
    "ureq",
    "attohttpc",
    "minreq",
    "sh -c",
    "bash -c",
    "powershell",
    "curl ",
    "wget ",
    "base64::decode",
    "libloading",
    "dlopen",
];

fn cargo() -> Command {
    Command::new("cargo") // greengate: ignore — the wrapped package manager
}

/// Every Cargo manifest and lockfile in the project, for restoring.
fn manifests(project: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![project.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = e.file_name();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if !matches!(name.to_str(), Some("target" | ".git" | "node_modules")) {
                    stack.push(e.path());
                }
            } else if name == "Cargo.toml" || name == "Cargo.lock" {
                out.push(e.path());
            }
        }
    }
    out
}

/// `<registry src>/<index>/<name>-<version>` for a fetched registry crate.
fn crate_dir(registry_src: &Path, name: &str, version: &str) -> Option<PathBuf> {
    std::fs::read_dir(registry_src)
        .ok()?
        .flatten()
        .map(|i| i.path().join(format!("{name}-{version}")))
        .find(|d| d.is_dir())
}

/// The proc-macro entry file, if the crate is a proc-macro.
fn proc_macro_source(dir: &Path) -> Option<PathBuf> {
    let manifest: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
        .ok()?
        .parse()
        .ok()?;
    let lib = manifest.get("lib")?;
    let is_pm = lib
        .get("proc-macro")
        .or_else(|| lib.get("proc_macro"))?
        .as_bool()?;
    if !is_pm {
        return None;
    }
    let path = lib
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("src/lib.rs");
    Some(dir.join(path))
}

pub fn run(opts: InstallOpts<'_>) -> Result<Report> {
    let Some((sub, rest)) = opts.args.split_first() else {
        bail!("expected a cargo command, e.g. `greengate install cargo add serde`");
    };
    if !matches!(
        sub.as_str(),
        "add" | "update" | "fetch" | "generate-lockfile"
    ) {
        bail!(
            "`cargo {sub}` is not supported; greengate install wraps `cargo add`, `update`, `fetch` and `generate-lockfile`"
        );
    }
    let project = std::env::current_dir()?;
    if !project.join("Cargo.toml").is_file() {
        bail!("no Cargo.toml in the current directory");
    }
    let mut report = Report::new("install");
    report.no_fail = opts.no_fail;
    let _scratch = Scratch::new()?;

    // ── 1. Plan ──────────────────────────────────────────────────────────────
    terminal::info("Plan: updating the lockfile (no crate code runs)...");
    let backup = Backup::take(manifests(&project), &[project.join("Cargo.lock")]);
    let current = deps::load(&project.join("Cargo.lock")).ok();
    let plan_cmd: Vec<String> = match sub.as_str() {
        "fetch" if current.is_some() => Vec::new(),
        "fetch" => vec!["generate-lockfile".into()],
        _ => opts.args.clone(),
    };
    if !plan_cmd.is_empty() {
        let status = cargo()
            .args(&plan_cmd)
            .status()
            .context("could not run cargo")?;
        if !status.success() {
            backup.restore()?;
            bail!("`cargo {}` failed ({status})", plan_cmd.join(" "));
        }
    }
    let planned = match deps::load(&project.join("Cargo.lock")) {
        Ok(l) => l,
        Err(e) => {
            backup.restore()?;
            return Err(e);
        }
    };
    let named = if sub == "add" {
        extract_crate_names(rest)
    } else {
        Vec::new()
    };
    let named: Vec<String> = named
        .iter()
        .map(|n| n.split('@').next().unwrap_or(n).to_string())
        .collect();
    plan_policy(
        &mut report,
        &planned,
        current.as_ref(),
        Some((
            crate::modules::slopsquat::Ecosystem::Cargo,
            &named,
            &opts.policy.allow_cargo_crates,
        )),
        &opts,
    )?;
    if must_halt(&report, &opts) {
        backup.restore()?;
        eprintln!(
            "Install halted at the plan: Cargo.toml and Cargo.lock were restored; nothing was fetched."
        );
        return Ok(report);
    }

    // ── 2–3. Fetch and verify ────────────────────────────────────────────────
    terminal::info("Fetch: downloading crate sources (cargo verifies each checksum)...");
    let status = cargo()
        .args(["fetch", "--locked"])
        .status()
        .context("could not run cargo fetch")?;
    if !status.success() {
        if opts.plan_only {
            backup.restore()?;
        }
        bail!("`cargo fetch --locked` failed ({status})");
    }
    report.checks.push(
        Check::passed("install:fetch")
            .with_source("cargo fetch verified every crate against its Cargo.lock checksum"),
    );

    // ── 4. Inspect ───────────────────────────────────────────────────────────
    let before: HashSet<(String, String)> = current
        .as_ref()
        .map(|c| {
            c.dependencies()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect()
        })
        .unwrap_or_default();
    let registry_src = locate_cargo_registry_src();
    let mut build_time: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for p in planned.dependencies() {
        if before.contains(&(p.name.clone(), p.version.clone()))
            || !matches!(p.source, Source::Registry { .. })
        {
            continue;
        }
        let Some(dir) = crate_dir(&registry_src, &p.name, &p.version) else {
            missing.push(p.id());
            continue;
        };
        let mut files: Vec<(&str, PathBuf)> = Vec::new();
        if let CrateSource::BuildScript(path) =
            find_build_script(&registry_src, &p.name, &p.version)
        {
            files.push(("build script", path));
        }
        if let Some(path) = proc_macro_source(&dir) {
            files.push(("proc-macro", path));
        }
        for (kind, path) in files {
            build_time.push(format!("{} ({kind})", p.id()));
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            let strong: Vec<String> = cargo_audit::scan_build_rs_signals(&src)
                .into_iter()
                .filter(|s| STRONG.iter().any(|t| s.contains(t.trim())))
                .collect();
            let blob = super::inspect::encoded_blob(&src);
            if strong.is_empty() && blob.is_none() {
                continue;
            }
            let mut evidence = strong.join(", ");
            if let Some(len) = blob {
                if !evidence.is_empty() {
                    evidence.push_str("; ");
                }
                evidence.push_str(&format!(
                    "a {len}-character encoded blob (likely obfuscated)"
                ));
            }
            let allowlisted = opts
                .policy
                .allow_cargo_crates
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&p.name));
            let finding = package_finding(
                "INSTALL/SuspiciousBuildScript",
                if allowlisted {
                    Severity::Medium
                } else {
                    Severity::High
                },
                &p.name,
                &p.version,
                &path,
                format!(
                    "its {kind} ({}) runs at `cargo build` with full access: {evidence}{}",
                    path.file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default(),
                    if allowlisted { " — allowlisted" } else { "" }
                ),
            );
            if allowlisted {
                report.warnings.push(finding);
            } else {
                report.findings.push(finding);
            }
        }
    }
    if !missing.is_empty() {
        report.checks.push(Check::incomplete(
            "install:inspect",
            format!("sources not found after fetch for: {}", missing.join(", ")),
        ));
    } else {
        report
            .checks
            .push(Check::passed("install:inspect").with_source(format!(
                "{} new crate(s) run code at build time{}",
                build_time.len(),
                if build_time.is_empty() {
                    String::new()
                } else {
                    format!(": {}", build_time.join(", "))
                }
            )));
    }
    report
        .checks
        .push(Check::passed("install:execute").with_source(
            "nothing ran: build scripts and proc-macros run at `cargo build`, after this gate",
        ));

    if opts.plan_only {
        backup.restore()?;
        print_install(
            &report,
            "Plan only: Cargo.toml and Cargo.lock were restored.",
        );
    } else if !report.findings.is_empty() && !opts.no_fail {
        backup.restore()?;
        print_install(
            &report,
            "Cargo.toml and Cargo.lock were restored; do not build until the findings are resolved.",
        );
    } else {
        print_install(&report, "");
    }
    Ok(report)
}
