//! The JavaScript install flow, shared by npm and pnpm.

use super::inspect::{self, Installed, ScriptPackage};
use super::sandbox::{self, Isolation, Sandbox};
use super::{
    InstallOpts, Scratch, bun, ignore_scripts, isolation_missing, must_halt, npm, package_finding,
    plan_policy, pnpm, print_install, rel, unfinished, yarn,
};
use crate::deps::{self, Lockfile};
use crate::report::{Check, Report, Severity};
use crate::utils::terminal;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Js {
    Npm,
    Pnpm,
    Yarn1,
    Berry,
    Bun,
}

enum Sub {
    Npm(npm::Sub),
    Pnpm(pnpm::Sub),
    Yarn(yarn::Sub),
    Bun(bun::Sub),
}

impl Js {
    fn program(self) -> &'static str {
        match (self, cfg!(windows)) {
            // Yarn 1 and Bun install npm-shaped trees: npm rebuilds them.
            (Js::Npm | Js::Yarn1 | Js::Bun, false) => "npm",
            (Js::Npm | Js::Yarn1 | Js::Bun, true) => "npm.cmd",
            (Js::Pnpm, false) => "pnpm",
            (Js::Pnpm, true) => "pnpm.cmd",
            (Js::Berry, false) => "yarn",
            (Js::Berry, true) => "yarn.cmd",
        }
    }

    fn manifests(self) -> &'static [&'static str] {
        match self {
            Js::Npm => npm::MANIFESTS,
            Js::Pnpm => pnpm::MANIFESTS,
            Js::Yarn1 => yarn::MANIFESTS_V1,
            Js::Berry => yarn::MANIFESTS_BERRY,
            Js::Bun => bun::MANIFESTS,
        }
    }

    fn lockfile_in(self, dir: &Path) -> Option<PathBuf> {
        let names: &[&str] = match self {
            Js::Npm => &["package-lock.json", "npm-shrinkwrap.json"],
            Js::Pnpm => &["pnpm-lock.yaml"],
            Js::Yarn1 | Js::Berry => &["yarn.lock"],
            Js::Bun => &["bun.lock"],
        };
        names.iter().map(|f| dir.join(f)).find(|p| p.is_file())
    }

    fn installed(self, dir: &Path) -> Vec<Installed> {
        match self {
            Js::Npm | Js::Yarn1 | Js::Bun => {
                inspect::installed_packages(&dir.join("node_modules"))
            }
            Js::Pnpm => pnpm::installed_packages(&dir.join("node_modules")),
            Js::Berry => yarn::installed_packages(dir),
        }
    }
}

/// Copy every manifest the plan changed back into the project.
fn apply_plan(js: Js, work: &Path, project: &Path) -> Result<()> {
    let changed: &[&str] = match js {
        Js::Npm => &["package.json", "package-lock.json", "npm-shrinkwrap.json"],
        Js::Pnpm => &["package.json", "pnpm-lock.yaml"],
        Js::Yarn1 | Js::Berry => &["package.json", "yarn.lock"],
        Js::Bun => &["package.json", "bun.lock"],
    };
    let mut stack = vec![work.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let path = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if e.file_name() != "node_modules" {
                    stack.push(path);
                }
                continue;
            }
            if !changed.iter().any(|c| e.file_name() == *c) {
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

/// Script packages in dependency order: a package's dependencies run first.
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

pub fn run(js: Js, opts: InstallOpts<'_>) -> Result<Report> {
    let sub = match js {
        Js::Npm => Sub::Npm(npm::parse_args(&opts.args)?),
        Js::Pnpm => Sub::Pnpm(pnpm::parse_args(&opts.args)?),
        Js::Yarn1 | Js::Berry => Sub::Yarn(yarn::parse_args(&opts.args)?),
        Js::Bun => Sub::Bun(bun::parse_args(&opts.args)?),
    };
    let project = std::env::current_dir()?;
    let mut report = Report::new("install");
    report.no_fail = opts.no_fail;
    let scratch = Scratch::new()?;
    let work = scratch.0.join("project");
    std::fs::create_dir_all(&work)?;

    // ── 1. Plan ──────────────────────────────────────────────────────────────
    terminal::info("Plan: resolving the full dependency tree (no package code runs)...");
    npm::stage(&project, &work, js.manifests())?;
    npm::link_local_specs(&project, &work, &opts.args)?;
    if js == Js::Berry {
        for dir in yarn::BERRY_DIRS {
            copy_dir(&project.join(dir), &work.join(dir))?;
        }
    }
    match &sub {
        Sub::Npm(s) => npm::plan(&work, s)?,
        Sub::Pnpm(s) => pnpm::plan(&work, s)?,
        Sub::Yarn(s) => yarn::plan(&work, s, js == Js::Berry)?,
        Sub::Bun(s) => bun::plan(&work, s)?,
    }
    let planned = deps::load(
        &js.lockfile_in(&work)
            .context("planning produced no lockfile")?,
    )?;
    let current = js.lockfile_in(&project).and_then(|p| deps::load(&p).ok());
    let named = crate::modules::slopsquat::npm_packages_from_args(&opts.args);
    plan_policy(
        &mut report,
        &planned,
        current.as_ref(),
        Some((
            crate::modules::slopsquat::Ecosystem::Npm,
            &named,
            &opts.policy.allow_postinstall,
        )),
        &opts,
    )?;
    if must_halt(&report, &opts) {
        eprintln!("Install halted at the plan: nothing was downloaded and no package code ran.");
        return Ok(report);
    }
    // `--ignore-scripts` (Berry: `--mode=skip-build`) holds for dependency
    // scripts too, not only the project's own.
    let no_scripts =
        ignore_scripts(&opts.args) || (js == Js::Berry && yarn::skip_build(&opts.args));

    // ── 2. Fetch ─────────────────────────────────────────────────────────────
    let target = if opts.plan_only {
        work.clone()
    } else {
        apply_plan(js, &work, &project)?;
        project.clone()
    };
    terminal::info("Fetch: downloading and extracting with every install script off...");
    match &sub {
        Sub::Npm(s) => npm::fetch(&target, s)?,
        Sub::Pnpm(s) => pnpm::fetch(&target, s)?,
        Sub::Yarn(s) => yarn::fetch(&target, s, js == Js::Berry)?,
        Sub::Bun(s) => bun::fetch(&target, s)?,
    }
    report.checks.push(Check::passed("install:fetch"));

    // ── 3. Verify artifacts ──────────────────────────────────────────────────
    let installed = js.installed(&target);
    let planned_ids: HashSet<(String, String)> = planned
        .dependencies()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    // Local, git and URL packages are recorded by their spec, not the
    // version in their package.json.
    let planned_by_name: HashSet<&str> = planned
        .dependencies()
        .filter(|p| !p.source.is_registry())
        .map(|p| p.name.as_str())
        .collect();
    for pkg in &installed {
        if !planned_ids.contains(&(pkg.name.clone(), pkg.version.clone()))
            && !planned_by_name.contains(pkg.name.as_str())
        {
            report.findings.push(package_finding(
                "INSTALL/UnplannedPackage",
                Severity::High,
                &pkg.name,
                &pkg.version,
                &pkg.dir,
                "installed, but not in the planned lockfile".into(),
            ));
        }
    }
    report.checks.push(Check::passed("install:verify-artifacts").with_source(format!(
        "the package manager verified every tarball against the lockfile integrity; {} installed package(s) checked against the plan",
        installed.len()
    )));

    // ── 4. Inspect ───────────────────────────────────────────────────────────
    let isolation = sandbox::detect(opts.isolate)?;
    let pnpm_policy = (js == Js::Pnpm).then(|| pnpm::build_policy(&target));
    let bun_untrusted = (js == Js::Bun).then(|| bun::untrusted(&target));
    let mut approved: Vec<ScriptPackage> = Vec::new();
    for sp in inspect::script_packages(&installed) {
        if let Some(policy) = &pnpm_policy
            && !policy.allows(&sp.pkg.name)
        {
            // pnpm will not build it, so neither will greengate.
            report.warnings.push(package_finding(
                "INSTALL/BuildNotAllowed",
                Severity::Low,
                &sp.pkg.name,
                &sp.pkg.version,
                &sp.pkg.dir,
                format!(
                    "{} — not run: pnpm only builds packages in onlyBuiltDependencies",
                    sp.evidence()
                ),
            ));
            continue;
        }
        if let Some(untrusted) = &bun_untrusted
            && untrusted.contains(&sp.pkg.dir)
        {
            report.warnings.push(package_finding(
                "INSTALL/BuildNotAllowed",
                Severity::Low,
                &sp.pkg.name,
                &sp.pkg.version,
                &sp.pkg.dir,
                format!(
                    "{} — not run: Bun does not trust it (trustedDependencies)",
                    sp.evidence()
                ),
            ));
            continue;
        }
        let allowlisted = opts
            .policy
            .allow_postinstall
            .iter()
            .any(|a| a == &sp.pkg.name);
        let verb = if opts.plan_only { "would run" } else { "runs" };
        if no_scripts {
            if sp.suspicious() {
                report.warnings.push(package_finding(
                    "INSTALL/SuspiciousScript",
                    Severity::Medium,
                    &sp.pkg.name,
                    &sp.pkg.version,
                    &sp.pkg.dir,
                    format!("{} — not run (--ignore-scripts)", sp.evidence()),
                ));
            }
            approved.push(sp);
        } else if !sp.suspicious() {
            approved.push(sp);
        } else if allowlisted || (isolation == Isolation::Bwrap && js != Js::Berry) {
            // Isolated, a script can reach nothing its package's own code
            // could not reach at runtime; report it and let it run there.
            // Yarn Berry builds every package in one step, where isolation
            // cannot keep packages apart, so Berry holds these back instead.
            report.warnings.push(package_finding(
                "INSTALL/SuspiciousScript",
                Severity::Medium,
                &sp.pkg.name,
                &sp.pkg.version,
                &sp.pkg.dir,
                format!(
                    "{} — {verb} {}",
                    sp.evidence(),
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
                &sp.pkg.name,
                &sp.pkg.version,
                &sp.pkg.dir,
                format!(
                    "{} — {} ({})",
                    sp.evidence(),
                    if opts.plan_only {
                        "would not run"
                    } else {
                        "not run"
                    },
                    if js == Js::Berry {
                        "Yarn builds all packages in one step; allowlist it, or set dependenciesMeta.<name>.built = false so Yarn never builds it"
                    } else {
                        "no isolation available; allowlist it to run it"
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
            "{} package(s) {} install scripts{}",
            names.len(),
            if no_scripts {
                "have (none run: --ignore-scripts)"
            } else {
                "run"
            },
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
    if no_scripts {
        report.checks.push(
            Check::passed("install:execute").with_source(
                "--ignore-scripts: no install scripts ran, the project's own included",
            ),
        );
        print_install(&report, "");
        return Ok(report);
    }
    if !approved.is_empty()
        && isolation_missing(
            &mut report,
            &opts,
            isolation,
            "install scripts were not run",
        )
    {
        return Ok(report);
    }
    if unfinished(&report, &opts) {
        print_install(&report, "Install halted before running any install script.");
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
    let mut done: HashSet<String> = HashSet::new();
    if js == Js::Berry {
        run_berry_builds(&mut report, &target, &tmp, &order, isolation, &opts);
    }
    for sp in order.iter().filter(|_| js != Js::Berry) {
        // pnpm rebuilds every installed copy of a name at once.
        if js == Js::Pnpm && !done.insert(sp.pkg.name.clone()) {
            continue;
        }
        let network = opts.policy.script_network.contains(&sp.pkg.name);
        let id = format!("{}@{}", sp.pkg.name, sp.pkg.version);
        terminal::info(&format!("Running install scripts of {id}..."));
        let own: Vec<PathBuf> = match js {
            Js::Npm | Js::Yarn1 | Js::Bun | Js::Berry => vec![sp.pkg.dir.clone()],
            Js::Pnpm => installed
                .iter()
                .filter(|p| p.name == sp.pkg.name)
                .map(|p| p.dir.clone())
                .collect(),
        };
        // npm writes nothing but the package; pnpm also writes its own state
        // in the project, so the project is writable but the store and .git
        // are not, and project-root writes are checked afterwards.
        let (writable, read_only) = match js {
            Js::Npm | Js::Yarn1 | Js::Bun | Js::Berry => (Vec::new(), Vec::new()),
            Js::Pnpm => (
                vec![target.clone()],
                vec![target.join("node_modules/.pnpm"), target.join(".git")],
            ),
        };
        let watch_root = isolation == Isolation::None || js == Js::Pnpm;
        let sandbox = Sandbox {
            isolation,
            project: &target,
            tmp: &tmp,
            writable,
            read_only,
            inner: own.clone(),
            network,
            env_allow: &opts.policy.env_allow,
        };
        let skip: &[&str] = if isolation == Isolation::None {
            &[".git"]
        } else {
            &[".git", "node_modules"]
        };
        let before = watch_root.then(|| inspect::snapshot(&target, skip));
        let watch = if isolation == Isolation::None {
            inspect::Watch::start(&[&target])
        } else {
            None
        };
        if isolation == Isolation::None && watch.is_none() {
            monitoring_gaps.push(format!("{id}: filesystem watcher unavailable"));
        }
        let args = match js {
            Js::Npm | Js::Yarn1 | Js::Bun | Js::Berry => {
                npm::rebuild_args(&sp.pkg.name, &sp.pkg.version)
            }
            Js::Pnpm => pnpm::rebuild_args(&sp.pkg.name),
        };
        let output = sandbox
            .command(js.program(), &args)
            .output()
            .with_context(|| format!("could not run install scripts of {id}"))?;
        if !output.status.success() {
            record_failure(&mut report, sp, &output);
        }

        // pnpm's own state: node_modules outside the store, and its
        // `_tmp_*` files in the project root.
        let bookkeeping = |p: &PathBuf| {
            js == Js::Pnpm
                && ((p.starts_with(target.join("node_modules"))
                    && !p.starts_with(target.join("node_modules/.pnpm")))
                    || (p.parent() == Some(target.as_path())
                        && p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("_tmp_"))))
        };
        let outside = |p: &PathBuf| !own.iter().any(|o| p.starts_with(o)) && !bookkeeping(p);
        if let Some(before) = before {
            let after = inspect::snapshot(&target, skip);
            let c = inspect::changes(&before, &after);
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
                        &sp.pkg.name,
                        &sp.pkg.version,
                        &sp.pkg.dir,
                        format!(
                            "its install script {what} {} file(s) outside its package: {}",
                            foreign.len(),
                            shown.join(", ")
                        ),
                    ));
                }
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
                            &sp.pkg.name,
                            &sp.pkg.version,
                            &sp.pkg.dir,
                            format!(
                                "created and deleted files outside its package while running: {}",
                                foreign.join(", ")
                            ),
                        ));
                    }
                }
                Err(e) => monitoring_gaps.push(format!("{id}: {e}")),
            }
        }
    }
    if !monitoring_gaps.is_empty() {
        report.checks.push(Check::incomplete(
            "install:monitoring",
            monitoring_gaps.join("; "),
        ));
    }

    // The project's own lifecycle scripts (--ignore-scripts returned above).
    // They are the project's code, so they run normally.
    {
        let manifest: serde_json::Value = std::fs::read_to_string(project.join("package.json"))
            .ok()
            .and_then(|m| serde_json::from_str(&m).ok())
            .unwrap_or_default();
        for hook in npm::root_hooks(&manifest) {
            let result = match js {
                Js::Npm => npm::run_root_hook(&project, &hook),
                Js::Yarn1 | Js::Berry => yarn::run_root_hook(&project, &hook),
                Js::Bun => bun::run_root_hook(&project, &hook),
                Js::Pnpm => pnpm::run_root_hook(&project, &hook),
            };
            if let Err(e) = result {
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

/// Copy a directory tree (Berry's `.yarn/releases` and friends).
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    if !from.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)?.flatten() {
        let dest = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), dest)?;
        }
    }
    Ok(())
}

/// Berry builds every approved package in one `yarn rebuild`: it cannot
/// target one without rewriting the lockfile. The project is writable for
/// Berry's state; `.git`, the cache and every unplugged package except the
/// ones building are read-only, and project-root writes are checked after.
fn run_berry_builds(
    report: &mut Report,
    target: &Path,
    tmp: &Path,
    order: &[ScriptPackage],
    isolation: Isolation,
    opts: &InstallOpts<'_>,
) {
    if order.is_empty() {
        return;
    }
    if report
        .findings
        .iter()
        .any(|f| f.rule == "INSTALL/SuspiciousScript")
    {
        report.checks.push(Check::incomplete(
            "install:execute",
            "a held-back script blocks the Yarn build step, which would also build it; no builds ran — builds stay pending, and a plain `yarn install` would run them all",
        ));
        return;
    }
    let network = order
        .iter()
        .any(|s| opts.policy.script_network.contains(&s.pkg.name));
    let sandbox = Sandbox {
        isolation,
        project: target,
        tmp,
        writable: vec![target.to_path_buf()],
        read_only: vec![
            target.join(".git"),
            target.join(".yarn/unplugged"),
            target.join(".yarn/cache"),
        ],
        inner: order.iter().map(|s| s.pkg.dir.clone()).collect(),
        network,
        env_allow: &opts.policy.env_allow,
    };
    let skip: &[&str] = &[".git", ".yarn", "node_modules"];
    let before = inspect::snapshot(target, skip);
    terminal::info(&format!(
        "Running install scripts of {} package(s) (Yarn builds them together)...",
        order.len()
    ));
    let mut cmd = sandbox.command("yarn", &["rebuild".to_string()]);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    match cmd.output() {
        Ok(out) if !out.status.success() => {
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            // Yarn reports each failed build as `YN0009: │ <locator> couldn't be
            // built successfully (…, logs can be found here: <path>)`; the
            // script's own error is in that log.
            let mut refused = false;
            for line in log.lines().filter(|l| l.contains("YN0009")) {
                let locator = line.split('│').nth(1).unwrap_or(line).trim();
                // `name@<range>`; a scoped name starts with its own `@`.
                let name = locator
                    .get(1..)
                    .and_then(|l| l.find('@'))
                    .map_or(locator, |i| &locator[..=i]);
                let build_log = line
                    .split("logs can be found here: ")
                    .nth(1)
                    .map(|p| p.trim_end_matches(')').trim())
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .unwrap_or_default();
                if build_log.contains("EROFS") || build_log.contains("read-only file system") {
                    refused = true;
                    report.findings.push(package_finding(
                        "INSTALL/BlockedWrite",
                        Severity::High,
                        name.trim_end_matches('@'),
                        "",
                        target,
                        "its install script tried to write outside its own package directory; the sandbox refused".into(),
                    ));
                }
            }
            if !refused {
                report.checks.push(Check::error(
                    "install:execute",
                    format!(
                        "a build failed: {}",
                        log.lines().rev().take(4).collect::<Vec<_>>().join(" | ")
                    ),
                ));
            }
        }
        Ok(_) => {}
        Err(e) => report.checks.push(Check::error(
            "install:execute",
            format!("could not run yarn rebuild: {e}"),
        )),
    }
    let c = inspect::changes(&before, &inspect::snapshot(target, skip));
    let changed: Vec<String> = c
        .created
        .iter()
        .chain(&c.modified)
        .chain(&c.deleted)
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".pnp."))
        })
        .take(5)
        .map(|p| rel(p, target))
        .collect();
    if !changed.is_empty() {
        report.findings.push(package_finding(
            "INSTALL/ForeignWrite",
            Severity::High,
            "yarn build",
            "",
            target,
            format!(
                "install scripts changed files in the project: {}",
                changed.join(", ")
            ),
        ));
    }
}

/// A failed script: a refused write is a finding; anything else an error,
/// with a hint when it looks like it needed the network.
fn record_failure(report: &mut Report, sp: &ScriptPackage, output: &std::process::Output) {
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
    let id = format!("{}@{}", sp.pkg.name, sp.pkg.version);
    if log.contains("EROFS") || log.contains("read-only file system") {
        report.findings.push(package_finding(
            "INSTALL/BlockedWrite",
            Severity::High,
            &sp.pkg.name,
            &sp.pkg.version,
            &sp.pkg.dir,
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
            pkg: Installed {
                dir: PathBuf::from(format!("node_modules/{name}")),
                name: name.into(),
                version: "1.0.0".into(),
                manifest: serde_json::Value::Null,
            },
            hooks: vec![],
            signals: vec![],
            blob: None,
            helpers: vec![],
        };
        let order = execution_order(&lock, vec![sp("a"), sp("b")]);
        let names: Vec<&str> = order.iter().map(|s| s.pkg.name.as_str()).collect();
        assert_eq!(names, ["b", "a"]);
    }
}
