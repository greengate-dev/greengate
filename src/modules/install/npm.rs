//! npm: plan with `--package-lock-only`, fetch with `npm ci --ignore-scripts`,
//! run each approved package's install scripts with `npm rebuild <name>@<v>`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

fn npm() -> Command {
    Command::new(if cfg!(windows) { "npm.cmd" } else { "npm" }) // greengate: ignore — the wrapped package manager
}

pub enum Sub {
    /// `npm install [specs…] [flags…]`: resolve (possibly adding packages).
    Install(Vec<String>),
    /// `npm ci [flags…]`: install exactly the lockfile.
    Ci(Vec<String>),
}

/// Parse the arguments after `npm`.
pub fn parse_args(args: &[String]) -> Result<Sub> {
    let Some((sub, rest)) = args.split_first() else {
        bail!("expected an npm install command, e.g. `greengate install npm ci`");
    };
    if rest
        .iter()
        .any(|a| a == "-g" || a == "--global" || a.starts_with("--location=global"))
    {
        bail!("greengate install does not handle global installs");
    }
    match sub.as_str() {
        "install" | "i" | "in" | "add" | "isntall" => Ok(Sub::Install(rest.to_vec())),
        "ci" | "clean-install" | "install-clean" => Ok(Sub::Ci(rest.to_vec())),
        other => bail!(
            "`npm {other}` is not an install; greengate install wraps `npm install` and `npm ci`"
        ),
    }
}

impl Sub {
    /// Flags that shape which packages `npm ci` installs (`--omit=dev`, …).
    fn ci_flags(&self) -> Vec<String> {
        let args = match self {
            Sub::Install(a) | Sub::Ci(a) => a,
        };
        args.iter()
            .filter(|a| {
                [
                    "--omit",
                    "--include",
                    "--production",
                    "--legacy-peer-deps",
                    "--strict-peer-deps",
                    "--workspace",
                    "-w",
                ]
                .iter()
                .any(|f| a.starts_with(f))
            })
            .cloned()
            .collect()
    }
}

const MANIFESTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    ".npmrc",
];

/// Copy the files npm resolves from — every package.json (workspaces
/// included), the lockfile and .npmrc — into `work`, keeping their paths.
pub fn stage(project: &Path, work: &Path) -> Result<()> {
    let mut stack = vec![project.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .flatten()
        {
            let path = e.path();
            let name = e.file_name();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if !matches!(name.to_str(), Some("node_modules" | ".git" | "target")) {
                    stack.push(path);
                }
            } else if MANIFESTS.iter().any(|m| name == *m) {
                let rel = path.strip_prefix(project).unwrap_or(&path);
                let dest = work.join(rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&path, &dest)?;
            }
        }
    }
    Ok(())
}

/// Make relative `file:` / `link:` dependencies (local tarballs and
/// directories) resolvable from `work`: link each target at the same
/// relative location. Specs come from the staged manifests and from `args`.
pub fn link_local_specs(project: &Path, work: &Path, args: &[String]) -> Result<()> {
    let mut targets: Vec<std::path::PathBuf> = Vec::new();
    let mut add = |base: &Path, spec: &str| {
        let rel = spec
            .strip_prefix("file:")
            .or_else(|| spec.strip_prefix("link:"))
            .unwrap_or(spec);
        let local = rel.starts_with("./")
            || rel.starts_with("../")
            || spec.starts_with("file:")
            || spec.starts_with("link:");
        if local && !Path::new(rel).is_absolute() {
            targets.push(base.join(rel));
        }
    };
    for a in args.iter().filter(|a| !a.starts_with('-')) {
        add(Path::new(""), a);
    }
    let mut stack = vec![work.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(e.path());
            } else if e.file_name() == "package.json" {
                let rel_dir = dir.strip_prefix(work).unwrap_or(&dir).to_path_buf();
                let manifest: serde_json::Value = std::fs::read_to_string(e.path())
                    .ok()
                    .and_then(|m| serde_json::from_str(&m).ok())
                    .unwrap_or_default();
                for section in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ] {
                    for spec in manifest
                        .get(section)
                        .and_then(|s| s.as_object())
                        .into_iter()
                        .flatten()
                    {
                        if let Some(s) = spec.1.as_str() {
                            add(&rel_dir, s);
                        }
                    }
                }
            }
        }
    }
    // The scratch root contains `work`; a link may land beside it, never
    // outside it.
    let scratch = work.parent().unwrap_or(work);
    for rel in targets {
        let source = normalize(&project.join(&rel));
        let dest = normalize(&work.join(&rel));
        if !dest.starts_with(scratch) || dest.exists() || !source.exists() {
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&source, &dest)?;
        #[cfg(not(unix))]
        if source.is_file() {
            std::fs::copy(&source, &dest)?;
        }
    }
    Ok(())
}

/// Resolve `.` and `..` lexically.
fn normalize(p: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("could not run {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

/// Phase 1: resolve the tree into `work/package-lock.json` without
/// downloading packages or running any code.
pub fn plan(work: &Path, sub: &Sub) -> Result<()> {
    match sub {
        Sub::Ci(_) => {
            if !work.join("package-lock.json").is_file()
                && !work.join("npm-shrinkwrap.json").is_file()
            {
                bail!("`npm ci` needs a package-lock.json or npm-shrinkwrap.json");
            }
            Ok(())
        }
        Sub::Install(args) => run(
            npm()
                .current_dir(work)
                .args([
                    "install",
                    "--package-lock-only",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ])
                .args(args),
            "`npm install --package-lock-only`",
        ),
    }
}

/// Phase 2: download and extract the planned tree with every script off.
pub fn fetch(dir: &Path, sub: &Sub) -> Result<()> {
    run(
        npm()
            .current_dir(dir)
            .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
            .args(sub.ci_flags()),
        "`npm ci --ignore-scripts`",
    )
}

/// Arguments that run the install scripts of exactly `name@version`.
/// Bins were linked by `npm ci`; relinking would write outside the package.
pub fn rebuild_args(name: &str, version: &str) -> Vec<String> {
    vec![
        "rebuild".into(),
        "--bin-links=false".into(),
        "--no-audit".into(),
        "--no-fund".into(),
        format!("{name}@{version}"),
    ]
}

/// The project's own lifecycle scripts that `npm ci` would have run.
pub fn root_hooks(manifest: &serde_json::Value) -> Vec<String> {
    let scripts = manifest.get("scripts").and_then(|s| s.as_object());
    ["preinstall", "install", "postinstall", "prepare"]
        .iter()
        .filter(|h| scripts.is_some_and(|s| s.contains_key(**h)))
        .map(|h| h.to_string())
        .collect()
}

pub fn run_root_hook(dir: &Path, hook: &str) -> Result<()> {
    run(
        npm().current_dir(dir).args(["run-script", hook]),
        &format!("the project's `{hook}` script"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn subcommands() {
        assert!(matches!(parse_args(&args(&["ci"])), Ok(Sub::Ci(_))));
        let Ok(sub) = parse_args(&args(&["i", "left-pad", "--omit=dev", "-D"])) else {
            panic!()
        };
        assert_eq!(sub.ci_flags(), ["--omit=dev"]);
        assert!(parse_args(&args(&["run", "build"])).is_err());
        assert!(parse_args(&args(&["install", "-g", "x"])).is_err());
    }
}
