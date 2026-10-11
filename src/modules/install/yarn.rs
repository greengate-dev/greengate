//! Yarn 1 and Yarn Berry (2+).
//!
//! Yarn 1 has no lockfile-only mode, so the plan is a full
//! `--ignore-scripts` install in the scratch copy (downloads, no code). Its
//! `node_modules` tree is npm's shape, so scripts run via `npm rebuild`.
//!
//! Berry plans with `--mode=update-lockfile` and fetches with
//! `--mode=skip-build`, which unplugs exactly the packages that have build
//! scripts. Berry cannot build one package at a time without rewriting the
//! lockfile, so its approved builds run in one sandboxed `yarn rebuild`.

use super::inspect::{self, Installed};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

fn yarn(dir: &Path) -> Command {
    let mut c = Command::new(if cfg!(windows) { "yarn.cmd" } else { "yarn" }); // greengate: ignore — the wrapped package manager
    c.current_dir(dir)
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    c
}

/// Whether `dir` uses Yarn 2+ (corepack picks the version from
/// `packageManager`).
pub fn is_berry(dir: &Path) -> bool {
    yarn(dir)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .split('.')
                .next()?
                .parse::<u32>()
                .ok()
        })
        .is_some_and(|major| major >= 2)
}

pub enum Sub {
    Install(Vec<String>),
    Add(Vec<String>),
}

pub fn parse_args(args: &[String]) -> Result<Sub> {
    match args.split_first() {
        None => Ok(Sub::Install(Vec::new())),
        Some((sub, rest)) => match sub.as_str() {
            "install" => Ok(Sub::Install(rest.to_vec())),
            "add" => Ok(Sub::Add(rest.to_vec())),
            s if s.starts_with('-') => Ok(Sub::Install(args.to_vec())),
            other => bail!(
                "`yarn {other}` is not an install; greengate install wraps `yarn install` and `yarn add`"
            ),
        },
    }
}

pub const MANIFESTS_V1: &[&str] = &["package.json", "yarn.lock", ".yarnrc", ".npmrc"];
pub const MANIFESTS_BERRY: &[&str] = &["package.json", "yarn.lock", ".yarnrc.yml"];
/// Berry keeps its own release, plugins and patches in the project.
pub const BERRY_DIRS: &[&str] = &[".yarn/releases", ".yarn/plugins", ".yarn/patches"];

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("could not run {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

fn without<'a>(args: &'a [String], drop: &[&str]) -> impl Iterator<Item = &'a String> {
    let drop: Vec<String> = drop.iter().map(|d| d.to_string()).collect();
    args.iter().filter(move |a| !drop.contains(a))
}

pub fn plan(work: &Path, sub: &Sub, berry: bool) -> Result<()> {
    let mut cmd = yarn(work);
    match (sub, berry) {
        (Sub::Install(a), false) => {
            cmd.args(["install", "--ignore-scripts", "--non-interactive"])
                .args(without(a, &["--frozen-lockfile", "--immutable"]));
        }
        (Sub::Add(a), false) => {
            cmd.args(["add", "--ignore-scripts", "--non-interactive"])
                .args(a);
        }
        (Sub::Install(a), true) => {
            cmd.args(["install", "--mode=update-lockfile"])
                .args(without(a, &["--immutable", "--frozen-lockfile"]));
        }
        (Sub::Add(a), true) => {
            cmd.args(["add", "--mode=update-lockfile"]).args(a);
        }
    }
    run(&mut cmd, "the yarn plan")
}

pub fn fetch(dir: &Path, sub: &Sub, berry: bool) -> Result<()> {
    let flags: Vec<String> = match sub {
        Sub::Install(a) | Sub::Add(a) => a
            .iter()
            .filter(|f| *f == "--production" || f.starts_with("--production="))
            .cloned()
            .collect(),
    };
    if berry {
        run(
            yarn(dir).args(["install", "--immutable", "--mode=skip-build"]),
            "`yarn install --immutable --mode=skip-build`",
        )
    } else {
        run(
            yarn(dir)
                .args([
                    "install",
                    "--frozen-lockfile",
                    "--ignore-scripts",
                    "--non-interactive",
                ])
                .args(flags),
            "`yarn install --frozen-lockfile --ignore-scripts`",
        )
    }
}

/// Berry with Plug'n'Play: the packages with build scripts are unplugged to
/// `.yarn/unplugged/<id>/node_modules/<name>`; everything else stays zipped.
/// With `nodeLinker: node-modules`, the tree is npm's shape.
pub fn installed_packages(dir: &Path) -> Vec<Installed> {
    if dir.join("node_modules").is_dir() {
        return inspect::installed_packages(&dir.join("node_modules"));
    }
    let mut out = Vec::new();
    let Ok(ids) = std::fs::read_dir(dir.join(".yarn/unplugged")) else {
        return out;
    };
    for id in ids.flatten() {
        out.extend(inspect::installed_packages(&id.path().join("node_modules")));
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

pub fn run_root_hook(dir: &Path, hook: &str) -> Result<()> {
    run(
        yarn(dir).args(["run", hook]),
        &format!("the project's `{hook}` script"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommands() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(matches!(parse_args(&[]), Ok(Sub::Install(_))));
        assert!(matches!(
            parse_args(&args(&["--frozen-lockfile"])),
            Ok(Sub::Install(_))
        ));
        assert!(matches!(parse_args(&args(&["add", "x"])), Ok(Sub::Add(_))));
        assert!(parse_args(&args(&["run", "build"])).is_err());
    }
}
