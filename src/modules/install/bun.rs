//! Bun: plan with `--lockfile-only`, fetch with `--frozen-lockfile
//! --ignore-scripts`. Bun runs dependency scripts only for trusted packages
//! (`trustedDependencies` plus its built-in list); `bun pm untrusted` names
//! the rest, and greengate leaves them unrun too. Bun's `node_modules` is
//! npm's shape, so approved scripts run via `npm rebuild`.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bun(dir: &Path) -> Command {
    let mut c = Command::new("bun"); // greengate: ignore — the wrapped package manager
    c.current_dir(dir);
    c
}

pub enum Sub {
    Install(Vec<String>),
    Add(Vec<String>),
}

pub fn parse_args(args: &[String]) -> Result<Sub> {
    let Some((sub, rest)) = args.split_first() else {
        return Ok(Sub::Install(Vec::new()));
    };
    if rest.iter().any(|a| a == "-g" || a == "--global") {
        bail!("greengate install does not handle global installs");
    }
    if rest.iter().any(|a| a == "--cwd" || a.starts_with("--cwd=")) {
        bail!("--cwd is not supported by greengate install; run it from that directory instead");
    }
    super::reject_overrides("bun", rest, &["lockfile-only", "ignore-scripts"])?;
    match sub.as_str() {
        "install" | "i" => Ok(Sub::Install(rest.to_vec())),
        "add" | "a" => Ok(Sub::Add(rest.to_vec())),
        other => bail!(
            "`bun {other}` is not an install; greengate install wraps `bun install` and `bun add`"
        ),
    }
}

pub const MANIFESTS: &[&str] = &["package.json", "bun.lock", "bunfig.toml", ".npmrc"];

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("could not run {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

/// greengate's flags come after the caller's.
pub fn plan(work: &Path, sub: &Sub) -> Result<()> {
    let mut cmd = bun(work);
    match sub {
        Sub::Install(a) => {
            cmd.arg("install")
                .args(a.iter().filter(|x| *x != "--frozen-lockfile"));
        }
        Sub::Add(a) => {
            cmd.arg("add").args(a);
        }
    }
    cmd.args(["--lockfile-only", "--ignore-scripts"]);
    run(&mut cmd, "`bun --lockfile-only`")
}

pub fn fetch(dir: &Path, sub: &Sub) -> Result<()> {
    let flags: Vec<String> = match sub {
        Sub::Install(a) | Sub::Add(a) => a
            .iter()
            .filter(|f| matches!(f.as_str(), "--production" | "-p" | "--omit=dev"))
            .cloned()
            .collect(),
    };
    run(
        bun(dir)
            .args(["install", "--frozen-lockfile", "--ignore-scripts"])
            .args(flags),
        "`bun install --frozen-lockfile --ignore-scripts`",
    )
}

/// Package directories whose scripts Bun's trust policy blocks.
pub fn untrusted(dir: &Path) -> HashSet<PathBuf> {
    let Ok(out) = bun(dir).args(["pm", "untrusted"]).output() else {
        return HashSet::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let path = l.trim().strip_prefix("./")?.split(" @").next()?;
            path.starts_with("node_modules/").then(|| dir.join(path))
        })
        .collect()
}

pub fn run_root_hook(dir: &Path, hook: &str) -> Result<()> {
    run(
        bun(dir).args(["run", hook]),
        &format!("the project's `{hook}` script"),
    )
}
