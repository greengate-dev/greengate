//! pnpm: plan with `--lockfile-only`, fetch with
//! `--frozen-lockfile --ignore-scripts`, run approved builds with
//! `pnpm rebuild <name>`.
//!
//! pnpm keeps packages in `node_modules/.pnpm/<id>/node_modules/<name>`, and
//! from pnpm 10 runs dependency build scripts only for packages it is told
//! to (`onlyBuiltDependencies`). greengate keeps that policy: it never runs a
//! build pnpm itself would not.

use super::inspect::{self, Installed};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

fn pnpm() -> Command {
    Command::new(if cfg!(windows) { "pnpm.cmd" } else { "pnpm" }) // greengate: ignore — the wrapped package manager
}

pub enum Sub {
    /// `pnpm install [flags…]`.
    Install(Vec<String>),
    /// `pnpm add <specs…> [flags…]`.
    Add(Vec<String>),
}

pub fn parse_args(args: &[String]) -> Result<Sub> {
    let Some((sub, rest)) = args.split_first() else {
        bail!(
            "expected a pnpm install command, e.g. `greengate install pnpm install --frozen-lockfile`"
        );
    };
    if rest.iter().any(|a| a == "-g" || a == "--global") {
        bail!("greengate install does not handle global installs");
    }
    if rest
        .iter()
        .any(|a| a == "-C" || a == "--dir" || a.starts_with("--dir="))
    {
        bail!("--dir is not supported by greengate install; run it from that directory instead");
    }
    super::reject_overrides("pnpm", rest, &["lockfile-only", "ignore-scripts"])?;
    match sub.as_str() {
        "install" | "i" => Ok(Sub::Install(rest.to_vec())),
        "add" => Ok(Sub::Add(rest.to_vec())),
        other => bail!(
            "`pnpm {other}` is not an install; greengate install wraps `pnpm install` and `pnpm add`"
        ),
    }
}

impl Sub {
    /// Flags that shape what `pnpm install` installs (`--prod`, `--filter`, …).
    fn install_flags(&self) -> Vec<String> {
        let args = match self {
            Sub::Install(a) | Sub::Add(a) => a,
        };
        args.iter()
            .filter(|a| {
                [
                    "--prod",
                    "-P",
                    "--dev",
                    "-D",
                    "--no-optional",
                    "--filter",
                    "-F",
                    "--recursive",
                    "-r",
                ]
                .iter()
                .any(|f| a.as_str() == *f || a.starts_with(&format!("{f}=")))
            })
            .cloned()
            .collect()
    }
}

pub const MANIFESTS: &[&str] = &[
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".npmrc",
    ".pnpmfile.cjs",
];

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("could not run {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

/// greengate's flags come after the caller's: pnpm takes the last value.
pub fn plan(work: &Path, sub: &Sub) -> Result<()> {
    let mut cmd = pnpm();
    cmd.current_dir(work);
    match sub {
        Sub::Install(args) => {
            cmd.arg("install")
                .args(args.iter().filter(|a| *a != "--frozen-lockfile"));
        }
        Sub::Add(args) => {
            cmd.arg("add").args(args);
        }
    }
    cmd.args(["--lockfile-only", "--ignore-scripts"]);
    run(&mut cmd, "`pnpm --lockfile-only`")
}

pub fn fetch(dir: &Path, sub: &Sub) -> Result<()> {
    run(
        pnpm()
            .current_dir(dir)
            .args([
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--config.side-effects-cache=false",
            ])
            .args(sub.install_flags()),
        "`pnpm install --frozen-lockfile --ignore-scripts`",
    )
}

/// Every package in pnpm's virtual store. The real directory of each lives
/// in `.pnpm/<id>/node_modules/<name>`; its dependencies there are symlinks.
pub fn installed_packages(node_modules: &Path) -> Vec<Installed> {
    let mut out = Vec::new();
    let Ok(ids) = std::fs::read_dir(node_modules.join(".pnpm")) else {
        return out;
    };
    for id in ids
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
    {
        let nm = id.path().join("node_modules");
        let Ok(entries) = std::fs::read_dir(&nm) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let dirs: Vec<std::path::PathBuf> = if name.starts_with('@') {
                std::fs::read_dir(&path)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|c| c.path())
                    .collect()
            } else {
                vec![path]
            };
            for d in dirs {
                // Symlinks are this package's dependencies, not packages here.
                if std::fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir())
                    && let Some(pkg) = inspect::read_package(&d)
                {
                    out.push(pkg);
                }
            }
        }
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

/// Which dependencies pnpm itself will build.
pub enum BuildPolicy {
    All,
    Only(Vec<String>),
    AllExcept(Vec<String>),
    None,
}

impl BuildPolicy {
    pub fn allows(&self, name: &str) -> bool {
        match self {
            BuildPolicy::All => true,
            BuildPolicy::Only(names) => names.iter().any(|n| n == name),
            BuildPolicy::AllExcept(names) => !names.iter().any(|n| n == name),
            BuildPolicy::None => false,
        }
    }
}

fn major_version() -> Option<u32> {
    let out = pnpm().arg("--version").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// pnpm's build settings, from `pnpm-workspace.yaml` and the `pnpm` field of
/// `package.json`.
pub fn build_policy(project: &Path) -> BuildPolicy {
    let workspace: serde_norway::Value =
        std::fs::read_to_string(project.join("pnpm-workspace.yaml"))
            .ok()
            .and_then(|y| serde_norway::from_str(&y).ok())
            .unwrap_or_default();
    let manifest: serde_json::Value = std::fs::read_to_string(project.join("package.json"))
        .ok()
        .and_then(|m| serde_json::from_str(&m).ok())
        .unwrap_or_default();
    let list = |key: &str| -> Option<Vec<String>> {
        let from_yaml = workspace.get(key).and_then(|v| v.as_sequence()).map(|s| {
            s.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        });
        let from_json = manifest
            .get("pnpm")
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            });
        from_yaml.or(from_json)
    };
    let all = workspace
        .get("dangerouslyAllowAllBuilds")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            manifest
                .get("pnpm")?
                .get("dangerouslyAllowAllBuilds")?
                .as_bool()
        })
        .unwrap_or(false);
    if all {
        return BuildPolicy::All;
    }
    if let Some(only) = list("onlyBuiltDependencies") {
        return BuildPolicy::Only(only);
    }
    if let Some(never) = list("neverBuiltDependencies") {
        return BuildPolicy::AllExcept(never);
    }
    // pnpm 10 builds nothing by default; earlier versions build everything.
    if major_version().is_some_and(|v| v < 10) {
        BuildPolicy::All
    } else {
        BuildPolicy::None
    }
}

/// Arguments that run the build scripts of `name` (every installed copy).
pub fn rebuild_args(name: &str) -> Vec<String> {
    vec![
        "rebuild".into(),
        "--config.side-effects-cache=false".into(),
        name.to_string(),
    ]
}

pub fn run_root_hook(dir: &Path, hook: &str) -> Result<()> {
    run(
        pnpm().current_dir(dir).args(["run", hook]),
        &format!("the project's `{hook}` script"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommands_and_flags() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let Ok(sub) = parse_args(&args(&["install", "--frozen-lockfile", "--prod"])) else {
            panic!()
        };
        assert_eq!(sub.install_flags(), ["--prod"]);
        assert!(matches!(parse_args(&args(&["add", "x"])), Ok(Sub::Add(_))));
        assert!(parse_args(&args(&["run", "build"])).is_err());
    }

    #[test]
    fn build_policy_from_workspace_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();
        let p = build_policy(dir.path());
        assert!(p.allows("esbuild") && !p.allows("evil"));
        std::fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "dangerouslyAllowAllBuilds: true\n",
        )
        .unwrap();
        assert!(build_policy(dir.path()).allows("anything"));
    }
}
