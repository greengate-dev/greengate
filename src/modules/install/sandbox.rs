//! Running dependency install scripts with as little reach as possible.
//!
//! With bubblewrap (Linux), a script runs in a sandbox where the whole system
//! is read-only except its own package directory and a private temp dir,
//! known credential files are masked, and — unless the package is allowed
//! network — there is no network at all. The package's own code will run at
//! runtime anyway; the sandbox makes sure install time grants nothing more.
//!
//! Without isolation, scripts still run with a scrubbed environment, and the
//! caller verifies the filesystem afterwards.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum IsolateMode {
    /// bubblewrap when it works here, otherwise none
    Auto,
    /// require bubblewrap
    Bwrap,
    /// run scripts directly (still with a scrubbed environment)
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    Bwrap,
    None,
}

impl Isolation {
    pub fn describe(self, network: bool) -> String {
        match self {
            Isolation::Bwrap => format!(
                "bubblewrap: read-only system, writes confined to the package, credentials masked, {}",
                if network {
                    "network allowed"
                } else {
                    "no network"
                }
            ),
            Isolation::None => {
                "not isolated: scrubbed environment, filesystem verified afterwards".into()
            }
        }
    }
}

/// Whether bubblewrap can actually create a sandbox here (it may be
/// installed but blocked, e.g. by disabled user namespaces).
fn bwrap_works() -> bool {
    Command::new("bwrap") // greengate: ignore — probing the sandbox tool
        .args([
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--unshare-net",
            "--",
            "true",
        ])
        .output()
        .is_ok_and(|o| o.status.success())
}

pub fn detect(mode: IsolateMode) -> Result<Isolation> {
    let available = cfg!(target_os = "linux") && bwrap_works();
    match (mode, available) {
        (IsolateMode::None, _) => Ok(Isolation::None),
        (_, true) => Ok(Isolation::Bwrap),
        (IsolateMode::Bwrap, false) => {
            bail!("--isolate bwrap: bubblewrap is not installed or cannot create a sandbox here")
        }
        (IsolateMode::Auto, false) => Ok(Isolation::None),
    }
}

/// Credential locations a script has no business reading.
const SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".docker",
    ".kube",
    ".config/gh",
    ".config/gcloud",
];
const SECRET_FILES: &[&str] = &[
    ".npmrc",
    ".yarnrc.yml",
    ".netrc",
    ".git-credentials",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
];

/// Environment variables that look like credentials.
pub fn is_secret_var(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASS",
        "_API_KEY",
        "_ACCESS_KEY",
        "_PRIVATE_KEY",
        "_AUTH",
    ]
    .iter()
    .any(|s| n.ends_with(s))
        || n.starts_with("AWS_")
        || matches!(
            n.as_str(),
            "SSH_AUTH_SOCK" | "NPM_TOKEN" | "GITHUB_TOKEN" | "GH_TOKEN"
        )
}

/// What a sandboxed command may touch.
pub struct Sandbox<'a> {
    pub isolation: Isolation,
    /// The project directory (working directory of the command).
    pub project: &'a Path,
    /// A private, writable temp directory (`TMPDIR`).
    pub tmp: &'a Path,
    /// Directories the command may write.
    pub writable: Vec<PathBuf>,
    pub network: bool,
    /// Variables kept even if they look like credentials.
    pub env_allow: &'a [String],
}

impl Sandbox<'_> {
    /// `program args…` wrapped for this sandbox, environment scrubbed.
    pub fn command(&self, program: &str, args: &[String]) -> Command {
        let mut cmd = match self.isolation {
            Isolation::None => {
                let mut c = Command::new(program); // greengate: ignore — running an approved install script
                c.args(args);
                c
            }
            Isolation::Bwrap => {
                let mut c = Command::new("bwrap"); // greengate: ignore — sandboxing an install script
                c.args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]);
                c.args(["--die-with-parent", "--unshare-pid"]);
                if !self.network {
                    c.arg("--unshare-net");
                }
                if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                    for d in SECRET_DIRS
                        .iter()
                        .map(|d| home.join(d))
                        .filter(|d| d.is_dir())
                    {
                        c.arg("--tmpfs").arg(d);
                    }
                    for f in SECRET_FILES
                        .iter()
                        .map(|f| home.join(f))
                        .filter(|f| f.is_file())
                    {
                        c.arg("--ro-bind").arg("/dev/null").arg(f);
                    }
                }
                // A project .npmrc may carry a registry token.
                let npmrc = self.project.join(".npmrc");
                if npmrc.is_file() {
                    c.arg("--ro-bind").arg("/dev/null").arg(&npmrc);
                }
                c.arg("--bind").arg(self.tmp).arg(self.tmp);
                for w in &self.writable {
                    c.arg("--bind").arg(w).arg(w);
                }
                c.arg("--chdir")
                    .arg(self.project)
                    .arg("--")
                    .arg(program)
                    .args(args);
                c
            }
        };
        cmd.current_dir(self.project);
        for (k, _) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if is_secret_var(&name) && !self.env_allow.iter().any(|a| a == &*name) {
                cmd.env_remove(&k);
            }
        }
        cmd.env("TMPDIR", self.tmp);
        // npm writes its cache and logs; keep them in the private temp dir.
        cmd.env("npm_config_cache", self.tmp.join("npm-cache"));
        cmd.env("npm_config_update_notifier", "false");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_variables_are_recognised() {
        for v in [
            "NPM_TOKEN",
            "github_token",
            "AWS_PROFILE",
            "MY_API_KEY",
            "SSH_AUTH_SOCK",
            "NODE_AUTH_TOKEN",
        ] {
            assert!(is_secret_var(v), "{v}");
        }
        for v in [
            "PATH",
            "HOME",
            "npm_config_registry",
            "CI",
            "TOKENIZER_MODE",
        ] {
            assert!(!is_secret_var(v), "{v}");
        }
    }
}
