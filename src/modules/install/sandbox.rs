//! Running dependency install scripts with as little reach as possible.
//!
//! With bubblewrap (Linux), a script runs in a sandbox where the system is
//! read-only, the home directory, `/tmp` and `/run` are private and empty
//! (except the toolchains a build needs, read-only), the project's secret
//! files (`.env*`, `.npmrc`, `.git/config`…) are masked, writes are confined
//! to its own package directory, and — unless the package is allowed network
//! — there is no network at all. It gets its own namespaces and terminal
//! session, so it cannot signal or type into anything outside.
//!
//! In both modes, the environment is reduced to an allowlist: what builds
//! need (`PATH`, compilers, proxies, package-manager settings), never what
//! looks like a credential. Without isolation, the caller also verifies the
//! filesystem afterwards.

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
                "bubblewrap: read-only system, private home and /tmp, project secrets masked, writes confined, {}",
                if network {
                    "network allowed"
                } else {
                    "no network"
                }
            ),
            Isolation::None => {
                "not isolated: allowlisted environment, filesystem verified afterwards".into()
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
            "--unshare-all",
            "--new-session",
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

/// Project files that may hold credentials (also matched as `<name>.*`
/// for `.env`).
const PROJECT_SECRETS: &[&str] = &[
    ".npmrc",
    ".yarnrc.yml",
    ".yarnrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".git/config",
];

/// Toolchains that live in the home directory, re-exposed read-only.
const HOME_TOOLCHAINS: &[&str] = &[
    ".nvm",
    ".volta",
    ".fnm",
    ".bun",
    ".deno",
    ".rustup",
    ".cargo",
    ".pyenv",
    ".local/bin",
    ".local/lib",
    ".local/share/uv",
    ".local/share/pnpm",
    ".local/share/fnm",
    ".cache/node/corepack",
    ".cache/node-gyp",
    ".node-gyp",
];

/// Variables naming a toolchain directory, re-exposed read-only too.
const TOOLCHAIN_VARS: &[&str] = &[
    "NVM_DIR",
    "VOLTA_HOME",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "PNPM_HOME",
    "COREPACK_HOME",
    "BUN_INSTALL",
    "PYENV_ROOT",
    "UV_PYTHON_INSTALL_DIR",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "JAVA_HOME",
];

/// Environment variables that look like credentials.
pub fn is_secret_var(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASS",
        "_KEY",
        "_AUTH",
        "_CREDENTIALS",
        "AUTHTOKEN",
    ]
    .iter()
    .any(|s| n.ends_with(s))
        || ["SECRET", "PASSWORD", "_AUTH", ":_", "CREDENTIAL"]
            .iter()
            .any(|s| n.contains(s))
        || n.starts_with("AWS_")
        || matches!(
            n.as_str(),
            "SSH_AUTH_SOCK" | "NPM_TOKEN" | "GITHUB_TOKEN" | "GH_TOKEN"
        )
}

/// Variables a build may need. Everything else is removed: a variable an
/// install script needs and greengate does not know goes in `env_allow`.
const ENV_KEEP: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "TERM",
    "TZ",
    "CI",
    "SOURCE_DATE_EPOCH",
    "MAKEFLAGS",
    "CC",
    "CXX",
    "CPP",
    "AR",
    "LD",
    "NM",
    "RANLIB",
    "STRIP",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_SYSROOT_DIR",
    "PYTHON",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
];
/// Prefixes of variables a build may need (package-manager settings).
const ENV_KEEP_PREFIX: &[&str] = &[
    "LC_",
    "npm_config_",
    "NPM_CONFIG_",
    "PIP_",
    "UV_",
    "YARN_",
    "COREPACK_",
    "NODE_",
    "PYTHON",
    "CARGO_",
    "RUSTUP_",
    "RUSTFLAGS",
];

/// Whether `name` matches an `env_allow` entry (exact, or `PREFIX_*`).
fn allowed(name: &str, env_allow: &[String]) -> bool {
    env_allow.iter().any(|a| match a.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => a == name,
    })
}

/// Whether an install script sees `name`: `env_allow` entries always; others
/// only when a build may need them and they do not look like credentials.
pub fn keep_var(name: &str, env_allow: &[String]) -> bool {
    allowed(name, env_allow)
        || (!is_secret_var(name)
            && (ENV_KEEP.contains(&name)
                || TOOLCHAIN_VARS.contains(&name)
                || ENV_KEEP_PREFIX.iter().any(|p| name.starts_with(p))))
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
    /// Paths inside `writable` that stay read-only (e.g. pnpm's package
    /// store under a writable project).
    pub read_only: Vec<PathBuf>,
    /// Paths inside `read_only` that are writable again (the running
    /// package's own directory).
    pub inner: Vec<PathBuf>,
    pub network: bool,
    /// Variables kept even if they look like credentials.
    pub env_allow: &'a [String],
}

impl Sandbox<'_> {
    /// `program args…` wrapped for this sandbox, environment reduced to the
    /// allowlist.
    pub fn command(&self, program: &str, args: &[String]) -> Command {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        self.command_with_home(program, args, home.as_deref())
    }

    fn command_with_home(&self, program: &str, args: &[String], home: Option<&Path>) -> Command {
        let mut cmd = match self.isolation {
            Isolation::None => {
                let mut c = Command::new(program); // greengate: ignore — running an approved install script
                c.args(args);
                c
            }
            Isolation::Bwrap => {
                let mut c = Command::new("bwrap"); // greengate: ignore — sandboxing an install script
                c.args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]);
                c.args(["--die-with-parent", "--new-session", "--unshare-all"]);
                if self.network {
                    c.arg("--share-net");
                }
                // Private, empty home, /tmp and /run (sockets of the session
                // live there); then what a build needs from them, read-only.
                let mut private: Vec<PathBuf> = vec!["/tmp".into(), "/run".into()];
                private.extend(home.map(Path::to_path_buf));
                private.retain(|p| p.is_dir() && p.parent().is_some());
                for p in &private {
                    c.arg("--tmpfs").arg(p);
                }
                for d in reexposed(home, &private, Path::new(program)) {
                    c.arg("--ro-bind").arg(&d).arg(&d);
                }
                c.arg("--ro-bind").arg(self.project).arg(self.project);
                if let Some(home) = home {
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
                c.arg("--bind").arg(self.tmp).arg(self.tmp);
                // Later mounts override earlier ones: writable, then read-only
                // carve-outs, then the project's secrets, then the writable
                // directories inside those.
                for w in &self.writable {
                    c.arg("--bind").arg(w).arg(w);
                }
                for r in self.read_only.iter().filter(|r| r.exists()) {
                    c.arg("--ro-bind").arg(r).arg(r);
                }
                for f in project_secrets(self.project) {
                    c.arg("--ro-bind").arg("/dev/null").arg(f);
                }
                for w in &self.inner {
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
            if !keep_var(&k.to_string_lossy(), self.env_allow) {
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

/// Files in the project root that may hold credentials: every `.env*` and
/// the [`PROJECT_SECRETS`] that exist.
fn project_secrets(project: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(project)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n == ".env" || n.starts_with(".env.")
        })
        .map(|e| e.path())
        .collect();
    out.extend(PROJECT_SECRETS.iter().map(|f| project.join(f)));
    out.retain(|p| p.is_file());
    out
}

/// Directories inside the `private` (emptied) ones that a build needs:
/// `PATH` entries, toolchains in the home directory and those named by
/// [`TOOLCHAIN_VARS`] and the directory of `program` when it is a path (a
/// virtualenv's `bin` as the whole virtualenv) — each also by its real path,
/// when it is a symlink.
fn reexposed(home: Option<&Path>, private: &[PathBuf], program: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(bin) = program.is_absolute().then(|| program.parent()).flatten() {
        dirs.push(bin.to_path_buf());
    }
    if let Some(home) = home {
        dirs.extend(HOME_TOOLCHAINS.iter().map(|d| home.join(d)));
    }
    dirs.extend(
        TOOLCHAIN_VARS
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from),
    );
    // systemd-resolved links /etc/resolv.conf into /run.
    if let Some(dir) = std::fs::canonicalize("/etc/resolv.conf")
        .ok()
        .and_then(|r| r.parent().map(Path::to_path_buf))
    {
        dirs.push(dir);
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs.into_iter().filter(|d| d.is_absolute() && d.is_dir()) {
        // A virtualenv's `bin` needs the rest of the virtualenv.
        let d = match d.parent().filter(|v| v.join("pyvenv.cfg").is_file()) {
            Some(venv) => venv.to_path_buf(),
            None => d,
        };
        let real = std::fs::canonicalize(&d).unwrap_or_else(|_| d.clone());
        for p in [d, real] {
            let inside = private.iter().any(|r| p.starts_with(r) && p != *r);
            if inside && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    // Parents before children, so a child mount is not hidden.
    out.sort_by_key(|p| p.components().count());
    out
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
        assert!(is_secret_var("npm_config_//registry.npmjs.org/:_authToken"));
        assert!(is_secret_var("STRIPE_KEY"));
    }

    #[test]
    fn environment_is_an_allowlist() {
        let allow = vec!["DATABASE_URL_RO".to_string(), "SHARP_*".to_string()];
        for v in [
            "PATH",
            "HOME",
            "CC",
            "LC_ALL",
            "npm_config_registry",
            "PIP_INDEX_URL",
            "HTTPS_PROXY",
            "NODE_OPTIONS",
            "DATABASE_URL_RO",
            "SHARP_DIST_BASE_URL",
        ] {
            assert!(keep_var(v, &allow), "{v} kept");
        }
        for v in [
            "DATABASE_URL",
            "REDIS_URL",
            "NODE_AUTH_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "UV_INDEX_PRIVATE_PASSWORD",
            "SENTRY_DSN",
            "TOKENIZER_MODE",
        ] {
            assert!(!keep_var(v, &allow), "{v} removed");
        }
    }

    /// The command line as strings, for checking what is mounted.
    fn argv(c: &Command) -> Vec<String> {
        c.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn bubblewrap_hides_home_tmp_run_and_project_secrets() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".env"), "DATABASE_URL=x").unwrap();
        std::fs::write(project.path().join(".env.local"), "X=y").unwrap();
        std::fs::write(project.path().join(".env.d"), "").unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        std::fs::write(project.path().join(".git/config"), "[remote]").unwrap();
        let tmp = project.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: &tmp,
            writable: Vec::new(),
            read_only: vec![project.path().join(".git")],
            inner: Vec::new(),
            network: false,
            env_allow: &[],
        };
        let a = argv(&sb.command_with_home("true", &[], Some(home.path())));
        let at = |flag: &str, path: &Path| {
            a.windows(2)
                .position(|w| w[0] == flag && w[1] == path.to_string_lossy())
        };
        assert!(at("--tmpfs", home.path()).is_some());
        assert!(at("--tmpfs", Path::new("/tmp")).is_some());
        assert!(a.contains(&"--unshare-all".to_string()));
        assert!(a.contains(&"--new-session".to_string()));
        assert!(!a.contains(&"--share-net".to_string()));
        // Masked after the read-only .git, so the mask wins.
        let masked = |f: &str| {
            a.windows(3).position(|w| {
                w[0] == "--ro-bind"
                    && w[1] == "/dev/null"
                    && w[2] == project.path().join(f).to_string_lossy()
            })
        };
        for f in [".env", ".env.local", ".env.d", ".git/config"] {
            assert!(masked(f).is_some(), "{f} masked: {a:?}");
        }
        assert!(masked(".git/config") > at("--ro-bind", &project.path().join(".git")));
    }

    #[test]
    fn virtualenvs_in_private_dirs_stay_visible() {
        let venv = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(venv.path().join("bin")).unwrap();
        std::fs::create_dir_all(venv.path().join("lib")).unwrap();
        std::fs::write(venv.path().join("pyvenv.cfg"), "").unwrap();
        let pip = venv.path().join("bin/pip");
        let private = [std::env::temp_dir()];
        let dirs = reexposed(None, &private, &pip);
        let venv_real = std::fs::canonicalize(venv.path()).unwrap();
        assert!(
            dirs.iter().any(|d| d == venv.path() || *d == venv_real),
            "{dirs:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_sandbox_cannot_read_masked_files() {
        if !bwrap_works() {
            eprintln!("bubblewrap unavailable here; skipped");
            return;
        }
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".env"), "DATABASE_URL=x").unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        std::fs::write(home.path().join("notes.txt"), "private").unwrap();
        let tmp = project.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: &tmp,
            writable: Vec::new(),
            read_only: Vec::new(),
            inner: Vec::new(),
            network: false,
            env_allow: &[],
        };
        let script = format!(
            "test -s package.json && test ! -s .env && test ! -e '{}' && echo ok",
            home.path().join("notes.txt").display()
        );
        let out = sb
            .command_with_home("sh", &["-c".into(), script], Some(home.path()))
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "ok",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
