//! Running dependency install scripts with as little reach as possible.
//!
//! With bubblewrap (Linux), a script runs in a sandbox where the system is
//! read-only, the home directory, `/tmp` and `/run` are private and empty
//! (except the toolchains a build needs, read-only), the project's secret
//! files (`.env*`, `.npmrc`, `.git/config`…, workspace packages' too) are
//! masked, writes are confined to its own package directory, and — unless
//! the package is allowed network — there is no network at all. It gets its
//! own namespaces and terminal session, so it cannot signal or type into
//! anything outside.
//!
//! In both modes, the environment is reduced to an allowlist: what builds
//! need (`PATH`, compilers, proxies, package-manager settings), never what
//! looks like a credential, and with credentials inside URLs (an index or
//! proxy URL's `user:password@`) removed; `env_allow` keeps a variable
//! exactly as it is. Without isolation, the caller also verifies the
//! filesystem afterwards.

use anyhow::{Result, bail};
use std::collections::HashSet;
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

/// Project files that may hold credentials, by name, in the root and in
/// workspace packages (`.env` and `.env.*` too).
const PROJECT_SECRETS: &[&str] = &[
    ".npmrc",
    ".yarnrc.yml",
    ".yarnrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
];

/// Whether a project file named `name` may hold credentials: `.env`,
/// `.env.*` and the [`PROJECT_SECRETS`].
pub fn is_secret_file(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.") || PROJECT_SECRETS.contains(&name)
}

/// Directories not searched for [`PROJECT_SECRETS`]: dependency and build
/// trees (virtualenvs are recognised by their `pyvenv.cfg`).
const SECRET_SEARCH_SKIP: &[&str] = &[
    ".git",
    "node_modules",
    ".pnpm-store",
    ".yarn",
    "bower_components",
    ".venv",
    "__pycache__",
    ".tox",
    ".nox",
    "target",
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
/// only when a build may need them and they do not look like credentials
/// (and then without credentials inside URLs: [`without_url_credentials`]).
pub fn keep_var(name: &str, env_allow: &[String]) -> bool {
    allowed(name, env_allow)
        || (!is_secret_var(name)
            && (ENV_KEEP.contains(&name)
                || TOOLCHAIN_VARS.contains(&name)
                || ENV_KEEP_PREFIX.iter().any(|p| name.starts_with(p))))
}

/// `value` with the user information (`user:password@`, `token@`) removed
/// from every URL in it, or `None` when no URL in it carries any. Kept
/// settings such as `PIP_INDEX_URL` or `HTTPS_PROXY` often embed a
/// credential; the URL itself stays, so a private index is not swapped for
/// a public one, it only refuses the unauthenticated request.
///
/// The user information is everything up to the last `@` before the path
/// (the first `/`): it may hold `:`, `,`, `;`, `?` or `#` written out
/// unencoded, and none of them hides the rest. Several URLs can share a
/// value, separated by whitespace or commas; a proxy written without a
/// scheme (`user:password@proxy:3128`) is covered too.
pub fn without_url_credentials(value: &str) -> Option<String> {
    let mut cut: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0;
    for word in value.split_inclusive(char::is_whitespace) {
        let w = word.trim_end();
        let schemes: Vec<usize> = w.match_indices("://").map(|(i, _)| i + 3).collect();
        for &start in &schemes {
            let end = w[start..].find(['/', '\\']).map_or(w.len(), |e| start + e);
            if let Some(at) = w[start..end].rfind('@') {
                cut.push((offset + start, offset + start + at + 1));
            }
        }
        if schemes.is_empty()
            && let Some(at) = w.rfind('@')
            && w[..at].contains(':')
            && !w[..at].contains(['/', '\\'])
        {
            cut.push((offset, offset + at + 1));
        }
        offset += word.len();
    }
    if cut.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(value.len());
    let mut pos = 0;
    for (from, to) in cut {
        if from >= pos {
            out.push_str(&value[pos..from]);
            pos = to;
        }
    }
    out.push_str(&value[pos..]);
    Some(out)
}

/// Reduce what `cmd` inherits of `vars` (the environment) to what an
/// install script may see: [`keep_var`], then [`without_url_credentials`]
/// on all but `env_allow` entries.
fn scrub_env(
    cmd: &mut Command,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    env_allow: &[String],
) {
    for (k, v) in vars {
        let name = k.to_string_lossy();
        if !keep_var(&name, env_allow) {
            cmd.env_remove(&k);
        } else if !allowed(&name, env_allow)
            && let Some(clean) = v.to_str().and_then(without_url_credentials)
        {
            cmd.env(&k, clean);
        }
    }
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
    /// A copy of the project (without secret files) mounted writable in its
    /// place, for a command that must write into its tree — pip resolving a
    /// local setuptools project writes its metadata there — without the
    /// project changing. Toolchains inside the project (a virtualenv) stay
    /// visible over it, read-only.
    pub project_copy: Option<&'a Path>,
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
                if let Some(copy) = self.project_copy {
                    c.arg("--bind").arg(copy).arg(self.project);
                    let project = [self.project.to_path_buf()];
                    for d in reexposed(home, &project, Path::new(program)) {
                        c.arg("--ro-bind").arg(&d).arg(&d);
                    }
                }
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
                // carve-outs, then the writable directories inside those,
                // then the project's secrets — last, so that no writable
                // directory (a workspace package is one) shows them again.
                for w in &self.writable {
                    c.arg("--bind").arg(w).arg(w);
                }
                for r in self.read_only.iter().filter(|r| r.exists()) {
                    c.arg("--ro-bind").arg(r).arg(r);
                }
                for w in &self.inner {
                    c.arg("--bind").arg(w).arg(w);
                }
                // A copy is made without them.
                for f in project_secrets(self.project)
                    .into_iter()
                    .filter(|_| self.project_copy.is_none())
                {
                    c.arg("--ro-bind").arg("/dev/null").arg(f);
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
        scrub_env(&mut cmd, std::env::vars_os(), self.env_allow);
        cmd.env("TMPDIR", self.tmp);
        // npm writes its cache and logs; keep them in the private temp dir.
        cmd.env("npm_config_cache", self.tmp.join("npm-cache"));
        cmd.env("npm_config_update_notifier", "false");
        cmd
    }
}

/// The most directories [`project_secrets`] searches; past it, it warns
/// that the rest are not masked.
const SECRET_SEARCH_MAX_DIRS: usize = 50_000;

/// Files in the project that may hold credentials: every `.env*` and
/// [`PROJECT_SECRETS`] file in the root and in workspace packages, at any
/// depth outside [`SECRET_SEARCH_SKIP`], and `.git/config` — each by its
/// real path, which is where the mask goes. Symlinked directories are
/// followed wherever they lead (a shared `config/` outside the project is
/// readable in the sandbox too), each real directory once; a link to the
/// project or one of its parents adds nothing, so it is not followed.
/// Searched once per project and run, not once per package.
fn project_secrets(project: &Path) -> Vec<PathBuf> {
    static FOUND: std::sync::Mutex<Vec<(PathBuf, Vec<PathBuf>)>> =
        std::sync::Mutex::new(Vec::new());
    let mut found = FOUND.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, files)) = found.iter().find(|(p, _)| p == project) {
        return files.clone();
    }
    let root = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::from([root.clone()]);
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        if seen.len() > SECRET_SEARCH_MAX_DIRS {
            crate::utils::terminal::warn(&format!(
                "More than {SECRET_SEARCH_MAX_DIRS} directories in {}: secret files past them are not masked from install scripts.",
                project.display()
            ));
            break;
        }
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            let path = e.path();
            if path.is_dir() {
                let Ok(real) = std::fs::canonicalize(&path) else {
                    continue;
                };
                if SECRET_SEARCH_SKIP.contains(&n.as_ref())
                    || real.join("pyvenv.cfg").is_file()
                    || root.starts_with(&real)
                    || !seen.insert(real.clone())
                {
                    continue;
                }
                stack.push(real);
            } else if is_secret_file(&n) && path.is_file() {
                out.extend(std::fs::canonicalize(&path).ok());
            }
        }
    }
    out.extend(std::fs::canonicalize(root.join(".git/config")).ok());
    out.sort();
    out.dedup();
    found.push((project.to_path_buf(), out.clone()));
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

    #[test]
    fn credentials_inside_urls_are_removed() {
        assert_eq!(
            without_url_credentials("https://user:s3cret@pypi.corp/simple").as_deref(),
            Some("https://pypi.corp/simple")
        );
        assert_eq!(
            without_url_credentials("https://tok@a.example/x http://u:p@b.example:8080")
                .as_deref(),
            Some("https://a.example/x http://b.example:8080")
        );
        // An `@` in the path is not user information.
        assert_eq!(
            without_url_credentials("https://registry.example/@scope/pkg"),
            None
        );
        assert_eq!(without_url_credentials("https://pypi.org/simple"), None);
        assert_eq!(without_url_credentials("localhost,.corp"), None);
        // Unencoded punctuation in the password does not end it early.
        for pw in ["dummy,password", "pw;x", "p?w", "p#w", "a:b@c"] {
            let url = format!("https://dummy-user:{pw}@example.invalid/simple");
            assert_eq!(
                without_url_credentials(&url).as_deref(),
                Some("https://example.invalid/simple"),
                "{pw}"
            );
        }
        assert_eq!(
            without_url_credentials(
                "https://u:p@a.example,https://b.example,https://v:q@c.example"
            )
            .as_deref(),
            Some("https://a.example,https://b.example,https://c.example")
        );
        // A proxy without a scheme; scp-style git remotes are not credentials.
        assert_eq!(
            without_url_credentials("user:pa,ss@proxy.corp:3128").as_deref(),
            Some("proxy.corp:3128")
        );
        assert_eq!(without_url_credentials("git@github.com:org/repo.git"), None);
    }

    #[test]
    fn kept_variables_lose_url_credentials_unless_allowed() {
        let vars = [
            ("PIP_INDEX_URL", "https://u:p@pypi.corp/simple"),
            ("PIP_EXTRA_INDEX_URL", "https://u:p@pypi.corp/extra"),
            ("HTTPS_PROXY", "http://proxy.corp:3128"),
            ("DATABASE_URL", "postgres://u:p@db/app"),
        ]
        .map(|(k, v)| (k.into(), v.into()));
        let mut cmd = Command::new("true");
        scrub_env(
            &mut cmd,
            vars.into_iter(),
            &["PIP_EXTRA_INDEX_URL".to_string()],
        );
        let env: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(env.contains(&(
            "PIP_INDEX_URL".into(),
            Some("https://pypi.corp/simple".into())
        )));
        assert!(env.contains(&("DATABASE_URL".into(), None)), "removed");
        // Allowed or clean: inherited as they are.
        assert!(
            !env.iter()
                .any(|(k, _)| k == "PIP_EXTRA_INDEX_URL" || k == "HTTPS_PROXY")
        );
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
        // Workspace packages' secrets too, but not dependencies' files.
        let app = project.path().join("packages/app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join(".env"), "DATABASE_URL=x").unwrap();
        std::fs::write(app.join(".npmrc"), "//r/:_authToken=x").unwrap();
        let dep = project.path().join("node_modules/dep");
        std::fs::create_dir_all(&dep).unwrap();
        std::fs::write(dep.join(".env"), "").unwrap();
        let tmp = project.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: &tmp,
            writable: Vec::new(),
            read_only: vec![project.path().join(".git")],
            inner: vec![app.clone()],
            network: false,
            env_allow: &[],
            project_copy: None,
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
        for f in [
            ".env",
            ".env.local",
            ".env.d",
            ".git/config",
            "packages/app/.env",
            "packages/app/.npmrc",
        ] {
            assert!(masked(f).is_some(), "{f} masked: {a:?}");
        }
        assert!(masked("node_modules/dep/.env").is_none());
        assert!(masked(".git/config") > at("--ro-bind", &project.path().join(".git")));
        // After the writable package directory, which would show it again.
        assert!(masked("packages/app/.env") > at("--bind", &app));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secrets_behind_directory_symlinks_are_masked() {
        if !bwrap_works() {
            eprintln!("bubblewrap unavailable here; skipped");
            return;
        }
        let project = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // A shared config directory the sandbox can see, and one it cannot
        // (under the private /tmp), both linked from a workspace package.
        let shared = tempfile::tempdir().unwrap();
        let hidden = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join(".env"), "SECRET=shared").unwrap();
        std::fs::write(shared.path().join("app.json"), "{}").unwrap();
        std::fs::create_dir_all(hidden.path().join("deep")).unwrap();
        std::fs::write(hidden.path().join("deep/.env"), "SECRET=hidden").unwrap();
        let app = project.path().join("packages/app");
        std::fs::create_dir_all(&app).unwrap();
        std::os::unix::fs::symlink(shared.path(), app.join("config")).unwrap();
        std::os::unix::fs::symlink(hidden.path(), app.join("other")).unwrap();
        // Cycles and links to a parent are not followed.
        std::os::unix::fs::symlink(project.path(), app.join("root")).unwrap();
        std::os::unix::fs::symlink(&app, shared.path().join("back")).unwrap();
        let found = project_secrets(project.path());
        let real = |p: &Path| std::fs::canonicalize(p).unwrap();
        assert_eq!(found, {
            let mut v = vec![
                real(&shared.path().join(".env")),
                real(&hidden.path().join("deep/.env")),
            ];
            v.sort();
            v
        });
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: tmp.path(),
            writable: Vec::new(),
            read_only: vec![shared.path().to_path_buf()],
            inner: Vec::new(),
            network: false,
            env_allow: &[],
            project_copy: None,
        };
        let script = "test -s packages/app/config/app.json && test ! -s packages/app/config/.env && echo ok";
        let out = sb
            .command_with_home("sh", &["-c".into(), script.into()], None)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "ok",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_project_copy_takes_the_writes() {
        if !bwrap_works() {
            eprintln!("bubblewrap unavailable here; skipped");
            return;
        }
        let project = tempfile::tempdir().unwrap();
        let copy = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("setup.py"), "original").unwrap();
        std::fs::write(copy.path().join("setup.py"), "copy").unwrap();
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: tmp.path(),
            writable: Vec::new(),
            read_only: Vec::new(),
            inner: Vec::new(),
            network: false,
            env_allow: &[],
            project_copy: Some(copy.path()),
        };
        let script = "cat setup.py && mkdir x.egg-info".to_string();
        let out = sb
            .command_with_home("sh", &["-c".into(), script], None)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "copy",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(copy.path().join("x.egg-info").is_dir());
        assert!(!project.path().join("x.egg-info").exists());
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
        let app = project.path().join("packages/app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join(".env"), "DATABASE_URL=x").unwrap();
        let tmp = project.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let sb = Sandbox {
            isolation: Isolation::Bwrap,
            project: project.path(),
            tmp: &tmp,
            writable: Vec::new(),
            read_only: Vec::new(),
            inner: vec![app],
            network: false,
            env_allow: &[],
            project_copy: None,
        };
        let script = format!(
            "test -s package.json && test ! -s .env && test ! -s packages/app/.env && test ! -e '{}' && echo ok",
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
