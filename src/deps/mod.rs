//! One dependency model for every lockfile format.
//!
//! Each supported lockfile parses into a [`Lockfile`]: its packages, the edges
//! between them, and which packages are the project's own code ("members" —
//! the root project and workspace packages). Audit, SBOM generation, the
//! install wrappers and `greengate deps` all read this one model, so they
//! agree on what a project depends on, what is direct and what is transitive.
//!
//! Formats that record no dependency edges (`requirements.txt`, `pylock.toml`
//! without them, `go.sum`) still list their packages; their graph simply
//! cannot answer "why is this here", and says so ([`Lockfile::edges_known`]).

mod cargo;
mod go;
mod npm;
mod python;

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

// ── Model ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "crates.io")]
    Cargo,
    #[serde(rename = "PyPI")]
    PyPI,
    #[serde(rename = "Go")]
    Go,
}

impl Ecosystem {
    /// The ecosystem name OSV uses.
    pub fn osv(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
        }
    }

    /// The package-URL type (https://github.com/package-url/purl-spec).
    pub fn purl_type(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Go => "golang",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    PackageLock,
    Yarn1,
    YarnBerry,
    Pnpm,
    Bun,
    CargoLock,
    UvLock,
    PoetryLock,
    Pylock,
    Requirements,
    GoMod,
    GoSum,
}

/// Where a package's code comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// A package registry. `url` is set only for a non-default registry.
    Registry {
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    Git {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        rev: Option<String>,
    },
    /// A tarball or archive URL outside any registry.
    Url { url: String },
    /// A local directory or file — the project's own code or a vendored copy.
    Path { path: String },
}

impl Source {
    pub fn registry() -> Source {
        Source::Registry { url: None }
    }

    pub fn is_registry(&self) -> bool {
        matches!(self, Source::Registry { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Not recorded by the lockfile and not derivable from its edges.
    Unknown,
    /// Only needed for development (tests, builds, tooling).
    Dev,
    /// Installed only when available or requested (optional / extras).
    Optional,
    /// Needed at runtime.
    Prod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Normal,
    Dev,
    Optional,
}

#[derive(Clone, Debug, Serialize)]
pub struct Package {
    pub name: String,
    /// Empty for a member whose version the lockfile does not record.
    pub version: String,
    pub source: Source,
    /// The integrity value the lockfile records (SRI string or `sha256:…`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    pub scope: Scope,
    /// Whether installing it runs package code, when the lockfile says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_script: Option<bool>,
    /// The project's own code: the root project or a workspace member.
    pub member: bool,
}

impl Package {
    pub fn new(name: impl Into<String>, version: impl Into<String>, source: Source) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            source,
            integrity: None,
            scope: Scope::Unknown,
            install_script: None,
            member: false,
        }
    }

    pub fn member(name: impl Into<String>, version: impl Into<String>, path: &str) -> Package {
        Package {
            member: true,
            ..Package::new(
                name,
                version,
                Source::Path {
                    path: path.to_string(),
                },
            )
        }
    }

    pub fn id(&self) -> String {
        if self.version.is_empty() {
            self.name.clone()
        } else {
            format!("{}@{}", self.name, self.version)
        }
    }
}

#[derive(Debug)]
pub struct Lockfile {
    pub path: PathBuf,
    pub format: Format,
    pub ecosystem: Ecosystem,
    pub packages: Vec<Package>,
    /// `edges[i]` — the dependencies of `packages[i]`.
    pub edges: Vec<Vec<(usize, EdgeKind)>>,
    /// False when the format records no dependency edges.
    pub edges_known: bool,
    /// Entries that name dependencies greengate could not resolve to an exact
    /// version (unpinned requirements, includes, `bun.lockb`…). Those packages
    /// are not checked by anything that reads this lockfile.
    pub unresolved: Vec<String>,
    /// Caveats about the graph that leave every package listed — e.g. no
    /// manifest beside the lockfile, so direct dependencies are unknown.
    pub notes: Vec<String>,
    /// Whether the format records which registry served each package. pnpm,
    /// Bun and Yarn Berry leave the configured default unrecorded, so
    /// `Source::Registry { url: None }` there may be a private registry.
    pub registry_recorded: bool,
}

impl Lockfile {
    fn new(path: &Path, format: Format, ecosystem: Ecosystem) -> Lockfile {
        Lockfile {
            path: path.to_path_buf(),
            format,
            ecosystem,
            packages: Vec::new(),
            edges: Vec::new(),
            edges_known: true,
            unresolved: Vec::new(),
            notes: Vec::new(),
            registry_recorded: !matches!(
                format,
                Format::Pnpm | Format::Bun | Format::YarnBerry | Format::GoMod | Format::GoSum
            ),
        }
    }

    /// Add a package and return its index.
    fn push(&mut self, package: Package) -> usize {
        self.packages.push(package);
        self.edges.push(Vec::new());
        self.packages.len() - 1
    }

    fn edge(&mut self, from: usize, to: usize, kind: EdgeKind) {
        if from == to {
            return;
        }
        if let Some(list) = self.edges.get_mut(from)
            && !list.iter().any(|(t, _)| *t == to)
        {
            list.push((to, kind));
        }
    }

    /// Third-party packages: everything that is not the project's own code.
    pub fn dependencies(&self) -> impl Iterator<Item = &Package> {
        self.packages.iter().filter(|p| !p.member)
    }

    /// Indices of packages a member depends on directly. Without edges, every
    /// listed package counts as direct.
    pub fn direct(&self) -> Vec<usize> {
        if !self.edges_known {
            return (0..self.packages.len())
                .filter(|&i| !self.packages[i].member)
                .collect();
        }
        let mut out: Vec<usize> = self
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.member)
            .flat_map(|(i, _)| self.edges[i].iter().map(|(t, _)| *t))
            .filter(|&t| !self.packages[t].member)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Shortest chain of packages from a member to `target`, member first.
    pub fn why(&self, target: usize) -> Option<Vec<usize>> {
        if !self.edges_known {
            return None;
        }
        let mut prev: Vec<Option<usize>> = vec![None; self.packages.len()];
        let mut seen = vec![false; self.packages.len()];
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, p) in self.packages.iter().enumerate() {
            if p.member {
                seen[i] = true;
                queue.push_back(i);
            }
        }
        while let Some(at) = queue.pop_front() {
            if at == target {
                let mut path = vec![at];
                let mut cur = at;
                while let Some(p) = prev[cur] {
                    path.push(p);
                    cur = p;
                }
                path.reverse();
                return Some(path);
            }
            for &(next, _) in &self.edges[at] {
                if !seen[next] {
                    seen[next] = true;
                    prev[next] = Some(at);
                    queue.push_back(next);
                }
            }
        }
        None
    }

    /// Fill in [`Scope::Unknown`] from the edges: a package reached from a
    /// member through a normal edge is prod; only through optional edges,
    /// optional; only through dev edges, dev. Scopes the lockfile recorded
    /// itself are kept.
    fn derive_scopes(&mut self) {
        if !self.edges_known {
            return;
        }
        let mut best = vec![Scope::Unknown; self.packages.len()];
        let mut queue: VecDeque<(usize, Scope)> = VecDeque::new();
        for (i, p) in self.packages.iter().enumerate() {
            if !p.member {
                continue;
            }
            for &(t, kind) in &self.edges[i] {
                let scope = match kind {
                    EdgeKind::Normal => Scope::Prod,
                    EdgeKind::Optional => Scope::Optional,
                    EdgeKind::Dev => Scope::Dev,
                };
                queue.push_back((t, scope));
            }
        }
        while let Some((at, scope)) = queue.pop_front() {
            // `Scope` orders Unknown < Dev < Optional < Prod: keep the widest.
            if scope <= best[at] {
                continue;
            }
            best[at] = scope;
            for &(t, kind) in &self.edges[at] {
                let next = if kind == EdgeKind::Optional && scope == Scope::Prod {
                    Scope::Optional
                } else {
                    scope
                };
                queue.push_back((t, next));
            }
        }
        for (p, scope) in self.packages.iter_mut().zip(best) {
            if p.scope == Scope::Unknown && !p.member {
                p.scope = scope;
            }
        }
    }
}

#[cfg(test)]
impl Lockfile {
    pub fn new_for_tests() -> Lockfile {
        Lockfile::new(Path::new("test.lock"), Format::PackageLock, Ecosystem::Npm)
    }
    pub fn add(&mut self, package: Package) -> usize {
        self.push(package)
    }
    pub fn link(&mut self, from: usize, to: usize) {
        self.edge(from, to, EdgeKind::Normal);
    }
}

// ── Discovery ─────────────────────────────────────────────────────────────────

/// Recognise a dependency file by name.
pub fn format_of(path: &Path) -> Option<Format> {
    let name = path.file_name()?.to_str()?;
    Some(match name {
        "package-lock.json" | "npm-shrinkwrap.json" => Format::PackageLock,
        // Yarn 1 and Berry share a name; the content tells them apart.
        "yarn.lock" => Format::Yarn1,
        "pnpm-lock.yaml" => Format::Pnpm,
        "bun.lock" | "bun.lockb" => Format::Bun,
        "Cargo.lock" => Format::CargoLock,
        "uv.lock" => Format::UvLock,
        "poetry.lock" => Format::PoetryLock,
        "requirements.txt" => Format::Requirements,
        "go.mod" => Format::GoMod,
        "go.sum" => Format::GoSum,
        n if n == "pylock.toml" || (n.starts_with("pylock.") && n.ends_with(".toml")) => {
            Format::Pylock
        }
        _ => return None,
    })
}

/// Parse one dependency file.
pub fn load(path: &Path) -> Result<Lockfile> {
    format_of(path)
        .with_context(|| format!("{} is not a supported dependency file", path.display()))?;
    if path.file_name().is_some_and(|n| n == "bun.lockb") {
        let mut lock = Lockfile::new(path, Format::Bun, Ecosystem::Npm);
        lock.edges_known = false;
        lock.unresolved.push(
            "binary bun.lockb is not supported — run `bun install --save-text-lockfile` to write bun.lock"
                .to_string(),
        );
        return Ok(lock);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    parse(path, &content)
}

/// Parse `content` as the dependency file at `path` — e.g. that file as it
/// was at another git revision. Sibling manifests are read from disk.
pub fn parse(path: &Path, content: &str) -> Result<Lockfile> {
    let format = format_of(path)
        .with_context(|| format!("{} is not a supported dependency file", path.display()))?;
    let mut lock = match format {
        Format::PackageLock => npm::package_lock(path, content),
        Format::Yarn1 | Format::YarnBerry => npm::yarn(path, content),
        Format::Pnpm => npm::pnpm(path, content),
        Format::Bun => npm::bun(path, content),
        Format::CargoLock => cargo::cargo_lock(path, content),
        Format::UvLock => python::uv_lock(path, content),
        Format::PoetryLock => python::poetry_lock(path, content),
        Format::Pylock => python::pylock(path, content),
        Format::Requirements => Ok(python::requirements(path, content)),
        Format::GoMod => go::go_mod(path, content),
        Format::GoSum => Ok(go::go_sum(path, content)),
    }
    .with_context(|| format!("could not parse {}", path.display()))?;
    lock.derive_scopes();
    Ok(lock)
}

/// Every dependency file found under a root.
pub struct Discovery {
    pub lockfiles: Vec<Lockfile>,
    /// Files that were found but could not be read or parsed.
    pub failed: Vec<(PathBuf, String)>,
}

impl Discovery {
    /// Directories holding more than one lockfile for the same ecosystem
    /// (e.g. `package-lock.json` beside `yarn.lock`). Which one the project
    /// really installs from is ambiguous.
    pub fn ambiguous(&self) -> Vec<(PathBuf, Vec<PathBuf>)> {
        let mut by_dir: BTreeMap<(PathBuf, Ecosystem), Vec<PathBuf>> = BTreeMap::new();
        for lock in &self.lockfiles {
            let dir = lock.path.parent().unwrap_or(Path::new("")).to_path_buf();
            by_dir
                .entry((dir, lock.ecosystem))
                .or_default()
                .push(lock.path.clone());
        }
        by_dir
            .into_iter()
            .filter(|(_, files)| files.len() > 1)
            .map(|((dir, _), files)| (dir, files))
            .collect()
    }
}

/// Find and parse every dependency file under `root` (honouring .gitignore),
/// skipping paths matching `exclude` globs (relative to `root`, as in
/// `[deps] exclude_patterns`). A directory with `go.mod` uses it rather than
/// its `go.sum`.
pub fn discover(root: &Path, exclude: &[String]) -> Discovery {
    let mut excluded = globset::GlobSetBuilder::new();
    for pattern in exclude {
        if let Ok(glob) = globset::Glob::new(pattern) {
            excluded.add(glob);
        }
    }
    let excluded = excluded
        .build()
        .unwrap_or_else(|_| globset::GlobSet::empty());
    let mut paths: Vec<PathBuf> = crate::utils::files::get_walker(root)
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .filter(|p| format_of(p).is_some())
        .filter(|p| !excluded.is_match(p.strip_prefix(root).unwrap_or(p)))
        .collect();
    paths.sort();
    let has_go_mod: Vec<PathBuf> = paths
        .iter()
        .filter(|p| format_of(p) == Some(Format::GoMod))
        .filter_map(|p| p.parent().map(Path::to_path_buf))
        .collect();
    paths.retain(|p| {
        format_of(p) != Some(Format::GoSum)
            || !p
                .parent()
                .is_some_and(|d| has_go_mod.iter().any(|g| g == d))
    });

    let mut found = Discovery {
        lockfiles: Vec::new(),
        failed: Vec::new(),
    };
    for path in paths {
        match load(&path) {
            Ok(lock) => found.lockfiles.push(lock),
            Err(e) => found.failed.push((path, format!("{e:#}"))),
        }
    }
    found
}

pub use python::normalize as normalize_python;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Index from a package name to the packages carrying it.
fn by_name(packages: &[Package]) -> HashMap<&str, Vec<usize>> {
    let mut map: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, p) in packages.iter().enumerate() {
        map.entry(p.name.as_str()).or_default().push(i);
    }
    map
}

/// Pick the package called `name` (at `version`, when given). A name with
/// several versions and no version to choose by resolves to all of them.
fn resolve_name(
    index: &HashMap<&str, Vec<usize>>,
    packages: &[Package],
    name: &str,
    version: Option<&str>,
) -> Vec<usize> {
    let candidates = index.get(name).map(Vec::as_slice).unwrap_or_default();
    match version {
        Some(v) => candidates
            .iter()
            .copied()
            .filter(|&i| packages[i].version == v)
            .collect(),
        None => candidates.to_vec(),
    }
}

/// The `package.json` beside a JS lockfile, if any.
fn sibling_package_json(lockfile: &Path) -> Option<serde_json::Value> {
    let path = lockfile.parent()?.join("package.json");
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

#[cfg(test)]
mod tests;
