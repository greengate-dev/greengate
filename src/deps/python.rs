//! Python: `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751) and pinned
//! `requirements.txt`.

use super::{Ecosystem, EdgeKind, Format, Lockfile, Package, Scope, Source};
use anyhow::{Context, Result};
use std::path::Path;
use toml::{Table, Value};

const PYPI_SIMPLE: &[&str] = &["https://pypi.org/simple", "https://pypi.org/simple/"];

/// PEP 503 name normalisation, so `Foo_Bar` and `foo-bar` match.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

fn registry(url: Option<&str>) -> Source {
    match url {
        Some(u) if !PYPI_SIMPLE.contains(&u) => Source::Registry {
            url: Some(u.to_string()),
        },
        _ => Source::registry(),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// The leading project name of a PEP 508 requirement (`requests[socks]>=2`).
fn requirement_name(spec: &str) -> &str {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    &spec[..end]
}

// ── uv.lock ───────────────────────────────────────────────────────────────────

fn uv_source(src: Option<&Value>) -> (Source, bool) {
    let Some(src) = src else {
        return (Source::registry(), false);
    };
    if let Some(dir) = str_of(src, "virtual").or_else(|| str_of(src, "editable")) {
        return (
            Source::Path {
                path: dir.to_string(),
            },
            true,
        );
    }
    if let Some(url) = str_of(src, "registry") {
        return (registry(Some(url)), false);
    }
    if let Some(git) = str_of(src, "git") {
        let (url, commit) = match git.split_once('#') {
            Some((u, c)) => (u, Some(c.to_string())),
            None => (git, None),
        };
        return (
            Source::Git {
                url: url.split('?').next().unwrap_or(url).to_string(),
                rev: commit,
            },
            false,
        );
    }
    if let Some(url) = str_of(src, "url") {
        return (
            Source::Url {
                url: url.to_string(),
            },
            false,
        );
    }
    let path = str_of(src, "path")
        .or_else(|| str_of(src, "directory"))
        .unwrap_or("");
    (
        Source::Path {
            path: path.to_string(),
        },
        false,
    )
}

pub fn uv_lock(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Table = content.parse().context("invalid TOML")?;
    let mut lock = Lockfile::new(path, Format::UvLock, Ecosystem::PyPI);
    let entries = doc
        .get("package")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut kept: Vec<&Value> = Vec::new();
    for entry in &entries {
        let Some(name) = str_of(entry, "name") else {
            continue;
        };
        let (source, member) = uv_source(entry.get("source"));
        let mut pkg = Package::new(
            normalize(name),
            str_of(entry, "version").unwrap_or(""),
            source,
        );
        pkg.member = member;
        pkg.integrity = entry
            .get("sdist")
            .and_then(|s| str_of(s, "hash"))
            .or_else(|| {
                entry
                    .get("wheels")
                    .and_then(Value::as_array)
                    .and_then(|w| w.first())
                    .and_then(|w| str_of(w, "hash"))
            })
            .map(str::to_string);
        lock.push(pkg);
        kept.push(entry);
    }

    let index = super::by_name(&lock.packages);
    let mut edges = Vec::new();
    for (i, entry) in kept.iter().enumerate() {
        let mut add = |deps: Option<&Value>, kind: EdgeKind| {
            for dep in deps.and_then(Value::as_array).into_iter().flatten() {
                let Some(name) = str_of(dep, "name") else {
                    continue;
                };
                let version = str_of(dep, "version");
                for t in super::resolve_name(&index, &lock.packages, &normalize(name), version) {
                    edges.push((i, t, kind));
                }
            }
        };
        add(entry.get("dependencies"), EdgeKind::Normal);
        for (table, kind) in [
            (entry.get("optional-dependencies"), EdgeKind::Optional),
            (entry.get("dev-dependencies"), EdgeKind::Dev),
        ] {
            for (_, group) in table.and_then(Value::as_table).into_iter().flatten() {
                add(Some(group), kind);
            }
        }
    }
    for (from, to, kind) in edges {
        lock.edge(from, to, kind);
    }
    Ok(lock)
}

// ── poetry.lock ───────────────────────────────────────────────────────────────

pub fn poetry_lock(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Table = content.parse().context("invalid TOML")?;
    let mut lock = Lockfile::new(path, Format::PoetryLock, Ecosystem::PyPI);
    let entries = doc
        .get("package")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut kept: Vec<&Value> = Vec::new();
    for entry in &entries {
        let (Some(name), Some(version)) = (str_of(entry, "name"), str_of(entry, "version")) else {
            continue;
        };
        let source = match entry.get("source") {
            Some(src) => {
                let url = str_of(src, "url").unwrap_or("").to_string();
                match str_of(src, "type") {
                    Some("git") => Source::Git {
                        url,
                        rev: str_of(src, "resolved_reference")
                            .or_else(|| str_of(src, "reference"))
                            .map(str::to_string),
                    },
                    Some("url") => Source::Url { url },
                    Some("file" | "directory") => Source::Path { path: url },
                    _ => registry(Some(&url)),
                }
            }
            None => Source::registry(),
        };
        let mut pkg = Package::new(normalize(name), version, source);
        // Poetry 2: `groups = ["main"]`; Poetry 1: `category = "main"`.
        let groups: Vec<&str> = entry
            .get("groups")
            .and_then(Value::as_array)
            .map(|g| g.iter().filter_map(Value::as_str).collect())
            .or_else(|| str_of(entry, "category").map(|c| vec![c]))
            .unwrap_or_default();
        if !groups.is_empty() {
            pkg.scope = if groups.contains(&"main") {
                if entry.get("optional").and_then(Value::as_bool) == Some(true) {
                    Scope::Optional
                } else {
                    Scope::Prod
                }
            } else {
                Scope::Dev
            };
        }
        pkg.integrity = entry
            .get("files")
            .and_then(Value::as_array)
            .and_then(|f| f.first())
            .and_then(|f| str_of(f, "hash"))
            .map(str::to_string);
        lock.push(pkg);
        kept.push(entry);
    }

    let index = super::by_name(&lock.packages);
    let mut edges = Vec::new();
    for (i, entry) in kept.iter().enumerate() {
        for (name, _) in entry
            .get("dependencies")
            .and_then(Value::as_table)
            .into_iter()
            .flatten()
        {
            for t in super::resolve_name(&index, &lock.packages, &normalize(name), None) {
                edges.push((i, t));
            }
        }
    }
    for (from, to) in edges {
        lock.edge(from, to, EdgeKind::Normal);
    }

    // The project itself lives in pyproject.toml.
    if let Some((root, deps)) = pyproject_member(path) {
        let root = lock.push(root);
        for (name, kind) in deps {
            for t in
                super::resolve_name(&super::by_name(&lock.packages), &lock.packages, &name, None)
            {
                if !lock.packages[t].member {
                    lock.edge(root, t, kind);
                }
            }
        }
    } else {
        lock.notes.push(
            "no pyproject.toml beside poetry.lock — direct dependencies are unknown".to_string(),
        );
    }
    Ok(lock)
}

/// The project in the sibling `pyproject.toml`, with its direct dependency
/// names: PEP 621 `[project]`, Poetry `[tool.poetry]`, and dependency groups.
fn pyproject_member(lockfile: &Path) -> Option<(Package, Vec<(String, EdgeKind)>)> {
    let text = std::fs::read_to_string(lockfile.parent()?.join("pyproject.toml")).ok()?;
    let doc: Table = text.parse().ok()?;
    let project = doc.get("project");
    let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
    let name = project
        .and_then(|p| str_of(p, "name"))
        .or_else(|| poetry.and_then(|p| str_of(p, "name")))
        .unwrap_or("root");
    let version = project
        .and_then(|p| str_of(p, "version"))
        .or_else(|| poetry.and_then(|p| str_of(p, "version")))
        .unwrap_or("");

    let mut deps: Vec<(String, EdgeKind)> = Vec::new();
    let mut add_specs = |list: Option<&Value>, kind: EdgeKind| {
        for spec in list
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            deps.push((normalize(requirement_name(spec)), kind));
        }
    };
    add_specs(
        project.and_then(|p| p.get("dependencies")),
        EdgeKind::Normal,
    );
    for (_, extra) in project
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(Value::as_table)
        .into_iter()
        .flatten()
    {
        add_specs(Some(extra), EdgeKind::Optional);
    }
    for (_, group) in doc
        .get("dependency-groups")
        .and_then(Value::as_table)
        .into_iter()
        .flatten()
    {
        add_specs(Some(group), EdgeKind::Dev);
    }
    let mut add_table = |table: Option<&Value>, kind: EdgeKind| {
        for (n, _) in table.and_then(Value::as_table).into_iter().flatten() {
            if n != "python" {
                deps.push((normalize(n), kind));
            }
        }
    };
    add_table(poetry.and_then(|p| p.get("dependencies")), EdgeKind::Normal);
    add_table(
        poetry.and_then(|p| p.get("dev-dependencies")),
        EdgeKind::Dev,
    );
    for (group, body) in poetry
        .and_then(|p| p.get("group"))
        .and_then(Value::as_table)
        .into_iter()
        .flatten()
    {
        let kind = if group == "main" {
            EdgeKind::Normal
        } else {
            EdgeKind::Dev
        };
        add_table(body.get("dependencies"), kind);
    }
    Some((Package::member(normalize(name), version, "."), deps))
}

// ── pylock.toml (PEP 751) ─────────────────────────────────────────────────────

pub fn pylock(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Table = content.parse().context("invalid TOML")?;
    let mut lock = Lockfile::new(path, Format::Pylock, Ecosystem::PyPI);
    let entries = doc
        .get("packages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut deps: Vec<(usize, String, Option<String>)> = Vec::new();
    let mut any_edges = false;
    for entry in &entries {
        let Some(name) = str_of(entry, "name") else {
            continue;
        };
        let version = str_of(entry, "version").unwrap_or("");
        let source = if let Some(vcs) = entry.get("vcs") {
            Source::Git {
                url: str_of(vcs, "url")
                    .or_else(|| str_of(vcs, "path"))
                    .unwrap_or("")
                    .to_string(),
                rev: str_of(vcs, "commit-id").map(str::to_string),
            }
        } else if let Some(dir) = entry.get("directory") {
            Source::Path {
                path: str_of(dir, "path").unwrap_or("").to_string(),
            }
        } else if let Some(archive) = entry.get("archive") {
            Source::Url {
                url: str_of(archive, "url")
                    .or_else(|| str_of(archive, "path"))
                    .unwrap_or("")
                    .to_string(),
            }
        } else {
            registry(str_of(entry, "index"))
        };
        if version.is_empty() && source.is_registry() {
            lock.unresolved.push(format!("{name}: no version recorded"));
            continue;
        }
        let mut pkg = Package::new(normalize(name), version, source);
        let first_hash = |v: Option<&Value>| -> Option<String> {
            let hashes = v?.get("hashes")?.as_table()?;
            let (alg, value) = hashes.iter().next()?;
            Some(format!("{alg}:{}", value.as_str()?))
        };
        pkg.integrity = first_hash(entry.get("sdist")).or_else(|| {
            first_hash(
                entry
                    .get("wheels")
                    .and_then(Value::as_array)
                    .and_then(|w| w.first()),
            )
        });
        let i = lock.push(pkg);
        for dep in entry
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            any_edges = true;
            if let Some(n) = str_of(dep, "name") {
                deps.push((i, normalize(n), str_of(dep, "version").map(str::to_string)));
            }
        }
    }
    if any_edges {
        let index = super::by_name(&lock.packages);
        let mut edges = Vec::new();
        for (from, name, version) in deps {
            for t in super::resolve_name(&index, &lock.packages, &name, version.as_deref()) {
                edges.push((from, t));
            }
        }
        for (from, to) in edges {
            lock.edge(from, to, EdgeKind::Normal);
        }
        // Edges between packages, but which are top-level still needs the
        // project: treat packages nothing depends on as direct.
        let mut depended: Vec<bool> = vec![false; lock.packages.len()];
        for list in &lock.edges {
            for (t, _) in list {
                depended[*t] = true;
            }
        }
        let root = lock.push(Package::member("project", "", "."));
        for (i, d) in depended.into_iter().enumerate() {
            if !d {
                lock.edge(root, i, EdgeKind::Normal);
            }
        }
    } else {
        lock.edges_known = false;
    }
    Ok(lock)
}

// ── requirements.txt ──────────────────────────────────────────────────────────

/// Pinned (`==` / `===`) requirements. Anything else that names a package —
/// ranges, `-r` includes, editable installs, URLs — is unresolved: its
/// version is unknown, and callers must say so rather than let it pass unseen.
pub fn requirements(path: &Path, content: &str) -> Lockfile {
    let mut lock = Lockfile::new(path, Format::Requirements, Ecosystem::PyPI);
    lock.edges_known = false;
    let mut index_url: Option<String> = None;
    // pip-compile writes `pkg==1.0 \` with `--hash` continuation lines.
    let joined = content.replace("\\\r\n", " ").replace("\\\n", " ");
    for raw in joined.lines() {
        // Inline comments need preceding whitespace (`#` can appear in URLs).
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            let (flag, value) = line.split_once([' ', '=']).unwrap_or((line, ""));
            match flag {
                "-r" | "--requirement" | "-e" | "--editable" => {
                    lock.unresolved.push(line.to_string())
                }
                "-i" | "--index-url" => index_url = Some(value.trim().to_string()),
                // Other pip options (`-c`, `--require-hashes`, …) name no package.
                _ => {}
            }
            continue;
        }
        // Drop environment markers and per-requirement options (`--hash=…`).
        let spec = line.split(';').next().unwrap_or("");
        let hash = line
            .split_whitespace()
            .find_map(|w| w.strip_prefix("--hash="))
            .map(str::to_string);
        let spec = spec.split(" --").next().unwrap_or("").trim();
        match spec.split_once("==") {
            Some((name, version)) if !name.contains("://") => {
                let name = name.split('[').next().unwrap_or("").trim();
                let version = version.trim_start_matches('=').trim();
                if name.is_empty() || version.is_empty() {
                    lock.unresolved.push(line.to_string());
                    continue;
                }
                let mut pkg =
                    Package::new(normalize(name), version, registry(index_url.as_deref()));
                pkg.integrity = hash;
                pkg.scope = Scope::Prod;
                lock.push(pkg);
            }
            _ => lock.unresolved.push(line.to_string()),
        }
    }
    lock
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_names() {
        assert_eq!(requirement_name("requests[socks]>=2"), "requests");
        assert_eq!(requirement_name("Django==4.2"), "Django");
        assert_eq!(
            requirement_name("zope.interface ; python_version > '3'"),
            "zope.interface"
        );
    }

    #[test]
    fn pep503() {
        assert_eq!(normalize("Foo__Bar.baz"), "foo-bar-baz");
    }
}
