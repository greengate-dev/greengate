//! `Cargo.lock` (v1–v4).

use super::{Ecosystem, EdgeKind, Format, Lockfile, Package, Source};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

const CRATES_IO: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

fn source_of(raw: Option<&str>) -> Source {
    let Some(raw) = raw else {
        // No source: a workspace member or path dependency.
        return Source::Path {
            path: String::new(),
        };
    };
    if CRATES_IO.contains(&raw) {
        return Source::registry();
    }
    if let Some(url) = raw
        .strip_prefix("registry+")
        .or_else(|| raw.strip_prefix("sparse+"))
    {
        return Source::Registry {
            url: Some(url.to_string()),
        };
    }
    if let Some(git) = raw.strip_prefix("git+") {
        // git+https://host/repo?rev=…#<commit>
        let (url, commit) = match git.split_once('#') {
            Some((u, c)) => (u, Some(c.to_string())),
            None => (git, None),
        };
        let url = url.split('?').next().unwrap_or(url);
        return Source::Git {
            url: url.to_string(),
            rev: commit,
        };
    }
    Source::Url {
        url: raw.to_string(),
    }
}

pub fn cargo_lock(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: toml::Table = content.parse().context("invalid TOML")?;
    let mut lock = Lockfile::new(path, Format::CargoLock, Ecosystem::Cargo);
    let entries = doc
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    for entry in &entries {
        let (Some(name), Some(version)) = (
            entry.get("name").and_then(|v| v.as_str()),
            entry.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let source_raw = entry.get("source").and_then(|v| v.as_str());
        let mut pkg = Package::new(name, version, source_of(source_raw));
        pkg.member = source_raw.is_none();
        pkg.integrity = entry
            .get("checksum")
            .and_then(|v| v.as_str())
            .map(|c| format!("sha256:{c}"));
        lock.push(pkg);
    }

    // Dependency strings: "name", "name version", or "name version (source)".
    let index = super::by_name(&lock.packages);
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (i, entry) in entries
        .iter()
        .filter(|e| e.get("name").is_some() && e.get("version").is_some())
        .enumerate()
    {
        for dep in entry
            .get("dependencies")
            .and_then(|d| d.as_array())
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
        {
            let mut parts = dep.splitn(3, ' ');
            let name = parts.next().unwrap_or("");
            let version = parts.next();
            for t in super::resolve_name(&index, &lock.packages, name, version) {
                edges.push((i, t));
            }
        }
    }
    // Cargo.lock does not say which edges are dev-only; the members'
    // manifests do.
    let dev_only = dev_only_dependencies(path);
    for (from, to) in edges {
        let kind = match dev_only.get(&lock.packages[from].name) {
            Some(names)
                if lock.packages[from].member && names.contains(&lock.packages[to].name) =>
            {
                EdgeKind::Dev
            }
            _ => EdgeKind::Normal,
        };
        lock.edge(from, to, kind);
    }
    Ok(lock)
}

/// For each workspace member (by package name), the crates it lists only under
/// `[dev-dependencies]`: read from the `Cargo.toml` beside the lockfile and
/// from each `[workspace] members` entry (`dir` or `dir/*`).
fn dev_only_dependencies(lockfile: &Path) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    let Some(root) = lockfile.parent() else {
        return out;
    };
    let read = |dir: &Path| -> Option<toml::Table> {
        std::fs::read_to_string(dir.join("Cargo.toml"))
            .ok()?
            .parse()
            .ok()
    };
    let Some(root_manifest) = read(root) else {
        return out;
    };
    let mut manifests = vec![root_manifest.clone()];
    for member in root_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .filter_map(|m| m.as_str())
    {
        if let Some(parent) = member.strip_suffix("/*") {
            for entry in std::fs::read_dir(root.join(parent))
                .into_iter()
                .flatten()
                .flatten()
            {
                manifests.extend(read(&entry.path()));
            }
        } else {
            manifests.extend(read(&root.join(member)));
        }
    }

    // Names as they appear in Cargo.lock: a renamed dependency's `package`.
    fn names(table: Option<&toml::Value>) -> Vec<String> {
        table
            .and_then(|t| t.as_table())
            .into_iter()
            .flatten()
            .map(|(key, spec)| {
                spec.get("package")
                    .and_then(|p| p.as_str())
                    .unwrap_or(key)
                    .to_string()
            })
            .collect()
    }
    for manifest in manifests {
        let Some(name) = manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
        else {
            continue;
        };
        let mut dev = names(manifest.get("dev-dependencies"));
        let mut other = names(manifest.get("dependencies"));
        other.extend(names(manifest.get("build-dependencies")));
        for (_, target) in manifest
            .get("target")
            .and_then(|t| t.as_table())
            .into_iter()
            .flatten()
        {
            dev.extend(names(target.get("dev-dependencies")));
            other.extend(names(target.get("dependencies")));
            other.extend(names(target.get("build-dependencies")));
        }
        dev.retain(|d| !other.contains(d));
        out.insert(name.to_string(), dev);
    }
    out
}
