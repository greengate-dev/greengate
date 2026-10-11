//! Go modules: `go.mod` (preferred) and `go.sum`.
//!
//! Since Go 1.17, `go.mod` lists every module the build needs — direct and
//! `// indirect` — at the version minimal version selection picked, so it is
//! the accurate list. `go.sum` also keeps hashes for versions that were only
//! consulted, so it is the fallback for older modules or a missing `go.mod`.
//! Neither records which module needs which, so edges below the main module
//! are unknown.

use super::{Ecosystem, EdgeKind, Format, Lockfile, Package, Source};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

pub fn go_mod(path: &Path, content: &str) -> Result<Lockfile> {
    let mut module = String::new();
    let mut go_version: Option<(u32, u32)> = None;
    // (module, version, indirect)
    let mut requires: Vec<(String, String, bool)> = Vec::new();
    // old module (any version) -> new module + version, or a local path
    let mut replaces: HashMap<String, Source> = HashMap::new();
    let mut replace_versions: HashMap<String, (String, String)> = HashMap::new();

    let mut block: Option<&str> = None;
    for raw in content.lines() {
        let (code, comment) = match raw.split_once("//") {
            Some((c, m)) => (c.trim(), m.trim()),
            None => (raw.trim(), ""),
        };
        if code.is_empty() {
            continue;
        }
        if code == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = match block {
            Some(b) => (b, code),
            None => {
                let (d, r) = code.split_once(char::is_whitespace).unwrap_or((code, ""));
                if r.trim() == "(" {
                    block = Some(match d {
                        "require" => "require",
                        "replace" => "replace",
                        _ => "other",
                    });
                    continue;
                }
                (d, r.trim())
            }
        };
        match directive {
            "module" => module = rest.trim_matches('"').to_string(),
            "go" => {
                let mut nums = rest.split('.').filter_map(|n| n.parse::<u32>().ok());
                go_version = nums.next().zip(nums.next());
            }
            "require" => {
                let mut f = rest.split_whitespace();
                if let (Some(m), Some(v)) = (f.next(), f.next()) {
                    requires.push((m.to_string(), v.to_string(), comment.contains("indirect")));
                }
            }
            "replace" => {
                let Some((old, new)) = rest.split_once("=>") else {
                    continue;
                };
                let old_mod = old.split_whitespace().next().unwrap_or("").to_string();
                let mut new_f = new.split_whitespace();
                match (new_f.next(), new_f.next()) {
                    (Some(n), Some(v)) => {
                        replace_versions.insert(old_mod, (n.to_string(), v.to_string()));
                    }
                    (Some(p), None) => {
                        replaces.insert(
                            old_mod,
                            Source::Path {
                                path: p.to_string(),
                            },
                        );
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Before 1.17, go.mod omitted most indirect modules: use go.sum instead.
    if go_version.is_some_and(|v| v < (1, 17)) || requires.is_empty() {
        let sum = path.with_file_name("go.sum");
        if let Ok(content) = std::fs::read_to_string(&sum) {
            return Ok(go_sum(&sum, &content));
        }
    }

    let mut lock = Lockfile::new(path, Format::GoMod, Ecosystem::Go);
    let main = lock.push(Package::member(module, "", "."));
    for (m, v, indirect) in requires {
        let pkg = if let Some(source) = replaces.get(&m) {
            Package::new(m, v, source.clone())
        } else if let Some((new_mod, new_v)) = replace_versions.get(&m) {
            Package::new(new_mod.clone(), new_v.clone(), Source::registry())
        } else {
            Package::new(m, v, Source::registry())
        };
        let i = lock.push(pkg);
        // go.mod says which modules the main module imports itself; the
        // indirect ones hang off modules whose edges it does not record.
        if !indirect {
            lock.edge(main, i, EdgeKind::Normal);
        }
    }
    Ok(lock)
}

pub fn go_sum(path: &Path, content: &str) -> Lockfile {
    let mut lock = Lockfile::new(path, Format::GoSum, Ecosystem::Go);
    lock.edges_known = false;
    let mut seen = std::collections::HashSet::new();
    for line in content.lines() {
        let mut f = line.split_whitespace();
        let (Some(module), Some(version)) = (f.next(), f.next()) else {
            continue;
        };
        // `<version>/go.mod` lines verify a go.mod file only, not a dependency.
        if version.ends_with("/go.mod") || !seen.insert((module.to_string(), version.to_string()))
        {
            continue;
        }
        lock.push(Package::new(module, version, Source::registry()));
    }
    lock
}
