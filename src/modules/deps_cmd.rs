//! `greengate deps` — inspect the dependency graph greengate reads from the
//! project's lockfiles: `deps list` shows every package, `deps why` shows how
//! a package got there.

use crate::deps::{self, Lockfile, Source};
use crate::report::Format;
use crate::utils::terminal;
use anyhow::Result;
use serde_json::{Value, json};
use std::path::Path;

fn source_label(source: &Source) -> String {
    match source {
        Source::Registry { url: None } => "registry".to_string(),
        Source::Registry { url: Some(u) } => format!("registry {u}"),
        Source::Git { url, rev } => match rev {
            Some(r) => format!("git {url}#{}", &r[..r.len().min(12)]),
            None => format!("git {url}"),
        },
        Source::Url { url } => format!("url {url}"),
        Source::Path { path } => format!("path {path}"),
    }
}

fn warn_problems(found: &deps::Discovery) {
    for (path, err) in &found.failed {
        terminal::warn(&format!("{}: {err}", path.display()));
    }
    for (dir, files) in found.ambiguous() {
        let names: Vec<String> = files
            .iter()
            .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        terminal::warn(&format!(
            "{}: several lockfiles for one ecosystem ({}) — which one is installed is ambiguous",
            dir.display(),
            names.join(", ")
        ));
    }
}

fn lockfile_json(lock: &Lockfile) -> Value {
    let direct = lock.direct();
    json!({
        "path": lock.path,
        "format": lock.format,
        "ecosystem": lock.ecosystem,
        "edges_known": lock.edges_known,
        "unresolved": lock.unresolved,
        "notes": lock.notes,
        "packages": lock.packages.iter().enumerate().filter(|(_, p)| !p.member).map(|(i, p)| {
            let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.remove("member");
                o.insert("direct".into(), json!(direct.contains(&i)));
                if lock.edges_known {
                    o.insert("dependencies".into(), json!(lock.edges[i].iter()
                        .map(|(t, _)| lock.packages[*t].id()).collect::<Vec<_>>()));
                }
            }
            v
        }).collect::<Vec<_>>(),
    })
}

pub fn run_list(root: &Path, exclude: &[String], format: Format) -> Result<()> {
    let found = deps::discover(root, exclude);
    if format == Format::Json {
        let out = json!({
            "lockfiles": found.lockfiles.iter().map(lockfile_json).collect::<Vec<_>>(),
            "ambiguous": found.ambiguous().iter().map(|(d, f)| json!({"dir": d, "files": f})).collect::<Vec<_>>(),
            "failed": found.failed.iter().map(|(p, e)| json!({"path": p, "error": e})).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    warn_problems(&found);
    if found.lockfiles.is_empty() {
        terminal::info("No supported dependency files found.");
        return Ok(());
    }
    for lock in &found.lockfiles {
        let direct = lock.direct();
        let total = lock.dependencies().count();
        eprintln!(
            "\n{} ({:?}) — {total} package(s), {} direct{}",
            lock.path.display(),
            lock.format,
            direct.len(),
            if lock.edges_known {
                ""
            } else {
                " (no dependency edges recorded)"
            }
        );
        let mut rows: Vec<(usize, &deps::Package)> = lock
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.member)
            .collect();
        rows.sort_by(|a, b| a.1.name.cmp(&b.1.name).then(a.1.version.cmp(&b.1.version)));
        for (i, p) in rows {
            println!(
                "  {:<50} {:<7} {:<8} {}",
                p.id(),
                if direct.contains(&i) { "direct" } else { "" },
                format!("{:?}", p.scope).to_lowercase(),
                source_label(&p.source)
            );
        }
        for u in &lock.unresolved {
            eprintln!("  ⚠️  not resolved: {u}");
        }
        for n in &lock.notes {
            eprintln!("  ℹ️  {n}");
        }
    }
    Ok(())
}

/// `query` is `name` or `name@version`.
pub fn run_why(root: &Path, exclude: &[String], query: &str) -> Result<()> {
    let found = deps::discover(root, exclude);
    warn_problems(&found);
    let (name, version) = match query.get(1..).and_then(|q| q.find('@')) {
        Some(at) => (&query[..=at], Some(&query[at + 2..])),
        None => (query, None),
    };
    let mut matched = false;
    for lock in &found.lockfiles {
        let norm = |n: &str| match lock.ecosystem {
            deps::Ecosystem::PyPI => deps::normalize_python(n),
            _ => n.to_string(),
        };
        let targets: Vec<usize> = lock
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.member && norm(&p.name) == norm(name))
            .filter(|(_, p)| version.is_none_or(|v| p.version == v))
            .map(|(i, _)| i)
            .collect();
        for t in targets {
            matched = true;
            let pkg = &lock.packages[t];
            match lock.why(t) {
                Some(path) => {
                    let chain: Vec<String> = path.iter().map(|&i| lock.packages[i].id()).collect();
                    println!("{} — {}", lock.path.display(), chain.join(" → "));
                }
                None => println!(
                    "{} — {} is listed, but {}",
                    lock.path.display(),
                    pkg.id(),
                    if lock.edges_known {
                        "nothing in the project depends on it (orphaned entry)"
                    } else {
                        "this format records no dependency edges"
                    }
                ),
            }
        }
    }
    if !matched {
        anyhow::bail!(
            "{query} is not in any dependency file under {}",
            root.display()
        );
    }
    Ok(())
}
