//! What the project's own manifests require of a dependency: the range in
//! `package.json`, `Cargo.toml` or `pyproject.toml` of the member that
//! depends on it. Lockfiles record what was resolved, not what was asked for.

use super::ranges;
use crate::deps::{Ecosystem, Format, Lockfile, Package, Source, normalize_python};
use crate::registry::requirements::pep508;
use std::path::{Path, PathBuf};

/// A requirement and the syntax it is written in.
#[derive(Debug, Clone, PartialEq)]
pub enum Req {
    /// npm, Cargo and Go syntax: evaluated per ecosystem.
    Native(String),
    /// Poetry's `^`/`~` syntax.
    Poetry(String),
}

impl Req {
    pub fn text(&self) -> &str {
        match self {
            Req::Native(s) | Req::Poetry(s) => s,
        }
    }

    pub fn allows(&self, eco: Ecosystem, version: &str) -> Option<bool> {
        match self {
            Req::Native(r) => ranges::allows(eco, r, version),
            Req::Poetry(r) => ranges::poetry_allows(r, version),
        }
    }
}

/// The requirement `member` (a package with `member: true` in `lock`)
/// declares on `dep`, if its manifest can be found and names it.
pub fn requirement(lock: &Lockfile, member: &Package, dep: &str) -> Option<Req> {
    let dir = lock.path.parent().unwrap_or(Path::new("."));
    match lock.ecosystem {
        Ecosystem::Npm => {
            let rel = match &member.source {
                Source::Path { path } if !path.is_empty() => path.as_str(),
                _ => ".",
            };
            npm(&dir.join(rel).join("package.json"), dep).map(Req::Native)
        }
        Ecosystem::Cargo => {
            let manifest = cargo_manifest(dir, &member.name)?;
            cargo(&manifest, dir, dep).map(Req::Native)
        }
        Ecosystem::PyPI => {
            let rel = match &member.source {
                Source::Path { path } if !path.is_empty() => path.as_str(),
                _ => ".",
            };
            python(&dir.join(rel).join("pyproject.toml"), dep, lock.format)
        }
        Ecosystem::Go => Some(Req::Native(String::new())),
    }
}

fn npm(path: &Path, dep: &str) -> Option<String> {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .find_map(|table| doc[table][dep].as_str())
    .map(str::to_string)
}

/// The `Cargo.toml` of the workspace member named `name`: the one beside the
/// lockfile, or one below it (Cargo.lock does not record member paths).
fn cargo_manifest(dir: &Path, name: &str) -> Option<PathBuf> {
    let named = |p: &Path| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|t| t.parse::<toml::Table>().ok())
            .is_some_and(|t| {
                t.get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    == Some(name)
            })
    };
    let root = dir.join("Cargo.toml");
    if named(&root) {
        return Some(root);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("target" | ".git" | "node_modules")
                ) {
                    stack.push(p);
                }
            } else if p.file_name().is_some_and(|n| n == "Cargo.toml") && named(&p) {
                return Some(p);
            }
        }
    }
    None
}

fn cargo(manifest: &Path, workspace_dir: &Path, dep: &str) -> Option<String> {
    let doc: toml::Table = std::fs::read_to_string(manifest).ok()?.parse().ok()?;
    let mut tables: Vec<&toml::Table> = ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|t| doc.get(*t).and_then(|v| v.as_table()))
        .collect();
    if let Some(targets) = doc.get("target").and_then(|t| t.as_table()) {
        for cfg in targets.values().filter_map(|v| v.as_table()) {
            tables.extend(
                ["dependencies", "dev-dependencies", "build-dependencies"]
                    .iter()
                    .filter_map(|t| cfg.get(*t).and_then(|v| v.as_table())),
            );
        }
    }
    for table in tables {
        for (key, value) in table {
            let package = value.get("package").and_then(|p| p.as_str()).unwrap_or(key);
            if package != dep {
                continue;
            }
            if let Some(v) = value.as_str() {
                return Some(v.to_string());
            }
            if value.get("workspace").and_then(|w| w.as_bool()) == Some(true) {
                let root: toml::Table = std::fs::read_to_string(workspace_dir.join("Cargo.toml"))
                    .ok()?
                    .parse()
                    .ok()?;
                let w = root.get("workspace")?.get("dependencies")?.get(key)?;
                return w
                    .as_str()
                    .or_else(|| w.get("version").and_then(|v| v.as_str()))
                    .map(str::to_string);
            }
            // A git or path dependency without a version allows anything
            // that source provides.
            return Some(
                value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string(),
            );
        }
    }
    None
}

fn python(path: &Path, dep: &str, format: Format) -> Option<Req> {
    let doc: toml::Table = std::fs::read_to_string(path).ok()?.parse().ok()?;
    let want = normalize_python(dep);
    let from_pep508 = |list: &toml::Value| {
        list.as_array()?
            .iter()
            .filter_map(|r| r.as_str())
            .filter_map(pep508)
            .find(|(n, _)| *n == want)
            .map(|(_, spec)| Req::Native(spec))
    };
    if let Some(project) = doc.get("project") {
        if let Some(r) = project.get("dependencies").and_then(from_pep508) {
            return Some(r);
        }
        if let Some(extras) = project
            .get("optional-dependencies")
            .and_then(|o| o.as_table())
            && let Some(r) = extras.values().find_map(from_pep508)
        {
            return Some(r);
        }
    }
    if let Some(groups) = doc.get("dependency-groups").and_then(|g| g.as_table())
        && let Some(r) = groups.values().find_map(from_pep508)
    {
        return Some(r);
    }
    if format == Format::PoetryLock || doc.get("tool").and_then(|t| t.get("poetry")).is_some() {
        let poetry = doc.get("tool")?.get("poetry")?;
        let mut tables: Vec<&toml::Table> = Vec::new();
        for key in ["dependencies", "dev-dependencies"] {
            if let Some(t) = poetry.get(key).and_then(|t| t.as_table()) {
                tables.push(t);
            }
        }
        if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
            tables.extend(
                groups
                    .values()
                    .filter_map(|g| g.get("dependencies").and_then(|d| d.as_table())),
            );
        }
        for t in tables {
            for (k, v) in t {
                if normalize_python(k) == want {
                    let spec = v
                        .as_str()
                        .or_else(|| v.get("version").and_then(|x| x.as_str()))
                        .unwrap_or("*");
                    return Some(Req::Poetry(spec.to_string()));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_requirements_including_workspace_and_renames() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\n[workspace.dependencies]\nserde = { version = \"1.0.100\" }\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("app")).unwrap();
        let app = dir.path().join("app/Cargo.toml");
        std::fs::write(
            &app,
            "[package]\nname = \"app\"\n[dependencies]\nserde = { workspace = true }\nrx = { package = \"regex\", version = \"1.5\" }\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
        )
        .unwrap();
        assert_eq!(cargo_manifest(dir.path(), "app"), Some(app.clone()));
        assert_eq!(cargo(&app, dir.path(), "serde").as_deref(), Some("1.0.100"));
        assert_eq!(cargo(&app, dir.path(), "regex").as_deref(), Some("1.5"));
        assert_eq!(cargo(&app, dir.path(), "libc").as_deref(), Some("0.2"));
        assert_eq!(cargo(&app, dir.path(), "rx"), None);
    }

    #[test]
    fn python_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pyproject.toml");
        std::fs::write(
            &p,
            "[project]\ndependencies = [\"Requests>=2.30,<3\"]\n[project.optional-dependencies]\nfast = [\"orjson>=3\"]\n[dependency-groups]\ndev = [\"pytest~=8.0\"]\n",
        )
        .unwrap();
        assert_eq!(
            python(&p, "requests", Format::UvLock),
            Some(Req::Native(">=2.30,<3".into()))
        );
        assert_eq!(
            python(&p, "orjson", Format::UvLock),
            Some(Req::Native(">=3".into()))
        );
        assert_eq!(
            python(&p, "pytest", Format::UvLock),
            Some(Req::Native("~=8.0".into()))
        );
        std::fs::write(
            &p,
            "[tool.poetry.dependencies]\npython = \"^3.10\"\nurllib3 = { version = \"^1.26\" }\n[tool.poetry.group.dev.dependencies]\nblack = \"^24.1\"\n",
        )
        .unwrap();
        let r = python(&p, "urllib3", Format::PoetryLock).unwrap();
        assert_eq!(r, Req::Poetry("^1.26".into()));
        assert_eq!(r.allows(Ecosystem::PyPI, "2.0.0"), Some(false));
        assert_eq!(
            python(&p, "black", Format::PoetryLock),
            Some(Req::Poetry("^24.1".into()))
        );
    }
}
