//! JavaScript lockfiles: npm (`package-lock.json` v1–v3), Yarn 1, Yarn Berry,
//! pnpm (v5–v9) and Bun (`bun.lock`).

use super::{Ecosystem, EdgeKind, Format, Lockfile, Package, Scope, Source};
use anyhow::{Context, Result};
use serde_json::Value;
use serde_yaml::Value as Yaml;
use std::collections::HashMap;
use std::path::Path;

const DEP_SECTIONS: &[(&str, EdgeKind)] = &[
    ("dependencies", EdgeKind::Normal),
    ("optionalDependencies", EdgeKind::Optional),
    ("devDependencies", EdgeKind::Dev),
    // npm 7+ and Bun install peers; resolve them when present.
    ("peerDependencies", EdgeKind::Normal),
];

/// Classify a resolved URL or protocol string.
fn source_from_resolved(resolved: &str) -> Source {
    let r = resolved.trim();
    if r.is_empty() {
        return Source::registry();
    }
    if let Some(path) = r.strip_prefix("file:").or_else(|| r.strip_prefix("link:")) {
        return Source::Path {
            path: path.to_string(),
        };
    }
    if r.starts_with("git+")
        || r.starts_with("git:")
        || r.starts_with("github:")
        || r.starts_with("git@")
        || r.contains("codeload.github.com")
    {
        let (url, rev) = match r.rsplit_once('#') {
            Some((u, c)) => (u, Some(c.to_string())),
            None => (r, None),
        };
        return Source::Git {
            url: url.to_string(),
            rev,
        };
    }
    if r.starts_with("http://") || r.starts_with("https://") {
        // Registry tarballs live under `/<name>/-/<file>.tgz`.
        if r.contains("/-/") {
            let default = r.starts_with("https://registry.npmjs.org/")
                || r.starts_with("https://registry.yarnpkg.com/");
            let base = r.split("/-/").next().unwrap_or(r);
            let registry = base
                .strip_prefix("https://")
                .or_else(|| base.strip_prefix("http://"))
                .and_then(|rest| rest.split('/').next())
                .map(|host| format!("{}//{host}/", &r[..r.find("//").unwrap_or(0)]));
            return Source::Registry {
                url: if default { None } else { registry },
            };
        }
        return Source::Url { url: r.to_string() };
    }
    Source::Path {
        path: r.to_string(),
    }
}

/// Split `name@version` (the name may be scoped: `@scope/name@1.0`).
fn split_ident(ident: &str) -> Option<(&str, &str)> {
    let at = ident.get(1..)?.find('@')? + 1;
    Some((&ident[..at], &ident[at + 1..]))
}

/// Drop pnpm/Bun peer-dependency suffixes: `1.0.0(react@18)` / `1.0.0_react@18`.
fn strip_peers(version: &str) -> &str {
    let v = version.split('(').next().unwrap_or(version);
    v.split('_').next().unwrap_or(v)
}

// ── package-lock.json / npm-shrinkwrap.json ──────────────────────────────────

pub fn package_lock(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Value = serde_json::from_str(content).context("invalid JSON")?;
    let mut lock = Lockfile::new(path, Format::PackageLock, Ecosystem::Npm);
    match doc.get("packages").and_then(Value::as_object) {
        Some(packages) => package_lock_v2(&mut lock, packages),
        None => package_lock_v1(&mut lock, &doc),
    }
    Ok(lock)
}

/// The package name at an install path: the part after the last `node_modules/`.
fn name_at(key: &str) -> &str {
    match key.rfind("node_modules/") {
        Some(i) => &key[i + "node_modules/".len()..],
        None => key,
    }
}

/// The install path a dependency `name` resolves to from `from`, by Node's
/// lookup: `<from>/node_modules/<name>`, then each ancestor's, then the root's.
fn node_resolve<'a>(
    keys: &'a HashMap<String, usize>,
    from: &str,
    name: &str,
) -> Option<&'a usize> {
    let mut at = from.to_string();
    loop {
        let candidate = if at.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{at}/node_modules/{name}")
        };
        if let Some(i) = keys.get(&candidate) {
            return Some(i);
        }
        if at.is_empty() {
            return None;
        }
        at = match at.rfind("/node_modules/") {
            Some(i) => at[..i].to_string(),
            // A workspace path ("packages/x") falls back to the root.
            None => String::new(),
        };
    }
}

fn package_lock_v2(lock: &mut Lockfile, packages: &serde_json::Map<String, Value>) {
    // key -> package index; links point at their target's key.
    let mut keys: HashMap<String, usize> = HashMap::new();
    let mut links: Vec<(String, String)> = Vec::new();
    let mut order: Vec<(&String, &Value)> = packages.iter().collect();
    order.sort_by(|a, b| a.0.cmp(b.0));

    for (key, entry) in &order {
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            if let Some(target) = entry.get("resolved").and_then(Value::as_str) {
                links.push(((*key).clone(), target.to_string()));
            }
            continue;
        }
        let in_node_modules = key.starts_with("node_modules/") || key.contains("/node_modules/");
        let member = key.is_empty() || !in_node_modules;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| name_at(key));
        let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
        let mut pkg = if member {
            Package::member(name, version, if key.is_empty() { "." } else { key })
        } else {
            Package::new(
                name,
                version,
                source_from_resolved(entry.get("resolved").and_then(Value::as_str).unwrap_or("")),
            )
        };
        if !member {
            pkg.integrity = entry
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_string);
            pkg.install_script =
                Some(entry.get("hasInstallScript").and_then(Value::as_bool) == Some(true));
            let flag = |f: &str| entry.get(f).and_then(Value::as_bool) == Some(true);
            pkg.scope = if flag("dev") {
                Scope::Dev
            } else if flag("optional") || flag("devOptional") {
                Scope::Optional
            } else {
                Scope::Prod
            };
        }
        let i = lock.push(pkg);
        keys.insert((*key).clone(), i);
    }
    for (link, target) in links {
        if let Some(&i) = keys.get(&target) {
            keys.insert(link, i);
        }
    }

    let mut edges = Vec::new();
    for (key, entry) in &order {
        let Some(&from) = keys.get(*key) else {
            continue;
        };
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        for (section, kind) in DEP_SECTIONS {
            for name in entry
                .get(*section)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(n, _)| n)
            {
                if let Some(&to) = node_resolve(&keys, key, name) {
                    edges.push((from, to, *kind));
                }
            }
        }
    }
    for (from, to, kind) in edges {
        lock.edge(from, to, kind);
    }
}

/// lockfileVersion 1: a nested `dependencies` tree with `requires` maps.
fn package_lock_v1(lock: &mut Lockfile, doc: &Value) {
    let root = lock.push(Package::member(
        doc.get("name").and_then(Value::as_str).unwrap_or("root"),
        doc.get("version").and_then(Value::as_str).unwrap_or(""),
        ".",
    ));
    // Install path -> index, built the same way v2 keys look.
    let mut keys: HashMap<String, usize> = HashMap::new();
    let mut requires: Vec<(String, usize, Vec<String>)> = Vec::new();

    fn walk(
        lock: &mut Lockfile,
        deps: &serde_json::Map<String, Value>,
        prefix: &str,
        keys: &mut HashMap<String, usize>,
        requires: &mut Vec<(String, usize, Vec<String>)>,
    ) {
        for (name, entry) in deps {
            let key = if prefix.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{prefix}/node_modules/{name}")
            };
            let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
            let mut pkg = Package::new(
                name.as_str(),
                version,
                source_from_resolved(entry.get("resolved").and_then(Value::as_str).unwrap_or("")),
            );
            pkg.integrity = entry
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_string);
            if entry.get("dev").and_then(Value::as_bool) == Some(true) {
                pkg.scope = Scope::Dev;
            } else if entry.get("optional").and_then(Value::as_bool) == Some(true) {
                pkg.scope = Scope::Optional;
            }
            let i = lock.push(pkg);
            keys.insert(key.clone(), i);
            let req: Vec<String> = entry
                .get("requires")
                .and_then(Value::as_object)
                .map(|r| r.keys().cloned().collect())
                .unwrap_or_default();
            requires.push((key.clone(), i, req));
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                walk(lock, nested, &key, keys, requires);
            }
        }
    }
    if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        walk(lock, deps, "", &mut keys, &mut requires);
        // v1 does not list the root's own requirements; top-level entries are
        // as close as it gets.
        for name in deps.keys() {
            if let Some(&i) = keys.get(&format!("node_modules/{name}")) {
                let kind = if lock.packages[i].scope == Scope::Dev {
                    EdgeKind::Dev
                } else {
                    EdgeKind::Normal
                };
                lock.edge(root, i, kind);
            }
        }
    }
    for (key, from, req) in requires {
        for name in req {
            if let Some(&to) = node_resolve(&keys, &key, &name) {
                lock.edge(from, to, EdgeKind::Normal);
            }
        }
    }
}

// ── Yarn ──────────────────────────────────────────────────────────────────────

pub fn yarn(path: &Path, content: &str) -> Result<Lockfile> {
    if content.contains("\n__metadata:") || content.starts_with("__metadata:") {
        yarn_berry(path, content)
    } else {
        Ok(yarn1(path, content))
    }
}

/// The real package name of a Yarn descriptor `name@range`; for an alias
/// `alias@npm:real@^1`, that is `real`.
fn yarn_descriptor_name(descriptor: &str) -> Option<String> {
    let (name, range) = split_ident(descriptor)?;
    if let Some(aliased) = range.strip_prefix("npm:")
        && let Some((real, _)) = split_ident(aliased)
    {
        return Some(real.to_string());
    }
    Some(name.to_string())
}

fn yarn1(path: &Path, content: &str) -> Lockfile {
    let mut lock = Lockfile::new(path, Format::Yarn1, Ecosystem::Npm);
    // descriptor ("name@range") -> package index
    let mut specs: HashMap<String, usize> = HashMap::new();
    // (from, section, name, range)
    let mut deps: Vec<(usize, EdgeKind, String, String)> = Vec::new();

    struct Entry {
        descriptors: Vec<String>,
        version: String,
        resolved: String,
        integrity: Option<String>,
        deps: Vec<(EdgeKind, String, String)>,
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut section: Option<EdgeKind> = None;
    for line in content.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let text = line.trim();
        if indent == 0 && text.ends_with(':') {
            let descriptors = text
                .trim_end_matches(':')
                .split(',')
                .map(|d| d.trim().trim_matches('"').to_string())
                .collect();
            entries.push(Entry {
                descriptors,
                version: String::new(),
                resolved: String::new(),
                integrity: None,
                deps: Vec::new(),
            });
            section = None;
            continue;
        }
        let Some(entry) = entries.last_mut() else {
            continue;
        };
        if indent == 2 {
            section = match text {
                "dependencies:" => Some(EdgeKind::Normal),
                "optionalDependencies:" => Some(EdgeKind::Optional),
                _ => None,
            };
            let (key, value) = text.split_once(' ').unwrap_or((text, ""));
            let value = value.trim().trim_matches('"').to_string();
            match key {
                "version" => entry.version = value,
                "resolved" => entry.resolved = value,
                "integrity" => entry.integrity = Some(value),
                _ => {}
            }
        } else if indent >= 4
            && let Some(kind) = section
            && let Some((name, range)) = text.split_once(' ')
        {
            entry.deps.push((
                kind,
                name.trim_matches('"').to_string(),
                range.trim().trim_matches('"').to_string(),
            ));
        }
    }

    for e in entries {
        let Some(name) = e.descriptors.first().and_then(|d| yarn_descriptor_name(d)) else {
            continue;
        };
        let resolved = e.resolved.split('#').next().unwrap_or("");
        let source = if e.resolved.contains("codeload.github.com") || e.resolved.starts_with("git")
        {
            source_from_resolved(&e.resolved)
        } else {
            source_from_resolved(resolved)
        };
        let mut pkg = Package::new(name, e.version, source);
        pkg.integrity = e.integrity;
        let i = lock.push(pkg);
        for d in e.descriptors {
            specs.insert(d, i);
        }
        for (kind, n, r) in e.deps {
            deps.push((i, kind, n, r));
        }
    }

    // Yarn 1 does not record the project itself: take it from package.json.
    let root = add_package_json_member(&mut lock, &mut deps);
    for (from, kind, name, range) in deps {
        if let Some(&to) = specs.get(&format!("{name}@{range}")) {
            lock.edge(from, to, kind);
        }
    }
    if root.is_none() {
        lock.notes.push(
            "no package.json beside yarn.lock — direct dependencies are unknown".to_string(),
        );
    }
    lock
}

/// Add the project in the sibling `package.json` as a member, queueing its
/// dependency ranges for resolution. Returns its index.
fn add_package_json_member(
    lock: &mut Lockfile,
    deps: &mut Vec<(usize, EdgeKind, String, String)>,
) -> Option<usize> {
    let manifest = super::sibling_package_json(&lock.path)?;
    let root = lock.push(Package::member(
        manifest
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("root"),
        manifest
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or(""),
        ".",
    ));
    for (section, kind) in DEP_SECTIONS {
        for (name, range) in manifest
            .get(*section)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if let Some(range) = range.as_str() {
                deps.push((root, *kind, name.clone(), range.to_string()));
            }
        }
    }
    Some(root)
}

fn yarn_berry(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Yaml = serde_yaml::from_str(content).context("invalid YAML")?;
    let mut lock = Lockfile::new(path, Format::YarnBerry, Ecosystem::Npm);
    let Some(map) = doc.as_mapping() else {
        return Ok(lock);
    };
    let mut specs: HashMap<String, usize> = HashMap::new();
    let mut deps: Vec<(usize, EdgeKind, String, String)> = Vec::new();
    let mut workspace_dirs: Vec<(usize, String)> = Vec::new();

    for (key, entry) in map {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        let descriptors: Vec<&str> = key.split(',').map(str::trim).collect();
        let resolution = entry.get("resolution").and_then(Yaml::as_str).unwrap_or("");
        let Some((name, locator)) = split_ident(resolution) else {
            continue;
        };
        let version = entry
            .get("version")
            .and_then(Yaml::as_str)
            .unwrap_or("")
            .to_string();
        let i = if let Some(dir) = locator.strip_prefix("workspace:") {
            let i = lock.push(Package::member(name, "", dir));
            workspace_dirs.push((i, dir.to_string()));
            i
        } else {
            let source = if locator.starts_with("npm:") || locator.starts_with("patch:") {
                Source::registry()
            } else {
                source_from_resolved(locator)
            };
            // Yarn's `checksum` hashes its own cache zip, not the tarball, so
            // it is not an integrity value for the package.
            lock.push(Package::new(name, version, source))
        };
        for d in descriptors {
            specs.insert(d.trim_matches('"').to_string(), i);
        }
        for (section, kind) in [
            ("dependencies", EdgeKind::Normal),
            ("optionalDependencies", EdgeKind::Optional),
            ("peerDependencies", EdgeKind::Normal),
        ] {
            for (n, r) in entry
                .get(section)
                .and_then(Yaml::as_mapping)
                .into_iter()
                .flatten()
            {
                if let (Some(n), Some(r)) = (n.as_str(), r.as_str()) {
                    deps.push((i, kind, n.to_string(), r.to_string()));
                }
            }
        }
    }

    // Berry merges a workspace's dev and prod dependencies; its package.json
    // says which were dev.
    let base = path.parent().unwrap_or(Path::new("."));
    let mut dev_names: HashMap<usize, Vec<String>> = HashMap::new();
    for (i, dir) in &workspace_dirs {
        let manifest = std::fs::read_to_string(base.join(dir).join("package.json"))
            .ok()
            .and_then(|m| serde_json::from_str::<Value>(&m).ok());
        if let Some(dev) = manifest
            .as_ref()
            .and_then(|m| m.get("devDependencies"))
            .and_then(Value::as_object)
        {
            dev_names.insert(*i, dev.keys().cloned().collect());
        }
    }

    for (from, mut kind, name, range) in deps {
        if dev_names.get(&from).is_some_and(|d| d.contains(&name)) {
            kind = EdgeKind::Dev;
        }
        let to = specs
            .get(&format!("{name}@{range}"))
            .or_else(|| specs.get(&format!("{name}@npm:{range}")));
        if let Some(&to) = to {
            lock.edge(from, to, kind);
        }
    }
    Ok(lock)
}

// ── pnpm ──────────────────────────────────────────────────────────────────────

/// Parse a pnpm `packages:` key into (name, version-with-peers).
/// v9: `name@1.0.0`; v6–v8: `/name@1.0.0(peer@1)`; v5: `/name/1.0.0_peer@1`.
fn pnpm_key(key: &str) -> Option<(String, String)> {
    let k = key.strip_prefix('/').unwrap_or(key);
    // After any `@scope/`, an `@` before the next `/` means `name@version`
    // (v6+). Otherwise it is v5's `name/version`, whose peer suffix
    // (`_react@18`) has an `@` of its own.
    let unscoped = match k.strip_prefix('@') {
        Some(rest) => rest.split_once('/').map_or("", |(_, r)| r),
        None => k,
    };
    let at = unscoped.find('@');
    let slash = unscoped.find('/');
    if at.is_some() && slash.is_none_or(|s| at < Some(s)) {
        let (name, version) = split_ident(k)?;
        return Some((name.to_string(), version.to_string()));
    }
    let (name, version) = k.rsplit_once('/')?;
    Some((name.to_string(), version.to_string()))
}

pub fn pnpm(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Yaml = serde_yaml::from_str(content).context("invalid YAML")?;
    let mut lock = Lockfile::new(path, Format::Pnpm, Ecosystem::Npm);
    // `lockfileVersion: 5.4` (number) or `'9.0'` (string).
    let v5 = match doc.get("lockfileVersion") {
        Some(Yaml::Number(n)) => n.as_f64().is_some_and(|v| v < 6.0),
        Some(Yaml::String(v)) => v
            .split('.')
            .next()
            .and_then(|m| m.parse::<u32>().ok())
            .is_some_and(|m| m < 6),
        _ => false,
    };

    // (name, version without peers) -> index; the full key also maps there.
    let mut ids: HashMap<(String, String), usize> = HashMap::new();
    let mut keyed: HashMap<String, usize> = HashMap::new();
    for (key, entry) in doc
        .get("packages")
        .and_then(Yaml::as_mapping)
        .into_iter()
        .flatten()
    {
        let Some(key) = key.as_str() else { continue };
        let Some((name, version)) = pnpm_key(key) else {
            continue;
        };
        let base = strip_peers(&version).to_string();
        let i = match ids.get(&(name.clone(), base.clone())) {
            Some(&i) => i,
            None => {
                let resolution = entry.get("resolution");
                let source = match resolution {
                    Some(r) if r.get("tarball").is_some() => {
                        source_from_resolved(r.get("tarball").and_then(Yaml::as_str).unwrap_or(""))
                    }
                    Some(r) if r.get("repo").is_some() => Source::Git {
                        url: r
                            .get("repo")
                            .and_then(Yaml::as_str)
                            .unwrap_or("")
                            .to_string(),
                        rev: r.get("commit").and_then(Yaml::as_str).map(str::to_string),
                    },
                    Some(r) if r.get("directory").is_some() => Source::Path {
                        path: r
                            .get("directory")
                            .and_then(Yaml::as_str)
                            .unwrap_or("")
                            .to_string(),
                    },
                    _ => Source::registry(),
                };
                let mut pkg = Package::new(name.clone(), base.clone(), source);
                pkg.integrity = resolution
                    .and_then(|r| r.get("integrity"))
                    .and_then(Yaml::as_str)
                    .map(str::to_string);
                if let Some(b) = entry.get("requiresBuild").and_then(Yaml::as_bool) {
                    pkg.install_script = Some(b);
                }
                match entry.get("dev").and_then(Yaml::as_bool) {
                    Some(true) => pkg.scope = Scope::Dev,
                    Some(false) => pkg.scope = Scope::Prod,
                    None => {}
                }
                let i = lock.push(pkg);
                ids.insert((name.clone(), base.clone()), i);
                i
            }
        };
        keyed.insert(key.to_string(), i);
    }

    // Importers: the workspace projects (v9 always; v6+ workspaces). Older
    // single-project files keep the sections at the top level.
    let mut importers: Vec<(String, Yaml)> = doc
        .get("importers")
        .and_then(Yaml::as_mapping)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.clone())))
        .collect();
    if importers.is_empty() {
        importers.push((".".to_string(), doc.clone()));
    }
    let manifest = super::sibling_package_json(path);
    let mut members: HashMap<String, usize> = HashMap::new();
    for (dir, _) in &importers {
        let name = if dir == "." {
            manifest
                .as_ref()
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("root")
                .to_string()
        } else {
            dir.clone()
        };
        let i = lock.push(Package::member(name, "", dir));
        members.insert(dir.clone(), i);
    }

    // Resolve a dependency `name: <version>` as written in an importer or snapshot.
    let resolve = |name: &str, version: &str, from_dir: &str| -> Option<usize> {
        if let Some(link) = version.strip_prefix("link:") {
            let target = normalize_join(from_dir, link);
            return members.get(&target).copied();
        }
        // A leading `/` is a full key (v5–v8 aliases: `/real-name/1.0.0`,
        // `/real-name@1.0.0`).
        if version.starts_with('/') {
            let (n, v) = pnpm_key(version)?;
            return ids.get(&(n, strip_peers(&v).to_string())).copied();
        }
        let bare = version.split('(').next().unwrap_or(version);
        // v6+ write aliases as `real-name@version`. In v5 an `@` here belongs
        // to the peer suffix (`18.0.0_react@18.0.0`), never to an alias.
        let (name, version) = match split_ident(bare).filter(|_| !v5) {
            Some((real, v)) => (real, v),
            None => (name, bare),
        };
        // v5's `_peer@1` suffix belongs to the version only.
        ids.get(&(name.to_string(), strip_peers(version).to_string()))
            .copied()
    };

    let mut edges = Vec::new();
    for (dir, section) in &importers {
        let Some(&from) = members.get(dir) else {
            continue;
        };
        for (sec, kind) in DEP_SECTIONS {
            for (n, spec) in section
                .get(*sec)
                .and_then(Yaml::as_mapping)
                .into_iter()
                .flatten()
            {
                let Some(n) = n.as_str() else { continue };
                // v6+: `{specifier, version}`; v5: the version itself.
                let version = spec
                    .get("version")
                    .and_then(Yaml::as_str)
                    .or_else(|| spec.as_str())
                    .unwrap_or("");
                if let Some(to) = resolve(n, version, dir) {
                    edges.push((from, to, *kind));
                }
            }
        }
    }
    // Package-to-package edges: v9 in `snapshots`, earlier in `packages`.
    let graph = doc
        .get("snapshots")
        .or_else(|| doc.get("packages"))
        .and_then(Yaml::as_mapping);
    for (key, entry) in graph.into_iter().flatten() {
        let Some(key) = key.as_str() else { continue };
        let from = keyed.get(key).copied().or_else(|| {
            let (name, version) = pnpm_key(key)?;
            ids.get(&(name, strip_peers(&version).to_string())).copied()
        });
        let Some(from) = from else { continue };
        for (sec, kind) in [
            ("dependencies", EdgeKind::Normal),
            ("optionalDependencies", EdgeKind::Optional),
        ] {
            for (n, v) in entry
                .get(sec)
                .and_then(Yaml::as_mapping)
                .into_iter()
                .flatten()
            {
                if let (Some(n), Some(v)) = (n.as_str(), v.as_str())
                    && let Some(to) = resolve(n, v, ".")
                {
                    edges.push((from, to, kind));
                }
            }
        }
    }
    for (from, to, kind) in edges {
        lock.edge(from, to, kind);
    }
    Ok(lock)
}

/// Join a relative importer path onto another, normalising `.` and `..`.
fn normalize_join(base: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = if base == "." {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

// ── Bun ───────────────────────────────────────────────────────────────────────

/// `bun.lock` is JSON with trailing commas (and possibly comments).
fn jsonc_to_json(input: &str) -> String {
    let bytes: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(&n) = bytes.get(i + 1) {
                    out.push(n);
                    i += 1;
                }
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if bytes.get(i + 1) == Some(&'/') => {
                while i < bytes.len() && bytes[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '/' if bytes.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            ',' => {
                // Drop a comma whose next significant character (past
                // whitespace and comments) closes a container.
                if !matches!(next_significant(&bytes, i + 1), Some('}') | Some(']')) {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// The first character from `i` that is not whitespace or inside a comment.
fn next_significant(chars: &[char], mut i: usize) -> Option<char> {
    while i < chars.len() {
        match (chars[i], chars.get(i + 1)) {
            (c, _) if c.is_whitespace() => i += 1,
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            (c, _) => return Some(c),
        }
    }
    None
}

/// Split a `bun.lock` package key ("a/@s/b/c") into package names.
fn bun_path(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut parts = key.split('/');
    while let Some(p) = parts.next() {
        if p.starts_with('@') {
            out.push(format!("{p}/{}", parts.next().unwrap_or("")));
        } else {
            out.push(p.to_string());
        }
    }
    out
}

pub fn bun(path: &Path, content: &str) -> Result<Lockfile> {
    let doc: Value = serde_json::from_str(&jsonc_to_json(content)).context("invalid bun.lock")?;
    let mut lock = Lockfile::new(path, Format::Bun, Ecosystem::Npm);
    let empty = serde_json::Map::new();
    let packages = doc
        .get("packages")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    // package path ("a/b") -> index
    let mut keys: HashMap<String, usize> = HashMap::new();
    // workspace dir -> member index
    let mut members: HashMap<String, usize> = HashMap::new();
    let mut infos: Vec<(String, usize, Value)> = Vec::new();

    for (key, entry) in packages {
        let Some(arr) = entry.as_array() else {
            continue;
        };
        let Some((name, spec)) = arr.first().and_then(Value::as_str).and_then(split_ident) else {
            continue;
        };
        if let Some(dir) = spec.strip_prefix("workspace:") {
            // Workspace members are listed under `workspaces` too; index both.
            let i = lock.push(Package::member(name, "", dir));
            keys.insert(key.clone(), i);
            members.insert(dir.to_string(), i);
            continue;
        }
        let (source, info, integrity) = if spec.starts_with("git")
            || spec.starts_with("github:")
            || spec.starts_with("file:")
            || spec.starts_with("link:")
            || spec.starts_with("http")
        {
            (source_from_resolved(spec), arr.get(1), None)
        } else if semver::Version::parse(spec).is_err() {
            // Not a version: a local tarball or directory (`./x.tgz`,
            // `x-1.0.0.tgz`, `../pkg`), recorded as [ident, info, integrity].
            (
                Source::Path {
                    path: spec.to_string(),
                },
                arr.get(1),
                arr.get(2).and_then(Value::as_str),
            )
        } else {
            let registry = arr.get(1).and_then(Value::as_str).unwrap_or("");
            let source = if registry.is_empty() {
                Source::registry()
            } else {
                Source::Registry {
                    url: Some(registry.to_string()),
                }
            };
            (source, arr.get(2), arr.get(3).and_then(Value::as_str))
        };
        let version = match &source {
            Source::Registry { .. } => spec.to_string(),
            _ => String::new(),
        };
        let mut pkg = Package::new(name, version, source);
        pkg.integrity = integrity.map(str::to_string);
        let i = lock.push(pkg);
        keys.insert(key.clone(), i);
        infos.push((key.clone(), i, info.cloned().unwrap_or(Value::Null)));
    }

    // Workspaces: "" is the root project.
    let mut workspace_deps: Vec<(usize, String, Value)> = Vec::new();
    for (dir, ws) in doc
        .get("workspaces")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let i = match members.get(if dir.is_empty() { "." } else { dir }) {
            Some(&i) => i,
            None => {
                let name = ws
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(if dir.is_empty() { "root" } else { dir });
                let i = lock.push(Package::member(
                    name,
                    "",
                    if dir.is_empty() { "." } else { dir },
                ));
                members.insert(dir.clone(), i);
                i
            }
        };
        let member_key = keys
            .iter()
            .find(|(_, v)| **v == i)
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        workspace_deps.push((i, member_key, ws.clone()));
    }

    // Resolve `name` from package path `from` (Bun nests like node_modules).
    let resolve = |from: &str, name: &str| -> Option<usize> {
        let mut prefix = if from.is_empty() {
            Vec::new()
        } else {
            bun_path(from)
        };
        loop {
            let mut cand = prefix.clone();
            cand.push(name.to_string());
            if let Some(&i) = keys.get(&cand.join("/")) {
                return Some(i);
            }
            prefix.pop()?;
        }
    };

    let mut edges = Vec::new();
    for (from, key, info) in infos.iter().map(|(k, i, v)| (*i, k.as_str(), v)) {
        for (section, kind) in DEP_SECTIONS {
            for name in info
                .get(*section)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(n, _)| n)
            {
                if let Some(to) = resolve(key, name) {
                    edges.push((from, to, *kind));
                }
            }
        }
    }
    for (from, key, ws) in &workspace_deps {
        for (section, kind) in DEP_SECTIONS {
            for name in ws
                .get(*section)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(n, _)| n)
            {
                if let Some(to) = resolve(key, name) {
                    edges.push((*from, to, *kind));
                }
            }
        }
    }
    for (from, to, kind) in edges {
        lock.edge(from, to, kind);
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonc_drops_trailing_commas_and_comments_but_not_string_content() {
        let src = r#"{ "a": [1, 2,], // note
            "b": "x,]/*y*/", /* c */ }"#;
        let v: Value = serde_json::from_str(&jsonc_to_json(src)).unwrap();
        assert_eq!(v["a"], serde_json::json!([1, 2]));
        assert_eq!(v["b"], "x,]/*y*/");
    }

    #[test]
    fn pnpm_keys_across_versions() {
        assert_eq!(pnpm_key("ms@2.1.3"), Some(("ms".into(), "2.1.3".into())));
        assert_eq!(
            pnpm_key("/@babel/core@7.0.0(supports-color@5)"),
            Some(("@babel/core".into(), "7.0.0(supports-color@5)".into()))
        );
        assert_eq!(
            pnpm_key("/lodash/4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            pnpm_key("/react-dom/18.0.0_react@18.0.0"),
            Some(("react-dom".into(), "18.0.0_react@18.0.0".into()))
        );
        assert_eq!(
            pnpm_key("/@types/node/20.1.0"),
            Some(("@types/node".into(), "20.1.0".into()))
        );
        assert_eq!(
            pnpm_key("my_pkg@1.0.0"),
            Some(("my_pkg".into(), "1.0.0".into()))
        );
        assert_eq!(strip_peers("7.0.0(supports-color@5)"), "7.0.0");
        assert_eq!(strip_peers("1.0.0_react@18.0.0"), "1.0.0");
    }

    #[test]
    fn node_resolution_walks_up_from_nested_paths() {
        let keys: HashMap<String, usize> = [
            ("node_modules/ms", 1),
            ("node_modules/debug/node_modules/ms", 2),
            ("node_modules/debug", 3),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(node_resolve(&keys, "node_modules/debug", "ms"), Some(&2));
        assert_eq!(node_resolve(&keys, "", "ms"), Some(&1));
        assert_eq!(node_resolve(&keys, "packages/app", "ms"), Some(&1));
        assert_eq!(node_resolve(&keys, "node_modules/debug", "debug"), Some(&3));
        assert_eq!(node_resolve(&keys, "", "nope"), None);
    }

    #[test]
    fn registry_detection_from_resolved_urls() {
        assert_eq!(
            source_from_resolved("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
            Source::registry()
        );
        assert_eq!(
            source_from_resolved("https://npm.acme.dev/@acme/x/-/x-1.0.0.tgz"),
            Source::Registry {
                url: Some("https://npm.acme.dev/".into())
            }
        );
        assert!(matches!(
            source_from_resolved("git+ssh://git@github.com/a/b.git#abc123"),
            Source::Git { rev: Some(r), .. } if r == "abc123"
        ));
        assert!(matches!(
            source_from_resolved("file:../local"),
            Source::Path { .. }
        ));
        assert!(matches!(
            source_from_resolved("https://example.com/pkg.tgz"),
            Source::Url { .. }
        ));
    }
}
