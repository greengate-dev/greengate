//! What each version of a package requires of its dependencies, for working
//! out how a vulnerable dependency can be raised to a fixed version.
//!
//! npm and crates.io publish this for every version in one document (the
//! packument; the sparse index file). PyPI does not: each version's
//! `requires_dist` is a separate request, so [`of_version`] fetches one.

use super::{Key, MAX_DOCUMENT_BYTES, USER_AGENT, base, segment};
use crate::deps::{Ecosystem, normalize_python};
use crate::utils::http::{self, Fetched};
use serde::Deserialize;
use std::collections::HashMap;

/// One published version and its requirements, by dependency name.
#[derive(Debug, Clone, Default)]
pub struct VersionReqs {
    pub version: String,
    /// Withdrawn versions are never suggested.
    pub withdrawn: bool,
    /// Dependency name (normalised for PyPI) → requirement strings. Empty for
    /// a PyPI version until [`of_version`] fills it.
    pub requires: HashMap<String, Vec<String>>,
}

/// Every version of `name`, oldest first.
pub fn all_versions(eco: Ecosystem, name: &str) -> Fetched<Vec<VersionReqs>> {
    let fetched = match eco {
        Ecosystem::Npm => npm(name),
        Ecosystem::Cargo => crates(name),
        Ecosystem::PyPI => pypi_versions(name),
        Ecosystem::Go => Fetched::Unavailable("Go module requirements are not fetched".into()),
    };
    match fetched {
        Fetched::Json(mut list) => {
            list.sort_by(|a, b| Key::parse(eco, &a.version).cmp(&Key::parse(eco, &b.version)));
            Fetched::Json(list)
        }
        other => other,
    }
}

/// What `name@version` requires.
pub fn of_version(
    eco: Ecosystem,
    name: &str,
    version: &str,
) -> Fetched<HashMap<String, Vec<String>>> {
    if eco == Ecosystem::PyPI {
        return pypi_requires(name, version);
    }
    match all_versions(eco, name) {
        Fetched::Json(list) => match list.into_iter().find(|v| v.version == version) {
            Some(v) => Fetched::Json(v.requires),
            None => Fetched::NotFound,
        },
        Fetched::NotFound => Fetched::NotFound,
        Fetched::Unavailable(e) => Fetched::Unavailable(e),
    }
}

/// Whether `version` is a pre-release, which is only suggested when nothing
/// else fixes the problem.
pub fn is_prerelease(eco: Ecosystem, version: &str) -> bool {
    Key::parse(eco, version).is_none_or(|k| k.is_pre())
}

/// `a < b` in the ecosystem's ordering; `None` when either does not parse.
pub fn less(eco: Ecosystem, a: &str, b: &str) -> Option<bool> {
    Some(Key::parse(eco, a)? < Key::parse(eco, b)?)
}

// ── npm ───────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    versions: HashMap<String, NpmVersion>,
}

#[derive(Deserialize)]
struct NpmVersion {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional: HashMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer: HashMap<String, String>,
    #[serde(default)]
    deprecated: Option<serde_json::Value>,
}

fn npm(name: &str) -> Fetched<Vec<VersionReqs>> {
    let url = format!(
        "{}/{}",
        base("GREENGATE_NPM_REGISTRY", "https://registry.npmjs.org"),
        segment(name).replace("%40", "@")
    );
    match http::get_json_capped::<Packument>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(p) => Fetched::Json(
            p.versions
                .into_iter()
                .map(|(version, m)| {
                    let mut requires: HashMap<String, Vec<String>> = HashMap::new();
                    for (dep, spec) in m.dependencies.into_iter().chain(m.optional).chain(m.peer) {
                        requires.entry(dep).or_default().push(npm_spec(&spec));
                    }
                    VersionReqs {
                        version,
                        withdrawn: m
                            .deprecated
                            .as_ref()
                            .and_then(|d| d.as_str())
                            .is_some_and(|d| !d.is_empty()),
                        requires,
                    }
                })
                .collect(),
        ),
        Fetched::NotFound => Fetched::NotFound,
        Fetched::Unavailable(e) => Fetched::Unavailable(e),
    }
}

/// The range in an npm dependency spec: `npm:other@^1.2` aliases keep their
/// range; anything else is returned as written.
fn npm_spec(spec: &str) -> String {
    match spec.strip_prefix("npm:") {
        Some(alias) => alias
            .get(1..)
            .and_then(|a| a.find('@'))
            .map_or_else(|| "*".to_string(), |at| alias[at + 2..].to_string()),
        None => spec.to_string(),
    }
}

// ── crates.io (sparse index) ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    deps: Vec<IndexDep>,
    #[serde(default)]
    yanked: bool,
}

#[derive(Deserialize)]
struct IndexDep {
    name: String,
    req: String,
    #[serde(default)]
    kind: Option<String>,
    /// The real crate when the dependency is renamed.
    #[serde(default)]
    package: Option<String>,
}

/// The sparse-index path of a crate (https://doc.rust-lang.org/cargo/reference/registry-index.html).
fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

fn crates(name: &str) -> Fetched<Vec<VersionReqs>> {
    let url = format!(
        "{}/{}",
        base("GREENGATE_CRATES_INDEX", "https://index.crates.io"),
        index_path(name)
    );
    match http::get_text_capped(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(text) => {
            let mut out = Vec::new();
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(l) = serde_json::from_str::<IndexLine>(line) else {
                    return Fetched::Unavailable(format!("unreadable index entry for {name}"));
                };
                let mut requires: HashMap<String, Vec<String>> = HashMap::new();
                // Dev-dependencies never reach the crate's users.
                for d in l
                    .deps
                    .into_iter()
                    .filter(|d| d.kind.as_deref() != Some("dev"))
                {
                    requires
                        .entry(d.package.unwrap_or(d.name))
                        .or_default()
                        .push(d.req);
                }
                out.push(VersionReqs {
                    version: l.vers,
                    withdrawn: l.yanked,
                    requires,
                });
            }
            Fetched::Json(out)
        }
        Fetched::NotFound => Fetched::NotFound,
        Fetched::Unavailable(e) => Fetched::Unavailable(e),
    }
}

// ── PyPI ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PypiProject {
    #[serde(default)]
    releases: HashMap<String, Vec<PypiFile>>,
}

#[derive(Deserialize)]
struct PypiFile {
    #[serde(default)]
    yanked: bool,
}

#[derive(Deserialize)]
struct PypiVersionDoc {
    info: PypiVersionInfo,
}

#[derive(Deserialize)]
struct PypiVersionInfo {
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
}

fn pypi_versions(name: &str) -> Fetched<Vec<VersionReqs>> {
    let url = format!(
        "{}/pypi/{}/json",
        base("GREENGATE_PYPI_URL", "https://pypi.org"),
        segment(name)
    );
    match http::get_json_capped::<PypiProject>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(p) => Fetched::Json(
            p.releases
                .into_iter()
                .filter(|(_, files)| !files.is_empty())
                .map(|(version, files)| VersionReqs {
                    version,
                    withdrawn: files.iter().all(|f| f.yanked),
                    requires: HashMap::new(),
                })
                .collect(),
        ),
        Fetched::NotFound => Fetched::NotFound,
        Fetched::Unavailable(e) => Fetched::Unavailable(e),
    }
}

fn pypi_requires(name: &str, version: &str) -> Fetched<HashMap<String, Vec<String>>> {
    let url = format!(
        "{}/pypi/{}/{}/json",
        base("GREENGATE_PYPI_URL", "https://pypi.org"),
        segment(name),
        segment(version)
    );
    match http::get_json_capped::<PypiVersionDoc>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(doc) => {
            let mut requires: HashMap<String, Vec<String>> = HashMap::new();
            for (dep, spec) in doc
                .info
                .requires_dist
                .unwrap_or_default()
                .iter()
                .filter_map(|r| pep508(r))
            {
                requires.entry(dep).or_default().push(spec);
            }
            Fetched::Json(requires)
        }
        Fetched::NotFound => Fetched::NotFound,
        Fetched::Unavailable(e) => Fetched::Unavailable(e),
    }
}

/// `name[extras] (>=1.0, <2) ; markers` → (normalised name, specifier).
/// Requirements that only apply with an extra are skipped: they bind only
/// projects that ask for that extra.
pub fn pep508(req: &str) -> Option<(String, String)> {
    let (spec, marker) = match req.split_once(';') {
        Some((s, m)) => (s, Some(m)),
        None => (req, None),
    };
    if marker.is_some_and(|m| m.contains("extra")) {
        return None;
    }
    let spec = spec.trim();
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(spec.len());
    let name = &spec[..end];
    if name.is_empty() {
        return None;
    }
    let mut rest = spec[end..].trim();
    if rest.starts_with('[') {
        rest = rest.split_once(']').map_or("", |(_, r)| r).trim();
    }
    // A direct URL reference (`name @ https://…`) pins no version range.
    if rest.starts_with('@') {
        return None;
    }
    let rest = rest.trim_start_matches('(').trim_end_matches(')').trim();
    Some((normalize_python(name), rest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_index_paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("Serde_JSON"), "se/rd/serde_json");
    }

    #[test]
    fn pep508_requirements() {
        assert_eq!(
            pep508("urllib3 (<3,>=1.21.1)"),
            Some(("urllib3".into(), "<3,>=1.21.1".into()))
        );
        assert_eq!(
            pep508("Charset_Normalizer>=2; python_version >= '3.7'"),
            Some(("charset-normalizer".into(), ">=2".into()))
        );
        assert_eq!(
            pep508("requests[socks]>=2.0"),
            Some(("requests".into(), ">=2.0".into()))
        );
        assert_eq!(pep508("PySocks!=1.5.7,>=1.5.6; extra == \"socks\""), None);
        assert_eq!(pep508("idna"), Some(("idna".into(), String::new())));
        assert_eq!(pep508("pkg @ https://example.com/pkg.whl"), None);
    }

    #[test]
    fn npm_alias_specs() {
        assert_eq!(npm_spec("^1.2.0"), "^1.2.0");
        assert_eq!(npm_spec("npm:string-width@^4.2.0"), "^4.2.0");
        assert_eq!(npm_spec("npm:@scope/pkg@~2.0.0"), "~2.0.0");
    }
}
