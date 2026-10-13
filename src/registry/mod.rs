//! Per-release registry metadata: what greengate knows about one exact
//! version of a package and the version before it.
//!
//! A package that has been safe for years can still publish a compromised
//! release. The signals for that live on the release, not the package: how
//! recently it was published, whether it suddenly runs code at install time,
//! whether it lost the provenance its predecessor had, whether someone else
//! published it. This module fetches those facts from npm, PyPI and
//! crates.io; `deps check` turns them into policy.

pub mod requirements;

use crate::deps::Ecosystem;
use crate::utils::files;
use crate::utils::http::{self, Fetched};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const USER_AGENT: &str =
    "greengate-supply-chain-gate (https://github.com/greengate-dev/greengate)";
/// npm packuments for busy packages exceed 30 MB.
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;
/// Releases do not change once published, but yanks and deprecations do.
const CACHE_TTL_SECS: u64 = 6 * 3600;

/// Facts about one published release. `None` means the registry does not
/// expose that fact — not that it is absent.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Release {
    /// Publication time, unix seconds.
    pub published: Option<u64>,
    /// Whether installing this release runs package code: npm lifecycle
    /// scripts / node-gyp, or a PyPI release with no wheels (built from source).
    pub install_script: Option<bool>,
    /// Account that published it.
    pub publisher: Option<String>,
    /// Whether it carries publish provenance (npm attestations, PEP 740,
    /// crates.io trusted publishing).
    pub provenance: Option<bool>,
    /// Deprecation or yank message, if withdrawn.
    pub withdrawn: Option<String>,
    /// The license the registry records, as written there (usually SPDX).
    /// PyPI only records it per project, so this is the latest release's.
    #[serde(default)]
    pub license: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct History {
    pub this: Release,
    /// The highest earlier version and its facts, if there is one.
    pub previous: Option<(String, Release)>,
    /// Everyone who published an earlier version. Maintainer teams rotate
    /// who publishes; an account that never published this package before is
    /// the signal worth raising.
    #[serde(default)]
    pub earlier_publishers: Vec<String>,
}

/// Distinct publishers of the versions ordered before `version`.
fn earlier_publishers<'a>(
    eco: Ecosystem,
    version: &str,
    releases: impl Iterator<Item = (&'a str, Option<&'a str>)>,
) -> Vec<String> {
    let Some(target) = Key::parse(eco, version) else {
        return Vec::new();
    };
    let mut out: Vec<String> = releases
        .filter(|(v, _)| Key::parse(eco, v).is_some_and(|k| k < target))
        .filter_map(|(_, by)| by.map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one per package; not worth a Box
pub enum Lookup {
    Found(History),
    /// The registry does not have this version (or package).
    Missing,
    /// The registry could not be asked; the reason says why.
    Unavailable(String),
}

/// Look up `name@version`. `registry` overrides the default npm registry.
pub fn lookup(eco: Ecosystem, name: &str, version: &str, registry: Option<&str>) -> Lookup {
    if let Some(cached) = cache_read(eco, name, version) {
        return Lookup::Found(cached);
    }
    let result = match eco {
        Ecosystem::Npm => npm(name, version, registry),
        Ecosystem::PyPI => pypi(name, version),
        Ecosystem::Cargo => crates(name, version),
        Ecosystem::Go => Lookup::Unavailable("Go module release metadata is not checked".into()),
    };
    if let Lookup::Found(h) = &result {
        cache_write(eco, name, version, h);
    }
    result
}

fn base(var: &str, default: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Percent-encode a path segment (npm scopes become `@scope%2Fname`).
fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'@') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// ── Version ordering ──────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Semver(semver::Version),
    Pep440(pep440_rs::Version),
}

impl Key {
    fn parse(eco: Ecosystem, v: &str) -> Option<Key> {
        match eco {
            Ecosystem::PyPI => pep440_rs::Version::from_str(v).ok().map(Key::Pep440),
            _ => semver::Version::parse(v.strip_prefix('v').unwrap_or(v))
                .ok()
                .map(Key::Semver),
        }
    }

    fn is_pre(&self) -> bool {
        match self {
            Key::Semver(v) => !v.pre.is_empty(),
            Key::Pep440(v) => v.any_prerelease(),
        }
    }
}

/// The highest version below `version` among `versions`. Pre-releases are
/// only predecessors of pre-releases.
fn previous<'a>(
    eco: Ecosystem,
    version: &str,
    versions: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let target = Key::parse(eco, version)?;
    let allow_pre = target.is_pre();
    versions
        .filter_map(|v| Some((Key::parse(eco, v)?, v)))
        .filter(|(k, _)| *k < target && (allow_pre || !k.is_pre()))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, v)| v.to_string())
}

/// The highest of `versions` in the ecosystem's ordering (unparseable ones
/// sort lowest).
pub fn highest(eco: Ecosystem, versions: &[String]) -> Option<String> {
    versions
        .iter()
        .max_by(|a, b| Key::parse(eco, a).cmp(&Key::parse(eco, b)))
        .cloned()
}

// ── npm ───────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    time: HashMap<String, String>,
    #[serde(default)]
    versions: HashMap<String, NpmVersion>,
}

#[derive(Deserialize)]
struct NpmVersion {
    #[serde(default)]
    scripts: HashMap<String, serde_json::Value>,
    #[serde(default)]
    gypfile: Option<bool>,
    #[serde(rename = "_npmUser", default)]
    npm_user: Option<NpmUser>,
    #[serde(default)]
    dist: Option<NpmDist>,
    #[serde(default)]
    deprecated: Option<serde_json::Value>,
    /// `"MIT"`, or the old `{ "type": "MIT" }` form.
    #[serde(default)]
    license: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct NpmUser {
    name: Option<String>,
}

#[derive(Deserialize)]
struct NpmDist {
    attestations: Option<serde_json::Value>,
}

fn npm_release(p: &Packument, v: &str) -> Option<Release> {
    let m = p.versions.get(v)?;
    let scripted = ["preinstall", "install", "postinstall"]
        .iter()
        .any(|s| m.scripts.contains_key(*s));
    Some(Release {
        published: p.time.get(v).and_then(|t| iso_to_unix(t)),
        install_script: Some(scripted || m.gypfile == Some(true)),
        publisher: m.npm_user.as_ref().and_then(|u| u.name.clone()),
        provenance: Some(
            m.dist
                .as_ref()
                .and_then(|d| d.attestations.as_ref())
                .is_some_and(|a| a.get("provenance").is_some()),
        ),
        withdrawn: m
            .deprecated
            .as_ref()
            .and_then(|d| d.as_str())
            .filter(|d| !d.is_empty())
            .map(str::to_string),
        license: m.license.as_ref().and_then(|l| {
            l.as_str()
                .or_else(|| l.get("type").and_then(|t| t.as_str()))
                .map(str::to_string)
        }),
    })
}

fn npm(name: &str, version: &str, registry: Option<&str>) -> Lookup {
    let base = registry
        .map(|r| r.trim_end_matches('/').to_string())
        .unwrap_or_else(|| base("GREENGATE_NPM_REGISTRY", "https://registry.npmjs.org"));
    let url = format!("{base}/{}", segment(name).replace("%40", "@"));
    match http::get_json_capped::<Packument>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(p) => {
            let Some(this) = npm_release(&p, version) else {
                return Lookup::Missing;
            };
            let previous = previous(
                Ecosystem::Npm,
                version,
                p.versions.keys().map(String::as_str),
            )
            .and_then(|pv| npm_release(&p, &pv).map(|r| (pv, r)));
            let earlier_publishers = earlier_publishers(
                Ecosystem::Npm,
                version,
                p.versions.iter().map(|(v, m)| {
                    (
                        v.as_str(),
                        m.npm_user.as_ref().and_then(|u| u.name.as_deref()),
                    )
                }),
            );
            Lookup::Found(History {
                this,
                previous,
                earlier_publishers,
            })
        }
        Fetched::NotFound => Lookup::Missing,
        Fetched::Unavailable(e) => Lookup::Unavailable(e),
    }
}

// ── PyPI ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PypiProject {
    #[serde(default)]
    info: PypiInfo,
    #[serde(default)]
    releases: HashMap<String, Vec<PypiFile>>,
}

#[derive(Deserialize, Default)]
struct PypiInfo {
    license_expression: Option<String>,
    license: Option<String>,
    #[serde(default)]
    classifiers: Vec<String>,
}

impl PypiInfo {
    /// The SPDX expression if declared (PEP 639), else the `License ::`
    /// classifiers, else a short free-text `license` field.
    fn license(&self) -> Option<String> {
        if let Some(e) = self
            .license_expression
            .as_ref()
            .filter(|e| !e.trim().is_empty())
        {
            return Some(e.trim().to_string());
        }
        let classifiers: Vec<&str> = self
            .classifiers
            .iter()
            .filter_map(|c| c.strip_prefix("License :: "))
            .map(|c| c.rsplit(" :: ").next().unwrap_or(c))
            .collect();
        if !classifiers.is_empty() {
            return Some(classifiers.join(" OR "));
        }
        // Some projects paste the whole license text here.
        self.license
            .as_ref()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && l.len() <= 80 && !l.contains('\n'))
            .map(str::to_string)
    }
}

#[derive(Deserialize)]
struct PypiFile {
    filename: String,
    packagetype: String,
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    yanked: bool,
    yanked_reason: Option<String>,
}

fn pypi_release(name: &str, version: &str, files: &[PypiFile], pypi: &str) -> Option<Release> {
    if files.is_empty() {
        return None;
    }
    // PEP 740 provenance is per file; probe one, preferring a wheel.
    let probe = files
        .iter()
        .find(|f| f.packagetype == "bdist_wheel")
        .unwrap_or(&files[0]);
    let provenance = match http::status_of(
        &format!(
            "{pypi}/integrity/{}/{}/{}/provenance",
            segment(name),
            segment(version),
            segment(&probe.filename)
        ),
        USER_AGENT,
    ) {
        Some(200) => Some(true),
        Some(404) => Some(false),
        _ => None,
    };
    Some(Release {
        published: files
            .iter()
            .filter_map(|f| f.upload_time_iso_8601.as_deref().and_then(iso_to_unix))
            .min(),
        // No wheel means pip builds the sdist, running its build backend.
        install_script: Some(!files.iter().any(|f| f.packagetype == "bdist_wheel")),
        publisher: None,
        provenance,
        withdrawn: files.iter().all(|f| f.yanked).then(|| {
            files
                .iter()
                .find_map(|f| f.yanked_reason.clone().filter(|r| !r.is_empty()))
                .unwrap_or_else(|| "yanked".to_string())
        }),
        license: None,
    })
}

fn pypi(name: &str, version: &str) -> Lookup {
    let pypi = base("GREENGATE_PYPI_URL", "https://pypi.org");
    let url = format!("{pypi}/pypi/{}/json", segment(name));
    match http::get_json_capped::<PypiProject>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(p) => {
            // Release keys are as published; match PEP 440-equal spellings.
            let key = |v: &str| pep440_rs::Version::from_str(v).ok();
            let wanted = key(version);
            let Some((this_key, files)) = p
                .releases
                .iter()
                .find(|(k, _)| *k == version || (wanted.is_some() && key(k) == wanted))
            else {
                return Lookup::Missing;
            };
            let Some(mut this) = pypi_release(name, this_key, files, &pypi) else {
                return Lookup::Missing;
            };
            this.license = p.info.license();
            let with_files = p
                .releases
                .iter()
                .filter(|(_, f)| !f.is_empty())
                .map(|(k, _)| k.as_str());
            let previous = previous(Ecosystem::PyPI, this_key, with_files)
                .and_then(|pv| pypi_release(name, &pv, &p.releases[&pv], &pypi).map(|r| (pv, r)));
            // PyPI does not say who uploaded a release.
            Lookup::Found(History {
                this,
                previous,
                earlier_publishers: Vec::new(),
            })
        }
        Fetched::NotFound => Lookup::Missing,
        Fetched::Unavailable(e) => Lookup::Unavailable(e),
    }
}

// ── crates.io ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CrateDoc {
    #[serde(default)]
    versions: Vec<CrateVersion>,
}

#[derive(Deserialize)]
struct CrateVersion {
    num: String,
    created_at: Option<String>,
    #[serde(default)]
    yanked: bool,
    yank_message: Option<String>,
    published_by: Option<CrateUser>,
    trustpub_data: Option<serde_json::Value>,
    license: Option<String>,
}

#[derive(Deserialize)]
struct CrateUser {
    login: Option<String>,
}

fn crate_release(v: &CrateVersion) -> Release {
    Release {
        published: v.created_at.as_deref().and_then(iso_to_unix),
        // Build scripts and proc-macros are only visible in the source; the
        // install preflight checks them after fetching.
        install_script: None,
        publisher: v.published_by.as_ref().and_then(|u| u.login.clone()),
        provenance: Some(v.trustpub_data.as_ref().is_some_and(|t| !t.is_null())),
        withdrawn: v.yanked.then(|| {
            v.yank_message
                .clone()
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "yanked".into())
        }),
        license: v.license.clone(),
    }
}

fn crates(name: &str, version: &str) -> Lookup {
    let url = format!(
        "{}/api/v1/crates/{}",
        base("GREENGATE_CRATES_URL", "https://crates.io"),
        segment(name)
    );
    match http::get_json_capped::<CrateDoc>(&url, MAX_DOCUMENT_BYTES, USER_AGENT) {
        Fetched::Json(doc) => {
            let Some(this) = doc.versions.iter().find(|v| v.num == version) else {
                return Lookup::Missing;
            };
            let previous = previous(
                Ecosystem::Cargo,
                version,
                doc.versions.iter().map(|v| v.num.as_str()),
            )
            .and_then(|pv| {
                doc.versions
                    .iter()
                    .find(|v| v.num == pv)
                    .map(|v| (pv, crate_release(v)))
            });
            let earlier_publishers = earlier_publishers(
                Ecosystem::Cargo,
                version,
                doc.versions.iter().map(|v| {
                    (
                        v.num.as_str(),
                        v.published_by.as_ref().and_then(|u| u.login.as_deref()),
                    )
                }),
            );
            Lookup::Found(History {
                this: crate_release(this),
                previous,
                earlier_publishers,
            })
        }
        Fetched::NotFound => Lookup::Missing,
        Fetched::Unavailable(e) => Lookup::Unavailable(e),
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Bumped whenever `History` changes shape, so older entries are refetched
/// instead of read with fields silently defaulted.
const CACHE_FORMAT: u32 = 2;

#[derive(Serialize, Deserialize)]
struct Cached {
    #[serde(default)]
    format: u32,
    fetched_at: u64,
    history: History,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn cache_path(eco: Ecosystem, name: &str, version: &str) -> Option<std::path::PathBuf> {
    Some(
        files::cache_root()?
            .join("registry")
            .join(eco.osv())
            .join(format!("{}@{}.json", segment(name), segment(version))),
    )
}

fn cache_read(eco: Ecosystem, name: &str, version: &str) -> Option<History> {
    let c: Cached =
        serde_json::from_slice(&std::fs::read(cache_path(eco, name, version)?).ok()?).ok()?;
    (c.format == CACHE_FORMAT && now_secs().saturating_sub(c.fetched_at) < CACHE_TTL_SECS)
        .then_some(c.history)
}

fn cache_write(eco: Ecosystem, name: &str, version: &str, history: &History) {
    let Some(path) = cache_path(eco, name, version) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let c = Cached {
        format: CACHE_FORMAT,
        fetched_at: now_secs(),
        history: history.clone(),
    };
    if let Ok(bytes) = serde_json::to_vec(&c) {
        let _ = std::fs::write(path, bytes);
    }
}

// ── Time ──────────────────────────────────────────────────────────────────────

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` → unix seconds.
pub fn iso_to_unix(s: &str) -> Option<u64> {
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Days from civil (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let mut t = days * 86_400 + h * 3600 + mi * 60 + sec;
    // A numeric offset (`+02:00`) after the seconds and any fraction.
    let rest = s.get(19..).unwrap_or("");
    let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if let Some(sign @ ('+' | '-')) = rest.chars().next() {
        let oh = rest.get(1..3)?.parse::<i64>().ok()?;
        let om = rest
            .get(4..6)
            .and_then(|m| m.parse::<i64>().ok())
            .unwrap_or(0);
        let off = oh * 3600 + om * 60;
        t -= if sign == '+' { off } else { -off };
    }
    u64::try_from(t).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_times() {
        assert_eq!(iso_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_to_unix("2024-01-01T00:00:00.123Z"), Some(1_704_067_200));
        assert_eq!(
            iso_to_unix("2024-01-01T02:00:00+02:00"),
            Some(1_704_067_200)
        );
        assert_eq!(
            iso_to_unix("2024-01-01T00:00:00.000000+00:00"),
            Some(1_704_067_200)
        );
        assert_eq!(iso_to_unix("garbage"), None);
    }

    #[test]
    fn previous_version_ordering() {
        let v = ["1.0.0", "1.2.0", "1.10.0", "2.0.0-rc.1", "2.0.0"];
        assert_eq!(
            previous(Ecosystem::Npm, "2.0.0", v.into_iter()),
            Some("1.10.0".into())
        );
        assert_eq!(
            previous(Ecosystem::Npm, "2.0.0-rc.2", v.into_iter()),
            Some("2.0.0-rc.1".into())
        );
        assert_eq!(previous(Ecosystem::Npm, "1.0.0", v.into_iter()), None);
        let p = ["2.31.0", "2.32.0", "2.32.0rc1", "2.4"];
        assert_eq!(
            previous(Ecosystem::PyPI, "2.32.0", p.into_iter()),
            Some("2.31.0".into())
        );
    }

    #[test]
    fn npm_install_script_and_provenance_detection() {
        let p: Packument = serde_json::from_value(serde_json::json!({
            "time": {"1.0.0": "2024-01-01T00:00:00.000Z", "1.0.1": "2024-02-01T00:00:00.000Z"},
            "versions": {
                "1.0.0": {"_npmUser": {"name": "alice"},
                          "dist": {"attestations": {"provenance": {"predicateType": "x"}}}},
                "1.0.1": {"_npmUser": {"name": "mallory"}, "scripts": {"postinstall": "node x.js"},
                          "deprecated": "use 2.x", "dist": {}}
            }
        }))
        .unwrap();
        let old = npm_release(&p, "1.0.0").unwrap();
        let new = npm_release(&p, "1.0.1").unwrap();
        assert_eq!(
            (old.install_script, new.install_script),
            (Some(false), Some(true))
        );
        assert_eq!((old.provenance, new.provenance), (Some(true), Some(false)));
        assert_eq!(new.publisher.as_deref(), Some("mallory"));
        assert_eq!(new.withdrawn.as_deref(), Some("use 2.x"));
        assert_eq!(new.published, Some(1_706_745_600));
    }
}
