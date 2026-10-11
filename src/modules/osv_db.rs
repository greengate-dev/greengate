//! Offline OSV vulnerability data.
//!
//! `greengate db update` downloads OSV's per-ecosystem `all.zip` snapshot and
//! turns it into a small on-disk index: one shard file per hash bucket of
//! package names, so an audit reads only the shards for the packages it asks
//! about instead of hundreds of thousands of advisories.
//!
//! Matching follows the OSV schema's evaluation rules: an explicit `versions`
//! list, then `SEMVER` / `ECOSYSTEM` ranges evaluated event by event. A version
//! or range greengate cannot order is reported as *unknown* — never as "not
//! affected" — so the caller can mark the check incomplete.

use crate::utils::{files, http, terminal};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Ecosystems with an offline snapshot, by their OSV names.
pub const ECOSYSTEMS: &[&str] = &["npm", "crates.io", "PyPI", "Go"];

/// Bumped when the on-disk layout changes; older indexes are rebuilt.
const INDEX_VERSION: u32 = 1;
const SHARDS: u64 = 256;
/// npm's archive is ~220 MB and growing; leave generous headroom.
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn snapshot_base() -> String {
    std::env::var("GREENGATE_OSV_DB_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .map_or_else(
            || "https://osv-vulnerabilities.storage.googleapis.com".to_string(),
            |u| u.trim_end_matches('/').to_string(),
        )
}

fn db_root() -> Result<PathBuf> {
    files::cache_root()
        .map(|c| c.join("osv-db"))
        .context("no cache directory: set HOME or GREENGATE_CACHE_DIR")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── Index format ──────────────────────────────────────────────────────────────

/// `meta.json` beside the shards.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub index_version: u32,
    pub ecosystem: String,
    pub source: String,
    pub etag: Option<String>,
    /// When the snapshot was last confirmed current with the server (unix s).
    pub checked_at: u64,
    pub advisories: usize,
    pub packages: usize,
}

impl Meta {
    pub fn age(&self) -> Duration {
        Duration::from_secs(now_secs().saturating_sub(self.checked_at))
    }
}

/// One `affected` block of one advisory, for one package.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Entry {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Range {
    #[serde(rename = "type")]
    pub kind: String,
    pub events: Vec<Event>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

impl Entry {
    /// The first `fixed` version in any range, for remediation text.
    pub fn fixed_in(&self) -> Option<&str> {
        self.ranges
            .iter()
            .flat_map(|r| &r.events)
            .find_map(|e| match e {
                Event::Fixed(v) => Some(v.as_str()),
                _ => None,
            })
    }
}

/// Lookup key for a package name. PyPI names are case- and
/// separator-insensitive (PEP 503); the others are taken as written.
fn normalize(eco: &str, name: &str) -> String {
    if eco == "PyPI" {
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
    } else {
        name.to_string()
    }
}

/// Stable bucket for a package key (FNV-1a), independent of the Rust version.
fn shard_of(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h % SHARDS
}

fn shard_file(dir: &Path, shard: u64) -> PathBuf {
    dir.join("shards").join(format!("{shard:02x}.json"))
}

// ── Building the index ────────────────────────────────────────────────────────

/// Index every advisory in an OSV `all.zip` for `eco`, keyed by normalized
/// package name. Withdrawn advisories and `affected` blocks for other
/// ecosystems (archives cross-list them) are skipped.
fn build_index<R: Read + std::io::Seek>(
    eco: &str,
    archive: R,
) -> Result<(BTreeMap<String, Vec<Entry>>, usize)> {
    let mut zip = zip::ZipArchive::new(archive).context("not a valid OSV zip archive")?;
    let mut index: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    let mut advisories = 0usize;
    let mut buf = String::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        if !file.name().ends_with(".json") {
            continue;
        }
        buf.clear();
        file.read_to_string(&mut buf)
            .with_context(|| format!("could not read {} from the archive", file.name()))?;
        let doc: Value = serde_json::from_str(&buf)
            .with_context(|| format!("{} is not valid JSON", file.name()))?;
        if doc.get("withdrawn").is_some_and(|w| !w.is_null()) {
            continue;
        }
        let mut counted = false;
        for affected in doc["affected"].as_array().into_iter().flatten() {
            if affected["package"]["ecosystem"].as_str() != Some(eco) {
                continue;
            }
            let Some(name) = affected["package"]["name"].as_str() else {
                continue;
            };
            index
                .entry(normalize(eco, name))
                .or_default()
                .push(entry_from(&doc, affected));
            counted = true;
        }
        advisories += usize::from(counted);
    }
    Ok((index, advisories))
}

fn entry_from(doc: &Value, affected: &Value) -> Entry {
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect()
    };
    let ranges = affected["ranges"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| Range {
            kind: r["type"].as_str().unwrap_or("").to_string(),
            events: r["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| {
                    let get = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_string);
                    get("introduced")
                        .map(Event::Introduced)
                        .or_else(|| get("fixed").map(Event::Fixed))
                        .or_else(|| get("last_affected").map(Event::LastAffected))
                        .or_else(|| get("limit").map(Event::Limit))
                })
                .collect(),
        })
        .collect();
    // Same preferences as the online path: GHSA severity label, advisory link.
    let refs = doc["references"].as_array();
    let reference = refs
        .and_then(|refs| {
            refs.iter()
                .find(|r| r["type"].as_str() == Some("ADVISORY"))
                .or_else(|| refs.first())
        })
        .and_then(|r| r["url"].as_str())
        .map(str::to_string);
    Entry {
        id: doc["id"].as_str().unwrap_or("UNKNOWN").to_string(),
        summary: doc["summary"].as_str().unwrap_or("").to_string(),
        severity: doc["database_specific"]["severity"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        reference,
        versions: strings(&affected["versions"]),
        ranges,
    }
}

fn write_index(dir: &Path, index: &BTreeMap<String, Vec<Entry>>, meta: &Meta) -> Result<()> {
    std::fs::create_dir_all(dir.join("shards"))?;
    let mut shards: Vec<BTreeMap<&str, &Vec<Entry>>> = vec![BTreeMap::new(); SHARDS as usize];
    for (name, entries) in index {
        if let Some(shard) = shards.get_mut(shard_of(name) as usize) {
            shard.insert(name, entries);
        }
    }
    for (i, shard) in shards.iter().enumerate() {
        std::fs::write(shard_file(dir, i as u64), serde_json::to_vec(shard)?)?;
    }
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(meta)?)?;
    Ok(())
}

// ── Update / status ───────────────────────────────────────────────────────────

pub fn load_meta(eco: &str) -> Option<Meta> {
    let dir = db_root().ok()?.join(eco);
    let meta: Meta = serde_json::from_slice(&std::fs::read(dir.join("meta.json")).ok()?).ok()?;
    (meta.index_version == INDEX_VERSION).then_some(meta)
}

/// Download (if changed) and index the snapshot for `eco`.
pub fn update(eco: &str) -> Result<Meta> {
    anyhow::ensure!(
        ECOSYSTEMS.contains(&eco),
        "unsupported ecosystem '{eco}' (supported: {})",
        ECOSYSTEMS.join(", ")
    );
    let root = db_root()?;
    std::fs::create_dir_all(&root)?;
    let dir = root.join(eco);
    let url = format!("{}/{}/all.zip", snapshot_base(), eco);
    let previous = load_meta(eco);

    let archive = root.join(format!(".{eco}.download"));
    let etag = previous.as_ref().and_then(|m| m.etag.as_deref());
    match http::download(&url, &archive, MAX_ARCHIVE_BYTES, etag)? {
        http::Download::NotModified => {
            let mut meta = previous.context("server answered 304 without a local snapshot")?;
            meta.checked_at = now_secs();
            std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
            Ok(meta)
        }
        http::Download::Fetched { etag } => {
            let built = std::fs::File::open(&archive)
                .map_err(anyhow::Error::from)
                .and_then(|f| build_index(eco, std::io::BufReader::new(f)));
            let _ = std::fs::remove_file(&archive);
            let (index, advisories) = built?;
            let meta = Meta {
                index_version: INDEX_VERSION,
                ecosystem: eco.to_string(),
                source: url,
                etag,
                checked_at: now_secs(),
                advisories,
                packages: index.len(),
            };
            // Build beside the live index, then swap, so a failed or
            // interrupted update never leaves a half-written one in use.
            let staging = root.join(format!(".{eco}.staging"));
            let _ = std::fs::remove_dir_all(&staging);
            write_index(&staging, &index, &meta)?;
            let retired = root.join(format!(".{eco}.old"));
            let _ = std::fs::remove_dir_all(&retired);
            if dir.exists() {
                std::fs::rename(&dir, &retired)?;
            }
            std::fs::rename(&staging, &dir)?;
            let _ = std::fs::remove_dir_all(&retired);
            Ok(meta)
        }
    }
}

pub fn run_update(ecosystems: &[String]) -> Result<()> {
    for eco in ecosystems {
        terminal::info(&format!("Updating offline OSV data for {eco}..."));
        let meta = update(eco).with_context(|| format!("updating {eco} failed"))?;
        terminal::success(&format!(
            "{eco}: {} advisories for {} packages (source {})",
            meta.advisories, meta.packages, meta.source
        ));
    }
    Ok(())
}

pub fn run_status(json: bool) -> Result<()> {
    let rows: Vec<(&str, Option<Meta>)> = ECOSYSTEMS.iter().map(|e| (*e, load_meta(e))).collect();
    if json {
        let out: Vec<Value> = rows
            .iter()
            .map(|(eco, meta)| match meta {
                Some(m) => serde_json::json!({
                    "ecosystem": eco,
                    "checked_at": m.checked_at,
                    "age_hours": m.age().as_secs() / 3600,
                    "advisories": m.advisories,
                    "packages": m.packages,
                }),
                None => serde_json::json!({ "ecosystem": eco, "checked_at": null }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    eprintln!("Offline OSV data ({})", db_root()?.display());
    for (eco, meta) in rows {
        match meta {
            Some(m) => eprintln!(
                "  {eco:<10} {:>4} h old · {} advisories · {} packages",
                m.age().as_secs() / 3600,
                m.advisories,
                m.packages
            ),
            None => eprintln!("  {eco:<10} not downloaded — run `greengate db update`"),
        }
    }
    Ok(())
}

// ── Lookup ────────────────────────────────────────────────────────────────────

/// An open, fresh-enough snapshot for one ecosystem.
pub struct Snapshot {
    eco: String,
    dir: PathBuf,
    pub meta: Meta,
    shards: HashMap<u64, HashMap<String, Vec<Entry>>>,
}

/// Why a snapshot cannot be used.
pub enum Unavailable {
    Missing,
    Stale(Duration),
}

impl Snapshot {
    pub fn open(eco: &str, max_age: Duration) -> Result<Snapshot, Unavailable> {
        let meta = load_meta(eco).ok_or(Unavailable::Missing)?;
        if meta.age() > max_age {
            return Err(Unavailable::Stale(meta.age()));
        }
        let dir = db_root().map_err(|_| Unavailable::Missing)?.join(eco);
        Ok(Snapshot {
            eco: eco.to_string(),
            dir,
            meta,
            shards: HashMap::new(),
        })
    }

    /// Advisories affecting `name@version`. `Err` carries why the answer is
    /// unknown (an unreadable shard, a version greengate cannot order).
    pub fn lookup(&mut self, name: &str, version: &str) -> Result<Vec<Entry>, String> {
        let key = normalize(&self.eco, name);
        let shard = shard_of(&key);
        if !self.shards.contains_key(&shard) {
            let bytes = std::fs::read(shard_file(&self.dir, shard))
                .map_err(|e| format!("offline index shard unreadable: {e}"))?;
            let parsed = serde_json::from_slice(&bytes)
                .map_err(|e| format!("offline index shard corrupt: {e}"))?;
            self.shards.insert(shard, parsed);
        }
        let entries = self
            .shards
            .get(&shard)
            .and_then(|s| s.get(&key))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut hits = Vec::new();
        for entry in entries {
            match affects(&self.eco, entry, version) {
                Some(true) => hits.push(entry.clone()),
                Some(false) => {}
                None => {
                    return Err(format!(
                        "cannot evaluate {} for {name}@{version}: unrecognised version format",
                        entry.id
                    ));
                }
            }
        }
        Ok(hits)
    }
}

// ── Version matching ──────────────────────────────────────────────────────────

/// A version in one ecosystem's ordering.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Ver {
    Semver(semver::Version),
    Pep440(pep440_rs::Version),
}

fn parse_version(eco: &str, kind: &str, v: &str) -> Option<Ver> {
    if eco == "PyPI" && kind != "SEMVER" {
        return pep440_rs::Version::from_str(v).ok().map(Ver::Pep440);
    }
    // npm, crates.io and Go order by SemVer; Go writes a `v` prefix.
    let v = v.strip_prefix('v').unwrap_or(v);
    semver::Version::parse(v).ok().map(Ver::Semver)
}

/// Does `entry` affect `version`? `None` when it cannot be decided.
fn affects(eco: &str, entry: &Entry, version: &str) -> Option<bool> {
    let bare = |v: &str| v.strip_prefix('v').unwrap_or(v).to_string();
    if entry.versions.iter().any(|v| bare(v) == bare(version)) {
        return Some(true);
    }
    let mut undecided = false;
    for range in &entry.ranges {
        // Git ranges are commit hashes; OSV pairs them with an explicit
        // `versions` list, checked above.
        if range.kind == "GIT" {
            continue;
        }
        match in_range(eco, range, version) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => undecided = true,
        }
    }
    if undecided { None } else { Some(false) }
}

/// OSV schema evaluation: walk the events in version order; `introduced`
/// opens an affected span, `fixed` closes it at that version, `last_affected`
/// closes it after that version.
fn in_range(eco: &str, range: &Range, version: &str) -> Option<bool> {
    let target = parse_version(eco, &range.kind, version)?;
    let mut events: Vec<(Option<Ver>, &Event)> = Vec::with_capacity(range.events.len());
    for event in &range.events {
        let raw = match event {
            Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) => v,
            // `limit` only bounds git ranges.
            Event::Limit(_) => continue,
        };
        let parsed = if matches!(event, Event::Introduced(v) if v == "0") {
            None // "0" — before every version
        } else {
            Some(parse_version(eco, &range.kind, raw)?)
        };
        events.push((parsed, event));
    }
    events.sort_by(|a, b| match (&a.0, &b.0) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    });
    let mut affected = false;
    for (at, event) in &events {
        match (event, at) {
            (Event::Introduced(_), None) => affected = true,
            (Event::Introduced(_), Some(v)) if target >= *v => affected = true,
            (Event::Fixed(_), Some(v)) if target >= *v => affected = false,
            (Event::LastAffected(_), Some(v)) if target > *v => affected = false,
            _ => {}
        }
    }
    Some(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(kind: &str, events: &[(&str, &str)]) -> Range {
        Range {
            kind: kind.into(),
            events: events
                .iter()
                .map(|(k, v)| match *k {
                    "introduced" => Event::Introduced(v.to_string()),
                    "fixed" => Event::Fixed(v.to_string()),
                    "last_affected" => Event::LastAffected(v.to_string()),
                    _ => Event::Limit(v.to_string()),
                })
                .collect(),
        }
    }

    fn entry(ranges: Vec<Range>, versions: &[&str]) -> Entry {
        Entry {
            id: "T-1".into(),
            summary: String::new(),
            severity: None,
            reference: None,
            versions: versions.iter().map(|v| v.to_string()).collect(),
            ranges,
        }
    }

    #[test]
    fn introduced_fixed_span() {
        let e = entry(
            vec![range(
                "SEMVER",
                &[("introduced", "0"), ("fixed", "4.17.21")],
            )],
            &[],
        );
        assert_eq!(affects("npm", &e, "4.17.20"), Some(true));
        assert_eq!(affects("npm", &e, "4.17.21"), Some(false));
        assert_eq!(affects("npm", &e, "5.0.0"), Some(false));
    }

    #[test]
    fn multiple_spans_and_last_affected() {
        let e = entry(
            vec![range(
                "SEMVER",
                &[
                    ("introduced", "1.0.0"),
                    ("fixed", "1.2.0"),
                    ("introduced", "2.0.0"),
                    ("last_affected", "2.3.0"),
                ],
            )],
            &[],
        );
        assert_eq!(affects("crates.io", &e, "0.9.0"), Some(false));
        assert_eq!(affects("crates.io", &e, "1.1.5"), Some(true));
        assert_eq!(affects("crates.io", &e, "1.5.0"), Some(false));
        assert_eq!(affects("crates.io", &e, "2.3.0"), Some(true));
        assert_eq!(affects("crates.io", &e, "2.3.1"), Some(false));
    }

    #[test]
    fn events_are_evaluated_in_version_order_not_listing_order() {
        let e = entry(
            vec![range(
                "SEMVER",
                &[("fixed", "2.0.0"), ("introduced", "1.0.0")],
            )],
            &[],
        );
        assert_eq!(affects("npm", &e, "1.5.0"), Some(true));
        assert_eq!(affects("npm", &e, "2.0.0"), Some(false));
    }

    #[test]
    fn prereleases_order_before_the_release() {
        let e = entry(
            vec![range("SEMVER", &[("introduced", "0"), ("fixed", "2.0.0")])],
            &[],
        );
        assert_eq!(affects("npm", &e, "2.0.0-rc.1"), Some(true));
    }

    #[test]
    fn go_versions_match_with_or_without_v_prefix() {
        let e = entry(
            vec![range("SEMVER", &[("introduced", "0"), ("fixed", "1.9.2")])],
            &[],
        );
        assert_eq!(affects("Go", &e, "v1.9.1"), Some(true));
        assert_eq!(affects("Go", &e, "v1.9.2"), Some(false));
    }

    #[test]
    fn pypi_uses_pep440_ordering() {
        // Under SemVer "1.0.post1" does not parse; under PEP 440 it sorts after 1.0.
        let e = entry(
            vec![range(
                "ECOSYSTEM",
                &[("introduced", "0"), ("fixed", "1.0.post1")],
            )],
            &[],
        );
        assert_eq!(affects("PyPI", &e, "1.0"), Some(true));
        assert_eq!(affects("PyPI", &e, "1.0.post1"), Some(false));
        assert_eq!(affects("PyPI", &e, "1.0rc1"), Some(true));
    }

    #[test]
    fn explicit_versions_list_wins_and_git_ranges_are_skipped() {
        let e = entry(
            vec![range(
                "GIT",
                &[("introduced", "abc123"), ("fixed", "def456")],
            )],
            &["2.1.0"],
        );
        assert_eq!(affects("npm", &e, "2.1.0"), Some(true));
        assert_eq!(affects("npm", &e, "2.2.0"), Some(false));
    }

    #[test]
    fn unparseable_versions_are_unknown_not_safe() {
        let e = entry(
            vec![range("SEMVER", &[("introduced", "0"), ("fixed", "1.0.0")])],
            &[],
        );
        assert_eq!(affects("npm", &e, "not-a-version"), None);
    }

    #[test]
    fn pypi_names_are_normalized() {
        assert_eq!(
            normalize("PyPI", "Django_REST.framework"),
            "django-rest-framework"
        );
        assert_eq!(normalize("npm", "Foo_Bar"), "Foo_Bar");
    }

    fn osv_zip(docs: &[Value]) -> std::io::Cursor<Vec<u8>> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (i, d) in docs.iter().enumerate() {
            w.start_file(format!("A-{i}.json"), opts).unwrap();
            std::io::Write::write_all(&mut w, d.to_string().as_bytes()).unwrap();
        }
        let mut c = w.finish().unwrap();
        c.set_position(0);
        c
    }

    #[test]
    fn build_index_filters_ecosystem_and_withdrawn() {
        let docs = [
            serde_json::json!({
                "id": "GHSA-1", "summary": "proto pollution",
                "database_specific": {"severity": "HIGH"},
                "references": [{"type": "WEB", "url": "w"}, {"type": "ADVISORY", "url": "a"}],
                "affected": [
                    {"package": {"ecosystem": "npm", "name": "lodash"},
                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
                    {"package": {"ecosystem": "NuGet", "name": "lodash"}}
                ]
            }),
            serde_json::json!({
                "id": "GHSA-2", "withdrawn": "2024-01-01T00:00:00Z",
                "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]
            }),
        ];
        let (index, advisories) = build_index("npm", osv_zip(&docs)).unwrap();
        assert_eq!(advisories, 1);
        let entries = &index["lodash"];
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity.as_deref(), Some("HIGH"));
        assert_eq!(entries[0].reference.as_deref(), Some("a"));
        assert_eq!(entries[0].fixed_in(), Some("4.17.21"));
    }
}
