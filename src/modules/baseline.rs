//! Baselines: known findings that should not fail CI, so a gate only fails on
//! what a change introduces.
//!
//! Each finding gets a fingerprint that survives the code around it moving:
//!
//! ```text
//! gg1:HMAC-SHA256(salt, rule ‖ path ‖ H(match) ‖ H(context))
//! ```
//!
//! `match` is the text the rule matched (the secret itself, for a secret
//! rule) and `context` the two non-blank lines either side, whitespace
//! collapsed and the match blanked out. Secrets are never written to the
//! baseline in plain text; but the salt sits in the same file, so anyone with
//! the baseline can confirm a *guessed* secret. The HMAC stops precomputed
//! lookups, not a guess at a weak secret.
//!
//! A finding is known when, in order:
//! 1. its fingerprint is in the baseline (exact);
//! 2. an entry has the same rule, path and match — the nearest line wins
//!    (the code around it changed);
//! 3. exactly one entry, anywhere, has the same rule and match, and exactly
//!    one finding is left to claim it (the file was moved or renamed).
//!
//! Every entry is claimed at most once, so a second copy of a known secret is
//! still a new finding.

use crate::report::{Finding, Location};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const BASELINE_FILE: &str = ".greengate-baseline.json";
const VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The gate that recorded it: `scan`, `audit` or `ci-lint`.
    pub tool: String,
    pub fingerprint: String,
    /// Keyed hash of the matched text, for matching moved findings; empty
    /// when the finding has no matched text.
    #[serde(rename = "match")]
    pub match_hash: String,
    pub rule_id: String,
    pub path: String,
    pub line_hint: usize,
    /// Which of several identical matches in one file, top to bottom.
    pub occurrence: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub version: u32,
    /// Hex. Keys every fingerprint in this file; see the module docs.
    pub salt: String,
    pub generator: String,
    pub entries: Vec<Entry>,
}

impl Baseline {
    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        from_hex(&self.salt).context("the baseline's salt is not hex")
    }
}

/// A 0.3 baseline entry: exact path, rule and line.
#[derive(Deserialize, PartialEq, Eq, Hash)]
pub struct LegacyEntry {
    pub path: String,
    pub rule_id: String,
    pub line: usize,
}

pub enum Loaded {
    Missing,
    /// Written by greengate 0.3; `greengate baseline migrate` upgrades it.
    V1(HashSet<LegacyEntry>),
    V2(Baseline),
}

pub fn load(path: &Path) -> Result<Loaded> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Missing),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
    };
    if text.trim_start().starts_with('[') {
        let entries: Vec<LegacyEntry> = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid baseline", path.display()))?;
        return Ok(Loaded::V1(
            entries
                .into_iter()
                .map(|e| LegacyEntry {
                    path: normalize_path(&e.path),
                    ..e
                })
                .collect(),
        ));
    }
    let baseline: Baseline = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid baseline", path.display()))?;
    if baseline.version != VERSION {
        bail!(
            "{} is baseline version {}; this greengate reads versions 1 and {VERSION}",
            path.display(),
            baseline.version
        );
    }
    Ok(Loaded::V2(baseline))
}

/// Replace `tool`'s entries in the baseline at `path` with `keyed`, keeping
/// other gates' entries and the existing salt.
pub fn save(path: &Path, tool: &str, salt: &[u8], keyed: &[Keyed]) -> Result<usize> {
    let mut entries: Vec<Entry> = match load(path)? {
        Loaded::V2(b) if b.salt_bytes()? == salt => {
            b.entries.into_iter().filter(|e| e.tool != tool).collect()
        }
        _ => Vec::new(),
    };
    entries.extend(keyed.iter().map(|k| Entry {
        tool: tool.to_string(),
        fingerprint: k.fingerprint.clone(),
        match_hash: k.match_hash.clone(),
        rule_id: k.rule.clone(),
        path: k.path.clone(),
        line_hint: k.line,
        occurrence: k.occurrence,
    }));
    entries.sort_by(|a, b| {
        (&a.tool, &a.path, a.line_hint, &a.rule_id).cmp(&(
            &b.tool,
            &b.path,
            b.line_hint,
            &b.rule_id,
        ))
    });
    let baseline = Baseline {
        version: VERSION,
        salt: to_hex(salt),
        generator: format!("greengate {}", env!("CARGO_PKG_VERSION")),
        entries,
    };
    std::fs::write(path, serde_json::to_string_pretty(&baseline)? + "\n")
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(keyed.len())
}

/// A fresh random salt for a new baseline.
pub fn new_salt() -> Result<Vec<u8>> {
    let mut salt = vec![0u8; 32];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow::anyhow!("no randomness for a salt: {e}"))?;
    Ok(salt)
}

// ── Subjects: what a fingerprint is computed from ─────────────────────────────

/// The text a rule matched on a line, if the gate can say (secret rules can).
pub type Matcher<'a> = &'a dyn Fn(&str, &str) -> Option<String>;

/// File contents by path, read once each: from disk, or from a git revision.
type Reader<'a> = Box<dyn Fn(&Path) -> Option<String> + 'a>;

pub struct Sources<'a> {
    read: Reader<'a>,
    cache: HashMap<PathBuf, Option<Vec<String>>>,
}

impl<'a> Sources<'a> {
    pub fn new(read: impl Fn(&Path) -> Option<String> + 'a) -> Sources<'a> {
        Sources {
            read: Box::new(read),
            cache: HashMap::new(),
        }
    }

    fn lines(&mut self, path: &Path) -> Option<&[String]> {
        let read = &self.read;
        self.cache
            .entry(path.to_path_buf())
            .or_insert_with(|| read(path).map(|t| t.lines().map(str::to_string).collect()))
            .as_deref()
    }
}

pub struct Subject {
    pub rule: String,
    pub path: String,
    pub line: usize,
    pub matched: String,
    pub context: String,
}

/// The rule as fingerprinted: complexity rules carry their measurement in
/// the id (`SMELL/LongFunction (80 lines, max 50)`), which must not count.
pub fn rule_key(rule: &str) -> &str {
    if rule.starts_with("SMELL/") {
        rule.split(" (").next().unwrap_or(rule)
    } else {
        rule
    }
}

pub fn normalize_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    p
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Up to two non-blank lines either side of `idx`, and the line itself, with
/// `matched` blanked out and whitespace collapsed.
fn context_of(lines: &[String], idx: usize, matched: &str) -> String {
    let redact = |l: &str| {
        let l = if matched.is_empty() {
            l.to_string()
        } else {
            l.replace(matched, "\u{2588}")
        };
        collapse(&l)
    };
    let mut before: Vec<String> = lines[..idx]
        .iter()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(2)
        .map(|l| redact(l))
        .collect();
    before.reverse();
    let after = lines[idx + 1..]
        .iter()
        .filter(|l| !l.trim().is_empty())
        .take(2)
        .map(|l| redact(l));
    before
        .into_iter()
        .chain([redact(&lines[idx])])
        .chain(after)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn subject(f: &Finding, sources: &mut Sources<'_>, matcher: Option<Matcher<'_>>) -> Subject {
    let rule = rule_key(&f.rule).to_string();
    match &f.location {
        Location::File {
            path,
            line: Some(line),
        } => {
            let p = normalize_path(&path.to_string_lossy());
            let lines = sources.lines(path).filter(|l| *line <= l.len());
            let Some(lines) = lines else {
                return Subject {
                    rule,
                    path: p,
                    line: *line,
                    matched: String::new(),
                    context: String::new(),
                };
            };
            let text = &lines[line - 1];
            let matched = matcher
                .and_then(|m| m(&f.rule, text))
                .unwrap_or_else(|| collapse(text));
            Subject {
                context: context_of(lines, line - 1, &matched),
                rule,
                path: p,
                line: *line,
                matched,
            }
        }
        Location::File { path, line: None } => Subject {
            rule,
            path: normalize_path(&path.to_string_lossy()),
            line: 0,
            matched: String::new(),
            context: String::new(),
        },
        Location::Package {
            ecosystem,
            name,
            source,
            ..
        } => Subject {
            rule,
            path: source
                .as_ref()
                .map(|s| normalize_path(&s.to_string_lossy()))
                .unwrap_or_default(),
            line: 0,
            // Not the version: an upgrade that is still affected is the same
            // known problem.
            matched: format!("{ecosystem}:{name}"),
            context: String::new(),
        },
        Location::Url { url } => Subject {
            rule,
            path: url.clone(),
            line: 0,
            matched: String::new(),
            context: String::new(),
        },
        Location::Project => Subject {
            rule,
            path: String::new(),
            line: 0,
            matched: String::new(),
            context: String::new(),
        },
    }
}

// ── Keys ──────────────────────────────────────────────────────────────────────

/// A subject's keyed hashes, as stored in (or compared with) a baseline.
#[derive(Clone, Debug)]
pub struct Keyed {
    pub fingerprint: String,
    pub match_hash: String,
    pub rule: String,
    pub path: String,
    pub line: usize,
    pub occurrence: usize,
}

impl From<&Entry> for Keyed {
    fn from(e: &Entry) -> Keyed {
        Keyed {
            fingerprint: e.fingerprint.clone(),
            match_hash: e.match_hash.clone(),
            rule: e.rule_id.clone(),
            path: e.path.clone(),
            line: e.line_hint,
            occurrence: e.occurrence,
        }
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub fn key(salt: &[u8], subjects: &[Subject]) -> Vec<Keyed> {
    let mut keyed: Vec<Keyed> = subjects
        .iter()
        .map(|s| Keyed {
            fingerprint: format!(
                "gg1:{}",
                &to_hex(&hmac(
                    salt,
                    &[
                        s.rule.as_bytes(),
                        b"\0",
                        s.path.as_bytes(),
                        b"\0",
                        &Sha256::digest(s.matched.as_bytes()),
                        &Sha256::digest(s.context.as_bytes()),
                    ],
                ))[..32]
            ),
            // Empty when nothing was matched: such findings cannot move.
            match_hash: if s.matched.is_empty() {
                String::new()
            } else {
                to_hex(&hmac(salt, &[b"match\0", s.matched.as_bytes()]))[..24].to_string()
            },
            rule: s.rule.clone(),
            path: s.path.clone(),
            line: s.line,
            occurrence: 0,
        })
        .collect();
    // Number identical matches within a file from the top.
    let mut order: Vec<usize> = (0..keyed.len()).collect();
    order.sort_by_key(|&i| keyed[i].line);
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    for i in order {
        let k = &keyed[i];
        let n = seen
            .entry((k.rule.clone(), k.path.clone(), k.match_hash.clone()))
            .or_insert(0);
        keyed[i].occurrence = *n;
        *n += 1;
    }
    keyed
}

// ── Matching ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Known {
    Exact,
    /// Same file, same match; the code around it changed.
    Shifted,
    /// Same match, only one candidate, in another file.
    Moved {
        from: String,
    },
}

/// Which of `current` are already in `known`, and how. Also returns how many
/// `known` entries nothing claimed (fixed, or changed beyond recognition).
pub fn match_known(current: &[Keyed], known: &[Keyed]) -> (Vec<Option<Known>>, usize) {
    let mut used = vec![false; known.len()];
    let mut out: Vec<Option<Known>> = vec![None; current.len()];

    // 1. Exact fingerprint.
    let mut by_fp: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, k) in known.iter().enumerate() {
        by_fp.entry(&k.fingerprint).or_default().push(j);
    }
    for (i, c) in current.iter().enumerate() {
        if let Some(j) = by_fp
            .get(c.fingerprint.as_str())
            .and_then(|js| js.iter().copied().find(|&j| !used[j]))
        {
            used[j] = true;
            out[i] = Some(Known::Exact);
        }
    }

    // 2. Same rule, path and match: the nearest line.
    for (i, c) in current.iter().enumerate() {
        if out[i].is_some() {
            continue;
        }
        let nearest = known
            .iter()
            .enumerate()
            .filter(|(j, k)| {
                !used[*j] && k.rule == c.rule && k.path == c.path && k.match_hash == c.match_hash
            })
            .min_by_key(|(_, k)| (k.line.abs_diff(c.line), k.occurrence.abs_diff(c.occurrence)))
            .map(|(j, _)| j);
        if let Some(j) = nearest {
            used[j] = true;
            out[i] = Some(Known::Shifted);
        }
    }

    // 3. Same rule and match elsewhere, when that is unambiguous. Findings
    //    with nothing matched (whole-file, project-level) cannot move.
    let mut left: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (i, c) in current.iter().enumerate() {
        if out[i].is_none() {
            left.entry((&c.rule, &c.match_hash)).or_default().push(i);
        }
    }
    let mut free: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (j, k) in known.iter().enumerate() {
        if !used[j] {
            free.entry((&k.rule, &k.match_hash)).or_default().push(j);
        }
    }
    for (key, is) in &left {
        if let (Some(js), [i]) = (free.get(key), is.as_slice())
            && let [j] = js.as_slice()
            && !key.1.is_empty()
        {
            used[*j] = true;
            out[*i] = Some(Known::Moved {
                from: known[*j].path.clone(),
            });
        }
    }

    (out, used.iter().filter(|u| !**u).count())
}

// ── Hex ───────────────────────────────────────────────────────────────────────

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231() {
        // Test case 2.
        assert_eq!(
            to_hex(&hmac(b"Jefe", &[b"what do ya ", b"want for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block size.
        assert_eq!(
            to_hex(&hmac(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    fn subj(rule: &str, path: &str, line: usize, matched: &str, context: &str) -> Subject {
        Subject {
            rule: rule.into(),
            path: path.into(),
            line,
            matched: matched.into(),
            context: context.into(),
        }
    }

    #[test]
    fn fingerprint_hides_the_secret_and_depends_on_salt() {
        let s = [subj("AWS", "a.env", 3, "AKIAIOSFODNN7SECRET1", "x=█")];
        let a = key(b"salt-a", &s);
        let b = key(b"salt-b", &s);
        assert!(a[0].fingerprint.starts_with("gg1:"));
        assert_ne!(a[0].fingerprint, b[0].fingerprint);
        assert!(!a[0].fingerprint.contains("AKIA"));
        assert!(!a[0].match_hash.contains("AKIA"));
    }

    #[test]
    fn tiers() {
        let salt = b"s";
        let known = key(
            salt,
            &[
                subj("AWS", "a.env", 3, "K1", "ctx"),
                subj("AWS", "a.env", 9, "K2", "ctx2"),
                subj("AWS", "old.env", 1, "K3", "c"),
            ],
        );
        let current = key(
            salt,
            &[
                subj("AWS", "a.env", 3, "K1", "ctx"),     // exact
                subj("AWS", "a.env", 14, "K2", "edited"), // shifted
                subj("AWS", "new.env", 1, "K3", "c"),     // moved
                subj("AWS", "a.env", 20, "K2", "edited"), // a second copy: new
            ],
        );
        let (m, unused) = match_known(&current, &known);
        assert_eq!(m[0], Some(Known::Exact));
        assert_eq!(m[1], Some(Known::Shifted));
        assert_eq!(
            m[2],
            Some(Known::Moved {
                from: "old.env".into()
            })
        );
        assert_eq!(m[3], None);
        assert_eq!(unused, 0);
    }

    #[test]
    fn ambiguous_moves_stay_new() {
        let salt = b"s";
        let known = key(
            salt,
            &[subj("R", "x", 1, "M", ""), subj("R", "y", 1, "M", "")],
        );
        let current = key(salt, &[subj("R", "z", 1, "M", "")]);
        let (m, unused) = match_known(&current, &known);
        assert_eq!(m[0], None);
        assert_eq!(unused, 2);
    }

    #[test]
    fn context_skips_blank_lines_and_redacts() {
        let lines: Vec<String> = ["a", "", "b", "c", "key = SECRET  ", "", "d", "e", "f"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(context_of(&lines, 4, "SECRET"), "b\nc\nkey = █\nd\ne");
    }

    #[test]
    fn rule_key_drops_measurements() {
        assert_eq!(
            rule_key("SMELL/LongFunction (80 lines, max 50)"),
            "SMELL/LongFunction"
        );
        assert_eq!(
            rule_key("High Entropy String (base64)"),
            "High Entropy String (base64)"
        );
        assert_eq!(normalize_path("./src\\a.rs"), "src/a.rs");
    }
}
