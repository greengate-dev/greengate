//! Governed exceptions: `.greengate/exceptions.toml`.
//!
//! An exception waives specific findings for a limited time, and says who
//! decided and why. Every field but `ticket` is required, and no exception
//! may run longer than `[policy] max_exception_days` (90 by default). When it
//! expires, its findings count again and the report names the exception and
//! its owner.
//!
//! ```toml
//! [[exception]]
//! id = "EX-12"
//! match = { advisory = "GHSA-xxxx-xxxx-xxxx", package = "lodash" }
//! reason = "Not reachable: we never call template()"
//! owner = "@payments-team"
//! expires = "2026-12-31"
//! ticket = "SEC-481"
//! ```
//!
//! `match` names one finding (`{ fingerprint = "gg1:…" }`, from a report), a
//! rule (`{ rule = "CI/UnpinnedAction", path = ".github/workflows/*.yml" }`,
//! `path` and `package` optional) or an advisory (`{ advisory = "GHSA-…" }`,
//! `package` optional).

use crate::modules::baseline::{normalize_path, rule_key};
use crate::report::{Finding, Location};
use crate::utils::dates;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use std::path::Path;

pub const EXCEPTIONS_FILE: &str = ".greengate/exceptions.toml";

/// Exceptions this close to expiry are warned about.
pub const WARN_DAYS: i64 = 14;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    exception: Vec<Exception>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub id: String,
    #[serde(rename = "match")]
    pub matches: Match,
    pub reason: String,
    pub owner: String,
    /// `YYYY-MM-DD`; the exception lapses at the end of that day (UTC).
    pub expires: String,
    #[serde(default)]
    pub ticket: Option<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub fingerprint: Option<String>,
    pub rule: Option<String>,
    pub path: Option<String>,
    pub advisory: Option<String>,
    pub package: Option<String>,
}

pub struct Rule {
    pub exception: Exception,
    /// Last day it applies, as a day number.
    pub expires: i64,
    path: Option<GlobMatcher>,
}

pub struct Exceptions {
    pub rules: Vec<Rule>,
}

/// The exceptions file, validated. `Ok(None)` when there is none; `Err`
/// lists every problem in it.
pub fn load(dir: &Path, max_days: u32, today: i64) -> Result<Option<Exceptions>> {
    let path = dir.join(EXCEPTIONS_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("could not read {EXCEPTIONS_FILE}")),
    };
    parse(&text, max_days, today)
        .map(Some)
        .map_err(|errors| anyhow::anyhow!(errors.join("\n")))
        .context(crate::utils::config::ConfigError(EXCEPTIONS_FILE))
}

pub fn parse(text: &str, max_days: u32, today: i64) -> Result<Exceptions, Vec<String>> {
    let file: File = toml::from_str(text).map_err(|e| vec![e.to_string()])?;
    let mut errors = Vec::new();
    let mut rules = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for ex in file.exception {
        let label = if ex.id.trim().is_empty() {
            "an exception".to_string()
        } else {
            format!("exception {}", ex.id)
        };
        let mut bad = |msg: String| errors.push(format!("{label}: {msg}"));
        if ex.id.trim().is_empty() {
            bad("`id` is empty".into());
        } else if !ids.insert(ex.id.clone()) {
            bad("duplicate `id`".into());
        }
        if ex.reason.trim().is_empty() {
            bad("`reason` is empty".into());
        }
        if ex.owner.trim().is_empty() {
            bad("`owner` is empty".into());
        }
        let expires = dates::parse_ymd(&ex.expires);
        match expires {
            None => bad(format!(
                "`expires` must be a YYYY-MM-DD date, not {:?}",
                ex.expires
            )),
            Some(day) if day - today > i64::from(max_days) => bad(format!(
                "expires {} — more than {max_days} days away ([policy] max_exception_days)",
                ex.expires
            )),
            Some(_) => {}
        }
        let m = &ex.matches;
        let kinds = [&m.fingerprint, &m.rule, &m.advisory]
            .iter()
            .filter(|k| k.is_some())
            .count();
        if kinds != 1 {
            bad("`match` needs exactly one of `fingerprint`, `rule` or `advisory`".into());
        }
        if m.fingerprint.is_some() && (m.path.is_some() || m.package.is_some()) {
            bad("a `fingerprint` match names one finding; drop `path` and `package`".into());
        }
        if m.advisory.is_some() && m.path.is_some() {
            bad("an `advisory` match takes `package`, not `path`".into());
        }
        if let Some(fp) = &m.fingerprint
            && !fp.starts_with("gg1:")
        {
            bad(format!("fingerprint {fp:?} is not a gg1: fingerprint"));
        }
        let path = match m.path.as_deref().map(Glob::new) {
            Some(Ok(g)) => Some(g.compile_matcher()),
            Some(Err(e)) => {
                bad(format!("`path` is not a valid glob: {e}"));
                None
            }
            None => None,
        };
        if let Some(day) = expires {
            rules.push(Rule {
                exception: ex,
                expires: day,
                path,
            });
        }
    }
    if errors.is_empty() {
        Ok(Exceptions { rules })
    } else {
        Err(errors)
    }
}

impl Rule {
    pub fn expired(&self, today: i64) -> bool {
        today > self.expires
    }

    pub fn matches(&self, f: &Finding) -> bool {
        let m = &self.exception.matches;
        if let Some(fp) = &m.fingerprint {
            return f.fingerprint.as_deref() == Some(fp.as_str());
        }
        if let Some(rule) = &m.rule
            && rule_key(rule) != rule_key(&f.rule)
        {
            return false;
        }
        if let Some(adv) = &m.advisory {
            let id = f.rule.strip_prefix("OSV/").unwrap_or(&f.rule);
            if !id.eq_ignore_ascii_case(adv) {
                return false;
            }
        }
        if let Some(glob) = &self.path {
            let path = match &f.location {
                Location::File { path, .. }
                | Location::Package {
                    source: Some(path), ..
                } => normalize_path(&path.to_string_lossy()),
                _ => return false,
            };
            if !glob.is_match(&path) {
                return false;
            }
        }
        if let Some(pkg) = &m.package {
            let Location::Package { name, version, .. } = &f.location else {
                return false;
            };
            let (want_name, want_version) =
                match pkg.rsplit_once('@').filter(|(n, _)| !n.is_empty()) {
                    Some((n, v)) => (n, Some(v)),
                    None => (pkg.as_str(), None),
                };
            if !name.eq_ignore_ascii_case(want_name)
                || want_version.is_some_and(|v| version.as_deref() != Some(v))
            {
                return false;
            }
        }
        true
    }
}

impl Exceptions {
    pub fn find(&self, f: &Finding) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(f))
    }
}

/// `[audit] ignore_advisories` as exceptions-file entries, skipping
/// advisories `existing` already covers.
pub fn migrate_entries(
    advisories: &[String],
    existing: Option<&Exceptions>,
    owner: &str,
    expires: &str,
) -> String {
    let covered = |adv: &str| {
        existing.is_some_and(|ex| {
            ex.rules.iter().any(|r| {
                r.exception
                    .matches
                    .advisory
                    .as_deref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(adv))
                    && r.exception.matches.package.is_none()
            })
        })
    };
    let mut out = String::new();
    for adv in advisories.iter().filter(|a| !covered(a)) {
        out.push_str(&format!(
            "\n[[exception]]\nid = {}\nmatch = {{ advisory = {} }}\nreason = \"Migrated from [audit] ignore_advisories; replace with the real reason\"\nowner = {}\nexpires = \"{expires}\"\n",
            toml_str(&format!("EX-{adv}")),
            toml_str(adv),
            toml_str(owner),
        ));
    }
    out
}

/// `greengate exceptions migrate`.
pub fn run_migrate(cfg: &crate::utils::config::Config, owner: Option<String>) -> Result<()> {
    use crate::utils::terminal;
    let max_days = cfg.policy.max_exception_days;
    let today = dates::today();
    let advisories = &cfg.audit.ignore_advisories;
    if advisories.is_empty() {
        terminal::info("[audit] ignore_advisories is empty; nothing to migrate.");
        return Ok(());
    }
    let dir = Path::new(".");
    let existing = load(dir, max_days, today)?;
    let owner = owner
        .or_else(|| {
            let out = std::process::Command::new("git") // greengate: ignore — reads the committer email
                .args(["config", "user.email"])
                .output()
                .ok()?;
            let email = String::from_utf8_lossy(&out.stdout).trim().to_string();
            (!email.is_empty()).then_some(email)
        })
        .unwrap_or_else(|| "unassigned".to_string());
    let expires = dates::format_ymd(today + i64::from(max_days));
    let added = migrate_entries(advisories, existing.as_ref(), &owner, &expires);
    if added.is_empty() {
        terminal::info(&format!(
            "Every advisory in [audit] ignore_advisories is already in {EXCEPTIONS_FILE}."
        ));
    } else {
        let path = dir.join(EXCEPTIONS_FILE);
        let mut text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            "# Governed exceptions: see `greengate exceptions list`.\n".to_string()
        });
        text.push_str(&added);
        // Never write a file the gates would then reject.
        parse(&text, max_days, today).map_err(|e| anyhow::anyhow!(e.join("; ")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, text)?;
        terminal::success(&format!(
            "Added {} exception(s) to {EXCEPTIONS_FILE}, owned by {owner} and expiring {expires}.",
            added.matches("[[exception]]").count()
        ));
    }
    terminal::info(
        "Give each a real reason, then remove `ignore_advisories` from .greengate.toml.",
    );
    Ok(())
}

/// `greengate exceptions list`.
pub fn run_list(cfg: &crate::utils::config::Config) -> Result<()> {
    let today = dates::today();
    let Some(ex) = load(Path::new("."), cfg.policy.max_exception_days, today)? else {
        crate::utils::terminal::info(&format!("No {EXCEPTIONS_FILE}."));
        return Ok(());
    };
    for r in &ex.rules {
        let e = &r.exception;
        let state = if r.expired(today) {
            "EXPIRED".to_string()
        } else {
            format!("{} day(s) left", r.expires - today)
        };
        println!(
            "{}  {}  owner {}  until {} ({state})",
            e.id,
            describe(&e.matches),
            e.owner,
            e.expires
        );
        println!(
            "    {}{}",
            e.reason,
            e.ticket
                .as_deref()
                .map(|t| format!(" [{t}]"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

/// A match in a line: `rule CI/UnpinnedAction in .github/**`.
pub fn describe(m: &Match) -> String {
    let mut parts = Vec::new();
    if let Some(v) = &m.fingerprint {
        parts.push(format!("finding {v}"));
    }
    if let Some(v) = &m.rule {
        parts.push(format!("rule {v}"));
    }
    if let Some(v) = &m.advisory {
        parts.push(format!("advisory {v}"));
    }
    if let Some(v) = &m.package {
        parts.push(format!("package {v}"));
    }
    if let Some(v) = &m.path {
        parts.push(format!("in {v}"));
    }
    parts.join(" ")
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    const TODAY: i64 = 20_737; // 2026-10-11

    fn one(m: &str, expires: &str) -> Result<Exceptions, Vec<String>> {
        parse(
            &format!(
                "[[exception]]\nid = \"EX-1\"\nmatch = {m}\nreason = \"r\"\nowner = \"@o\"\nexpires = \"{expires}\"\n"
            ),
            90,
            TODAY,
        )
    }

    fn vuln(rule: &str, name: &str, version: &str) -> Finding {
        let mut f = Finding::package(rule, Severity::High, "npm", name, "m");
        if let Location::Package {
            version: v, source, ..
        } = &mut f.location
        {
            *v = Some(version.into());
            *source = Some("web/package-lock.json".into());
        }
        f
    }

    #[test]
    fn advisory_and_package() {
        let ex = one(
            r#"{ advisory = "GHSA-aaaa", package = "lodash" }"#,
            "2026-11-01",
        )
        .unwrap();
        let r = &ex.rules[0];
        assert!(r.matches(&vuln("OSV/GHSA-AAAA", "lodash", "4.17.20")));
        assert!(!r.matches(&vuln("OSV/GHSA-aaaa", "underscore", "1.0.0")));
        assert!(!r.matches(&vuln("OSV/GHSA-bbbb", "lodash", "4.17.20")));
        let pinned = one(
            r#"{ advisory = "GHSA-aaaa", package = "lodash@4.17.20" }"#,
            "2026-11-01",
        )
        .unwrap();
        assert!(!pinned.rules[0].matches(&vuln("OSV/GHSA-aaaa", "lodash", "4.17.21")));
    }

    #[test]
    fn rule_and_path_glob() {
        let ex = one(
            r#"{ rule = "CI/UnpinnedAction", path = ".github/workflows/*.yml" }"#,
            "2026-11-01",
        )
        .unwrap();
        let hit = Finding::in_file(
            "CI/UnpinnedAction",
            Severity::Medium,
            "./.github/workflows/ci.yml",
            4,
            "m",
        );
        let miss = Finding::in_file("CI/UnpinnedAction", Severity::Medium, "other.yml", 4, "m");
        assert!(ex.rules[0].matches(&hit));
        assert!(!ex.rules[0].matches(&miss));
    }

    #[test]
    fn fingerprint() {
        let ex = one(r#"{ fingerprint = "gg1:abc" }"#, "2026-11-01").unwrap();
        let mut f = Finding::in_file("AWS", Severity::High, "a", 1, "m");
        assert!(!ex.rules[0].matches(&f));
        f.fingerprint = Some("gg1:abc".into());
        assert!(ex.rules[0].matches(&f));
    }

    #[test]
    fn validation() {
        let err = |m: &str, e: &str| one(m, e).err().unwrap().join("; ");
        assert!(err(r#"{ rule = "R" }"#, "2027-06-01").contains("more than 90 days"));
        assert!(err(r#"{ rule = "R" }"#, "2026-02-30").contains("YYYY-MM-DD"));
        assert!(err(r#"{ package = "x" }"#, "2026-11-01").contains("exactly one"));
        assert!(err(r#"{ rule = "R", advisory = "A" }"#, "2026-11-01").contains("exactly one"));
        assert!(
            err(r#"{ advisory = "A", path = "x" }"#, "2026-11-01").contains("takes `package`")
        );
        assert!(err(r#"{ fingerprint = "abc" }"#, "2026-11-01").contains("gg1:"));
        assert!(one(r#"{ rule = "R", colour = "x" }"#, "2026-11-01").is_err());
        let missing_owner = parse(
            "[[exception]]\nid = \"EX-1\"\nmatch = { rule = \"R\" }\nreason = \"r\"\nexpires = \"2026-11-01\"\n",
            90,
            TODAY,
        );
        assert!(missing_owner.err().unwrap()[0].contains("owner"));
        // An expired exception is valid: its findings simply count again.
        let old = one(r#"{ rule = "R" }"#, "2026-01-01").unwrap();
        assert!(old.rules[0].expired(TODAY));
    }

    #[test]
    fn migrate_skips_covered_advisories() {
        let existing = one(r#"{ advisory = "GHSA-aaaa" }"#, "2026-11-01").unwrap();
        let out = migrate_entries(
            &["GHSA-aaaa".into(), "RUSTSEC-2026-0001".into()],
            Some(&existing),
            "dev@example.com",
            "2027-01-09",
        );
        assert!(!out.contains("GHSA-aaaa"));
        assert!(out.contains(r#"advisory = "RUSTSEC-2026-0001""#));
        let parsed = parse(&out, 90, TODAY).unwrap();
        assert_eq!(parsed.rules.len(), 1);
    }
}
