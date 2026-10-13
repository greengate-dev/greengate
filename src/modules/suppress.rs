//! Which findings a gate counts: one pass shared by `scan`, `audit` and
//! `ci-lint`, after inline `greengate: ignore` comments (which the scanner
//! applies itself):
//!
//! 1. governed exceptions (`.greengate/exceptions.toml`) — an expired one no
//!    longer suppresses, and says so;
//! 2. findings already present at the `--new-since` base;
//! 3. the baseline (`--since-baseline`), or recording one (`--update-baseline`).
//!
//! Suppressed findings are not dropped: they move to the report's
//! `suppressed` list with the reason, so every waiver stays visible.

use crate::modules::baseline::{
    self, BASELINE_FILE, Keyed, Known, Loaded, Matcher, Sources, Subject,
};
use crate::modules::exceptions::{self, WARN_DAYS};
use crate::report::{Finding, Location, Severity, Suppression, SuppressionKind};
use crate::utils::{dates, terminal};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BaselineMode {
    #[default]
    Off,
    /// `--since-baseline`: findings in the baseline are suppressed.
    Compare,
    /// `--update-baseline`: record the current findings; they pass.
    Update,
}

impl BaselineMode {
    pub fn from_flags(update: bool, compare: bool) -> BaselineMode {
        if update {
            BaselineMode::Update
        } else if compare {
            BaselineMode::Compare
        } else {
            BaselineMode::Off
        }
    }
}

/// Gate options that come from flags and `[policy]`.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub baseline: BaselineMode,
    pub max_exception_days: u32,
}

impl Policy {
    pub fn new(baseline: BaselineMode, cfg: &crate::utils::config::Config) -> Policy {
        Policy {
            baseline,
            max_exception_days: cfg.policy.max_exception_days,
        }
    }
}

pub struct Options<'a> {
    /// The gate, as recorded in baseline entries.
    pub tool: &'static str,
    pub policy: Policy,
    pub matcher: Option<Matcher<'a>>,
    /// `--new-since`: a label for the base and the findings present there.
    pub base: Option<(String, Vec<Subject>)>,
}

#[derive(Default, Debug)]
pub struct Outcome {
    /// Per input finding: why it is suppressed, or `None` if it counts.
    pub verdicts: Vec<Option<Suppression>>,
    /// Things to tell the user (expired exceptions, baseline summary).
    pub notes: Vec<String>,
    /// For the report's `warnings`: exceptions about to expire.
    pub warnings: Vec<Finding>,
}

fn suppression(kind: SuppressionKind, reason: String) -> Suppression {
    Suppression::new(kind, Some(reason))
}

/// Fail fast on an invalid exceptions file, before a gate does its work.
pub fn preflight(cfg: &crate::utils::config::Config) -> Result<()> {
    exceptions::load(
        Path::new("."),
        cfg.policy.max_exception_days,
        dates::today(),
    )
    .map(|_| ())
}

pub fn apply(findings: &mut [Finding], opts: &Options<'_>) -> Result<Outcome> {
    apply_in(Path::new("."), dates::today(), findings, opts)
}

fn apply_in(
    dir: &Path,
    today: i64,
    findings: &mut [Finding],
    opts: &Options<'_>,
) -> Result<Outcome> {
    let n = findings.len();
    let mut out = Outcome {
        verdicts: vec![None; n],
        ..Outcome::default()
    };
    let exceptions = exceptions::load(dir, opts.policy.max_exception_days, today)?;
    let baseline_path = dir.join(BASELINE_FILE);
    let loaded = baseline::load(&baseline_path)?;

    // Fingerprints are keyed with the baseline's salt, so they stay stable
    // across runs and exceptions can name them.
    let persistent = match (&loaded, opts.policy.baseline) {
        (Loaded::V2(b), _) => Some(b.salt_bytes()?),
        (_, BaselineMode::Update) => Some(baseline::new_salt()?),
        _ => None,
    };
    let salt = match (&persistent, &opts.base) {
        (Some(s), _) => Some(s.clone()),
        (None, Some(_)) => Some(baseline::new_salt()?),
        (None, None) => None,
    };
    let keyed: Vec<Keyed> = match &salt {
        Some(salt) => {
            let mut sources = Sources::new(|p| std::fs::read_to_string(dir.join(p)).ok());
            let subjects: Vec<Subject> = findings
                .iter()
                .map(|f| baseline::subject(f, &mut sources, opts.matcher))
                .collect();
            baseline::key(salt, &subjects)
        }
        None => Vec::new(),
    };
    if persistent.is_some() {
        for (f, k) in findings.iter_mut().zip(&keyed) {
            f.fingerprint = Some(k.fingerprint.clone());
        }
    }

    // ── 1. Exceptions ─────────────────────────────────────────────────────────
    if let Some(ex) = &exceptions {
        let mut expired: BTreeMap<&str, (usize, &exceptions::Rule)> = BTreeMap::new();
        let mut soon: BTreeMap<&str, &exceptions::Rule> = BTreeMap::new();
        for (i, f) in findings.iter_mut().enumerate() {
            let Some(rule) = ex.find(f) else { continue };
            let e = &rule.exception;
            let mut s = Suppression::new(SuppressionKind::Exception, Some(e.reason.clone()));
            s.id = Some(e.id.clone());
            s.owner = Some(e.owner.clone());
            s.expires = Some(e.expires.clone());
            if rule.expired(today) {
                s.expired = true;
                f.message = format!(
                    "{} (exception {} expired {}, owner {})",
                    f.message, e.id, e.expires, e.owner
                );
                f.suppression = Some(s);
                expired.entry(&e.id).or_insert((0, rule)).0 += 1;
            } else {
                if rule.expires - today < WARN_DAYS {
                    soon.insert(&e.id, rule);
                }
                out.verdicts[i] = Some(s);
            }
        }
        for (id, (count, rule)) in expired {
            out.notes.push(format!(
                "exception {id} expired on {} (owner {}): {count} finding(s) count again",
                rule.exception.expires, rule.exception.owner
            ));
        }
        for (id, rule) in soon {
            let days = rule.expires - today;
            let msg = format!(
                "exception {id} (owner {}) expires on {} — {}",
                rule.exception.owner,
                rule.exception.expires,
                match days {
                    0 => "today".to_string(),
                    1 => "tomorrow".to_string(),
                    d => format!("in {d} days"),
                }
            );
            out.notes.push(msg.clone());
            out.warnings.push(Finding::project(
                "EXCEPTION/ExpiresSoon",
                Severity::Low,
                msg,
            ));
        }
    }

    let undecided = |verdicts: &[Option<Suppression>]| -> Vec<usize> {
        (0..n).filter(|&i| verdicts[i].is_none()).collect()
    };

    // ── 2. Already present at the --new-since base ────────────────────────────
    if let (Some((label, base)), Some(salt)) = (&opts.base, &salt) {
        let known = baseline::key(salt, base);
        let idx = undecided(&out.verdicts);
        let current: Vec<Keyed> = idx.iter().map(|&i| keyed[i].clone()).collect();
        let (matched, _) = baseline::match_known(&current, &known);
        let mut already = 0;
        for (k, &i) in idx.iter().enumerate() {
            if let Some(how) = &matched[k] {
                already += 1;
                let mut s = suppression(
                    SuppressionKind::Baseline,
                    match how {
                        Known::Moved { from } => format!("present at {label} in {from}"),
                        _ => format!("present at {label}"),
                    },
                );
                s.id = Some(label.clone());
                out.verdicts[i] = Some(s);
            }
        }
        out.notes.push(format!(
            "New since {label}: {} new finding(s); {already} already present there",
            idx.len() - already
        ));
    }

    // ── 3. Baseline ───────────────────────────────────────────────────────────
    match opts.policy.baseline {
        BaselineMode::Off => {}
        BaselineMode::Update => {
            let Some(salt) = &persistent else {
                unreachable!("update mode always has a salt")
            };
            let idx = undecided(&out.verdicts);
            let record: Vec<Keyed> = idx.iter().map(|&i| keyed[i].clone()).collect();
            if matches!(loaded, Loaded::V1(_)) {
                out.notes.push(format!(
                    "Replacing the version-1 baseline in {BASELINE_FILE}; entries of other gates are not carried over"
                ));
            }
            let saved = baseline::save(&baseline_path, opts.tool, salt, &record)?;
            for i in idx {
                out.verdicts[i] = Some(suppression(
                    SuppressionKind::Baseline,
                    "recorded in the baseline".into(),
                ));
            }
            out.notes.push(format!(
                "Baseline saved: {saved} {} finding(s) written to {BASELINE_FILE}",
                opts.tool
            ));
        }
        BaselineMode::Compare => match &loaded {
            Loaded::Missing => out.notes.push(format!(
                "No baseline at {BASELINE_FILE}; every finding counts (create one with --update-baseline)"
            )),
            Loaded::V1(legacy) => {
                let idx = undecided(&out.verdicts);
                let mut hits = 0;
                for i in idx {
                    let Location::File {
                        path,
                        line: Some(line),
                    } = &findings[i].location
                    else {
                        continue;
                    };
                    let entry = baseline::LegacyEntry {
                        path: baseline::normalize_path(&path.to_string_lossy()),
                        rule_id: findings[i].rule.clone(),
                        line: *line,
                    };
                    if legacy.contains(&entry) {
                        hits += 1;
                        out.verdicts[i] = Some(suppression(
                            SuppressionKind::Baseline,
                            "in the baseline (version 1, exact line)".into(),
                        ));
                    }
                }
                out.notes.push(format!(
                    "Baseline: {hits} known finding(s) suppressed. {BASELINE_FILE} is version 1, which only matches exact lines; run `greengate baseline migrate`"
                ));
            }
            Loaded::V2(b) => {
                let known: Vec<Keyed> = b
                    .entries
                    .iter()
                    .filter(|e| e.tool == opts.tool)
                    .map(Keyed::from)
                    .collect();
                let idx = undecided(&out.verdicts);
                let current: Vec<Keyed> = idx.iter().map(|&i| keyed[i].clone()).collect();
                let (matched, unclaimed) = baseline::match_known(&current, &known);
                let mut hits = 0;
                for (k, &i) in idx.iter().enumerate() {
                    let Some(how) = &matched[k] else { continue };
                    hits += 1;
                    let mut s = suppression(
                        SuppressionKind::Baseline,
                        match how {
                            Known::Exact => "in the baseline".to_string(),
                            Known::Shifted => {
                                "in the baseline (the code around it changed)".to_string()
                            }
                            Known::Moved { from } => format!("in the baseline at {from} (moved)"),
                        },
                    );
                    s.id = Some(keyed[i].fingerprint.clone());
                    out.verdicts[i] = Some(s);
                }
                let mut note = format!(
                    "Baseline: {hits} known finding(s) suppressed, {} new",
                    idx.len() - hits
                );
                if unclaimed > 0 {
                    note.push_str(&format!(
                        "; {unclaimed} baseline entr{} no longer found (fixed? refresh with --update-baseline)",
                        if unclaimed == 1 { "y" } else { "ies" }
                    ));
                }
                out.notes.push(note);
            }
        },
    }
    Ok(out)
}

/// Split `items` by `verdicts`: those that count, and those suppressed.
pub fn partition<T>(
    items: Vec<T>,
    verdicts: &[Option<Suppression>],
) -> (Vec<T>, Vec<(T, Suppression)>) {
    let mut kept = Vec::new();
    let mut gone = Vec::new();
    for (item, verdict) in items.into_iter().zip(verdicts) {
        match verdict {
            Some(s) => gone.push((item, s.clone())),
            None => kept.push(item),
        }
    }
    (kept, gone)
}

/// Text output: notes, then a one-line tally of suppressions by kind, then
/// each finding waived by an exception or by config (the waivers someone
/// must answer for, so they are always named).
pub fn print_summary(outcome_notes: &[String], suppressed: &[Finding]) {
    for note in outcome_notes {
        if note.contains("count again") || note.contains("expires on") {
            terminal::warn(note);
        } else {
            terminal::info(note);
        }
    }
    if suppressed.is_empty() {
        return;
    }
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for f in suppressed {
        let kind = match f.suppression.as_ref().map(|s| s.kind) {
            Some(SuppressionKind::Inline) => "inline",
            Some(SuppressionKind::Exception) => "exception",
            Some(SuppressionKind::Baseline) => "baseline",
            Some(SuppressionKind::Config) => "ignore_advisories",
            Some(SuppressionKind::Triage) => "triage",
            None => "other",
        };
        *tally.entry(kind).or_default() += 1;
    }
    terminal::info(&format!(
        "Suppressed {} finding(s): {} (all listed in --report)",
        suppressed.len(),
        tally
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for f in suppressed {
        let Some(s) = &f.suppression else { continue };
        match s.kind {
            SuppressionKind::Exception => eprintln!(
                "  [exception {} · {} · until {}] {} {} — {}",
                s.id.as_deref().unwrap_or("?"),
                s.owner.as_deref().unwrap_or("?"),
                s.expires.as_deref().unwrap_or("?"),
                f.rule,
                location_label(&f.location),
                s.reason.as_deref().unwrap_or("")
            ),
            SuppressionKind::Config => eprintln!(
                "  [ignore_advisories] {} {}",
                f.rule,
                location_label(&f.location)
            ),
            _ => {}
        }
    }
}

fn location_label(l: &Location) -> String {
    match l {
        Location::File {
            path,
            line: Some(line),
        } => format!("{}:{line}", path.display()),
        Location::File { path, line: None } => path.display().to_string(),
        Location::Package { name, version, .. } => match version {
            Some(v) => format!("{name}@{v}"),
            None => name.clone(),
        },
        Location::Url { url } => url.clone(),
        Location::Project => "project".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: i64 = 20_737; // 2026-10-11

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn file_finding(path: &str, line: usize) -> Finding {
        Finding::in_file(
            "AWS Access Key",
            Severity::High,
            path,
            line,
            "AWS Access Key",
        )
    }

    fn opts(mode: BaselineMode) -> Options<'static> {
        Options {
            tool: "scan",
            policy: Policy {
                baseline: mode,
                max_exception_days: 90,
            },
            matcher: None,
            base: None,
        }
    }

    #[test]
    fn baseline_survives_lines_moving() {
        let dir = tmp();
        let env = dir.path().join("app.env");
        std::fs::write(&env, "A=1\nKEY=AKIAIOSFODNN7SECRET1\n").unwrap();
        let mut found = vec![file_finding("app.env", 2)];
        let out = apply_in(dir.path(), TODAY, &mut found, &opts(BaselineMode::Update)).unwrap();
        assert!(out.verdicts[0].is_some(), "recorded findings pass");
        let saved = std::fs::read_to_string(dir.path().join(BASELINE_FILE)).unwrap();
        assert!(saved.contains("\"version\": 2"));
        assert!(
            !saved.contains("AKIA"),
            "no plaintext secrets in the baseline"
        );

        // Lines inserted above it: still known. A new secret: not.
        std::fs::write(
            &env,
            "# header\n\nA=1\nKEY=AKIAIOSFODNN7SECRET1\nNEW=AKIAIOSFODNN7SECRET2\n",
        )
        .unwrap();
        let mut found = vec![file_finding("app.env", 4), file_finding("app.env", 5)];
        let out = apply_in(dir.path(), TODAY, &mut found, &opts(BaselineMode::Compare)).unwrap();
        assert!(out.verdicts[0].is_some());
        assert!(out.verdicts[1].is_none());
        assert!(
            found[0]
                .fingerprint
                .as_deref()
                .is_some_and(|f| f.starts_with("gg1:"))
        );
    }

    #[test]
    fn exceptions_suppress_until_they_expire() {
        let dir = tmp();
        std::fs::create_dir(dir.path().join(".greengate")).unwrap();
        std::fs::write(
            dir.path().join(exceptions::EXCEPTIONS_FILE),
            r#"
[[exception]]
id = "EX-1"
match = { rule = "AWS Access Key", path = "fixtures/**" }
reason = "test fixture"
owner = "@sec"
expires = "2026-10-20"

[[exception]]
id = "EX-2"
match = { rule = "AWS Access Key", path = "old/**" }
reason = "legacy"
owner = "@legacy"
expires = "2026-10-01"
"#,
        )
        .unwrap();
        let mut found = vec![
            file_finding("fixtures/a.env", 1),
            file_finding("old/b.env", 1),
            file_finding("src/c.env", 1),
        ];
        let out = apply_in(dir.path(), TODAY, &mut found, &opts(BaselineMode::Off)).unwrap();
        let s = out.verdicts[0].as_ref().unwrap();
        assert_eq!(s.id.as_deref(), Some("EX-1"));
        assert!(
            out.verdicts[1].is_none(),
            "expired exception no longer applies"
        );
        assert!(
            found[1]
                .message
                .contains("exception EX-2 expired 2026-10-01, owner @legacy")
        );
        assert!(found[1].suppression.as_ref().is_some_and(|s| s.expired));
        assert!(out.verdicts[2].is_none());
        assert_eq!(out.warnings.len(), 1, "EX-1 expires within 14 days");
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("EX-2") && n.contains("count again"))
        );
    }

    #[test]
    fn invalid_exceptions_are_a_config_error() {
        let dir = tmp();
        std::fs::create_dir(dir.path().join(".greengate")).unwrap();
        std::fs::write(
            dir.path().join(exceptions::EXCEPTIONS_FILE),
            "[[exception]]\nid = \"EX-1\"\nmatch = { rule = \"R\" }\nreason = \"\"\nowner = \"o\"\nexpires = \"2030-01-01\"\n",
        )
        .unwrap();
        let err = apply_in(dir.path(), TODAY, &mut [], &opts(BaselineMode::Off)).unwrap_err();
        assert!(
            err.downcast_ref::<crate::utils::config::ConfigError>()
                .is_some()
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("`reason` is empty") && msg.contains("more than 90 days"),
            "{msg}"
        );
    }
}
