//! The review as terminal text, a pull-request comment, JSON, and check-run
//! annotations.

use super::fix::{Guidance, Step};
use super::{Change, Kind, Review, lockfile_line};
use crate::modules::github::Annotation;
use crate::report::{Finding, Location, Report, Status};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Hidden marker that identifies greengate's review comment, so it is
/// updated in place instead of piling up.
pub const MARKER: &str = "<!-- greengate:deps-review -->";

/// Rows in the comment's change table.
const MAX_ROWS: usize = 60;

pub fn first_step(g: &Guidance) -> Option<String> {
    g.steps.first().map(step_line)
}

fn step_line(s: &Step) -> String {
    match s {
        Step::Refresh { command } => command.clone(),
        Step::RaiseRequirement { command, .. } => command.clone(),
        Step::UpgradeParent {
            parent,
            from,
            to,
            compatible,
            command,
        } => format!(
            "{command}  ({parent} {from} → {to}{})",
            if *compatible {
                ""
            } else {
                ", outside your current requirement"
            }
        ),
        Step::Override { file, snippet } => format!("in {file}: {}", snippet.replace('\n', " ")),
        Step::Edit { file, change } => format!("in {file}: {change}"),
    }
}

fn kind_mark(k: Kind) -> &'static str {
    match k {
        Kind::Added => "+",
        Kind::Removed => "-",
        Kind::Upgraded => "↑",
        Kind::Downgraded => "↓",
    }
}

fn by_lockfile(review: &Review) -> BTreeMap<&PathBuf, Vec<&Change>> {
    let mut m: BTreeMap<&PathBuf, Vec<&Change>> = BTreeMap::new();
    for c in &review.changes {
        m.entry(&c.lockfile).or_default().push(c);
    }
    m
}

fn display_path(p: &std::path::Path) -> String {
    p.to_string_lossy().trim_start_matches("./").to_string()
}

fn finding_label(f: &Finding) -> String {
    match &f.location {
        Location::Package { name, version, .. } => match version {
            Some(v) => format!("{name}@{v}"),
            None => name.clone(),
        },
        Location::File { path, .. } => display_path(path),
        Location::Url { url } => url.clone(),
        Location::Project => "project".into(),
    }
}

fn tally(review: &Review) -> String {
    let count = |k: Kind| review.changes.iter().filter(|c| c.kind == k).count();
    let parts: Vec<String> = [
        (Kind::Added, "added"),
        (Kind::Upgraded, "upgraded"),
        (Kind::Downgraded, "downgraded"),
        (Kind::Removed, "removed"),
    ]
    .iter()
    .filter(|(k, _)| count(*k) > 0)
    .map(|(k, w)| format!("{} {w}", count(*k)))
    .collect();
    if parts.is_empty() {
        "no dependency changes".into()
    } else {
        parts.join(", ")
    }
}

// ── Terminal ──────────────────────────────────────────────────────────────────

pub fn text(review: &Review, report: &Report) {
    eprintln!();
    eprintln!(
        "Dependency review: {} since {}",
        tally(review),
        review.base_label
    );
    for (lock, changes) in by_lockfile(review) {
        eprintln!();
        eprintln!("  {}", display_path(lock));
        for c in changes {
            let mut notes: Vec<String> = Vec::new();
            if c.kind != Kind::Removed {
                notes.push(if c.direct {
                    "direct".into()
                } else {
                    "transitive".into()
                });
                if let Some(l) = &c.license {
                    notes.push(l.clone());
                }
            }
            if !c.introduced.is_empty() {
                notes.push(format!(
                    "introduces {}",
                    c.introduced
                        .iter()
                        .map(|a| a.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !c.fixed.is_empty() {
                notes.push(format!(
                    "fixes {}",
                    c.fixed
                        .iter()
                        .map(|a| a.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            eprintln!(
                "    {} {} {}  {}",
                kind_mark(c.kind),
                c.name,
                c.versions(),
                notes.join(" · ")
            );
            if !c.direct && c.kind != Kind::Removed && c.why.len() > 1 {
                eprintln!("        via {}", c.why[..c.why.len() - 1].join(" → "));
            }
        }
    }
    let print = |title: &str, list: &[Finding]| {
        if list.is_empty() {
            return;
        }
        eprintln!();
        eprintln!("{title} ({}):", list.len());
        for f in list {
            eprintln!(
                "  [{}] {} {} — {}",
                format!("{:?}", f.severity).to_uppercase(),
                f.rule,
                finding_label(f),
                f.message
            );
            if let Some(fix) = &f.remediation {
                eprintln!("      fix: {fix}");
            }
        }
    };
    print("Blocking", &report.findings);
    print("Warnings", &report.warnings);
    let guidance: Vec<&Guidance> = review
        .changes
        .iter()
        .filter_map(|c| c.fix.as_ref())
        .collect();
    if !guidance.is_empty() {
        eprintln!();
        eprintln!("How to fix:");
        for g in guidance {
            eprintln!(
                "  {}@{} → {}",
                g.package,
                g.version,
                g.fixed_in.as_deref().unwrap_or("no fixed release yet")
            );
            for s in &g.steps {
                eprintln!("      {}", step_line(s));
            }
            for n in &g.notes {
                eprintln!("      note: {n}");
            }
        }
    }
    eprintln!();
    match report.status() {
        Status::Findings => eprintln!(
            "Dependency review failed: {} blocking issue(s).",
            report.findings.len()
        ),
        _ if report.unfinished().next().is_some() => {}
        _ => crate::utils::terminal::success("Dependency review passed."),
    }
}

// ── Pull-request comment ──────────────────────────────────────────────────────

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn markdown(review: &Review, report: &Report) -> String {
    let status = match report.status() {
        Status::Passed => "✅ **passed**",
        Status::Findings => "❌ **failed**",
        Status::Incomplete => "⚠️ **incomplete**",
        Status::Error => "⚠️ **error**",
    };
    let mut md = format!(
        "{MARKER}\n## greengate dependency review\n\n{status} — {} since {}\n",
        tally(review),
        md_escape(&review.base_label)
    );
    if !report.findings.is_empty() {
        md.push_str(&format!("\n### Blocking ({})\n\n", report.findings.len()));
        for f in &report.findings {
            md.push_str(&format!(
                "- **{}** `{}` — {}{}\n",
                f.rule,
                finding_label(f),
                md_escape(&f.message),
                f.remediation
                    .as_ref()
                    .map(|r| format!("<br>Fix: `{}`", md_escape(r)))
                    .unwrap_or_default()
            ));
        }
    }
    if !review.changes.is_empty() {
        md.push_str("\n### Changes\n\n| | Package | Version | Dependency | License | Advisories |\n|---|---|---|---|---|---|\n");
        // Changes with something to say first; the table is capped to keep
        // the comment within GitHub's size limit.
        let mut rows: Vec<&Change> = review.changes.iter().collect();
        rows.sort_by_key(|c| (c.introduced.is_empty() && c.fixed.is_empty(), !c.direct));
        let shown = rows.len().min(MAX_ROWS);
        for c in &rows[..shown] {
            let adv = {
                let mut parts = Vec::new();
                if !c.introduced.is_empty() {
                    parts.push(format!(
                        "introduces {}",
                        c.introduced
                            .iter()
                            .map(|a| format!("`{}`", a.id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !c.fixed.is_empty() {
                    parts.push(format!(
                        "fixes {}",
                        c.fixed
                            .iter()
                            .map(|a| format!("`{}`", a.id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                parts.join("; ")
            };
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} |\n",
                kind_mark(c.kind),
                c.name,
                md_escape(&c.versions()),
                if c.kind == Kind::Removed {
                    String::new()
                } else if c.direct {
                    "direct".into()
                } else {
                    format!(
                        "via {}",
                        md_escape(&c.why.iter().rev().nth(1).cloned().unwrap_or_default())
                    )
                },
                md_escape(c.license.as_deref().unwrap_or("")),
                adv
            ));
        }
        if rows.len() > shown {
            md.push_str(&format!(
                "\n_…and {} more; run `greengate deps review` for the full list._\n",
                rows.len() - shown
            ));
        }
    }
    let guidance: Vec<&Guidance> = review
        .changes
        .iter()
        .filter_map(|c| c.fix.as_ref())
        .collect();
    if !guidance.is_empty() {
        md.push_str("\n### How to fix\n\n");
        for g in guidance {
            md.push_str(&format!(
                "**{}@{}** → {}\n\n",
                g.package,
                g.version,
                g.fixed_in
                    .as_deref()
                    .map_or("no fixed release yet".to_string(), |f| format!("`{f}`"))
            ));
            for s in &g.steps {
                match s {
                    Step::Override { file, snippet } => {
                        md.push_str(&format!(
                            "- in `{file}`:\n  ```\n  {}\n  ```\n",
                            snippet.replace('\n', "\n  ")
                        ));
                    }
                    other => md.push_str(&format!("- `{}`\n", md_escape(&step_line(other)))),
                }
            }
            for n in &g.notes {
                md.push_str(&format!("- _{}_\n", md_escape(n)));
            }
            md.push('\n');
        }
    }
    if !report.warnings.is_empty() {
        md.push_str(&format!(
            "\n<details><summary>Warnings ({})</summary>\n\n",
            report.warnings.len()
        ));
        for f in &report.warnings {
            md.push_str(&format!(
                "- {} `{}` — {}\n",
                f.rule,
                finding_label(f),
                md_escape(&f.message)
            ));
        }
        md.push_str("\n</details>\n");
    }
    let unfinished: Vec<String> = report
        .unfinished()
        .map(|c| {
            format!(
                "- {} — {}",
                c.id,
                c.reason.as_deref().unwrap_or("did not complete")
            )
        })
        .collect();
    if !unfinished.is_empty() {
        md.push_str(&format!(
            "\n**Not every check completed:**\n{}\n",
            unfinished.join("\n")
        ));
    }
    if !report.suppressed.is_empty() {
        md.push_str(&format!(
            "\n_{} finding(s) waived by exceptions._\n",
            report.suppressed.len()
        ));
    }
    // GitHub rejects comments over 65,536 characters.
    const LIMIT: usize = 60_000;
    if md.len() > LIMIT {
        let mut cut = LIMIT;
        while !md.is_char_boundary(cut) {
            cut -= 1;
        }
        md.truncate(cut);
        md.push_str("\n\n_…truncated; run `greengate deps review` for the full review._\n");
    }
    md
}

// ── JSON ──────────────────────────────────────────────────────────────────────

pub fn json(review: &Review, report: &Report) -> Value {
    json!({
        "schema": "greengate.deps-review/v1",
        "base": { "rev": review.base_rev, "label": review.base_label },
        "changes": review.changes,
        "report": report.to_json(0),
    })
}

// ── Check-run annotations ─────────────────────────────────────────────────────

pub fn annotations(report: &Report) -> Vec<Annotation> {
    let mut out = Vec::new();
    for (list, level) in [(&report.findings, "failure"), (&report.warnings, "warning")] {
        for f in list.iter() {
            let Location::Package {
                name,
                version,
                source: Some(lockfile),
                ..
            } = &f.location
            else {
                continue;
            };
            out.push(Annotation {
                path: display_path(lockfile),
                line: lockfile_line(lockfile, name, version.as_deref()).unwrap_or(1),
                level,
                title: format!("{} {}", f.rule, finding_label(f)),
                message: match &f.remediation {
                    Some(r) => format!("{}\nFix: {r}", f.message),
                    None => f.message.clone(),
                },
            });
        }
    }
    out
}
