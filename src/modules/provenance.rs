//! Code provenance gate — differentiated visibility (and gating) for
//! AI-authored changes.
//!
//! When an agent writes much of a diff, "who/what wrote this" becomes a
//! first-class question: AI-generated code warrants extra scrutiny and, for some
//! teams, a policy ceiling. This module classifies each commit in a range as
//! AI- or human-authored from its trailers and author identity, attributes the
//! added lines, reports the split, and can fail the build when the AI-authored
//! share of new code exceeds a configured threshold.

use crate::utils::terminal;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::process::Command;

pub struct ProvenanceOpts {
    /// Base ref to diff against (range is `base..HEAD`).
    pub base: String,
    /// Fail if the AI-authored share of added lines exceeds this percent.
    /// `None` = report only (never fails).
    pub max_ai_lines_pct: Option<u8>,
    /// Output format: "text" (default), "json", or "sarif".
    pub format: String,
}

/// (substring, display name) for tools we recognise. Matched case-insensitively
/// against commit trailers and author identity — never free message text, to
/// avoid classifying a commit that merely *mentions* a tool.
const AI_TOOLS: &[(&str, &str)] = &[
    ("claude", "Claude"),
    ("copilot", "GitHub Copilot"),
    ("cursor", "Cursor"),
    ("aider", "Aider"),
    ("devin", "Devin"),
    ("codex", "Codex"),
    ("gemini", "Gemini"),
];

/// Classify a commit as AI-authored (returning the tool's display name) or human
/// (`None`). **Pure** — fully unit-testable without git.
pub fn classify(author_name: &str, author_email: &str, message: &str) -> Option<String> {
    // 1. Trailers are the strongest signal: `Co-Authored-By:` / `Assisted-By:`.
    for line in message.lines() {
        let l = line.trim().to_ascii_lowercase();
        let value = l
            .strip_prefix("co-authored-by:")
            .or_else(|| l.strip_prefix("assisted-by:"));
        if let Some(v) = value {
            for (needle, display) in AI_TOOLS {
                if v.contains(needle) {
                    return Some((*display).to_string());
                }
            }
        }
    }

    // 2. Strong free-text markers (tool-inserted, not incidental mentions).
    let lower = message.to_ascii_lowercase();
    if lower.contains("generated with claude") || lower.contains("🤖 generated with") {
        return Some("Claude".to_string());
    }

    // 3. Author identity (bot accounts).
    let ident = format!("{author_name}\n{author_email}").to_ascii_lowercase();
    for (needle, display) in AI_TOOLS {
        if ident.contains(needle) {
            return Some((*display).to_string());
        }
    }

    None
}

// ── git plumbing ─────────────────────────────────────────────────────────────

fn git(args: &[&str]) -> Result<String> {
    let out = Command::new("git") // greengate: ignore — reading commit metadata for provenance
        .args(args)
        .output()
        .context("failed to run git (is this a git repository?)")?;
    if !out.status.success() {
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

struct CommitInfo {
    short: String,
    tool: Option<String>,
    added_lines: usize,
    subject: String,
}

fn added_lines(hash: &str) -> usize {
    let Ok(out) = git(&["show", "--numstat", "--format=", hash]) else {
        return 0;
    };
    out.lines()
        .filter_map(|l| l.split('\t').next())
        .filter_map(|a| a.parse::<usize>().ok()) // "-" (binary) → skipped
        .sum()
}

fn collect_commits(range: &str) -> Result<Vec<CommitInfo>> {
    let hashes = git(&["rev-list", "--no-merges", range])
        .with_context(|| format!("could not list commits for range '{range}'"))?;

    let mut commits = Vec::new();
    for hash in hashes.lines().filter(|l| !l.is_empty()) {
        // author-name \0 author-email \0 subject \0 full-body
        let meta = git(&["show", "-s", "--format=%an%x00%ae%x00%s%x00%B", hash])?;
        let mut parts = meta.splitn(4, '\0');
        let name = parts.next().unwrap_or("");
        let email = parts.next().unwrap_or("");
        let subject = parts.next().unwrap_or("").to_string();
        let body = parts.next().unwrap_or("");
        commits.push(CommitInfo {
            short: hash.chars().take(8).collect(),
            tool: classify(name, email, body),
            added_lines: added_lines(hash),
            subject,
        });
    }
    Ok(commits)
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Computed provenance figures for a commit range.
struct Summary<'a> {
    range: &'a str,
    commits: &'a [CommitInfo],
    ai_commits: usize,
    human_commits: usize,
    ai_lines: usize,
    total_lines: usize,
    ai_line_pct: u64,
    by_tool: Vec<(String, usize)>,
}

pub fn run_provenance(opts: ProvenanceOpts) -> Result<()> {
    let range = format!("{}..HEAD", opts.base);
    let commits = collect_commits(&range)?;

    let ai_commits = commits.iter().filter(|c| c.tool.is_some()).count();
    let ai_lines: usize = commits
        .iter()
        .filter(|c| c.tool.is_some())
        .map(|c| c.added_lines)
        .sum();
    let total_lines: usize = commits.iter().map(|c| c.added_lines).sum();
    let ai_line_pct = if total_lines > 0 {
        (ai_lines as f64 / total_lines as f64 * 100.0).round() as u64
    } else {
        0
    };
    let mut by_tool: Vec<(String, usize)> = Vec::new();
    for c in &commits {
        if let Some(t) = &c.tool {
            match by_tool.iter_mut().find(|(name, _)| name == t) {
                Some((_, n)) => *n += 1,
                None => by_tool.push((t.clone(), 1)),
            }
        }
    }
    by_tool.sort_by_key(|(_, n)| std::cmp::Reverse(*n)); // most-used tool first

    let s = Summary {
        range: &range,
        commits: &commits,
        ai_commits,
        human_commits: commits.len() - ai_commits,
        ai_lines,
        total_lines,
        ai_line_pct,
        by_tool,
    };

    match opts.format.as_str() {
        "json" => emit_json(&s),
        "sarif" => emit_sarif(&s),
        _ => emit_text(&s),
    }

    // Gate applies regardless of output format.
    if let Some(max) = opts.max_ai_lines_pct {
        if ai_line_pct > max as u64 {
            return Err(anyhow::anyhow!(
                "Provenance gate: AI-authored code is {ai_line_pct}% of new lines, exceeding the {max}% ceiling."
            ));
        }
        if opts.format == "text" {
            terminal::success(&format!(
                "Provenance gate passed: {ai_line_pct}% AI-authored ≤ {max}% ceiling."
            ));
        }
    }

    Ok(())
}

fn emit_text(s: &Summary<'_>) {
    if s.commits.is_empty() {
        terminal::info(&format!(
            "Provenance: no commits in {} — nothing to analyse.",
            s.range
        ));
        return;
    }
    terminal::info(&format!(
        "Provenance: {} commit(s) in {}",
        s.commits.len(),
        s.range
    ));
    eprintln!(
        "  AI-authored:    {} commit(s)  ·  +{} line(s)",
        s.ai_commits, s.ai_lines
    );
    eprintln!(
        "  Human-authored: {} commit(s)  ·  +{} line(s)",
        s.human_commits,
        s.total_lines - s.ai_lines
    );
    eprintln!("  AI-authored share of new lines: {}%", s.ai_line_pct);
    if !s.by_tool.is_empty() {
        let summary: Vec<String> = s.by_tool.iter().map(|(t, n)| format!("{t} {n}")).collect();
        eprintln!("  By tool: {}", summary.join(", "));
    }
    eprintln!();
    for c in s.commits {
        eprintln!(
            "  {} [{:<14}] +{:<5} {}",
            c.short,
            c.tool.as_deref().unwrap_or("human"),
            c.added_lines,
            c.subject.chars().take(60).collect::<String>()
        );
    }
}

fn emit_json(s: &Summary<'_>) {
    let commits: Vec<Value> = s
        .commits
        .iter()
        .map(|c| {
            json!({
                "commit": c.short,
                "tool": c.tool,
                "ai_authored": c.tool.is_some(),
                "added_lines": c.added_lines,
                "subject": c.subject,
            })
        })
        .collect();
    let by_tool: serde_json::Map<String, Value> = s
        .by_tool
        .iter()
        .map(|(k, n)| (k.clone(), Value::from(*n)))
        .collect();
    let out = json!({
        "range": s.range,
        "total_commits": s.commits.len(),
        "ai_commits": s.ai_commits,
        "human_commits": s.human_commits,
        "ai_lines": s.ai_lines,
        "human_lines": s.total_lines - s.ai_lines,
        "ai_line_pct": s.ai_line_pct,
        "by_tool": by_tool,
        "commits": commits,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

fn emit_sarif(s: &Summary<'_>) {
    // One result per AI-authored commit. Provenance is commit-scoped, so results
    // carry the commit + tool in `properties` rather than a file location.
    let results: Vec<Value> = s
        .commits
        .iter()
        .filter(|c| c.tool.is_some())
        .map(|c| {
            let tool = c.tool.as_deref().unwrap_or("AI");
            json!({
                "ruleId": "ai-authored-code",
                "level": "note",
                "message": { "text": format!(
                    "Commit {} ({} +{} lines) was authored with {tool}.",
                    c.short, c.subject, c.added_lines
                )},
                "properties": { "commit": c.short, "tool": tool, "addedLines": c.added_lines }
            })
        })
        .collect();
    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "greengate-provenance",
                "rules": [{
                    "id": "ai-authored-code",
                    "name": "AiAuthoredCode",
                    "shortDescription": { "text": "Code authored by an AI assistant" }
                }]
            }},
            "results": results,
            "properties": {
                "range": s.range,
                "aiLinePct": s.ai_line_pct,
                "aiCommits": s.ai_commits,
                "totalCommits": s.commits.len()
            }
        }]
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_co_authored_by_trailer() {
        let msg = "Add feature\n\nCo-Authored-By: Claude <noreply@anthropic.com>";
        assert_eq!(classify("Dev", "dev@x.com", msg).as_deref(), Some("Claude"));
    }

    #[test]
    fn detects_copilot_and_cursor_trailers() {
        assert_eq!(
            classify(
                "Dev",
                "d@x",
                "x\n\nCo-authored-by: GitHub Copilot <bot@github>"
            )
            .as_deref(),
            Some("GitHub Copilot")
        );
        assert_eq!(
            classify("Dev", "d@x", "x\n\nAssisted-by: Cursor").as_deref(),
            Some("Cursor")
        );
    }

    #[test]
    fn detects_generated_with_marker() {
        let msg = "Refactor\n\n🤖 Generated with Claude Code";
        assert_eq!(classify("Dev", "d@x", msg).as_deref(), Some("Claude"));
    }

    #[test]
    fn detects_bot_author_identity() {
        assert_eq!(
            classify("aider", "aider@aider.chat", "tidy up").as_deref(),
            Some("Aider")
        );
    }

    #[test]
    fn plain_human_commit_is_none() {
        // Mentioning a tool in prose must NOT classify it as AI-authored.
        let msg = "Fix cursor position bug in the editor";
        assert_eq!(classify("Alice", "alice@example.com", msg), None);
    }
}
