/// `greengate ci-lint` — GitHub Actions workflow security linter.
///
/// Scans `.github/workflows/*.yml` for common CI pipeline attack vectors:
///
/// | Rule                             | Severity | Description                                    |
/// |----------------------------------|----------|------------------------------------------------|
/// | CI/UnpinnedAction                | medium   | `uses:` ref is a tag/branch, not a commit SHA  |
/// | CI/ExpressionInjection           | critical | User-controlled `${{...}}` in a run: step      |
/// | CI/PullRequestTargetWithCheckout | critical | `pull_request_target` + checkout of PR code    |
use crate::modules::scanner::{Severity, covering_ignore};
use crate::modules::suppress::{self, Policy};
use crate::report::{Check, Finding, Report, Suppression, SuppressionKind};
use crate::utils::output::ReportFormat;
use crate::utils::terminal;
use anyhow::Result;
use regex::Regex;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CiLintFinding {
    pub path: PathBuf,
    /// 1-based line number; 0 = whole-file (structural) finding.
    pub line: usize,
    pub rule_id: &'static str,
    pub message: String,
    pub severity: Severity,
}

pub struct CiLintOpts {
    pub format: ReportFormat,
    /// If Some, scan only this file. If None, auto-discover .github/workflows/.
    pub file: Option<String>,
    pub policy: Policy,
}

// ── Compiled regexes ──────────────────────────────────────────────────────────

/// Matches a `uses:` line and captures the action ref after `@`.
/// Handles both mapping keys (`uses: ...`) and list items (`- uses: ...`).
/// Group 1: everything before `@`; Group 2: the ref itself.
static RE_USES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:-\s+)?uses:\s+([^\s@]+)@([^\s#]+)").unwrap());

/// A "pinned" ref is a full 40-char commit SHA or `sha256:<64-hex>`.
static RE_PINNED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})$").unwrap());

/// User-controlled GitHub Actions expression contexts that enable script injection.
/// These values flow from untrusted PR/issue metadata and must not be used
/// directly inside `run:` steps.
static RE_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$\{\{[^}]*github\.(event\.pull_request\.(body|title|head\.ref|head\.label|base\.ref)|event\.issue\.(body|title)|event\.comment\.body|event\.review\.body|head_ref|base_ref)[^}]*\}\}",
    )
    .unwrap()
});

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_ci_lint(opts: CiLintOpts) -> Result<Report> {
    let mut report = Report::new("ci-lint");
    let files = match opts.file {
        Some(ref f) => vec![PathBuf::from(f)],
        None => find_workflow_files(),
    };

    if files.is_empty() {
        terminal::info("No GitHub Actions workflow files found (.github/workflows/*.yml)");
    } else {
        terminal::info(&format!(
            "CI lint: scanning {} workflow file(s)...",
            files.len()
        ));
    }

    let mut all_findings: Vec<CiLintFinding> = Vec::new();
    // Covered by a `# greengate: ignore` on the line or the line above.
    let mut inline: Vec<Finding> = Vec::new();
    for path in &files {
        match lint_workflow(path) {
            Ok(findings) => {
                let text = std::fs::read_to_string(path).unwrap_or_default();
                let lines: Vec<&str> = text.lines().collect();
                for f in findings {
                    let reason = (f.line > 0)
                        .then(|| covering_ignore(&lines, f.line - 1))
                        .flatten();
                    match reason {
                        Some(reason) => {
                            let mut r = Finding::in_file(
                                f.rule_id,
                                f.severity.into(),
                                &f.path,
                                f.line,
                                &f.message,
                            );
                            r.suppression = Some(Suppression::new(
                                SuppressionKind::Inline,
                                (!reason.is_empty()).then_some(reason),
                            ));
                            inline.push(r);
                        }
                        None => all_findings.push(f),
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⚠️  Skipping {}: {}", path.display(), e);
                report.checks.push(Check::incomplete(
                    format!("workflow:{}", path.display()),
                    format!("could not be linted: {e}"),
                ));
            }
        }
    }

    let mut found: Vec<Finding> = all_findings
        .iter()
        .map(|f| Finding::in_file(f.rule_id, f.severity.into(), &f.path, f.line, &f.message))
        .collect();
    let outcome = suppress::apply(
        &mut found,
        &suppress::Options {
            tool: "ci-lint",
            policy: opts.policy,
            matcher: None,
            base: None,
        },
    )?;
    let (active, gone) = suppress::partition(
        all_findings.into_iter().zip(found).collect(),
        &outcome.verdicts,
    );
    let (all_findings, active_findings): (Vec<CiLintFinding>, Vec<Finding>) =
        active.into_iter().unzip();
    report.findings = active_findings;
    report.suppressed = inline;
    report
        .suppressed
        .extend(gone.into_iter().map(|((_, mut f), s)| {
            f.suppression = Some(s);
            f
        }));
    report.warnings = outcome.warnings;

    // Structured formats always print a document, even an empty one, so
    // stdout stays parseable.
    match opts.format {
        ReportFormat::Json => emit_json(&all_findings)?,
        ReportFormat::Sarif => emit_sarif(&all_findings)?,
        ReportFormat::Text if all_findings.is_empty() => {
            if !files.is_empty() && report.unfinished().next().is_none() {
                terminal::success("CI lint: no issues found.");
            }
        }
        ReportFormat::Text => emit_text(&all_findings),
    }
    if opts.format == ReportFormat::Text {
        suppress::print_summary(&outcome.notes, &report.suppressed);
    }
    report.print_unfinished();
    Ok(report)
}

// ── File discovery ────────────────────────────────────────────────────────────

fn find_workflow_files() -> Vec<PathBuf> {
    let dir = std::path::Path::new(".github/workflows");
    if !dir.exists() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
        .collect();
    files.sort(); // deterministic order
    files
}

// ── Per-file linter ───────────────────────────────────────────────────────────

fn lint_workflow(path: &Path) -> Result<Vec<CiLintFinding>> {
    let content = std::fs::read_to_string(path)?;
    let mut findings: Vec<CiLintFinding> = Vec::new();

    // Rule 1 & 2: line-by-line pattern checks (gives accurate line numbers).
    findings.extend(check_line_patterns(path, &content));

    // Rule 3: structural check via YAML parsing (no line numbers available).
    findings.extend(check_prt_checkout(path, &content));

    Ok(findings)
}

// ── Rule 1 & 2: line-level checks ────────────────────────────────────────────

fn check_line_patterns(path: &Path, content: &str) -> Vec<CiLintFinding> {
    let mut findings = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let line_no = i + 1;

        // CI/UnpinnedAction — `uses:` with a non-SHA ref
        if let Some(caps) = RE_USES.captures(line) {
            let action = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let ref_part = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if !RE_PINNED.is_match(ref_part) && !action.starts_with("./") {
                findings.push(CiLintFinding {
                    path: path.to_path_buf(),
                    line: line_no,
                    rule_id: "CI/UnpinnedAction",
                    message: format!(
                        "Action `{action}` is pinned to `{ref_part}` (a mutable ref). \
                         Pin to a full commit SHA to prevent supply-chain attacks: \
                         `{action}@<40-char-sha>`."
                    ),
                    severity: Severity::Medium,
                });
            }
        }

        // CI/ExpressionInjection — user-controlled expression in any workflow line
        if RE_INJECTION.is_match(line) {
            findings.push(CiLintFinding {
                path: path.to_path_buf(),
                line: line_no,
                rule_id: "CI/ExpressionInjection",
                message: "User-controlled expression `${{ ... }}` used directly in workflow. \
                     An attacker can craft a PR/issue to inject arbitrary shell commands. \
                     Assign the value to an env var first: `env: SAFE: ${{ expr }}` \
                     then reference `$SAFE` in `run:`."
                    .to_string(),
                severity: Severity::Critical,
            });
        }
    }

    findings
}

// ── Rule 3: pull_request_target + unsafe checkout ────────────────────────────

/// Returns true if the YAML value tree contains `pull_request_target` anywhere
/// in the `on:` trigger section.
fn has_pull_request_target(on_value: &serde_norway::Value) -> bool {
    match on_value {
        serde_norway::Value::String(s) => s == "pull_request_target",
        serde_norway::Value::Sequence(seq) => seq.iter().any(has_pull_request_target),
        serde_norway::Value::Mapping(map) => map
            .keys()
            .any(|k| k.as_str() == Some("pull_request_target")),
        _ => false,
    }
}

/// Returns true if a step's `with.ref` value contains a pull-request head ref
/// expression — meaning the checkout will fetch untrusted PR code.
fn step_checks_out_pr_code(step: &serde_norway::Value) -> bool {
    let uses = step
        .get("uses")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if !uses.contains("checkout") {
        return false;
    }

    let ref_value = step
        .get("with")
        .and_then(|w| w.get("ref"))
        .and_then(|r| r.as_str())
        .unwrap_or_default();

    ref_value.contains("pull_request") || ref_value.contains("head_ref")
}

fn check_prt_checkout(path: &Path, content: &str) -> Vec<CiLintFinding> {
    let yaml: serde_norway::Value = match serde_norway::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Check the `on:` key for pull_request_target
    let on_value = match yaml.get("on") {
        Some(v) => v,
        None => return Vec::new(),
    };

    if !has_pull_request_target(on_value) {
        return Vec::new();
    }

    // Walk all jobs → steps looking for a checkout of PR code
    let Some(jobs) = yaml.get("jobs").and_then(|j| j.as_mapping()) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for (_job_name, job) in jobs {
        let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) else {
            continue;
        };
        for step in steps {
            if step_checks_out_pr_code(step) {
                findings.push(CiLintFinding {
                    path: path.to_path_buf(),
                    line: 0,
                    rule_id: "CI/PullRequestTargetWithCheckout",
                    message: "Workflow uses `pull_request_target` (runs with write permissions) \
                              AND checks out PR head code. This allows a malicious PR to execute \
                              arbitrary code with repo write access. Either remove the `ref:` \
                              override, or switch to `pull_request` trigger."
                        .to_string(),
                    severity: Severity::Critical,
                });
                break; // one finding per file is enough
            }
        }
    }

    findings
}

// ── Output formatters ─────────────────────────────────────────────────────────

fn emit_text(findings: &[CiLintFinding]) {
    eprintln!("\n  🚨 CI lint: {} issue(s) found:\n", findings.len());
    for f in findings {
        let loc = if f.line > 0 {
            format!("{}:{}", f.path.display(), f.line)
        } else {
            f.path.display().to_string()
        };
        eprintln!(
            "  [{}] [{}] {}\n    {}\n",
            f.severity.as_str().to_uppercase(),
            f.rule_id,
            loc,
            f.message
        );
    }
}

fn emit_json(findings: &[CiLintFinding]) -> Result<()> {
    let out = json!({
        "total": findings.len(),
        "findings": findings.iter().map(|f| json!({
            "rule":     f.rule_id,
            "severity": f.severity,
            "file":     f.path.to_string_lossy(),
            "line":     f.line,
            "message":  f.message,
        })).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn emit_sarif(findings: &[CiLintFinding]) -> Result<()> {
    use std::collections::BTreeSet;
    let mut rule_ids: BTreeSet<&str> = BTreeSet::new();
    for f in findings {
        rule_ids.insert(f.rule_id);
    }
    let rules: Vec<_> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": format!("{} detected", id) },
                "helpUri": "https://github.com/greengate-dev/greengate"
            })
        })
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let level = f.severity.sarif_level();
            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": &f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.path.to_string_lossy(),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": { "startLine": if f.line > 0 { f.line } else { 1 } }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "greengate",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/greengate-dev/greengate",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn path() -> PathBuf {
        PathBuf::from(".github/workflows/ci.yml")
    }

    // ── CI/UnpinnedAction ─────────────────────────────────────────────────────

    #[test]
    fn unpinned_version_tag_is_flagged() {
        let content = "      - uses: actions/checkout@v4\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            findings.iter().any(|f| f.rule_id == "CI/UnpinnedAction"),
            "version tag @v4 should be flagged"
        );
    }

    #[test]
    fn unpinned_major_tag_is_flagged() {
        let content = "      - uses: actions/setup-node@v4.1.0\n";
        let findings = check_line_patterns(&path(), content);
        assert!(findings.iter().any(|f| f.rule_id == "CI/UnpinnedAction"));
    }

    #[test]
    fn unpinned_branch_ref_is_flagged() {
        let content = "      - uses: some-org/some-action@main\n";
        let findings = check_line_patterns(&path(), content);
        assert!(findings.iter().any(|f| f.rule_id == "CI/UnpinnedAction"));
    }

    #[test]
    fn pinned_sha_is_not_flagged() {
        // 40-char SHA
        let content = "      - uses: actions/checkout@7884fcad6a5eada6a4e4b48a17fef4e1f8b7a3b4\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            !findings.iter().any(|f| f.rule_id == "CI/UnpinnedAction"),
            "pinned SHA should not be flagged"
        );
    }

    #[test]
    fn local_action_ref_not_flagged() {
        let content = "      - uses: ./.github/actions/my-action\n";
        let findings = check_line_patterns(&path(), content);
        assert!(!findings.iter().any(|f| f.rule_id == "CI/UnpinnedAction"));
    }

    // ── CI/ExpressionInjection ────────────────────────────────────────────────

    #[test]
    fn pr_body_injection_is_flagged() {
        let content = "      - run: echo \"${{ github.event.pull_request.body }}\"\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CI/ExpressionInjection")
        );
    }

    #[test]
    fn pr_title_injection_is_flagged() {
        let content = "      - run: echo \"${{ github.event.pull_request.title }}\"\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CI/ExpressionInjection")
        );
    }

    #[test]
    fn head_ref_injection_is_flagged() {
        let content = "        run: git checkout ${{ github.head_ref }}\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CI/ExpressionInjection")
        );
    }

    #[test]
    fn safe_expression_not_flagged() {
        // github.sha and github.actor are not user-controlled injection vectors
        let content = "      - run: echo ${{ github.sha }}\n";
        let findings = check_line_patterns(&path(), content);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "CI/ExpressionInjection")
        );
    }

    // ── CI/PullRequestTargetWithCheckout ──────────────────────────────────────

    #[test]
    fn prt_with_pr_checkout_is_flagged() {
        let content = r#"
on: pull_request_target

jobs:
  build:
    steps:
      - uses: actions/checkout@7884fcad6a5eada6a4e4b48a17fef4e1f8b7a3b4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#;
        let findings = check_prt_checkout(&path(), content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CI/PullRequestTargetWithCheckout")
        );
    }

    #[test]
    fn prt_without_checkout_ref_is_clean() {
        let content = r#"
on: pull_request_target

jobs:
  build:
    steps:
      - uses: actions/checkout@7884fcad6a5eada6a4e4b48a17fef4e1f8b7a3b4
"#;
        let findings = check_prt_checkout(&path(), content);
        assert!(findings.is_empty());
    }

    #[test]
    fn pull_request_trigger_not_flagged() {
        // `pull_request` (read-only) is safe; only `pull_request_target` is risky
        let content = r#"
on: pull_request

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#;
        let findings = check_prt_checkout(&path(), content);
        assert!(findings.is_empty());
    }
}
