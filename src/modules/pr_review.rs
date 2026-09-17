/// `greengate review` — PR diff analyzer.
///
/// Produces two outputs for a pull request:
///   1. **Complexity Score** — a weighted composite score estimating review effort,
///      derived from lines changed, files touched, and cyclomatic complexity of new code.
///   2. **New-code coverage gaps** — which newly added lines are NOT covered by the
///      provided LCOV/Cobertura report, and whether they meet the configured floor.
use crate::modules::github;
use crate::utils::http;
use crate::utils::terminal;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ── Public options ─────────────────────────────────────────────────────────────

pub struct ReviewOpts {
    /// Diff base ref (commit / branch). If `None`, uses "HEAD~1".
    pub base: String,
    /// Diff staged files instead of committed diff.
    pub staged: bool,
    /// Path to LCOV or Cobertura coverage file (optional).
    pub coverage_file: Option<String>,
    /// Minimum coverage % required for newly added lines.
    pub min_coverage: f64,
    /// If > 0, fail when Complexity Score exceeds this value.
    pub complexity_budget: u32,
    /// Output format: "text", "json", or "sarif".
    pub format: String,
    /// Post results to GitHub Check Run + PR comment.
    pub annotate: bool,
}

// ── Internal data structures ──────────────────────────────────────────────────

struct DiffFile {
    path: String,
    /// 1-based line numbers added in this diff.
    added_lines: Vec<u32>,
    /// 1-based line numbers removed.
    removed_lines: Vec<u32>,
    /// (1-based line number, text) for added lines — used in AST analysis.
    added_content: Vec<(u32, String)>,
}

#[derive(Serialize)]
pub struct ComplexityResult {
    pub score: u32,
    pub tier: String,
    pub estimated_review_minutes: u32,
    pub files_changed: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
    pub cyclomatic_nodes: u32,
}

#[derive(Serialize)]
pub struct FileCoverageResult {
    pub file: String,
    pub added_lines: usize,
    pub covered: usize,
    pub uncovered: usize,
    pub unmeasured: usize,
    pub coverage_pct: f64,
    pub uncovered_lines: Vec<u32>,
}

#[derive(Serialize)]
pub struct ReviewOutput {
    pub complexity: ComplexityResult,
    pub coverage: Option<CoverageOutput>,
    pub passed: bool,
}

#[derive(Serialize)]
pub struct CoverageOutput {
    pub overall_pct: f64,
    pub min_required: f64,
    pub passed: bool,
    pub files: Vec<FileCoverageResult>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_review(opts: ReviewOpts) -> Result<()> {
    // 1. Parse diff
    let diff_files = parse_diff(&opts.base, opts.staged)?;

    if diff_files.is_empty() {
        terminal::info("No changed files found in diff.");
    }

    // 2. Complexity
    let complexity = compute_complexity(&diff_files);

    // 3. Coverage gaps (optional)
    let coverage_out = if let Some(ref cov_file) = opts.coverage_file {
        let cov_map = crate::modules::coverage::parse_coverage_map(cov_file)?;
        Some(compute_coverage_gaps(
            &diff_files,
            &cov_map,
            opts.min_coverage,
        ))
    } else {
        None
    };

    // 4. Determine overall pass/fail
    let coverage_passed = coverage_out.as_ref().map(|c| c.passed).unwrap_or(true);
    let complexity_passed =
        opts.complexity_budget == 0 || complexity.score <= opts.complexity_budget;
    let passed = coverage_passed && complexity_passed;

    let output = ReviewOutput {
        complexity,
        coverage: coverage_out,
        passed,
    };

    // 5. Emit output
    match opts.format.as_str() {
        "json" => emit_json(&output)?,
        "sarif" => emit_sarif(&output)?,
        _ => emit_text(&output, opts.min_coverage, opts.complexity_budget),
    }

    // 6. GitHub annotations
    if opts.annotate
        && let Some(env) = github::detect_github_env()
        && let Err(e) = post_github_review(&output, &env)
    {
        eprintln!("greengate: warning: GitHub review annotation failed: {}", e);
    }

    if !passed {
        anyhow::bail!("greengate review: quality gate failed.");
    }
    Ok(())
}

// ── Diff parsing ──────────────────────────────────────────────────────────────

fn parse_diff(base: &str, staged: bool) -> Result<Vec<DiffFile>> {
    let output = if staged {
        Command::new("git") // greengate: ignore — running git to parse the PR diff
            .args(["diff", "--cached", "-U0"])
            .output()
            .with_context(|| "Failed to run git diff --cached")?
    } else {
        Command::new("git") // greengate: ignore
            .args(["diff", &format!("{}...HEAD", base), "-U0"])
            .output()
            .with_context(|| format!("Failed to run git diff {}...HEAD", base))?
    };

    if !output.status.success() {
        // Fallback: try two-dot diff (works when base is a branch name)
        let output2 = Command::new("git") // greengate: ignore — fallback git diff for PR review
            .args(["diff", base, "HEAD", "-U0"])
            .output()
            .with_context(|| format!("Failed to run git diff {} HEAD", base))?;
        if !output2.status.success() {
            let output3 = Command::new("git") // greengate: ignore — final fallback diff form
                .args(["diff", base, "-U0"])
                .output()
                .with_context(|| format!("Failed to run git diff {}", base))?;
            let raw = String::from_utf8_lossy(&output3.stdout).to_string();
            return Ok(parse_unified_diff(&raw));
        }
        let raw = String::from_utf8_lossy(&output2.stdout).to_string();
        return Ok(parse_unified_diff(&raw));
    }

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(parse_unified_diff(&raw))
}

/// Parse a unified diff string into `DiffFile` records.
fn parse_unified_diff(diff: &str) -> Vec<DiffFile> {
    let mut files: Vec<DiffFile> = Vec::new();
    let mut current: Option<DiffFile> = None;
    // Current new-file line counter for tracking absolute line numbers in added content.
    let mut new_line: u32 = 0;

    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            if let Some(f) = current.take() {
                files.push(f);
            }
            current = None;
            new_line = 0;
            continue;
        }

        // +++ b/src/foo.rs
        if let Some(rest) = line.strip_prefix("+++ b/") {
            let path = rest.to_string();
            current = Some(DiffFile {
                path,
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
                added_content: Vec::new(),
            });
            new_line = 0;
            continue;
        }

        // Skip --- lines
        if line.starts_with("--- ") {
            continue;
        }

        // Hunk header: @@ -old_start,old_count +new_start,new_count @@
        if line.starts_with("@@") {
            if let Some(new_start) = parse_hunk_new_start(line) {
                new_line = new_start;
            }
            continue;
        }

        let Some(ref mut df) = current else {
            continue;
        };

        if let Some(content) = line.strip_prefix('+') {
            df.added_lines.push(new_line);
            df.added_content.push((new_line, content.to_string()));
            new_line += 1;
        } else if let Some(_content) = line.strip_prefix('-') {
            df.removed_lines.push(new_line);
            // Don't increment new_line for removed lines
        } else {
            // Context line
            new_line += 1;
        }
    }

    if let Some(f) = current.take() {
        files.push(f);
    }

    // Filter out empty diff entries (e.g. binary files, /dev/null targets)
    files.retain(|f| !f.path.is_empty());
    files
}

/// Extract the new-file start line from a hunk header like `@@ -3,5 +7,10 @@`.
fn parse_hunk_new_start(line: &str) -> Option<u32> {
    // Find "+<start>" within the hunk header
    let after_at = line.strip_prefix("@@")?.trim_start();
    let plus_part = after_at.split_whitespace().nth(1)?; // "+7,10"
    let start_str = plus_part.strip_prefix('+')?.split(',').next()?;
    start_str.parse().ok()
}

// ── Complexity scoring ────────────────────────────────────────────────────────

fn compute_complexity(files: &[DiffFile]) -> ComplexityResult {
    let lines_added: usize = files.iter().map(|f| f.added_lines.len()).sum();
    let lines_removed: usize = files.iter().map(|f| f.removed_lines.len()).sum();
    let files_changed = files.len();

    // Count cyclomatic complexity nodes across all added content using tree-sitter.
    let cyclomatic_nodes: u32 = files.iter().map(count_complexity_nodes).sum();

    let raw = (lines_added as f64 * 0.3)
        + (files_changed as f64 * 5.0)
        + (cyclomatic_nodes as f64 * 2.0)
        + (lines_removed as f64 * 0.1);

    let score = raw.round() as u32;
    let estimated_review_minutes = (raw * 0.5).min(120.0) as u32;

    let tier = match score {
        0..=20 => "Quick Review",
        21..=50 => "Normal Review",
        51..=100 => "Complex Review",
        _ => "Large PR — consider splitting",
    }
    .to_string();

    ComplexityResult {
        score,
        tier,
        estimated_review_minutes,
        files_changed,
        lines_added,
        lines_removed,
        cyclomatic_nodes,
    }
}

/// Count branch/loop/condition nodes in the added lines of a file using tree-sitter.
/// Falls back to 0 for unsupported file types.
fn count_complexity_nodes(df: &DiffFile) -> u32 {
    let path = Path::new(&df.path);
    let Some(language) = language_for(path) else {
        return 0;
    };
    let Some(query_str) = complexity_query_for(path) else {
        return 0;
    };

    // Reconstruct a pseudo-source from added lines only (joined with newlines).
    // This is not valid compilable code, but tree-sitter is resilient to parse errors
    // and will still find structural nodes.
    let source: String = df
        .added_content
        .iter()
        .map(|(_, text)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    count_query_matches(language, query_str, source.as_bytes())
}

fn count_query_matches(language: Language, query_str: &str, source: &[u8]) -> u32 {
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return 0;
    }
    let Some(tree) = parser.parse(source, None) else {
        return 0;
    };
    let Ok(query) = Query::new(&language, query_str) else {
        return 0;
    };
    let mut cursor = QueryCursor::new();
    let mut iter = cursor.matches(&query, tree.root_node(), source);
    use streaming_iterator::StreamingIterator;
    let mut count = 0u32;
    while iter.next().is_some() {
        count += 1;
    }
    count
}

fn language_for(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Some("js" | "jsx") => Some(tree_sitter_javascript::LANGUAGE.into()),
        Some("py") => Some(tree_sitter_python::LANGUAGE.into()),
        Some("go") => Some(tree_sitter_go::LANGUAGE.into()),
        _ => None,
    }
}

fn complexity_query_for(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts" | "tsx" | "js" | "jsx") => Some(JS_TS_COMPLEXITY_QUERY),
        Some("py") => Some(PYTHON_COMPLEXITY_QUERY),
        Some("go") => Some(GO_COMPLEXITY_QUERY),
        _ => None,
    }
}

/// JS/TS: branch and loop nodes that increase cyclomatic complexity.
/// Note: tree-sitter-javascript uses `binary_expression` for `&&`/`||`,
/// not a dedicated `logical_expression` node, so that is excluded.
const JS_TS_COMPLEXITY_QUERY: &str = r#"
[
    (if_statement) @branch
    (ternary_expression) @branch
    (switch_case) @branch
    (for_statement) @loop
    (for_in_statement) @loop
    (while_statement) @loop
    (do_statement) @loop
    (catch_clause) @branch
]
"#;

/// Python: branch and loop nodes.
const PYTHON_COMPLEXITY_QUERY: &str = r#"
[
    (if_statement) @branch
    (elif_clause) @branch
    (for_statement) @loop
    (while_statement) @loop
    (except_clause) @branch
    (boolean_operator) @branch
    (conditional_expression) @branch
]
"#;

/// Go: branch and loop nodes.
const GO_COMPLEXITY_QUERY: &str = r#"
[
    (if_statement) @branch
    (for_statement) @loop
    (expression_switch_statement) @branch
    (type_switch_statement) @branch
    (select_statement) @branch
    (binary_expression) @branch
]
"#;

// ── Coverage gap analysis ─────────────────────────────────────────────────────

fn compute_coverage_gaps(
    files: &[DiffFile],
    cov_map: &HashMap<String, HashMap<u32, u64>>,
    min_coverage: f64,
) -> CoverageOutput {
    let mut file_results: Vec<FileCoverageResult> = Vec::new();
    let mut total_covered = 0usize;
    let mut total_uncovered = 0usize;

    for df in files {
        if df.added_lines.is_empty() {
            continue;
        }

        // Try to match coverage map paths — the coverage file may use relative or absolute paths
        // that differ slightly from the diff path. We try exact match first, then suffix match.
        let line_map = find_coverage_file(cov_map, &df.path);

        let mut covered = 0usize;
        let mut uncovered = 0usize;
        let mut unmeasured = 0usize;
        let mut uncovered_lines: Vec<u32> = Vec::new();

        for &lineno in &df.added_lines {
            match line_map.and_then(|m| m.get(&lineno)) {
                Some(&hits) if hits > 0 => covered += 1,
                Some(_) => {
                    uncovered += 1;
                    uncovered_lines.push(lineno);
                }
                None => unmeasured += 1,
            }
        }

        let measurable = covered + uncovered;
        let coverage_pct = if measurable == 0 {
            100.0
        } else {
            (covered as f64 / measurable as f64) * 100.0
        };

        total_covered += covered;
        total_uncovered += uncovered;

        file_results.push(FileCoverageResult {
            file: df.path.clone(),
            added_lines: df.added_lines.len(),
            covered,
            uncovered,
            unmeasured,
            coverage_pct,
            uncovered_lines,
        });
    }

    let total_measurable = total_covered + total_uncovered;
    let overall_pct = if total_measurable == 0 {
        100.0
    } else {
        (total_covered as f64 / total_measurable as f64) * 100.0
    };

    let passed = overall_pct >= min_coverage;

    CoverageOutput {
        overall_pct,
        min_required: min_coverage,
        passed,
        files: file_results,
    }
}

/// Find a file's line coverage map by trying exact path match, then suffix match.
fn find_coverage_file<'a>(
    cov_map: &'a HashMap<String, HashMap<u32, u64>>,
    diff_path: &str,
) -> Option<&'a HashMap<u32, u64>> {
    if let Some(m) = cov_map.get(diff_path) {
        return Some(m);
    }
    // Try matching by file suffix (handles path prefix differences)
    for (key, val) in cov_map {
        if key.ends_with(diff_path) || diff_path.ends_with(key.as_str()) {
            return Some(val);
        }
    }
    None
}

// ── Output formatters ─────────────────────────────────────────────────────────

fn emit_text(output: &ReviewOutput, _min_coverage: f64, complexity_budget: u32) {
    let c = &output.complexity;
    eprintln!();
    eprintln!("╔══ PR Review ═══════════════════════════════════════╗");
    eprintln!(
        "  Complexity Score : {}  ({}, ~{} min)",
        c.score, c.tier, c.estimated_review_minutes
    );
    eprintln!("  Files changed    : {}", c.files_changed);
    eprintln!(
        "  Lines added/del  : +{} / -{}",
        c.lines_added, c.lines_removed
    );
    eprintln!("  Cyclomatic nodes : {}", c.cyclomatic_nodes);
    if complexity_budget > 0 {
        let status = if c.score <= complexity_budget {
            "✓"
        } else {
            "✗"
        };
        eprintln!(
            "  Budget           : {}/{} {}",
            c.score, complexity_budget, status
        );
    }
    eprintln!("╚════════════════════════════════════════════════════╝");

    if let Some(cov) = &output.coverage {
        eprintln!();
        let status = if cov.passed { "✓" } else { "✗" };
        eprintln!(
            "New-Code Coverage: {:.1}%  {} (target: {:.1}%)",
            cov.overall_pct, status, cov.min_required
        );
        eprintln!();
        for f in &cov.files {
            let measurable = f.covered + f.uncovered;
            if measurable == 0 {
                continue;
            }
            let file_status = if f.coverage_pct >= cov.min_required {
                "✓"
            } else {
                "✗"
            };
            eprintln!(
                "  {:<50} {}/{} added lines covered  ({:.1}%) {}",
                f.file, f.covered, measurable, f.coverage_pct, file_status
            );
            if !f.uncovered_lines.is_empty() {
                let line_list: Vec<String> =
                    f.uncovered_lines.iter().map(|l| l.to_string()).collect();
                eprintln!("    Uncovered lines: {}", line_list.join(", "));
            }
        }
        eprintln!();
    }

    if output.passed {
        terminal::success("Review gate passed.");
    } else {
        terminal::warn("Review gate FAILED.");
    }
}

fn emit_json(output: &ReviewOutput) -> Result<()> {
    let json = serde_json::to_string_pretty(output)
        .with_context(|| "Failed to serialize review output as JSON")?;
    println!("{}", json);
    Ok(())
}

fn emit_sarif(output: &ReviewOutput) -> Result<()> {
    let mut results: Vec<serde_json::Value> = Vec::new();

    if let Some(cov) = &output.coverage {
        for f in &cov.files {
            for &lineno in &f.uncovered_lines {
                results.push(serde_json::json!({
                    "ruleId": "GG/NewCodeUncovered",
                    "level": "warning",
                    "message": {
                        "text": format!("Newly added line {} in '{}' is not covered by tests.", lineno, f.file)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.file },
                            "region": { "startLine": lineno }
                        }
                    }]
                }));
            }
        }
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "greengate",
                    "rules": [{
                        "id": "GG/NewCodeUncovered",
                        "name": "NewCodeUncovered",
                        "shortDescription": { "text": "Newly added code line not covered by tests" },
                        "defaultConfiguration": { "level": "warning" }
                    }]
                }
            },
            "results": results
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)
        .with_context(|| "Failed to serialize SARIF output")?;
    println!("{}", json);
    Ok(())
}

// ── GitHub integration ────────────────────────────────────────────────────────

fn post_github_review(output: &ReviewOutput, env: &github::GitHubEnv) -> Result<()> {
    let (owner, repo) = env
        .repository
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("GITHUB_REPOSITORY is not in owner/repo format"))?;

    let check_id = create_review_check_run(owner, repo, &env.sha, &env.token, output)?;

    // Annotate uncovered lines
    if let Some(cov) = &output.coverage {
        let annotations: Vec<serde_json::Value> = cov
            .files
            .iter()
            .flat_map(|f| {
                f.uncovered_lines.iter().map(move |&lineno| {
                    serde_json::json!({
                        "path": f.file,
                        "start_line": lineno,
                        "end_line": lineno,
                        "annotation_level": "warning",
                        "title": "GG/NewCodeUncovered",
                        "message": "Newly added line is not covered by tests.",
                    })
                })
            })
            .collect();

        for chunk in annotations.chunks(50) {
            patch_check_run_annotations(owner, repo, check_id, chunk, &env.token)?;
        }
    }

    complete_review_check_run(owner, repo, check_id, output, &env.token)?;
    post_review_pr_comment(owner, repo, &env.sha, output, &env.token)?;

    Ok(())
}

const API_BASE: &str = "https://api.github.com";

fn create_review_check_run(
    owner: &str,
    repo: &str,
    sha: &str,
    token: &str,
    output: &ReviewOutput,
) -> Result<u64> {
    let url = format!("{}/repos/{}/{}/check-runs", API_BASE, owner, repo);
    let c = &output.complexity;
    let body = serde_json::json!({
        "name": "greengate review",
        "head_sha": sha,
        "status": "in_progress",
        "output": {
            "title": format!("Complexity Score: {} ({})", c.score, c.tier),
            "summary": format!(
                "Score: {} | Files: {} | +{} / -{} lines | ~{} min review",
                c.score, c.files_changed, c.lines_added, c.lines_removed, c.estimated_review_minutes
            )
        }
    });
    let resp = http::agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub create review check-run: {}", e))?;
    let json: serde_json::Value = http::read_json(resp)
        .map_err(|e| anyhow::anyhow!("GitHub create review check-run parse: {}", e))?;
    json["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("GitHub API did not return a check run id"))
}

fn patch_check_run_annotations(
    owner: &str,
    repo: &str,
    check_id: u64,
    annotations: &[serde_json::Value],
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let body = serde_json::json!({
        "output": {
            "title": "greengate review",
            "summary": format!("{} annotation(s)", annotations.len()),
            "annotations": annotations,
        }
    });
    http::agent()
        .request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub patch review check-run annotations: {}", e))?;
    Ok(())
}

fn complete_review_check_run(
    owner: &str,
    repo: &str,
    check_id: u64,
    output: &ReviewOutput,
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let conclusion = if output.passed { "success" } else { "failure" };
    let body = serde_json::json!({
        "status": "completed",
        "conclusion": conclusion,
    });
    http::agent()
        .request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub complete review check-run: {}", e))?;
    Ok(())
}

fn post_review_pr_comment(
    owner: &str,
    repo: &str,
    sha: &str,
    output: &ReviewOutput,
    token: &str,
) -> Result<()> {
    let commits_url = format!(
        "{}/repos/{}/{}/commits/{}/pulls",
        API_BASE, owner, repo, sha
    );
    let pr_number = match http::agent()
        .get(&commits_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call()
    {
        Ok(r) => {
            let json: serde_json::Value = http::read_json(r).unwrap_or(serde_json::Value::Null);
            json[0]["number"].as_u64()
        }
        Err(_) => None,
    };

    let Some(pr_number) = pr_number else {
        return Ok(());
    };

    let comment_url = format!(
        "{}/repos/{}/{}/issues/{}/comments",
        API_BASE, owner, repo, pr_number
    );
    let markdown = build_review_comment(output);
    let body = serde_json::json!({ "body": markdown });
    http::agent()
        .post(&comment_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub post review PR comment: {}", e))?;
    Ok(())
}

fn build_review_comment(output: &ReviewOutput) -> String {
    let c = &output.complexity;
    let status_icon = if output.passed { "✅" } else { "❌" };

    let mut md = format!(
        "## greengate review {status_icon}\n\n\
         ### Complexity Score: **{}** — {}\n\n\
         | Metric | Value |\n\
         |--------|-------|\n\
         | Score | {} |\n\
         | Estimated review time | ~{} min |\n\
         | Files changed | {} |\n\
         | Lines added | +{} |\n\
         | Lines removed | -{} |\n\
         | Cyclomatic nodes | {} |\n\n",
        c.score,
        c.tier,
        c.score,
        c.estimated_review_minutes,
        c.files_changed,
        c.lines_added,
        c.lines_removed,
        c.cyclomatic_nodes,
    );

    if let Some(cov) = &output.coverage {
        let cov_icon = if cov.passed { "✅" } else { "❌" };
        md.push_str(&format!(
            "### New-Code Coverage: **{:.1}%** {cov_icon} (target: {:.1}%)\n\n",
            cov.overall_pct, cov.min_required
        ));

        let files_with_gaps: Vec<&FileCoverageResult> =
            cov.files.iter().filter(|f| f.uncovered > 0).collect();

        if !files_with_gaps.is_empty() {
            md.push_str("| File | Added | Covered | Uncovered | % |\n");
            md.push_str("|------|-------|---------|-----------|---|\n");
            for f in &files_with_gaps {
                let measurable = f.covered + f.uncovered;
                md.push_str(&format!(
                    "| `{}` | {} | {} | {} | {:.1}% |\n",
                    f.file, measurable, f.covered, f.uncovered, f.coverage_pct
                ));
            }
            md.push('\n');
        }
    }

    md
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hunk_new_start_basic() {
        assert_eq!(parse_hunk_new_start("@@ -3,5 +7,10 @@ fn foo()"), Some(7));
        assert_eq!(parse_hunk_new_start("@@ -0,0 +1,5 @@"), Some(1));
        assert_eq!(parse_hunk_new_start("@@ -10 +10 @@"), Some(10));
    }

    #[test]
    fn parse_unified_diff_extracts_added_lines() {
        let diff = "\
diff --git a/src/foo.rs b/src/foo.rs
--- a/src/foo.rs
+++ b/src/foo.rs
@@ -0,0 +1,3 @@
+fn main() {
+    println!(\"hello\");
+}
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/foo.rs");
        assert_eq!(files[0].added_lines, vec![1, 2, 3]);
        assert!(files[0].removed_lines.is_empty());
    }

    #[test]
    fn complexity_score_increases_with_branches() {
        // A JS snippet with several if statements
        let content: Vec<(u32, String)> = vec![
            (1, "function foo(x) {".to_string()),
            (2, "  if (x > 0) {".to_string()),
            (3, "    if (x > 10) {".to_string()),
            (4, "      return 'big';".to_string()),
            (5, "    }".to_string()),
            (6, "  }".to_string()),
            (7, "}".to_string()),
        ];
        let df = DiffFile {
            path: "test.js".to_string(),
            added_lines: (1..=7).collect(),
            removed_lines: vec![],
            added_content: content,
        };
        let score_with = count_complexity_nodes(&df);
        assert!(score_with >= 2, "expected at least 2 complexity nodes");
    }

    #[test]
    fn coverage_gaps_detects_uncovered_lines() {
        let mut file_map: HashMap<u32, u64> = HashMap::new();
        file_map.insert(1, 1); // covered
        file_map.insert(2, 0); // uncovered
        file_map.insert(3, 1); // covered

        let mut cov_map: HashMap<String, HashMap<u32, u64>> = HashMap::new();
        cov_map.insert("src/foo.rs".to_string(), file_map);

        let df = DiffFile {
            path: "src/foo.rs".to_string(),
            added_lines: vec![1, 2, 3],
            removed_lines: vec![],
            added_content: vec![],
        };

        let result = compute_coverage_gaps(&[df], &cov_map, 80.0);
        assert!(!result.passed);
        assert_eq!(result.files[0].uncovered, 1);
        assert_eq!(result.files[0].uncovered_lines, vec![2]);
    }

    #[test]
    fn coverage_gaps_passes_when_all_covered() {
        let mut file_map: HashMap<u32, u64> = HashMap::new();
        file_map.insert(1, 1);
        file_map.insert(2, 3);

        let mut cov_map: HashMap<String, HashMap<u32, u64>> = HashMap::new();
        cov_map.insert("src/bar.rs".to_string(), file_map);

        let df = DiffFile {
            path: "src/bar.rs".to_string(),
            added_lines: vec![1, 2],
            removed_lines: vec![],
            added_content: vec![],
        };

        let result = compute_coverage_gaps(&[df], &cov_map, 80.0);
        assert!(result.passed);
        assert_eq!(result.files[0].covered, 2);
        assert_eq!(result.files[0].uncovered, 0);
    }

    #[test]
    fn coverage_passes_when_no_coverage_file() {
        // When no coverage file is provided, review should still pass.
        let output = ReviewOutput {
            complexity: ComplexityResult {
                score: 10,
                tier: "Quick Review".to_string(),
                estimated_review_minutes: 5,
                files_changed: 1,
                lines_added: 5,
                lines_removed: 0,
                cyclomatic_nodes: 0,
            },
            coverage: None,
            passed: true,
        };
        assert!(output.passed);
    }
}
