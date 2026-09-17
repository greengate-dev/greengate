use crate::modules::scanner::Finding;
use crate::utils::http;
use anyhow::Result;

// ── Environment detection ─────────────────────────────────────────────────────

pub struct GitHubEnv {
    pub token: String,
    pub repository: String, // "owner/repo"
    pub sha: String,
}

/// Returns `Some(GitHubEnv)` when all three required env vars are present.
pub fn detect_github_env() -> Option<GitHubEnv> {
    detect_github_env_from(|key| std::env::var(key).ok())
}

/// The detection logic, over an arbitrary variable lookup.
///
/// Split out so tests can exercise it without mutating the process environment.
/// `std::env::set_var` carries a safety contract that `cargo test` cannot honour:
/// tests run on parallel threads, so one test's write races every other test's
/// read. Injecting the lookup sidesteps the problem instead of asserting it away.
fn detect_github_env_from(lookup: impl Fn(&str) -> Option<String>) -> Option<GitHubEnv> {
    Some(GitHubEnv {
        token: lookup("GITHUB_TOKEN")?,
        repository: lookup("GITHUB_REPOSITORY")?,
        sha: lookup("GITHUB_SHA")?,
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Create a GitHub Check Run, annotate it with findings (batched in chunks of
/// 50 per the API limit), mark it complete, and post a PR review comment.
///
/// Failures are non-fatal: the caller logs a warning and continues.
pub fn annotate(findings: &[Finding], env: &GitHubEnv) -> Result<()> {
    let (owner, repo) = env
        .repository
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("GITHUB_REPOSITORY is not in owner/repo format"))?;

    let check_id = create_check_run(owner, repo, &env.sha, &env.token)?;

    // GitHub limits 50 annotations per PATCH call.
    for chunk in findings.chunks(50) {
        update_check_run_annotations(owner, repo, check_id, chunk, &env.token)?;
    }

    complete_check_run(owner, repo, check_id, findings.len(), &env.token)?;

    post_pr_summary_comment(owner, repo, &env.sha, findings, &env.token)?;

    Ok(())
}

// ── GitHub API helpers ────────────────────────────────────────────────────────

const API_BASE: &str = "https://api.github.com";

fn create_check_run(owner: &str, repo: &str, sha: &str, token: &str) -> Result<u64> {
    let url = format!("{}/repos/{}/{}/check-runs", API_BASE, owner, repo);
    let body = serde_json::json!({
        "name": "greengate",
        "head_sha": sha,
        "status": "in_progress",
    });
    let resp = http::agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub create check-run: {}", e))?;
    let json: serde_json::Value = http::read_json(resp)
        .map_err(|e| anyhow::anyhow!("GitHub create check-run parse: {}", e))?;
    json["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("GitHub API did not return a check run id"))
}

fn update_check_run_annotations(
    owner: &str,
    repo: &str,
    check_id: u64,
    chunk: &[Finding],
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let annotations: Vec<serde_json::Value> = chunk
        .iter()
        .map(|f| {
            let level = match f.severity.as_str() {
                "critical" | "high" => "failure",
                "medium" => "warning",
                _ => "notice",
            };
            serde_json::json!({
                "path": f.path.to_string_lossy(),
                "start_line": f.line,
                "end_line": f.line,
                "annotation_level": level,
                "title": &f.rule_id,
                "message": format!("[{}] Potential security issue detected.", f.rule_id),
            })
        })
        .collect();
    let body = serde_json::json!({
        "output": {
            "title": "greengate scan",
            "summary": format!("{} finding(s)", chunk.len()),
            "annotations": annotations,
        }
    });
    http::agent()
        .request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub update check-run annotations: {}", e))?;
    Ok(())
}

fn complete_check_run(
    owner: &str,
    repo: &str,
    check_id: u64,
    total: usize,
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let conclusion = if total == 0 { "success" } else { "failure" };
    let body = serde_json::json!({
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "greengate scan",
            "summary": format!("greengate found {} issue(s).", total),
        }
    });
    http::agent()
        .request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub complete check-run: {}", e))?;
    Ok(())
}

fn post_pr_summary_comment(
    owner: &str,
    repo: &str,
    sha: &str,
    findings: &[Finding],
    token: &str,
) -> Result<()> {
    // Look up the PR number associated with this commit SHA.
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
        // Commit is not associated with an open PR — skip the review comment.
        return Ok(());
    };

    let comment_url = format!(
        "{}/repos/{}/{}/issues/{}/comments",
        API_BASE, owner, repo, pr_number
    );

    let markdown = build_pr_summary(findings);
    let body = serde_json::json!({ "body": markdown });

    http::agent()
        .post(&comment_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub post PR comment: {}", e))?;
    Ok(())
}

/// Build a rich markdown summary suitable for a GitHub PR comment.
fn build_pr_summary(findings: &[Finding]) -> String {
    let total = findings.len();

    if total == 0 {
        return "## greengate scan results\n\n**No issues found.** All checks passed.\n"
            .to_string();
    }

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();

    let mut md = format!(
        "## greengate scan results\n\n\
         **{total} finding(s)** \
         ({critical} critical, {high} high, {medium} medium, {low} low)\n\n\
         | File | Line | Rule | Severity |\n\
         |------|------|------|----------|\n"
    );

    // Show up to 20 findings in the table; link to the Checks tab for the rest.
    for f in findings.iter().take(20) {
        md.push_str(&format!(
            "| `{}` | {} | `{}` | **{}** |\n",
            f.path.display(),
            f.line,
            f.rule_id,
            f.severity,
        ));
    }

    if total > 20 {
        md.push_str(&format!(
            "\n_...and {} more. See the **Checks** tab for all per-line annotations._\n",
            total - 20
        ));
    } else {
        md.push_str("\n_See the **Checks** tab for per-line annotations._\n");
    }

    md
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_github_env_returns_some_with_all_vars() {
        let env = detect_github_env_from(|key| match key {
            "GITHUB_TOKEN" => Some("tok".to_string()),
            "GITHUB_REPOSITORY" => Some("owner/repo".to_string()),
            "GITHUB_SHA" => Some("abc123".to_string()),
            _ => None,
        })
        .expect("all three variables are present");
        assert_eq!(env.token, "tok");
        assert_eq!(env.repository, "owner/repo");
        assert_eq!(env.sha, "abc123");
    }

    #[test]
    fn detect_github_env_returns_none_on_missing_token() {
        let env = detect_github_env_from(|key| match key {
            "GITHUB_REPOSITORY" => Some("owner/repo".to_string()),
            "GITHUB_SHA" => Some("abc123".to_string()),
            _ => None,
        });
        assert!(env.is_none());
    }
}
