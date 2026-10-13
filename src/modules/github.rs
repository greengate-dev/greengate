use crate::modules::scanner::{Finding, Severity};
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

/// The REST API root: `GITHUB_API_URL` (set by Actions, and on GitHub
/// Enterprise Server), else github.com.
fn api_base() -> String {
    std::env::var("GITHUB_API_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .map_or_else(
            || "https://api.github.com".to_string(),
            |u| u.trim_end_matches('/').to_string(),
        )
}

fn create_check_run(owner: &str, repo: &str, sha: &str, token: &str) -> Result<u64> {
    let url = format!("{}/repos/{}/{}/check-runs", api_base(), owner, repo);
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
        api_base(),
        owner,
        repo,
        check_id
    );
    let annotations: Vec<serde_json::Value> = chunk
        .iter()
        .map(|f| {
            let level = f.severity.github_level();
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
        api_base(),
        owner,
        repo,
        check_id
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
        api_base(),
        owner,
        repo,
        sha
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
        api_base(),
        owner,
        repo,
        pr_number
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

    let (mut critical, mut high, mut medium, mut low) = (0usize, 0usize, 0usize, 0usize);
    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }

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

// ── Dependency review ─────────────────────────────────────────────────────────

/// One check-run annotation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Annotation {
    pub path: String,
    pub line: usize,
    /// `failure`, `warning` or `notice`.
    pub level: &'static str,
    pub title: String,
    pub message: String,
}

fn call(method: &str, url: &str, token: &str) -> ureq::Request {
    http::agent()
        .request(method, url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
}

/// The pull request this run is for: from the Actions event payload, the
/// `refs/pull/<n>/merge` ref, or the commit's associated pull requests.
fn pr_number(env: &GitHubEnv, owner: &str, repo: &str) -> Option<u64> {
    if let Ok(path) = std::env::var("GITHUB_EVENT_PATH")
        && let Ok(text) = std::fs::read_to_string(path)
        && let Ok(event) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(n) = event["pull_request"]["number"].as_u64()
    {
        return Some(n);
    }
    if let Some(n) = std::env::var("GITHUB_REF").ok().and_then(|r| {
        r.strip_prefix("refs/pull/")?
            .split('/')
            .next()?
            .parse()
            .ok()
    }) {
        return Some(n);
    }
    let url = format!(
        "{}/repos/{owner}/{repo}/commits/{}/pulls",
        api_base(),
        env.sha
    );
    let json: serde_json::Value =
        http::read_json(call("GET", &url, &env.token).call().ok()?).ok()?;
    json[0]["number"].as_u64()
}

/// Create or update (by `marker`) greengate's comment on pull request `pr`.
fn upsert_comment(
    owner: &str,
    repo: &str,
    pr: u64,
    marker: &str,
    body: &str,
    token: &str,
) -> Result<()> {
    let base = api_base();
    for page in 1..=10 {
        let url =
            format!("{base}/repos/{owner}/{repo}/issues/{pr}/comments?per_page=100&page={page}");
        let comments: serde_json::Value = http::read_json(
            call("GET", &url, token)
                .call()
                .map_err(|e| anyhow::anyhow!("GitHub list comments: {e}"))?,
        )?;
        let Some(list) = comments.as_array().filter(|l| !l.is_empty()) else {
            break;
        };
        if let Some(id) = list
            .iter()
            .find(|c| c["body"].as_str().is_some_and(|b| b.contains(marker)))
            .and_then(|c| c["id"].as_u64())
        {
            call(
                "PATCH",
                &format!("{base}/repos/{owner}/{repo}/issues/comments/{id}"),
                token,
            )
            .send_json(serde_json::json!({ "body": body }))
            .map_err(|e| anyhow::anyhow!("GitHub update comment: {e}"))?;
            return Ok(());
        }
        if list.len() < 100 {
            break;
        }
    }
    call(
        "POST",
        &format!("{base}/repos/{owner}/{repo}/issues/{pr}/comments"),
        token,
    )
    .send_json(serde_json::json!({ "body": body }))
    .map_err(|e| anyhow::anyhow!("GitHub post comment: {e}"))?;
    Ok(())
}

/// Post a dependency review: the comment on the pull request (updated in
/// place), and a check run with an annotation per finding on its lockfile
/// line.
pub fn post_review(
    env: &GitHubEnv,
    body: &str,
    annotations: &[Annotation],
    status: crate::report::Status,
) -> Result<()> {
    let (owner, repo) = env
        .repository
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("GITHUB_REPOSITORY is not in owner/repo format"))?;
    let base = api_base();
    let title = "greengate dependency review";
    let summary = format!(
        "{} blocking, {} total annotation(s)",
        annotations.iter().filter(|a| a.level == "failure").count(),
        annotations.len()
    );
    let created: serde_json::Value = http::read_json(
        call(
            "POST",
            &format!("{base}/repos/{owner}/{repo}/check-runs"),
            &env.token,
        )
        .send_json(serde_json::json!({
            "name": title,
            "head_sha": env.sha,
            "status": "in_progress",
        }))
        .map_err(|e| anyhow::anyhow!("GitHub create check-run: {e}"))?,
    )?;
    let id = created["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("GitHub API did not return a check run id"))?;
    let url = format!("{base}/repos/{owner}/{repo}/check-runs/{id}");
    // At most 50 annotations per request.
    for chunk in annotations.chunks(50) {
        let list: Vec<serde_json::Value> = chunk
            .iter()
            .map(|a| {
                serde_json::json!({
                    "path": a.path,
                    "start_line": a.line,
                    "end_line": a.line,
                    "annotation_level": a.level,
                    "title": a.title,
                    "message": a.message,
                })
            })
            .collect();
        call("PATCH", &url, &env.token)
            .send_json(serde_json::json!({
                "output": { "title": title, "summary": summary, "annotations": list }
            }))
            .map_err(|e| anyhow::anyhow!("GitHub annotate check-run: {e}"))?;
    }
    use crate::report::Status;
    let conclusion = match status {
        Status::Passed => "success",
        Status::Findings => "failure",
        Status::Incomplete | Status::Error => "neutral",
    };
    call("PATCH", &url, &env.token)
        .send_json(serde_json::json!({
            "status": "completed",
            "conclusion": conclusion,
            "output": { "title": title, "summary": summary },
        }))
        .map_err(|e| anyhow::anyhow!("GitHub complete check-run: {e}"))?;
    if let Some(pr) = pr_number(env, owner, repo) {
        upsert_comment(
            owner,
            repo,
            pr,
            crate::modules::review::render_marker(),
            body,
            &env.token,
        )?;
    }
    Ok(())
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
