use crate::utils::terminal;
use anyhow::Result;
use std::path::Path;

struct LintIssue {
    file: String,
    line: usize,
    rule: &'static str,
    detail: String,
}

pub fn run_docker_lint(dockerfile_path: &str) -> Result<()> {
    terminal::info(&format!("Linting Dockerfile '{}'...", dockerfile_path));

    let content = match std::fs::read_to_string(dockerfile_path) {
        Ok(c) => c,
        Err(e) => anyhow::bail!("Cannot read {}: {}", dockerfile_path, e),
    };

    let issues = check_dockerfile(Path::new(dockerfile_path), &content);

    if issues.is_empty() {
        terminal::success("Dockerfile passed all lint checks.");
        return Ok(());
    }

    terminal::warn(&format!("Found {} issue(s):", issues.len()));
    for issue in &issues {
        if issue.line > 0 {
            eprintln!(
                "  [{}] {}:{} — {}",
                issue.rule, issue.file, issue.line, issue.detail
            );
        } else {
            eprintln!("  [{}] {} — {}", issue.rule, issue.file, issue.detail);
        }
    }

    anyhow::bail!("Docker lint failed: {} issue(s) found.", issues.len());
}

// ── Checks ────────────────────────────────────────────────────────────────────

const SECRET_ENV_PATTERNS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "TOKEN",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH_TOKEN",
    "CLIENT_SECRET",
];

fn check_dockerfile(path: &Path, content: &str) -> Vec<LintIssue> {
    let mut issues = Vec::new();
    let file = path.display().to_string();

    let mut has_user_directive = false;
    let mut has_healthcheck = false;
    // Track if we've seen `apt-get update` in a standalone RUN (stale cache risk)
    let mut standalone_apt_update: Option<usize> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = raw_line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let upper = trimmed.to_uppercase();

        // FROM — unpinned or :latest image
        if upper.starts_with("FROM ") {
            let after = trimmed[5..].trim();
            // Skip multi-stage alias lines like `FROM builder AS final`
            // and `FROM --platform=...` flags
            let image_token = if after.starts_with("--") {
                after.split_whitespace().nth(1).unwrap_or("")
            } else {
                after.split_whitespace().next().unwrap_or("")
            };

            // "scratch" and "AS <alias>" forms are fine
            let is_alias =
                image_token.eq_ignore_ascii_case("AS") || after.to_lowercase().contains(" as ");
            if image_token != "scratch" && !is_alias {
                let tag = image_token.split(':').nth(1).unwrap_or("");
                if tag.is_empty() || tag == "latest" {
                    issues.push(LintIssue {
                        file: file.clone(),
                        line: lineno,
                        rule: "no-latest-image",
                        detail: format!("FROM '{}' uses an unpinned or :latest tag", image_token),
                    });
                }
            }
        }

        // ADD — prefer COPY (allow URLs and tar archives)
        if upper.starts_with("ADD ") {
            let arg = trimmed[4..].trim();
            let src = arg.split_whitespace().next().unwrap_or("");
            let is_url = src.starts_with("http://") || src.starts_with("https://");
            let is_tar = src.ends_with(".tar.gz")
                || src.ends_with(".tar.bz2")
                || src.ends_with(".tar.xz")
                || src.ends_with(".tgz");
            if !is_url && !is_tar {
                issues.push(LintIssue {
                    file: file.clone(),
                    line: lineno,
                    rule: "prefer-copy-over-add",
                    detail:
                        "Use COPY instead of ADD unless fetching a URL or extracting a tar archive"
                            .to_string(),
                });
            }
        }

        // USER directive
        if upper.starts_with("USER ") {
            let user = trimmed[5..].trim();
            if user == "root" || user == "0" {
                issues.push(LintIssue {
                    file: file.clone(),
                    line: lineno,
                    rule: "no-root-user",
                    detail: "Container switches to root. Set a non-root USER".to_string(),
                });
            }
            has_user_directive = true;
        }

        // HEALTHCHECK
        if upper.starts_with("HEALTHCHECK") {
            has_healthcheck = true;
        }

        // ENV — secrets
        if upper.starts_with("ENV ") {
            let env_body = trimmed[4..].trim();
            // Supports both `ENV KEY=value` and `ENV KEY value`
            let key = env_body
                .split(['=', ' '])
                .next()
                .unwrap_or("")
                .to_uppercase();
            if SECRET_ENV_PATTERNS.iter().any(|pat| key.contains(pat)) {
                issues.push(LintIssue {
                    file: file.clone(),
                    line: lineno,
                    rule: "secret-in-env",
                    detail: format!(
                        "ENV '{}' may expose a secret — use ARG, runtime secrets, or a secrets manager instead",
                        key
                    ),
                });
            }
        }

        // RUN — apt-get hygiene
        if upper.starts_with("RUN ") {
            let run_body = trimmed[4..].to_lowercase();
            if run_body.contains("apt-get update") {
                if run_body.contains("apt-get install") {
                    // Combined layer — good; reset tracker
                    standalone_apt_update = None;
                    if !run_body.contains("--no-install-recommends") {
                        issues.push(LintIssue {
                            file: file.clone(),
                            line: lineno,
                            rule: "apt-no-recommends",
                            detail:
                                "Add --no-install-recommends to apt-get install to reduce image size"
                                    .to_string(),
                        });
                    }
                } else {
                    // Standalone apt-get update — stale cache risk
                    standalone_apt_update = Some(lineno);
                }
            } else if run_body.contains("apt-get install") {
                // apt-get install without a preceding update in the same layer
                if standalone_apt_update.is_some() {
                    issues.push(LintIssue {
                        file: file.clone(),
                        line: lineno,
                        rule: "apt-stale-cache",
                        detail: "apt-get update and apt-get install must be in the same RUN instruction to avoid stale cache".to_string(),
                    });
                    standalone_apt_update = None;
                }
                if !run_body.contains("--no-install-recommends") {
                    issues.push(LintIssue {
                        file: file.clone(),
                        line: lineno,
                        rule: "apt-no-recommends",
                        detail:
                            "Add --no-install-recommends to apt-get install to reduce image size"
                                .to_string(),
                    });
                }
            }
        }
    }

    // File-level checks (apply to the final image stage only)
    if !has_user_directive {
        issues.push(LintIssue {
            file: file.clone(),
            line: 0,
            rule: "no-user-directive",
            detail: "No USER directive found — container will run as root by default".to_string(),
        });
    }

    if !has_healthcheck {
        issues.push(LintIssue {
            file,
            line: 0,
            rule: "no-healthcheck",
            detail: "No HEALTHCHECK defined — add one for container health monitoring".to_string(),
        });
    }

    issues
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn check(content: &str) -> Vec<LintIssue> {
        check_dockerfile(Path::new("Dockerfile"), content)
    }

    fn rules(content: &str) -> Vec<&'static str> {
        check(content).into_iter().map(|i| i.rule).collect()
    }

    const CLEAN: &str = "FROM node:20.11.0\n\
        COPY . /app\n\
        RUN apt-get update && apt-get install -y --no-install-recommends curl\n\
        USER node\n\
        HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n";

    #[test]
    fn test_clean_dockerfile_no_issues() {
        assert!(
            check(CLEAN).is_empty(),
            "Expected no issues, got: {:?}",
            rules(CLEAN)
        );
    }

    #[test]
    fn test_latest_image_flagged() {
        let content = "FROM node:latest\nUSER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"no-latest-image"));
    }

    #[test]
    fn test_unpinned_image_flagged() {
        let content = "FROM node\nUSER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"no-latest-image"));
    }

    #[test]
    fn test_add_flagged() {
        let content = "FROM node:20\nADD . /app\nUSER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"prefer-copy-over-add"));
    }

    #[test]
    fn test_add_url_allowed() {
        let content = "FROM node:20\nADD https://example.com/file.txt /app/\nUSER app\nHEALTHCHECK CMD true\n";
        assert!(!rules(content).contains(&"prefer-copy-over-add"));
    }

    #[test]
    fn test_secret_in_env() {
        let content = "FROM node:20\nENV API_KEY=abc123\nUSER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"secret-in-env"));
    }

    #[test]
    fn test_no_user_directive() {
        let content = "FROM node:20\nCOPY . /app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"no-user-directive"));
    }

    #[test]
    fn test_root_user_flagged() {
        let content = "FROM node:20\nUSER root\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"no-root-user"));
    }

    #[test]
    fn test_no_healthcheck() {
        let content = "FROM node:20\nCOPY . /app\nUSER app\n";
        assert!(rules(content).contains(&"no-healthcheck"));
    }

    #[test]
    fn test_apt_no_recommends() {
        let content = "FROM ubuntu:22.04\n\
            RUN apt-get update && apt-get install -y curl\n\
            USER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"apt-no-recommends"));
    }

    #[test]
    fn test_apt_stale_cache() {
        let content = "FROM ubuntu:22.04\n\
            RUN apt-get update\n\
            RUN apt-get install -y --no-install-recommends curl\n\
            USER app\nHEALTHCHECK CMD true\n";
        assert!(rules(content).contains(&"apt-stale-cache"));
    }
}
