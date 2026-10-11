use crate::report::{Check, Finding, Report, Severity};
use crate::utils::terminal;
use anyhow::Result;
use serde_yaml::Value;
use std::path::Path;

struct LintIssue {
    file: String,
    container: String,
    rule: &'static str,
    detail: String,
}

pub fn run_lint(target_dir: &str) -> Result<Report> {
    terminal::info(&format!(
        "Linting Kubernetes manifests in '{}'...",
        target_dir
    ));

    let mut report = Report::new("lint");
    let yaml_files = collect_yaml_files(target_dir);

    if yaml_files.is_empty() {
        terminal::info("No YAML files found.");
        return Ok(report);
    }

    let mut all_issues: Vec<LintIssue> = Vec::new();
    let mut unparsed: Vec<String> = Vec::new();
    let mut templates = 0usize;

    for path in &yaml_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                // A single file may contain multiple YAML documents separated by ---
                let docs = split_yaml_docs(&content);
                for doc_str in docs {
                    match serde_yaml::from_str::<Value>(&doc_str) {
                        Ok(doc) => all_issues.extend(check_manifest(path, &doc)),
                        // Un-rendered Helm/Kustomize templates are common in
                        // repos and are not manifests yet.
                        Err(_) if doc_str.contains("{{") => templates += 1,
                        Err(e) => unparsed.push(format!("{}: {e}", path.display())),
                    }
                }
            }
            Err(e) => {
                terminal::warn(&format!("Cannot read {}: {}", path.display(), e));
                report.checks.push(Check::incomplete(
                    format!("manifest:{}", path.display()),
                    format!("could not be read: {e}"),
                ));
            }
        }
    }

    if templates > 0 {
        terminal::info(&format!(
            "Skipped {templates} un-rendered template document(s) — render them to lint."
        ));
    }

    // A document that is not a template and does not parse was never linted,
    // so a typo'd manifest cannot pass as a clean one.
    if !unparsed.is_empty() {
        terminal::warn(&format!(
            "{} YAML document(s) did not parse and were NOT linted:",
            unparsed.len()
        ));
        for u in &unparsed {
            eprintln!("  - {u}");
        }
        report.checks.push(Check::incomplete(
            "manifests:parse",
            format!(
                "{} YAML document(s) did not parse and were not linted",
                unparsed.len()
            ),
        ));
    }

    let files_checked = yaml_files.len();
    report.findings = all_issues
        .iter()
        .map(|i| {
            Finding::in_file(
                i.rule,
                Severity::Medium,
                &i.file,
                0,
                format!("container {}: {}", i.container, i.detail),
            )
        })
        .collect();

    if all_issues.is_empty() {
        if report.unfinished().next().is_none() {
            terminal::success(&format!(
                "All {} manifest(s) passed lint checks.",
                files_checked
            ));
        }
        report.print_unfinished();
        return Ok(report);
    }

    terminal::warn(&format!(
        "Found {} issue(s) across {} file(s):",
        all_issues.len(),
        files_checked
    ));

    for issue in &all_issues {
        eprintln!(
            "  [{}] {} (container: {}) — {}",
            issue.rule, issue.file, issue.container, issue.detail
        );
    }

    report.print_unfinished();
    eprintln!("K8s lint failed: {} issue(s) found.", all_issues.len());
    Ok(report)
}

// ── File discovery ────────────────────────────────────────────────────────────

fn collect_yaml_files(dir: &str) -> Vec<std::path::PathBuf> {
    let walker = ignore::WalkBuilder::new(dir).hidden(true).build();
    walker
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect()
}

/// Split a file's content into individual YAML document strings.
fn split_yaml_docs(content: &str) -> Vec<String> {
    // Split on lines that are exactly "---" (document separator)
    let mut docs: Vec<String> = Vec::new();
    let mut current = String::new();

    for line in content.lines() {
        if line.trim() == "---" {
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                docs.push(trimmed);
            }
            current = String::new();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        docs.push(trimmed);
    }

    if docs.is_empty() {
        docs.push(content.to_string());
    }
    docs
}

// ── Manifest checks ───────────────────────────────────────────────────────────

const WORKLOAD_KINDS: &[&str] = &["Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"];

fn check_manifest(path: &Path, doc: &Value) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    let kind = doc["kind"].as_str().unwrap_or("");
    if !WORKLOAD_KINDS.contains(&kind) {
        return issues;
    }

    // CronJob nests its pod template one level deeper
    let containers = if kind == "CronJob" {
        &doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
    } else {
        &doc["spec"]["template"]["spec"]["containers"]
    };

    let seq = match containers.as_sequence() {
        Some(s) => s,
        None => return issues,
    };

    let file = path.display().to_string();

    for container in seq {
        let name = container["name"]
            .as_str()
            .unwrap_or("<unnamed>")
            .to_string();

        // 1. Unpinned / latest image
        if let Some(image) = container["image"].as_str() {
            let tag = image.split(':').nth(1).unwrap_or("");
            if tag.is_empty() || tag == "latest" {
                issues.push(LintIssue {
                    file: file.clone(),
                    container: name.clone(),
                    rule: "no-latest-image",
                    detail: format!("Image '{}' uses an unpinned or :latest tag", image),
                });
            }
        }

        // 2. Missing resource limits
        let limits = &container["resources"]["limits"];
        if !limits.is_mapping() {
            issues.push(LintIssue {
                file: file.clone(),
                container: name.clone(),
                rule: "no-resource-limits",
                detail: "No resources.limits defined".to_string(),
            });
        } else {
            if limits["cpu"].is_null() {
                issues.push(LintIssue {
                    file: file.clone(),
                    container: name.clone(),
                    rule: "no-cpu-limit",
                    detail: "resources.limits.cpu is not set".to_string(),
                });
            }
            if limits["memory"].is_null() {
                issues.push(LintIssue {
                    file: file.clone(),
                    container: name.clone(),
                    rule: "no-memory-limit",
                    detail: "resources.limits.memory is not set".to_string(),
                });
            }
        }

        // 3. Running as root
        let run_as_user = &container["securityContext"]["runAsUser"];
        if run_as_user.as_u64() == Some(0) || run_as_user.as_i64() == Some(0) {
            issues.push(LintIssue {
                file: file.clone(),
                container: name.clone(),
                rule: "run-as-root",
                detail: "securityContext.runAsUser is 0 (root)".to_string(),
            });
        }

        // 4. Missing readiness probe (skip for Jobs/CronJobs — they run to completion)
        if !matches!(kind, "Job" | "CronJob") {
            if container["readinessProbe"].is_null() {
                issues.push(LintIssue {
                    file: file.clone(),
                    container: name.clone(),
                    rule: "no-readiness-probe",
                    detail: "readinessProbe is not defined".to_string(),
                });
            }
            if container["livenessProbe"].is_null() {
                issues.push(LintIssue {
                    file: file.clone(),
                    container: name.clone(),
                    rule: "no-liveness-probe",
                    detail: "livenessProbe is not defined".to_string(),
                });
            }
        }
    }

    issues
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn parse(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn check(yaml: &str) -> Vec<LintIssue> {
        check_manifest(Path::new("test.yaml"), &parse(yaml))
    }

    const GOOD_DEPLOYMENT: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:1.2.3
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
"#;

    #[test]
    fn test_good_deployment_no_issues() {
        let issues = check(GOOD_DEPLOYMENT);
        assert!(
            issues.is_empty(),
            "Expected no issues, got: {:?}",
            issues.iter().map(|i| i.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_latest_image_flagged() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        readinessProbe:
          httpGet: {path: /h, port: 80}
        livenessProbe:
          httpGet: {path: /h, port: 80}
"#;
        let issues = check(yaml);
        assert!(issues.iter().any(|i| i.rule == "no-latest-image"));
    }

    #[test]
    fn test_missing_resource_limits_flagged() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        readinessProbe:
          httpGet: {path: /h, port: 80}
        livenessProbe:
          httpGet: {path: /h, port: 80}
"#;
        let issues = check(yaml);
        assert!(issues.iter().any(|i| i.rule == "no-resource-limits"));
    }

    #[test]
    fn test_run_as_root_flagged() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          runAsUser: 0
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        readinessProbe:
          httpGet: {path: /h, port: 80}
        livenessProbe:
          httpGet: {path: /h, port: 80}
"#;
        let issues = check(yaml);
        assert!(issues.iter().any(|i| i.rule == "run-as-root"));
    }

    #[test]
    fn test_non_workload_kinds_skipped() {
        let yaml = r#"
apiVersion: v1
kind: Service
metadata:
  name: myservice
spec:
  selector:
    app: myapp
"#;
        let issues = check(yaml);
        assert!(issues.is_empty(), "Services should not be linted");
    }

    #[test]
    fn test_job_no_probe_required() {
        let yaml = r#"
apiVersion: batch/v1
kind: Job
spec:
  template:
    spec:
      containers:
      - name: worker
        image: worker:1.0
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
"#;
        let issues = check(yaml);
        // Jobs should not require probes
        assert!(!issues.iter().any(|i| i.rule == "no-readiness-probe"));
        assert!(!issues.iter().any(|i| i.rule == "no-liveness-probe"));
    }
}
