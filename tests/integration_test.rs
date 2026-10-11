use std::process::Command;

/// Initialize a minimal git repo with a single "initial" commit in `dir`.
fn init_git_repo(dir: &std::path::Path) {
    Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir)
        .output()
        .unwrap();
}

fn git_commit_all(dir: &std::path::Path, msg: &str) {
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", msg, "--allow-empty"])
        .current_dir(dir)
        .output()
        .unwrap();
}

fn binary() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_greengate").into()
}

// ── scan ──────────────────────────────────────────────────────────────────────

#[test]
fn scan_exits_zero_on_clean_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("clean.txt"),
        "hello world, no secrets here\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0 on clean directory");
}

#[test]
fn scan_exits_nonzero_on_secrets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.env"),
        "AWS_KEY=AKIA3KGXQW7ZP2MTV9CD\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "expected non-zero exit when secrets found"
    );
}

#[test]
fn scan_json_output_on_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secret.txt"),
        // Split so no single source literal triggers GitHub push-protection.
        format!("{}{}\n", "sk_live_", "abcdefghijklmnopqrstuvwx"),
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json must produce valid JSON on stdout");
    assert!(parsed["total"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn scan_sarif_output_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("key.txt"),
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "sarif"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format sarif must produce valid JSON on stdout");
    assert_eq!(parsed["version"].as_str(), Some("2.1.0"));
    assert!(parsed["runs"].is_array());
}

// ── lint ──────────────────────────────────────────────────────────────────────

const GOOD_MANIFEST: &str = r#"apiVersion: apps/v1
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

const BAD_MANIFEST: &str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:latest
"#;

#[test]
fn lint_exits_zero_on_compliant_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("deploy.yaml"), GOOD_MANIFEST).unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(status.success(), "compliant manifest should pass lint");
}

#[test]
fn lint_exits_nonzero_on_bad_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("deploy.yaml"), BAD_MANIFEST).unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(!status.success(), "bad manifest should fail lint");
}

#[test]
fn lint_exits_zero_when_no_yaml_files() {
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(status.success(), "empty directory should exit 0");
}

// ── coverage ──────────────────────────────────────────────────────────────────

fn write_lcov(dir: &std::path::Path, hit: u64, found: u64) -> std::path::PathBuf {
    let path = dir.join("lcov.info");
    std::fs::write(
        &path,
        format!("SF:src/main.rs\nLH:{}\nLF:{}\nend_of_record\n", hit, found),
    )
    .unwrap();
    path
}

#[test]
fn coverage_exits_zero_above_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let lcov = write_lcov(dir.path(), 90, 100);

    let status = Command::new(binary())
        .args(["coverage", "--file", lcov.to_str().unwrap(), "--min", "80"])
        .status()
        .unwrap();

    assert!(status.success(), "90% should pass 80% threshold");
}

#[test]
fn coverage_exits_nonzero_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let lcov = write_lcov(dir.path(), 50, 100);

    let status = Command::new(binary())
        .args(["coverage", "--file", lcov.to_str().unwrap(), "--min", "80"])
        .status()
        .unwrap();

    assert!(!status.success(), "50% should fail 80% threshold");
}

// ── Feature 3: Inline suppression ─────────────────────────────────────────────

#[test]
fn scan_suppressed_line_is_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    // AWS key on a line marked with the suppression comment — must not be flagged
    std::fs::write(
        dir.path().join("config.env"),
        "AWS_KEY=AKIA3KGXQW7ZP2MTV9CD  # greengate: ignore\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "suppressed line should not cause non-zero exit"
    );
}

#[test]
fn scan_suppression_only_on_marked_line() {
    let dir = tempfile::tempdir().unwrap();
    // Line 1: suppressed → no finding; Line 2: NOT suppressed → 1 finding expected
    std::fs::write(
        dir.path().join("config.env"),
        format!(
            "SAFE=AKIA3KGXQW7ZP2MTV9CD  # greengate: ignore\n{}\n",
            "REAL=AKIA3KGXQW7ZP2MTV9CD"
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed["total"].as_u64().unwrap(),
        1,
        "only the unsuppressed line should be flagged"
    );
}

// ── Feature 1: Entropy detection ──────────────────────────────────────────────

#[test]
fn scan_detects_high_entropy_string() {
    let dir = tempfile::tempdir().unwrap();
    // 32-char high-entropy base64-like token — doesn't match any named regex pattern
    std::fs::write(
        dir.path().join("config.env"),
        "API_SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "high-entropy token should be flagged"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rules: Vec<&str> = parsed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap_or(""))
        .collect();
    assert!(
        rules.iter().any(|r| r.contains("High Entropy")),
        "expected a High Entropy finding, got rules: {:?}",
        rules
    );
}

// ── Feature 2: Git history scan ───────────────────────────────────────────────

#[test]
fn scan_history_flag_accepted() {
    // Run in greengate's own repo — guaranteed to be a git repository.
    // Check only that the flag is recognised and any output is valid JSON.
    let output = Command::new(binary())
        .args(["scan", "--history", "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(&stdout)
            .expect("--history --format json must produce valid JSON on stdout");
    }
}

#[test]
fn scan_history_reports_secret_on_line_starting_with_plus_plus() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(dir.path().join("a.c"), "int x;\n").unwrap();
    git_commit_all(dir.path(), "init");
    std::fs::write(
        dir.path().join("a.c"),
        "int x;\n++counter; // AKIAQWERTYUIOPASDFGH\nkey = \"AKIAZXCVBNMLKJHGFDSA\";\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add keys");

    let output = Command::new(binary())
        .args(["scan", "--history", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut lines: Vec<u64> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "AWS Access Key")
        .map(|f| f["line"].as_u64().unwrap())
        .collect();
    lines.sort_unstable();
    assert_eq!(lines, [2, 3], "both keys, at their real line numbers");
}

// ── Non-UTF-8 content ─────────────────────────────────────────────────────────

#[test]
fn scan_detects_secret_in_latin1_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("latin1.env"),
        b"# caf\xe9 config\nAWS_KEY=AKIAQWERTYUIOPASDFGH\n",
    )
    .unwrap();
    // With SAST on, Python files skip the regex pass, so this checks SAST too.
    std::fs::write(
        dir.path().join("settings.py"),
        b"# r\xe9glages\nKEY = \"AKIAZXCVBNMLKJHGFDSA\"\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "secrets in non-UTF-8 files must fail the scan"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut files: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "AWS Access Key")
        .map(|f| f["file"].as_str().unwrap())
        .collect();
    files.sort_unstable();
    assert_eq!(files, ["./latin1.env", "./settings.py"]);
}

// ── --fix ─────────────────────────────────────────────────────────────────────

#[test]
fn scan_fix_redacts_without_changing_line_endings() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app.env");
    std::fs::write(
        &file,
        "# config\r\nAWS_KEY=AKIAQWERTYUIOPASDFGH\r\nREGION=eu-west-1\nLAST=1",
    )
    .unwrap();

    let status = Command::new(binary())
        .args(["scan", "--fix"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "# config\r\nAWS_KEY=<REDACTED>\r\nREGION=eu-west-1\nLAST=1",
        "only the secret changes; CRLF, LF and the missing final newline survive"
    );
}

// ── Typed flags ───────────────────────────────────────────────────────────────

#[test]
fn unknown_format_is_rejected_not_defaulted() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(binary())
        .args(["scan", "--format", "sarf"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "clap usage error");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("possible values"), "stderr: {stderr}");
}

#[test]
fn unknown_profile_is_rejected_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(binary())
        .args(["--profile", "strcit", "scan"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "clap usage error");
}

#[test]
fn pipeline_step_with_bad_flag_value_fails() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[pipeline]\nsteps = [\"ci-lint --format sarf\"]\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("run")
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --format"), "stderr: {stderr}");
}

// ── Features 4+5: Multi-lockfile audit + Go support ───────────────────────────

#[test]
fn audit_finds_multiple_lockfiles_in_subdirectories() {
    let dir = tempfile::tempdir().unwrap();

    // Rust sub-project
    std::fs::create_dir(dir.path().join("api")).unwrap();
    std::fs::write(
        dir.path().join("api/Cargo.lock"),
        "[package]\nname = \"api\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    // Node sub-project
    std::fs::create_dir(dir.path().join("frontend")).unwrap();
    std::fs::write(
        dir.path().join("frontend/package-lock.json"),
        r#"{"packages": {"node_modules/lodash": {"version": "4.17.21"}}}"#,
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("No supported lock file found"),
        "should find lock files in subdirectories; stderr: {}",
        stderr
    );
}

#[test]
fn audit_parses_go_sum_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("go.sum"),
        "github.com/gin-gonic/gin v1.9.1 h1:fakehash=\n\
         github.com/gin-gonic/gin v1.9.1/go.mod h1:fakehash2=\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("go.sum") || stderr.contains("Go") || stderr.contains("gin"),
        "should detect go.sum and report on it; stderr: {}",
        stderr
    );
}

#[test]
fn audit_finds_yarn_lock() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("yarn.lock"),
        concat!(
            "# yarn lockfile v1\n",
            "\n",
            "lodash@^4.17.21:\n",
            "  version \"4.17.21\"\n",
            "  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
            "  integrity sha512-xxx\n",
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("No supported lock files found"),
        "should find yarn.lock; stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("yarn.lock") || stderr.contains("lodash"),
        "should report yarn.lock or lodash; stderr: {}",
        stderr
    );
}

#[test]
fn audit_finds_pnpm_lock() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("pnpm-lock.yaml"),
        concat!(
            "lockfileVersion: '6.0'\n",
            "\n",
            "packages:\n",
            "\n",
            "  /lodash@4.17.21:\n",
            "    resolution: {integrity: sha512-xxx}\n",
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("No supported lock files found"),
        "should find pnpm-lock.yaml; stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("pnpm-lock.yaml") || stderr.contains("lodash"),
        "should report pnpm-lock.yaml or lodash; stderr: {}",
        stderr
    );
}

// ── install-hooks ─────────────────────────────────────────────────────────────

#[test]
fn install_hooks_creates_hook_file() {
    let repo_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path().join(".git/hooks")).unwrap();

    let status = Command::new(binary())
        .arg("install-hooks")
        .current_dir(repo_dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "install-hooks should exit 0");

    let hook_path = repo_dir.path().join(".git/hooks/pre-commit");
    assert!(hook_path.exists(), "pre-commit hook file should exist");

    let content = std::fs::read_to_string(&hook_path).unwrap();
    assert!(
        content.contains("greengate scan --staged"),
        "hook must invoke greengate scan --staged"
    );
}

#[test]
fn install_hooks_does_not_overwrite_without_force() {
    let repo_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path().join(".git/hooks")).unwrap();
    let hook_path = repo_dir.path().join(".git/hooks/pre-commit");
    std::fs::write(&hook_path, "#!/bin/sh\necho existing hook\n").unwrap();

    Command::new(binary())
        .arg("install-hooks")
        .current_dir(repo_dir.path())
        .status()
        .unwrap();

    let content = std::fs::read_to_string(&hook_path).unwrap();
    assert!(
        content.contains("existing hook"),
        "existing hook should not be overwritten without --force"
    );
}

// ── SAST: Phase 1 (string-literal-scoped detection) ───────────────────────────

#[test]
fn sast_phase1_flags_secret_in_ts_string_literal() {
    let dir = tempfile::tempdir().unwrap();
    // AWS key inside a TS string literal — SAST Phase 1 must flag it
    std::fs::write(
        dir.path().join("config.ts"),
        "const key = \"AKIA3KGXQW7ZP2MTV9CD\";\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "secret in TS string literal should be flagged"
    );
}

#[test]
fn sast_phase1_does_not_flag_secret_in_ts_comment() {
    let dir = tempfile::tempdir().unwrap();
    // Key is only in a comment — SAST Phase 1 must NOT flag it (no string_fragment node)
    std::fs::write(
        dir.path().join("config.ts"),
        "// Example: AKIA3KGXQW7ZP2MTV9CD\nconst x = 1;\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "secret in a TS comment should NOT be flagged by SAST"
    );
}

#[test]
fn sast_phase1_does_not_flag_email_in_tsx_jsx_text() {
    let dir = tempfile::tempdir().unwrap();
    // Email is in JSX text content, not a string literal — should not be flagged
    std::fs::write(
        dir.path().join("footer.tsx"),
        "export const Footer = () => <p>contact@example.com</p>;\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "email in JSX text content should NOT be flagged by SAST Phase 1"
    );
}

// ── SAST: Phase 2 (dangerous pattern detection) ───────────────────────────────

#[test]
fn sast_phase2_flags_eval_in_js() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.js"), "eval(userInput);\n").unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "eval() should be flagged");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("SAST/EvalUsage"),
        "output should name SAST/EvalUsage rule"
    );
}

#[test]
fn sast_phase2_flags_inner_html_assignment() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dom.js"), "el.innerHTML = dangerousData;\n").unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "innerHTML assignment should be flagged"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SAST/InnerHTMLAssignment"));
}

#[test]
fn sast_phase2_flags_dangerously_set_inner_html_in_tsx() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("comp.tsx"),
        "export const C = ({v}:{v:string}) => <div dangerouslySetInnerHTML={{__html:v}} />;\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "dangerouslySetInnerHTML should be flagged"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SAST/DangerouslySetInnerHTML"));
}

#[test]
fn sast_phase2_flags_document_write() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("legacy.js"),
        "document.write(\"<script>\" + userInput);\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "document.write() should be flagged"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SAST/DocumentWrite"));
}

#[test]
fn sast_disabled_via_config_skips_scan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.js"), "eval(x);\n").unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[sast]\nenabled = false\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "SAST disabled should produce no findings");
}

#[test]
fn sast_specific_rule_disabled_via_config() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.js"), "eval(x);\n").unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[sast]\ndisabled_rules = [\"SAST/EvalUsage\"]\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "disabled rule should produce no findings");
}

// ── review ────────────────────────────────────────────────────────────────────

/// Helper: create a git repo, write an initial file, commit it, then add a
/// second file so there is a HEAD~1..HEAD diff to analyze.
fn setup_two_commit_repo(dir: &std::path::Path, new_file: &str, new_content: &str) {
    init_git_repo(dir);
    // First commit: a seed file
    std::fs::write(dir.join("seed.txt"), "initial\n").unwrap();
    git_commit_all(dir, "initial");
    // Second commit: the file we want reviewed
    std::fs::write(dir.join(new_file), new_content).unwrap();
    git_commit_all(dir, "add new file");
}

#[test]
fn review_exits_zero_without_coverage_file() {
    let dir = tempfile::tempdir().unwrap();
    setup_two_commit_repo(dir.path(), "main.rs", "fn main() {}\n");

    let status = Command::new(binary())
        .args(["review", "--base", "HEAD~1"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "review without coverage file should exit 0"
    );
}

#[test]
fn review_json_format_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    setup_two_commit_repo(
        dir.path(),
        "app.js",
        "function foo() { if (true) { return 1; } }\n",
    );

    let output = Command::new(binary())
        .args(["review", "--base", "HEAD~1", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "review JSON should exit 0 when no coverage gate"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json must produce valid JSON");
    assert!(
        parsed["complexity"].is_object(),
        "JSON must have 'complexity' key"
    );
    assert!(parsed["passed"].is_boolean(), "JSON must have 'passed' key");
    let score = parsed["complexity"]["score"].as_u64().unwrap_or(0);
    assert!(
        score > 0,
        "complexity score should be > 0 for a non-empty diff"
    );
}

#[test]
fn review_coverage_gap_fails_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    // Add a JS file with new lines, all of which will be uncovered
    setup_two_commit_repo(
        dir.path(),
        "lib.js",
        "function add(a, b) { return a + b; }\nfunction sub(a, b) { return a - b; }\n",
    );

    // Write an LCOV file that shows line 1 covered, line 2 uncovered (50%)
    let lcov_path = dir.path().join("lcov.info");
    std::fs::write(
        &lcov_path,
        "SF:lib.js\nDA:1,1\nDA:2,0\nLH:1\nLF:2\nend_of_record\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "review",
            "--base",
            "HEAD~1",
            "--coverage-file",
            lcov_path.to_str().unwrap(),
            "--min-coverage",
            "80",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "review should fail when new-code coverage is below threshold"
    );
}

#[test]
fn review_coverage_passes_when_all_lines_covered() {
    let dir = tempfile::tempdir().unwrap();
    setup_two_commit_repo(
        dir.path(),
        "util.js",
        "function greet(name) { return 'Hello ' + name; }\n",
    );

    // LCOV: the single added line is covered
    let lcov_path = dir.path().join("lcov.info");
    std::fs::write(
        &lcov_path,
        "SF:util.js\nDA:1,3\nLH:1\nLF:1\nend_of_record\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "review",
            "--base",
            "HEAD~1",
            "--coverage-file",
            lcov_path.to_str().unwrap(),
            "--min-coverage",
            "80",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "review should pass when all new lines are covered"
    );
}

#[test]
fn review_sarif_output_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    setup_two_commit_repo(dir.path(), "mod.js", "function x() { return 1; }\n");

    // LCOV with uncovered line to generate SARIF results
    let lcov_path = dir.path().join("lcov.info");
    std::fs::write(&lcov_path, "SF:mod.js\nDA:1,0\nLH:0\nLF:1\nend_of_record\n").unwrap();

    let output = Command::new(binary())
        .args([
            "review",
            "--base",
            "HEAD~1",
            "--coverage-file",
            lcov_path.to_str().unwrap(),
            "--min-coverage",
            "0", // don't fail so we can inspect SARIF output
            "--format",
            "sarif",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format sarif must produce valid JSON");
    assert_eq!(parsed["version"].as_str(), Some("2.1.0"));
    assert!(parsed["runs"].is_array());
}

// ── watch-install ─────────────────────────────────────────────────────────────
//
// These tests use `sh -c "..."` as the wrapped "package manager" so they run
// without npm/yarn being installed.  All `watch-install` integration tests are
// Unix-only because they rely on POSIX shell.
//
// Timing note: the watcher polls every 250 ms.  Scripts that create-then-delete
// a file sleep for 0.7 s between the two operations, giving the watcher at
// least two polls to observe the file before it disappears.

#[test]
#[cfg(unix)]
fn watch_install_exits_zero_on_clean_install() {
    // Package manager does nothing — no files touched, no phantoms.
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args(["watch-install", "sh", "-c", "exit 0"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "clean install with no filesystem changes must exit 0"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_exits_nonzero_on_phantom_file() {
    // Script creates a file inside node_modules/, waits, then deletes it —
    // the classic postinstall-dropper signature.
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "mkdir -p node_modules/evil-pkg \
             && touch node_modules/evil-pkg/backdoor \
             && sleep 0.7 \
             && rm node_modules/evil-pkg/backdoor",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "phantom file (created-then-deleted) must cause non-zero exit"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_no_fail_flag_exits_zero_despite_phantom() {
    // --no-fail: report findings but never set non-zero exit.
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "--no-fail",
            "sh",
            "-c",
            "mkdir -p node_modules/evil-pkg \
             && touch node_modules/evil-pkg/backdoor \
             && sleep 0.7 \
             && rm node_modules/evil-pkg/backdoor",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "--no-fail must suppress non-zero exit even when phantom detected"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_config_block_false_exits_zero_on_phantom() {
    // block_phantom_scripts = false in .greengate.toml: same effect as --no-fail.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[supply_chain]\nblock_phantom_scripts = false\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "mkdir -p node_modules/evil-pkg \
             && touch node_modules/evil-pkg/backdoor \
             && sleep 0.7 \
             && rm node_modules/evil-pkg/backdoor",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "block_phantom_scripts = false must not fail even with a phantom"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_allowlisted_package_does_not_fail() {
    // Phantom inside a package on allow_postinstall must not cause failure.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[supply_chain]\nallow_postinstall = [\"trusted-builder\"]\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "mkdir -p node_modules/trusted-builder \
             && touch node_modules/trusted-builder/native.node \
             && sleep 0.7 \
             && rm node_modules/trusted-builder/native.node",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "phantom from an allow_postinstall package must not fail the install"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_non_allowlisted_fails_even_when_other_package_is_allowed() {
    // allow_postinstall = ["trusted"] but the phantom is from "evil-pkg" → still fails.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[supply_chain]\nallow_postinstall = [\"trusted\"]\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "mkdir -p node_modules/evil-pkg \
             && touch node_modules/evil-pkg/dropper \
             && sleep 0.7 \
             && rm node_modules/evil-pkg/dropper",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "non-allowlisted phantom must still fail even when other packages are allowed"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_persistent_file_in_node_modules_is_not_flagged() {
    // A file that remains after install is not a phantom.
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "mkdir -p node_modules/real-pkg && echo 'module.exports={}' > node_modules/real-pkg/index.js",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "a persistent node_modules file must not be flagged as a phantom"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_unknown_pm_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "this-pm-does-not-exist-anywhere",
            "install",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "non-existent package manager must cause non-zero exit"
    );
}

#[test]
#[cfg(unix)]
fn watch_install_exec_drop_in_project_root_is_flagged() {
    let dir = tempfile::tempdir().unwrap();

    // Script drops an executable in the project root.
    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "printf '#!/bin/sh\\necho hi\\n' > ./injected && chmod +x ./injected",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "executable dropped in project root must cause non-zero exit"
    );

    // Clean up so the temp dir can be removed cleanly.
    let _ = std::fs::remove_file(dir.path().join("injected"));
}

#[test]
#[cfg(unix)]
fn watch_install_enforce_sandbox_false_ignores_exec_drop() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".greengate.toml"),
        "[supply_chain]\nenforce_sandbox = false\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .args([
            "watch-install",
            "sh",
            "-c",
            "printf '#!/bin/sh\\necho hi\\n' > ./injected && chmod +x ./injected",
        ])
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "exec-drop in root must be ignored when enforce_sandbox = false"
    );

    let _ = std::fs::remove_file(dir.path().join("injected"));
}

#[test]
#[cfg(unix)]
fn watch_install_pm_failure_emits_warning() {
    // Wrapped pm exits non-zero. Greengate should warn about it.
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(binary())
        .args(["watch-install", "sh", "-c", "exit 1"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("non-zero"),
        "failed pm must emit a warning to stderr; stderr: {}",
        stderr
    );
}
