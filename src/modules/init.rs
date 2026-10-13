/// `greengate init` — interactive wizard that generates `.greengate.toml`.
///
/// Asks a few questions about the project and writes a tailored config file.
/// Aborts cleanly if the file already exists (unless --force is passed).
///
/// Pass `--ci github-actions` to also scaffold a `.github/workflows/greengate.yml`
/// workflow that uses the official greengate composite action.
use anyhow::Result;
use std::io::{self, BufRead, Write};

pub fn run_init(force: bool, ci: Option<&str>) -> Result<()> {
    let config_path = std::path::Path::new(".greengate.toml");

    if config_path.exists() && !force {
        anyhow::bail!(
            ".greengate.toml already exists. Run `greengate init --force` to overwrite."
        );
    }

    eprintln!("greengate init — generating .greengate.toml");
    eprintln!("Press Enter to accept the default shown in [brackets].\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    macro_rules! ask {
        ($prompt:expr, $default:expr) => {{
            eprint!("  {} [{}]: ", $prompt, $default);
            io::stderr().flush().ok();
            let input = lines.next().transpose()?.unwrap_or_default();
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                $default.to_string()
            } else {
                trimmed
            }
        }};
    }

    macro_rules! ask_bool {
        ($prompt:expr, $default:expr) => {{
            let default_str = if $default { "Y/n" } else { "y/N" };
            eprint!("  {} [{}]: ", $prompt, default_str);
            io::stderr().flush().ok();
            let input = lines.next().transpose()?.unwrap_or_default();
            let trimmed = input.trim().to_lowercase();
            match trimmed.as_str() {
                "y" | "yes" => true,
                "n" | "no" => false,
                _ => $default,
            }
        }};
    }

    // ── Scan ──────────────────────────────────────────────────────────────────
    eprintln!("[ Secret & SAST Scanning ]");
    let entropy_enabled = ask_bool!("Enable entropy-based secret detection?", true);
    let entropy_threshold = ask!("Entropy threshold (higher = fewer false positives)", "4.5");
    eprintln!();

    // ── Coverage ──────────────────────────────────────────────────────────────
    eprintln!("[ Coverage Gate ]");
    let coverage_file = ask!("LCOV file path", "coverage/lcov.info");
    let coverage_min = ask!("Minimum coverage %", "80");
    eprintln!();

    // ── K8s lint ──────────────────────────────────────────────────────────────
    eprintln!("[ Kubernetes Lint ]");
    let lint_dir = ask!("Kubernetes manifests directory", "./k8s");
    eprintln!();

    // ── Docker lint ───────────────────────────────────────────────────────────
    eprintln!("[ Docker Lint ]");
    let docker_file = ask!("Dockerfile path (leave blank to skip)", "");
    eprintln!();

    // ── Pipeline ──────────────────────────────────────────────────────────────
    eprintln!("[ Pipeline Runner ]");
    let run_pipeline = ask_bool!("Generate a default pipeline (greengate run)?", true);
    eprintln!();

    // ── Build TOML ────────────────────────────────────────────────────────────
    let mut toml = String::new();

    toml.push_str(&format!(
        "[scan]\n\
         entropy = {}\n\
         entropy_threshold = {}\n\
         entropy_min_length = 20\n\n",
        entropy_enabled, entropy_threshold
    ));

    toml.push_str(&format!(
        "[coverage]\n\
         file = \"{}\"\n\
         min = {}\n\n",
        coverage_file, coverage_min
    ));

    toml.push_str(&format!(
        "[lint]\n\
         target_dir = \"{}\"\n\n",
        lint_dir
    ));

    if !docker_file.is_empty() {
        toml.push_str(&format!(
            "[docker]\n\
             dockerfile = \"{}\"\n\n",
            docker_file
        ));
    }

    if run_pipeline {
        let mut steps: Vec<&str> = vec!["scan", "audit", "coverage"];
        if !docker_file.is_empty() {
            steps.push("docker-lint");
        }

        toml.push_str("[pipeline]\nsteps = [\n");
        for step in &steps {
            toml.push_str(&format!("  \"{}\",\n", step));
        }
        toml.push_str("]\n\n");
    }

    std::fs::write(config_path, &toml)?;

    eprintln!("✅ .greengate.toml written successfully.");
    eprintln!();

    // ── Optional: scaffold GitHub Actions workflow ────────────────────────────
    match ci {
        Some("github-actions") => {
            scaffold_github_actions(force)?;
        }
        Some(other) => {
            eprintln!(
                "⚠️  Unknown --ci provider '{}'. Supported: github-actions",
                other
            );
        }
        None => {}
    }

    eprintln!("Next steps:");
    eprintln!("  greengate scan          # scan for secrets & SAST issues");
    eprintln!("  greengate audit         # check dependencies for CVEs");
    eprintln!("  greengate coverage      # gate on test coverage");
    if !docker_file.is_empty() {
        eprintln!("  greengate docker-lint   # lint your Dockerfile");
    }
    if run_pipeline {
        eprintln!("  greengate run           # run all pipeline steps in order");
    }
    eprintln!("  greengate install-hooks # install git pre-commit hook");

    Ok(())
}

// ── GitHub Actions scaffolding ────────────────────────────────────────────────

/// Write `.github/workflows/greengate.yml` — a ready-to-use workflow that
/// downloads the greengate binary and runs the configured pipeline.
///
/// The generated workflow:
///   - Triggers on pushes to main/master and every pull request
///   - Uses the greengate composite action (reads from action.yml in this repo)
///   - Runs `greengate scan --format sarif` and uploads results to GitHub
///     Code Scanning (requires `security-events: write` permission)
///   - Runs `greengate run --profile ci` for the full pipeline gate
///   - Includes inline comments explaining each section
fn scaffold_github_actions(force: bool) -> Result<()> {
    let workflows_dir = std::path::Path::new(".github/workflows");
    std::fs::create_dir_all(workflows_dir)?;

    let workflow_path = workflows_dir.join("greengate.yml");

    if workflow_path.exists() && !force {
        eprintln!(
            "⚠️  .github/workflows/greengate.yml already exists. \
             Pass --force to overwrite."
        );
        return Ok(());
    }

    // Note: uses: lines reference version tags intentionally so the template
    // is readable. `greengate ci-lint` will flag them and guide the user
    // to pin them to commit SHAs for production hardening.
    let workflow = r#"# Generated by `greengate init --ci github-actions`.
#
# This workflow runs greengate on every push and pull request.
#
# SECURITY NOTE: The `uses:` lines below reference version tags.
# Run `greengate ci-lint` locally to get SHA-pinned equivalents
# suitable for production use.

name: greengate security gate

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  # Needed to post Check Run annotations and PR comments:
  checks: write
  # Needed to upload SARIF results to GitHub Code Scanning:
  security-events: write

jobs:
  greengate:
    name: greengate
    runs-on: ubuntu-latest

    steps:
      # Check out the repository so greengate can scan it.
      - name: Checkout
        uses: actions/checkout@v4  # TODO: pin to commit SHA

      # Run greengate scan and emit results as SARIF for GitHub Code Scanning.
      # This surfaces findings as inline annotations in the Files Changed tab.
      - name: Scan (SARIF)
        run: |
          curl -sSfL \
            "https://github.com/greengate-dev/greengate/releases/latest/download/greengate-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)-unknown-linux-musl" \
            -o /usr/local/bin/greengate 2>/dev/null \
          || curl -sSfL \
            "https://github.com/greengate-dev/greengate/releases/latest/download/greengate-latest-x86_64-unknown-linux-musl" \
            -o /usr/local/bin/greengate
          chmod +x /usr/local/bin/greengate
          greengate scan --format sarif > greengate-scan.sarif || true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3  # TODO: pin to commit SHA
        with:
          sarif_file: greengate-scan.sarif
          category: greengate-scan

      # Run the full pipeline (scan + audit + coverage + ci-lint, etc.)
      # as configured in .greengate.toml [pipeline].
      # This step fails the build if any gate is not met.
      - name: Run pipeline
        uses: greengate-dev/greengate@v0  # TODO: pin to commit SHA
        with:
          profile: ci
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"#;

    std::fs::write(&workflow_path, workflow)?;

    eprintln!("✅ .github/workflows/greengate.yml written successfully.");
    eprintln!();
    eprintln!("  Commit and push the workflow to enable it.");
    eprintln!(
        "  Run `greengate ci-lint` to get SHA-pinned action refs \
         for production hardening."
    );
    eprintln!();

    // Also write a Dependabot config block if none exists.
    let dependabot_path = std::path::Path::new(".github/dependabot.yml");
    if !dependabot_path.exists() {
        let dependabot = r#"# Generated by `greengate init --ci github-actions`.
# Keeps GitHub Actions pinned to the latest SHAs automatically.
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: "ci"
"#;
        std::fs::write(dependabot_path, dependabot)?;
        eprintln!("✅ .github/dependabot.yml written (auto-updates Action pins weekly).");
        eprintln!();
    }

    Ok(())
}
