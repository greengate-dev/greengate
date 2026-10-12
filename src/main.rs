use clap::{Parser, Subcommand};
use modules::scanner::{DiffMode, OutputFormat, ScanOpts};
use modules::tia::TiaFormat;
use std::process::ExitCode;
use utils::config::Profile;
use utils::output::ReportFormat;

mod deps;
mod modules;
mod registry;
mod report;
mod utils;

#[derive(Parser)]
#[command(name = "greengate")]
#[command(version)]
#[command(about = "A high-performance DevOps CLI tool in Rust", long_about = None)]
struct Cli {
    /// Apply a preset quality profile
    #[arg(long, global = true)]
    profile: Option<Profile>,

    /// Exit 0 even when some checks could not run (overrides [policy]
    /// on_incomplete). The output still reports the run as incomplete.
    #[arg(long, global = true)]
    allow_incomplete: bool,

    /// Also write the result as a report file: SARIF 2.1.0 when the path ends
    /// in `.sarif`, otherwise greengate.report/v1 JSON. Works on every gate.
    #[arg(long, global = true, value_name = "PATH")]
    report: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scans the current directory for hardcoded secrets and PII
    Scan {
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
        /// Only scan git-staged files (git diff --cached)
        #[arg(long)]
        staged: bool,
        /// Only scan files changed since REF (e.g. --changed-since HEAD~1).
        /// Every finding in those files counts; --new-since counts only new ones.
        #[arg(long, value_name = "REF")]
        changed_since: Option<String>,
        /// Deprecated alias of --changed-since
        #[arg(
            long,
            hide = true,
            value_name = "REF",
            conflicts_with = "changed_since"
        )]
        since: Option<String>,
        /// Only report findings that are new since the merge base with REF
        /// (default: the pull request's base branch in GitHub Actions). Files
        /// changed since then are scanned as they are and as they were.
        #[arg(long, value_name = "REF", num_args = 0..=1, default_missing_value = "",
              conflicts_with_all = ["staged", "history", "changed_since", "since", "update_baseline"])]
        new_since: Option<String>,
        /// Scan the entire git commit history for secrets (slow on large repos).
        #[arg(long)]
        history: bool,
        /// Post findings as a GitHub Check Run with per-line annotations and a PR review
        /// comment. Requires GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA env vars.
        /// No-op when env vars are absent.
        #[arg(long)]
        annotate: bool,
        /// Save current findings as the baseline (writes .greengate-baseline.json)
        #[arg(long, conflicts_with = "since_baseline")]
        update_baseline: bool,
        /// Only fail on findings not present in the saved baseline
        #[arg(long)]
        since_baseline: bool,
        /// Enrich each finding with git blame info (author + commit)
        #[arg(long)]
        blame: bool,
        /// Auto-redact detected secrets in-place (replaces matched values with `<REDACTED>`).
        /// SAST and structural findings are listed but not modified.
        #[arg(long)]
        fix: bool,
        /// Preview what --fix would change without writing to disk.
        #[arg(long)]
        dry_run: bool,
        /// Call an LLM to triage each finding as likely-real, likely-false-positive, or
        /// uncertain. Requires an API key in the env var set by `[triage] api_key_env`
        /// (default: ANTHROPIC_API_KEY). Configure model and endpoint in .greengate.toml.
        #[arg(long)]
        triage: bool,
    },
    /// Validates Kubernetes YAML manifests for resource limits and security issues
    Lint {
        /// Directory to scan for Kubernetes manifests (overrides config)
        #[arg(short, long)]
        dir: Option<String>,
    },
    /// Lints a Dockerfile for best-practice violations
    DockerLint {
        /// Path to the Dockerfile (overrides config)
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Parses an LCOV or Cobertura XML coverage file and fails if below threshold
    Coverage {
        /// Path to the coverage file (overrides config)
        #[arg(short, long)]
        file: Option<String>,
        /// Minimum coverage threshold percentage (overrides config)
        #[arg(short, long)]
        min: Option<f64>,
    },
    /// Installs greengate as a git pre-commit hook
    InstallHooks {
        /// Overwrite an existing hook without prompting
        #[arg(long)]
        force: bool,
    },
    /// Audits project dependencies for known vulnerabilities via the OSV database.
    /// Exits 0 when every dependency was checked and none is vulnerable, 1 on
    /// findings, and 3 when some could not be checked (see [policy] on_incomplete).
    Audit {
        /// Output format (json writes a greengate.report/v1 document to stdout)
        #[arg(long, default_value = "text")]
        format: report::Format,
        /// Use only the offline OSV snapshots (`greengate db update`); never
        /// query the API. Overrides [audit] source.
        #[arg(long)]
        offline: bool,
        /// Save current findings as the audit baseline (.greengate-baseline.json)
        #[arg(long, conflicts_with = "since_baseline")]
        update_baseline: bool,
        /// Only fail on findings not present in the saved baseline
        #[arg(long)]
        since_baseline: bool,
    },
    /// Inspect the dependency graph read from the project's lockfiles
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },
    /// Manage offline vulnerability data (OSV snapshots used by `audit`)
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Audits web performance via Google PageSpeed Insights (Lighthouse)
    Lighthouse {
        /// URL to audit (overrides config)
        #[arg(long)]
        url: Option<String>,
        /// Device strategy: mobile (default) or desktop (overrides config)
        #[arg(long)]
        strategy: Option<String>,
        /// Minimum Performance score 0–100 (overrides config)
        #[arg(long)]
        min_performance: Option<u8>,
        /// Minimum Accessibility score 0–100 (overrides config)
        #[arg(long)]
        min_accessibility: Option<u8>,
        /// Minimum Best Practices score 0–100 (overrides config)
        #[arg(long)]
        min_best_practices: Option<u8>,
        /// Minimum SEO score 0–100 (overrides config)
        #[arg(long)]
        min_seo: Option<u8>,
        /// Google PageSpeed Insights API key (overrides config and PAGESPEED_API_KEY env var)
        #[arg(long)]
        key: Option<String>,
    },
    /// Parses a Reassure performance report and gates on regressions
    Reassure {
        /// Path to current.perf file (overrides config)
        #[arg(long)]
        current: Option<String>,
        /// Path to baseline.perf file (overrides config; absence triggers report-only mode)
        #[arg(long)]
        baseline: Option<String>,
        /// Percentage mean-time increase allowed before failure (overrides config)
        #[arg(long)]
        threshold: Option<f64>,
    },
    /// Interactive wizard that generates a .greengate.toml config file.
    /// Pass --ci github-actions to also scaffold a ready-to-use GitHub Actions workflow.
    Init {
        /// Overwrite an existing .greengate.toml without prompting
        #[arg(long)]
        force: bool,
        /// Generate CI/CD integration scaffolding. Supported value: github-actions
        #[arg(long, value_name = "PROVIDER")]
        ci: Option<String>,
    },
    /// Re-runs scan automatically whenever source files change
    Watch {
        /// Only scan git-staged files on each change
        #[arg(long)]
        staged: bool,
        /// Poll interval in milliseconds (default: 2000)
        #[arg(long, default_value = "2000")]
        interval: u64,
    },
    /// Runs all pipeline steps defined in .greengate.toml in order and exits
    /// with the worst result; --report writes the merged report
    Run {
        /// Stop at the first step that does not pass (overrides [pipeline]
        /// fail_fast)
        #[arg(long)]
        fail_fast: bool,
    },
    /// Validates .greengate.toml and .greengate/exceptions.toml, and prints
    /// all resolved configuration values
    CheckConfig,
    /// Check a shell command before running it: plans every dependency
    /// install in it (`npm i x`, `uv add y`, `cd web && pnpm add z`…) with
    /// `greengate install --plan` — nothing is installed — and prints a
    /// greengate.report/v1 document. For agents and editors to wrap.
    /// Example: greengate check-command -- "npm install left-pad"
    CheckCommand {
        /// Directory the command would run in (default: current directory)
        #[arg(long)]
        cwd: Option<std::path::PathBuf>,
        /// Give up after this many seconds; the result is then incomplete
        #[arg(long, default_value = "120")]
        budget_secs: u64,
        /// The shell command (quote it, or pass it after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Agent hooks: check dependency installs before an AI agent runs them
    Hook {
        #[command(subcommand)]
        agent: HookAgent,
    },
    /// Manage the baseline of known findings (.greengate-baseline.json)
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Manage governed exceptions (.greengate/exceptions.toml)
    Exceptions {
        #[command(subcommand)]
        action: ExceptionsAction,
    },
    /// Generates a CycloneDX 1.5 SBOM from the project's dependency files.
    /// Use --attest to sign with Sigstore keyless signing (requires cosign in PATH).
    /// Use --verify to check an existing SBOM against a cosign bundle.
    Sbom {
        /// Build the SBOM from this dependency file only, instead of every one
        /// found under the current directory
        #[arg(long, value_name = "FILE")]
        lockfile: Option<String>,
        /// Write SBOM to a file instead of stdout (default when --attest is set: sbom.json)
        #[arg(short, long)]
        output: Option<String>,
        /// Sign the generated SBOM with Sigstore keyless signing via cosign
        #[arg(long, conflicts_with = "verify")]
        attest: bool,
        /// Path for the cosign bundle file (default: `<output>.bundle.json`)
        #[arg(long, value_name = "FILE")]
        bundle: Option<String>,
        /// Verify an existing SBOM against a cosign bundle instead of generating one
        #[arg(long, value_name = "SBOM_FILE", conflicts_with = "attest")]
        verify: Option<String>,
        /// Expected OIDC issuer for --verify, e.g. `https://token.actions.githubusercontent.com`
        #[arg(long, value_name = "ISSUER")]
        certificate_oidc_issuer: Option<String>,
        /// Expected signer identity for --verify (exact match)
        #[arg(long, value_name = "IDENTITY")]
        certificate_identity: Option<String>,
    },
    /// Wraps `pip install` with typosquat detection, post-install RECORD scanning,
    /// and executable-drop detection. Supports all pip install arguments.
    /// Example: greengate pip-install requests flask==2.3.0
    PipInstall {
        /// Arguments forwarded verbatim to pip
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
        /// pip / pip3 binary to invoke (default: pip)
        #[arg(long, default_value = "pip")]
        pip: String,
        /// Report findings but do not exit non-zero
        #[arg(long)]
        no_fail: bool,
    },
    /// Wraps `cargo add` with typosquat detection, build.rs static analysis,
    /// and transitive-dependency explosion guard.
    /// Example: greengate cargo-add serde tokio@1.0
    CargoAdd {
        /// Arguments forwarded verbatim to `cargo add`
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
        /// Report findings but do not exit non-zero
        #[arg(long)]
        no_fail: bool,
    },
    /// Installs dependencies with no package code running before greengate
    /// has checked the complete tree: plan (resolve + policy), fetch with
    /// scripts off, inspect every install script, then run approved scripts
    /// in a sandbox (bubblewrap: no network, writes confined, credentials
    /// masked) and verify the result. npm, pnpm, yarn, bun, pip, uv and cargo.
    /// Example: greengate install npm ci
    ///          greengate install --plan npm install left-pad
    Install {
        /// Stop after inspection: resolve, fetch and inspect in a scratch
        /// copy, change nothing in the project, run no package code
        #[arg(long)]
        plan: bool,
        /// How install scripts are isolated
        #[arg(long, value_enum, default_value = "auto")]
        isolate: modules::install::sandbox::IsolateMode,
        /// Report findings but do not exit non-zero
        #[arg(long)]
        no_fail: bool,
        /// pip binary for `install pip …` (e.g. a venv's pip)
        #[arg(long, default_value = "pip")]
        pip: String,
        /// Package manager: npm, pnpm, yarn, bun, pip, uv or cargo
        manager: String,
        /// The install command, e.g. `ci` or `install left-pad`
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
    },
    /// Wraps a package manager install and monitors for phantom dependencies
    /// (postinstall scripts that drop and delete binaries) and executable drops.
    /// Example: greengate watch-install npm install
    ///          greengate watch-install pnpm install --frozen-lockfile
    WatchInstall {
        /// Package manager to wrap: npm, yarn, pnpm, or bun
        #[arg(value_name = "PACKAGE_MANAGER")]
        package_manager: String,
        /// Arguments forwarded verbatim to the package manager
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
        /// Report findings but do not exit non-zero (overrides config block_phantom_scripts)
        #[arg(long)]
        no_fail: bool,
    },
    /// Scan a Docker/OCI container image for secrets and credentials baked into
    /// image layers. Requires Docker to be running. Pulls the image if not cached locally.
    /// Example: greengate image-scan nginx:latest
    ImageScan {
        /// Image reference to scan (e.g. nginx:latest, ghcr.io/org/app:sha-abc123)
        #[arg(value_name = "IMAGE")]
        image: String,
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
        /// Report findings but do not exit non-zero
        #[arg(long)]
        no_fail: bool,
    },
    /// Determines which test files are affected by changed source files using
    /// AST-based import analysis. Output is newline-separated by default so it
    /// can be piped directly into a test runner:
    ///   pytest $(greengate tia --base main)
    ///   npx jest $(greengate tia --base main)
    Tia {
        /// Diff base ref: commit, branch, or tag (default: HEAD~1)
        #[arg(long, default_value = "HEAD~1")]
        base: String,
        /// Diff against staged changes instead of committed diff
        #[arg(long)]
        staged: bool,
        /// Output format (newline is pipe-friendly)
        #[arg(long, default_value = "newline")]
        format: TiaFormat,
    },
    /// Lints GitHub Actions workflow files for security misconfigurations
    CiLint {
        /// Output format
        #[arg(long, default_value = "text")]
        format: ReportFormat,
        /// Path to a single workflow file to lint (instead of auto-discovering .github/workflows/)
        #[arg(long)]
        file: Option<String>,
        /// Save current findings as the ci-lint baseline (.greengate-baseline.json)
        #[arg(long, conflicts_with = "since_baseline")]
        update_baseline: bool,
        /// Only fail on findings not present in the saved baseline
        #[arg(long)]
        since_baseline: bool,
    },
    /// Analyzes a PR diff: outputs a Complexity Score and new-code coverage gaps
    Review {
        /// Diff base ref: commit, branch, or tag (default: HEAD~1)
        #[arg(long, default_value = "HEAD~1")]
        base: String,
        /// Diff against staged changes instead of committed diff
        #[arg(long)]
        staged: bool,
        /// Path to LCOV or Cobertura coverage file to cross-reference
        #[arg(long)]
        coverage_file: Option<String>,
        /// Minimum coverage % required for newly added lines (overrides config)
        #[arg(long)]
        min_coverage: Option<f64>,
        /// Fail if Complexity Score exceeds this value; 0 = warn only (overrides config)
        #[arg(long)]
        complexity_budget: Option<u32>,
        /// Output format
        #[arg(long, default_value = "text")]
        format: ReportFormat,
        /// Post results as a GitHub Check Run with annotations and a PR comment
        #[arg(long)]
        annotate: bool,
    },
    /// Report the AI-authored vs human-authored split of a commit range, and
    /// optionally fail when AI-authored code exceeds a share of new lines.
    Provenance {
        /// Base ref; the analysed range is `base..HEAD` (default: main)
        #[arg(long, default_value = "main")]
        base: String,
        /// Fail if AI-authored code exceeds this percent of added lines (0-100)
        #[arg(long)]
        max_ai_lines_pct: Option<u8>,
        /// Output format
        #[arg(long, default_value = "text")]
        format: ReportFormat,
    },
}

#[derive(Subcommand)]
enum DepsAction {
    /// List every package in every dependency file under a directory
    List {
        /// Directory to search (default: current directory)
        #[arg(long, default_value = ".")]
        path: std::path::PathBuf,
        /// Output format
        #[arg(long, default_value = "text")]
        format: report::Format,
    },
    /// Supply-chain policy gate: release risk for new or upgraded packages
    /// (cooldown, new install scripts, lost provenance, publisher changes,
    /// withdrawn releases) and lockfile policy for all of them (registry
    /// binding, dependency confusion, git/URL sources, missing integrity)
    Check {
        /// Compare against this git revision (default: the PR merge base in
        /// GitHub Actions, otherwise HEAD)
        #[arg(long, conflicts_with = "all")]
        base: Option<String>,
        /// Check every package against the registry, not just changed ones
        #[arg(long)]
        all: bool,
        /// Directory to search (default: current directory)
        #[arg(long, default_value = ".")]
        path: std::path::PathBuf,
    },
    /// Review what a change does to the dependency tree: every package added,
    /// removed, upgraded or downgraded since the merge base, with its license,
    /// the advisories it introduces or fixes, release risk and source policy,
    /// and how to fix each new advisory. [dependency_review] decides what fails.
    Review {
        /// Compare with the merge base of this ref and HEAD (default: the
        /// pull request's base branch in GitHub Actions, otherwise HEAD)
        #[arg(long)]
        base: Option<String>,
        /// Directory to search (default: current directory)
        #[arg(long, default_value = ".")]
        path: std::path::PathBuf,
        /// Output format: text, json (greengate.deps-review/v1) or markdown
        /// (the pull-request comment)
        #[arg(long, default_value = "text")]
        format: modules::review::ReviewFormat,
        /// Post the review to the pull request: one comment, updated in
        /// place, and a check run annotating lockfile lines. Needs
        /// GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_SHA.
        #[arg(long)]
        annotate: bool,
    },
    /// Show how a package ends up in the project: the chain from a direct
    /// dependency to it
    Why {
        /// Package name, optionally with @version
        package: String,
        /// Directory to search (default: current directory)
        #[arg(long, default_value = ".")]
        path: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum HookAgent {
    /// Claude Code PreToolUse hook: reads the event on stdin. Blocking
    /// findings deny the command, warnings or unfinished checks ask the
    /// user, and a clean result prints nothing (normal permissions apply).
    ClaudeCode {
        /// Give up after this many seconds and ask the user
        #[arg(long, default_value = "60")]
        budget_secs: u64,
        /// Approve dependency installs that pass, skipping the permission
        /// prompt (Claude Code deny rules still apply)
        #[arg(long)]
        allow_on_pass: bool,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Upgrade a version-1 baseline (exact lines) to version 2 (fingerprints
    /// that survive code moving). Re-scans, and keeps the findings the old
    /// baseline matched.
    Migrate,
}

#[derive(Subcommand)]
enum ExceptionsAction {
    /// Turn `[audit] ignore_advisories` into entries in
    /// .greengate/exceptions.toml, to be given a real reason and owner
    Migrate {
        /// Owner for the new entries (default: git user.email)
        #[arg(long)]
        owner: Option<String>,
    },
    /// List exceptions with their owner and expiry
    List,
}

#[derive(Subcommand)]
enum DbAction {
    /// Download or refresh OSV snapshots. Defaults to the ecosystems of the
    /// dependency files in the current directory.
    Update {
        /// Ecosystem to update (repeatable)
        #[arg(long = "ecosystem", value_name = "ECOSYSTEM",
              value_parser = ["npm", "crates.io", "PyPI", "Go"])]
        ecosystems: Vec<String>,
        /// Update every supported ecosystem
        #[arg(long, conflicts_with = "ecosystems")]
        all: bool,
    },
    /// Show each snapshot's age and size
    Status {
        /// Output format
        #[arg(long, default_value = "text")]
        format: report::Format,
    },
}

/// `greengate install` options for a legacy wrapper's command line.
fn install_opts<'a>(
    manager: &str,
    args: Vec<String>,
    no_fail: bool,
    pip: String,
    cfg: &'a utils::config::Config,
) -> modules::install::InstallOpts<'a> {
    modules::install::InstallOpts {
        manager: manager.to_string(),
        args,
        plan_only: false,
        isolate: modules::install::sandbox::IsolateMode::Auto,
        no_fail,
        pip,
        policy: &cfg.supply_chain,
        audit: &cfg.audit,
        review: &cfg.dependency_review,
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            // A bad config is a usage error, like a bad flag (clap exits 2);
            // anything else means the gate itself could not run.
            if e.downcast_ref::<utils::config::ConfigError>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::from(report::Status::Error.exit_code())
            }
        }
    }
}

/// Turns a command's [`report::Report`] into the process exit code.
struct Exit {
    on_incomplete: report::OnIncomplete,
    telemetry: utils::config::TelemetryConfig,
    t0: std::time::Instant,
    report_path: Option<std::path::PathBuf>,
}

impl Exit {
    fn finish(
        &self,
        command: &str,
        result: anyhow::Result<report::Report>,
    ) -> anyhow::Result<ExitCode> {
        let code = result
            .as_ref()
            .map_or(report::Status::Error.exit_code(), |r| {
                r.exit_code(self.on_incomplete)
            });
        modules::telemetry::emit(
            &modules::telemetry::command_metrics(
                command,
                self.t0.elapsed().as_millis() as u64,
                code == 0,
            ),
            &self.telemetry,
        );
        if let Some(path) = &self.report_path {
            // A gate that errored still leaves a report saying so, so CI
            // artifacts never go missing exactly when something broke.
            let errored;
            let written = match &result {
                Ok(r) => r,
                Err(e) => {
                    let mut r = report::Report::new("greengate");
                    r.checks
                        .push(report::Check::error(command, format!("{e:#}")));
                    errored = r;
                    &errored
                }
            };
            self.write_report(path, written)?;
        }
        result.map(|_| ExitCode::from(code))
    }

    fn write_report(&self, path: &std::path::Path, report: &report::Report) -> anyhow::Result<()> {
        use anyhow::Context;
        let sarif = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("sarif"));
        let doc = if sarif {
            report.to_sarif()
        } else {
            report.to_json(self.t0.elapsed().as_millis())
        };
        std::fs::write(path, serde_json::to_string_pretty(&doc)? + "\n")
            .with_context(|| format!("could not write report to {}", path.display()))
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let t0 = std::time::Instant::now();
    let cli = Cli::parse();

    // The agent hook runs before the config is loaded: a hook that exits 2
    // blocks the agent's command, so a broken .greengate.toml must not turn
    // into "block every shell command". Problems surface as an `ask`.
    if let Commands::Hook {
        agent:
            HookAgent::ClaudeCode {
                budget_secs,
                allow_on_pass,
            },
    } = &cli.command
    {
        use std::io::Read;
        let mut input = String::new();
        if std::io::stdin().read_to_string(&mut input).is_ok()
            && let Some(out) = modules::agent::claude_code_hook(
                &input,
                std::time::Duration::from_secs(*budget_secs),
                *allow_on_pass,
            )
        {
            println!("{out}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Suppress the "Loaded config" info message when emitting structured output
    // so that JSON/SARIF/JUnit parsers don't see unexpected text on stderr.
    let silent = matches!(
        cli.command,
        Commands::Scan { format, .. } if format != OutputFormat::Text
    );
    let mut cfg = if silent {
        utils::config::load_silent()?
    } else {
        utils::config::load()?
    };

    // Apply profile overrides on top of the loaded config
    if let Some(profile) = cli.profile {
        utils::config::apply_profile(&mut cfg, profile);
    }

    let exit = Exit {
        on_incomplete: if cli.allow_incomplete {
            report::OnIncomplete::Warn
        } else {
            cfg.policy.on_incomplete
        },
        telemetry: cfg.telemetry.clone(),
        t0,
        report_path: cli.report.clone(),
    };

    match cli.command {
        Commands::Scan {
            format,
            staged,
            changed_since,
            since,
            new_since,
            history,
            annotate,
            update_baseline,
            since_baseline,
            blame,
            fix,
            dry_run,
            triage,
        } => {
            use modules::suppress::{self, BaselineMode};
            suppress::preflight(&cfg)?;
            let text = format == OutputFormat::Text;
            if since.is_some() {
                utils::terminal::warn(
                    "--since is deprecated: use --changed-since (the same), or --new-since to count only new findings",
                );
            }
            let new_since = new_since
                .map(|r| modules::new_since::resolve(Some(&r)))
                .transpose()?;
            let diff = if history {
                Some(DiffMode::History)
            } else if staged {
                Some(DiffMode::Staged)
            } else if let Some(d) = &new_since {
                Some(DiffMode::Files(d.changed.clone()))
            } else {
                changed_since.or(since).map(DiffMode::Since)
            };

            let opts = ScanOpts {
                format,
                diff,
                config: &cfg.scan,
                sast_config: &cfg.sast,
            };
            let scan_t0 = std::time::Instant::now();
            let (mut findings, inline) =
                modules::scanner::split_suppressed(modules::scanner::collect_findings(&opts)?);
            let scan_duration_ms = scan_t0.elapsed().as_millis() as u64;

            // Enrich with git blame if requested
            if blame {
                modules::scanner::enrich_with_blame(&mut findings);
            }

            // --fix / --dry-run: redact secrets in-place before any other output
            if fix || dry_run {
                modules::scanner::apply_scan_fixes(&findings, &opts, dry_run)?;
                // After fixing, re-scan to confirm what remains (or just exit clean)
                if !dry_run {
                    return Ok(ExitCode::SUCCESS);
                }
            }

            // Exceptions, findings already at the --new-since base, baseline.
            let base = new_since
                .as_ref()
                .map(|d| modules::scanner::base_subjects(&opts, d))
                .transpose()?;
            let policy = suppress::Policy::new(
                BaselineMode::from_flags(update_baseline, since_baseline),
                &cfg,
            );
            let (findings, mut report, outcome) =
                modules::scanner::apply_suppressions(findings, inline, &opts, policy, base)?;

            // Baseline: save mode — recording findings is the point, not a failure.
            if update_baseline {
                if text {
                    suppress::print_summary(&outcome.notes, &[]);
                } else {
                    modules::scanner::emit_findings(&findings, format)?;
                }
                return exit.finish("scan", Ok(report));
            }

            // Telemetry — fire and forget, never fails the build
            modules::telemetry::emit(
                &modules::telemetry::scan_metrics(&findings, scan_duration_ms),
                &cfg.telemetry,
            );

            // Triage path — LLM annotates each finding before printing
            if triage && cfg.triage.enabled {
                let triage_results = modules::triage::triage_findings(&findings, &cfg.triage);
                modules::triage::emit_triaged(
                    &findings,
                    &triage_results,
                    cfg.triage.auto_suppress_threshold,
                );
                let reports = std::mem::take(&mut report.findings);
                for (mut f, t) in reports.into_iter().zip(&triage_results) {
                    let suppressed = t.as_ref().is_some_and(|t| {
                        modules::triage::should_auto_suppress(
                            t,
                            cfg.triage.auto_suppress_threshold,
                        )
                    });
                    if suppressed {
                        f.suppression = Some(report::Suppression::new(
                            report::SuppressionKind::Triage,
                            Some("triaged as a likely false positive".into()),
                        ));
                        report.suppressed.push(f);
                    } else {
                        report.findings.push(f);
                    }
                }
                if text {
                    suppress::print_summary(&outcome.notes, &report.suppressed);
                }
                return exit.finish("scan", Ok(report));
            }

            // Normal scan path
            if annotate
                && let Some(env) = modules::github::detect_github_env()
                && let Err(e) = modules::github::annotate(&findings, &env)
            {
                eprintln!("greengate: warning: GitHub annotation failed: {}", e);
            }
            modules::scanner::emit_findings(&findings, format)?;
            if text {
                suppress::print_summary(&outcome.notes, &report.suppressed);
            }
            return exit.finish("scan", Ok(report));
        }
        Commands::Lint { dir } => {
            let target = dir.unwrap_or(cfg.lint.target_dir);
            return exit.finish("lint", modules::k8s_lint::run_lint(&target));
        }
        Commands::DockerLint { file } => {
            let dockerfile = file.unwrap_or(cfg.docker.dockerfile);
            return exit.finish(
                "docker-lint",
                modules::docker_lint::run_docker_lint(&dockerfile),
            );
        }
        Commands::Coverage { file, min } => {
            let lcov_file = file.unwrap_or(cfg.coverage.file);
            let threshold = min.unwrap_or(cfg.coverage.min);
            return exit.finish(
                "coverage",
                modules::coverage::run_coverage(&lcov_file, threshold),
            );
        }
        Commands::InstallHooks { force } => {
            modules::hooks::run_install_hooks(force)?;
        }
        Commands::Deps {
            action: DepsAction::Check { base, all, path },
        } => {
            let result = modules::deps_check::run_deps_check(modules::deps_check::CheckOpts {
                root: &path,
                base: base.as_deref(),
                all,
                exclude: &cfg.deps.exclude_patterns,
                policy: &cfg.supply_chain,
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            });
            return exit.finish("deps-check", result);
        }
        Commands::Deps {
            action:
                DepsAction::Review {
                    base,
                    path,
                    format,
                    annotate,
                },
        } => {
            modules::suppress::preflight(&cfg)?;
            let result = modules::review::run_review(modules::review::ReviewOpts {
                root: &path,
                base: base.as_deref(),
                cfg: &cfg,
                format,
                annotate,
                policy: modules::suppress::Policy::new(Default::default(), &cfg),
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            });
            return exit.finish("deps-review", result);
        }
        Commands::Deps { action } => match action {
            DepsAction::List { path, format } => {
                modules::deps_cmd::run_list(&path, &cfg.deps.exclude_patterns, format)?
            }
            DepsAction::Why { package, path } => {
                modules::deps_cmd::run_why(&path, &cfg.deps.exclude_patterns, &package)?
            }
            DepsAction::Check { .. } | DepsAction::Review { .. } => {
                unreachable!("handled above")
            }
        },
        Commands::Db { action } => match action {
            DbAction::Update { ecosystems, all } => {
                let ecosystems: Vec<String> = if all {
                    modules::osv_db::ECOSYSTEMS
                        .iter()
                        .map(|e| e.to_string())
                        .collect()
                } else if ecosystems.is_empty() {
                    let found = modules::audit::project_ecosystems(
                        std::path::Path::new("."),
                        &cfg.deps.exclude_patterns,
                    );
                    anyhow::ensure!(
                        !found.is_empty(),
                        "No supported dependency files here. Pass --ecosystem or --all."
                    );
                    found.iter().map(|e| e.to_string()).collect()
                } else {
                    ecosystems
                };
                modules::osv_db::run_update(&ecosystems)?;
            }
            DbAction::Status { format } => {
                modules::osv_db::run_status(format == report::Format::Json)?;
            }
        },
        Commands::Audit {
            format,
            offline,
            update_baseline,
            since_baseline,
        } => {
            modules::suppress::preflight(&cfg)?;
            let policy = modules::suppress::Policy::new(
                modules::suppress::BaselineMode::from_flags(update_baseline, since_baseline),
                &cfg,
            );
            let result = modules::audit::run_audit(
                &cfg.audit,
                &cfg.deps.exclude_patterns,
                format,
                offline,
                policy,
            );
            if format == report::Format::Json
                && let Ok(report) = &result
            {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report.to_json(t0.elapsed().as_millis()))?
                );
            }
            return exit.finish("audit", result);
        }
        Commands::Lighthouse {
            url,
            strategy,
            min_performance,
            min_accessibility,
            min_best_practices,
            min_seo,
            key,
        } => {
            use modules::perf_lighthouse::{LighthouseOpts, LighthouseThresholds};

            let resolved_url = url.or_else(|| cfg.lighthouse.url.clone()).ok_or_else(|| {
                anyhow::anyhow!(
                    "No URL specified. Pass --url <URL> or set [lighthouse] url in .greengate.toml"
                )
            })?;

            let result = modules::perf_lighthouse::run_lighthouse(LighthouseOpts {
                url: &resolved_url,
                strategy: &strategy.unwrap_or(cfg.lighthouse.strategy),
                thresholds: LighthouseThresholds {
                    performance: min_performance.unwrap_or(cfg.lighthouse.min_performance),
                    accessibility: min_accessibility.unwrap_or(cfg.lighthouse.min_accessibility),
                    best_practices: min_best_practices
                        .unwrap_or(cfg.lighthouse.min_best_practices),
                    seo: min_seo.unwrap_or(cfg.lighthouse.min_seo),
                },
                api_key: key.or(cfg.lighthouse.api_key),
            });
            return exit.finish("lighthouse", result);
        }
        Commands::Reassure {
            current,
            baseline,
            threshold,
        } => {
            use modules::reassure::ReassureOpts;

            let current_path = current.unwrap_or(cfg.reassure.current);
            let baseline_path = baseline.unwrap_or(cfg.reassure.baseline);
            let resolved_threshold = threshold.unwrap_or(cfg.reassure.threshold);

            let baseline_opt = if std::path::Path::new(&baseline_path).exists() {
                Some(baseline_path.as_str())
            } else {
                None
            };

            let result = modules::reassure::run_reassure(ReassureOpts {
                current: &current_path,
                baseline: baseline_opt,
                threshold: resolved_threshold,
            });
            return exit.finish("reassure", result);
        }
        Commands::Init { force, ci } => {
            modules::init::run_init(force, ci.as_deref())?;
        }
        Commands::Watch { staged, interval } => {
            modules::watch::run_watch(modules::watch::WatchOpts {
                staged,
                interval_ms: interval,
            })?;
        }
        Commands::Run { fail_fast } => {
            let result = modules::pipeline::run_pipeline(
                &cfg,
                exit.on_incomplete,
                fail_fast || cfg.pipeline.fail_fast,
            );
            return exit.finish("run", result);
        }
        Commands::CheckConfig => {
            modules::check_config::run_check_config()?;
        }
        Commands::CheckCommand {
            cwd,
            budget_secs,
            command,
        } => {
            let cwd = match cwd {
                Some(c) => c,
                None => std::env::current_dir()?,
            };
            let outcome = modules::agent::check(
                &command.join(" "),
                &cwd,
                std::time::Duration::from_secs(budget_secs),
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome.report.to_json(t0.elapsed().as_millis()))?
            );
            return exit.finish("check-command", Ok(outcome.report));
        }
        Commands::Hook { .. } => unreachable!("handled before the config is loaded"),
        Commands::Baseline {
            action: BaselineAction::Migrate,
        } => {
            let opts = ScanOpts {
                format: OutputFormat::Text,
                diff: None,
                config: &cfg.scan,
                sast_config: &cfg.sast,
            };
            match modules::scanner::migrate_baseline(&opts)? {
                None => utils::terminal::info(&format!(
                    "{} is already version 2; nothing to migrate.",
                    modules::baseline::BASELINE_FILE
                )),
                Some((kept, total)) => utils::terminal::success(&format!(
                    "Baseline migrated to version 2: {kept} of {total} entries still match a finding{}",
                    if kept < total {
                        format!("; {} no longer match and were dropped", total - kept)
                    } else {
                        String::new()
                    }
                )),
            }
        }
        Commands::Exceptions { action } => match action {
            ExceptionsAction::Migrate { owner } => {
                modules::exceptions::run_migrate(&cfg, owner)?;
            }
            ExceptionsAction::List => {
                modules::exceptions::run_list(&cfg)?;
            }
        },
        Commands::Sbom {
            output,
            lockfile,
            attest,
            bundle,
            verify,
            certificate_oidc_issuer,
            certificate_identity,
        } => {
            if let Some(sbom_file) = verify {
                // Verify mode: check existing SBOM against a bundle.
                let bundle_path = bundle.unwrap_or_else(|| format!("{}.bundle.json", sbom_file));
                // Fall back to config-level identity constraints if not supplied on CLI.
                let issuer = certificate_oidc_issuer
                    .as_deref()
                    .or(cfg.sbom.expected_issuer.as_deref());
                let identity = certificate_identity
                    .as_deref()
                    .or(cfg.sbom.expected_identity.as_deref());
                let result =
                    modules::sbom::run_sbom_verify(&sbom_file, &bundle_path, issuer, identity);
                return exit.finish("sbom-verify", result);
            } else if attest {
                // Attest mode: generate SBOM then sign it.
                let sbom_out = output.unwrap_or_else(|| cfg.sbom.default_output.clone());
                let bundle_out = bundle.unwrap_or_else(|| format!("{}.bundle.json", sbom_out));
                modules::sbom::run_sbom(modules::sbom::SbomOpts {
                    output: Some(&sbom_out),
                    lockfile: lockfile.as_deref(),
                    exclude: &cfg.deps.exclude_patterns,
                })?;
                modules::sbom::run_sbom_attest(&sbom_out, &bundle_out)?;
            } else {
                modules::sbom::run_sbom(modules::sbom::SbomOpts {
                    output: output.as_deref(),
                    lockfile: lockfile.as_deref(),
                    exclude: &cfg.deps.exclude_patterns,
                })?;
            }
        }
        Commands::PipInstall { args, pip, no_fail } => {
            if modules::install::pip_supports_report(&pip) {
                let mut routed = vec!["install".to_string()];
                routed.extend(args.iter().filter(|a| *a != "install").cloned());
                modules::install::deprecation(
                    "pip-install",
                    Some(&format!("pip {}", routed.join(" "))),
                );
                let result =
                    modules::install::run_install(install_opts("pip", routed, no_fail, pip, &cfg));
                return exit.finish("pip-install", result);
            }
            modules::install::deprecation("pip-install", None);
            let result = modules::pip_audit::run_pip_install(modules::pip_audit::PipInstallOpts {
                pip,
                args,
                no_fail,
                allow_packages: cfg.supply_chain.allow_pip_packages,
                slopsquat_check: cfg.supply_chain.slopsquat_check,
                slopsquat_min_age_days: cfg.supply_chain.slopsquat_min_age_days,
                slopsquat_min_downloads: cfg.supply_chain.slopsquat_min_downloads,
                internal_packages: cfg.supply_chain.internal_packages.clone(),
            });
            return exit.finish("pip-install", result);
        }
        Commands::CargoAdd { args, no_fail } => {
            // `install cargo` needs a manifest here; without one, the legacy
            // path reports the same error it always did.
            if std::path::Path::new("Cargo.toml").is_file() {
                let mut routed = vec!["add".to_string()];
                routed.extend(args.iter().cloned());
                modules::install::deprecation(
                    "cargo-add",
                    Some(&format!("cargo {}", routed.join(" "))),
                );
                let result = modules::install::run_install(install_opts(
                    "cargo",
                    routed,
                    no_fail,
                    "pip".into(),
                    &cfg,
                ));
                return exit.finish("cargo-add", result);
            }
            modules::install::deprecation("cargo-add", None);
            let result = modules::cargo_audit::run_cargo_add(modules::cargo_audit::CargoAddOpts {
                args,
                no_fail,
                allow_crates: cfg.supply_chain.allow_cargo_crates,
                slopsquat_check: cfg.supply_chain.slopsquat_check,
                slopsquat_min_age_days: cfg.supply_chain.slopsquat_min_age_days,
                slopsquat_min_downloads: cfg.supply_chain.slopsquat_min_downloads,
                internal_packages: cfg.supply_chain.internal_packages.clone(),
            });
            return exit.finish("cargo-add", result);
        }
        Commands::ImageScan {
            image,
            format,
            no_fail,
        } => {
            let result = modules::image_scan::run_image_scan(modules::image_scan::ImageScanOpts {
                image,
                format,
                no_fail,
                scan_cfg: &cfg.scan,
            });
            return exit.finish("image-scan", result);
        }
        Commands::Install {
            plan,
            isolate,
            no_fail,
            pip,
            manager,
            args,
        } => {
            let result = modules::install::run_install(modules::install::InstallOpts {
                manager,
                args,
                plan_only: plan,
                isolate,
                no_fail,
                pip,
                policy: &cfg.supply_chain,
                audit: &cfg.audit,
                review: &cfg.dependency_review,
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            });
            return exit.finish("install", result);
        }
        Commands::WatchInstall {
            package_manager,
            args,
            no_fail,
        } => {
            if modules::install::accepts(&package_manager, &args) {
                modules::install::deprecation(
                    "watch-install",
                    Some(&format!("{package_manager} {}", args.join(" "))),
                );
                let result = modules::install::run_install(install_opts(
                    &package_manager,
                    args,
                    no_fail || !cfg.supply_chain.block_phantom_scripts,
                    "pip".into(),
                    &cfg,
                ));
                return exit.finish("watch-install", result);
            }
            modules::install::deprecation("watch-install", None);
            let result = modules::watch_install::run_watch_install(
                modules::watch_install::WatchInstallOpts {
                    package_manager,
                    args,
                    block_phantom_scripts: !no_fail && cfg.supply_chain.block_phantom_scripts,
                    enforce_sandbox: cfg.supply_chain.enforce_sandbox,
                    allow_postinstall: cfg.supply_chain.allow_postinstall,
                    slopsquat_check: cfg.supply_chain.slopsquat_check,
                    slopsquat_min_age_days: cfg.supply_chain.slopsquat_min_age_days,
                    slopsquat_min_downloads: cfg.supply_chain.slopsquat_min_downloads,
                    internal_packages: cfg.supply_chain.internal_packages.clone(),
                },
            );
            return exit.finish("watch-install", result);
        }
        Commands::Tia {
            base,
            staged,
            format,
        } => {
            modules::tia::run_tia(
                modules::tia::TiaOpts {
                    base,
                    staged,
                    format,
                },
                &cfg.tia,
            )?;
        }
        Commands::CiLint {
            format,
            file,
            update_baseline,
            since_baseline,
        } => {
            modules::suppress::preflight(&cfg)?;
            let policy = modules::suppress::Policy::new(
                modules::suppress::BaselineMode::from_flags(update_baseline, since_baseline),
                &cfg,
            );
            let result = modules::ci_lint::run_ci_lint(modules::ci_lint::CiLintOpts {
                format,
                file,
                policy,
            });
            return exit.finish("ci-lint", result);
        }
        Commands::Provenance {
            base,
            max_ai_lines_pct,
            format,
        } => {
            let result =
                modules::provenance::run_provenance(modules::provenance::ProvenanceOpts {
                    base,
                    max_ai_lines_pct,
                    format,
                });
            return exit.finish("provenance", result);
        }
        Commands::Review {
            base,
            staged,
            coverage_file,
            min_coverage,
            complexity_budget,
            format,
            annotate,
        } => {
            let result = modules::pr_review::run_review(modules::pr_review::ReviewOpts {
                base,
                staged,
                coverage_file,
                min_coverage: min_coverage.unwrap_or(cfg.review.min_new_code_coverage),
                complexity_budget: complexity_budget.unwrap_or(cfg.review.complexity_budget),
                format,
                annotate,
            });
            return exit.finish("review", result);
        }
    }

    // Only gates reach `exit.finish`; everything else (tia, init, sbom
    // generation, …) has no pass/fail result to report.
    if let Some(path) = &exit.report_path {
        utils::terminal::warn(&format!(
            "--report {} ignored: this command is not a gate and produces no report.",
            path.display()
        ));
    }
    Ok(ExitCode::SUCCESS)
}
