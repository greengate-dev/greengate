/// `greengate run` — pipeline runner.
///
/// Reads `[pipeline] steps = [...]` from `.greengate.toml` and runs each step
/// in order — all of them unless `[pipeline] fail_fast = true` — and exits
/// with the worst result.
///
/// Each step is either a bare command name ("scan") or a command with flags
/// ("coverage --min 80"). The runner dispatches directly to the same module
/// functions used by the CLI, so no subprocess spawning is needed.
use crate::modules::scanner::{OutputFormat, ScanOpts};
use crate::modules::tia::TiaFormat;
use crate::report::{Check, OnIncomplete, Report, Status};
use crate::utils::output::ReportFormat;
use crate::utils::{config, terminal};
use anyhow::Result;
use std::fmt::Display;
use std::str::FromStr;

/// Run every configured step in order and merge their results into one
/// report and one exit code. Checks keep their step as a prefix so the merged
/// report says where each came from. With `fail_fast`, stops at the first
/// step that does not pass under `on_incomplete`; the steps not run are
/// listed as incomplete, never as passed.
pub fn run_pipeline(
    cfg: &config::Config,
    on_incomplete: OnIncomplete,
    fail_fast: bool,
) -> Result<Report> {
    let steps = &cfg.pipeline.steps;

    if steps.is_empty() {
        anyhow::bail!(
            "No pipeline steps defined. Add [pipeline] steps = [\"scan\", ...] to .greengate.toml"
        );
    }

    terminal::info(&format!("Running pipeline: {} step(s)", steps.len()));

    let mut merged = Report::new("run");
    // (step, status, findings, passed) for the summary.
    let mut summary: Vec<(String, Option<Status>, usize, bool)> = Vec::new();
    let mut stopped_at: Option<String> = None;

    for (i, step_str) in steps.iter().enumerate() {
        let step_num = i + 1;
        let parts: Vec<&str> = step_str.split_whitespace().collect();
        let command = match parts.first() {
            Some(c) => *c,
            None => continue,
        };
        if let Some(failed) = &stopped_at {
            merged.checks.push(Check::incomplete(
                command,
                format!("not run: fail_fast stopped the pipeline after '{failed}'"),
            ));
            summary.push((step_str.clone(), None, 0, false));
            continue;
        }

        eprintln!();
        eprintln!(
            "─── Step {}/{}: {} ───────────────────────────────────",
            step_num,
            steps.len(),
            step_str
        );

        let step = match dispatch(command, &parts[1..], cfg) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("✗ Step '{command}' could not run: {e:#}");
                let mut failed = Report::new("run");
                failed.checks.push(Check::error(command, format!("{e:#}")));
                failed
            }
        };
        let status = step.status();
        let passed = step.exit_code(on_incomplete) == 0;
        let findings = step.findings.len();
        merge_step(&mut merged, command, step);
        summary.push((step_str.clone(), Some(status), findings, passed));

        if passed {
            terminal::success(&format!("Step '{}' {}.", command, status_word(status)));
        } else {
            eprintln!("✗ Step '{}' FAILED: {}.", command, status_word(status));
            if fail_fast {
                stopped_at = Some(command.to_string());
            }
        }
    }

    eprintln!();
    eprintln!("Pipeline summary:");
    for (step, status, findings, passed) in &summary {
        let (mark, what) = match status {
            None => ("-", "not run".to_string()),
            Some(s) => (
                if *passed { "✓" } else { "✗" },
                match (s, findings) {
                    (Status::Findings, n) => format!("{} ({n})", status_word(*s)),
                    _ => status_word(*s).to_string(),
                },
            ),
        };
        eprintln!("  {mark} {step:<28} {what}");
    }
    eprintln!();
    if merged.exit_code(on_incomplete) == 0 {
        terminal::success(&format!(
            "Pipeline {} ({} step(s)).",
            status_word(merged.status()),
            steps.len()
        ));
    } else {
        let failed = summary.iter().filter(|s| s.1.is_some() && !s.3).count();
        eprintln!(
            "Pipeline failed: {} — {failed} of {} step(s) did not pass.",
            status_word(merged.status()),
            steps.len()
        );
    }
    Ok(merged)
}

fn merge_step(into: &mut Report, step: &str, report: Report) {
    let prefix = |id: &str| {
        if id == step {
            id.to_string()
        } else {
            format!("{step}/{id}")
        }
    };
    into.checks.extend(report.checks.into_iter().map(|mut c| {
        c.id = prefix(&c.id);
        c
    }));
    // A step that ran to completion is itself a check, so the merged report
    // lists every step that ran, not just the ones that had something to say.
    if !into
        .checks
        .iter()
        .any(|c| c.id == step || c.id.starts_with(&format!("{step}/")))
    {
        into.checks.push(Check::passed(step));
    }
    into.findings.extend(report.findings);
    into.suppressed.extend(report.suppressed);
    into.warnings.extend(report.warnings);
}

fn status_word(status: Status) -> &'static str {
    match status {
        Status::Passed => "passed",
        Status::Findings => "found policy violations",
        Status::Incomplete => "was incomplete",
        Status::Error => "failed to run",
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

/// A step's `--since-baseline` flag, with `[policy]` (exceptions always apply).
fn baseline_policy(args: &[&str], cfg: &config::Config) -> crate::modules::suppress::Policy {
    use crate::modules::suppress::{BaselineMode, Policy};
    Policy::new(
        BaselineMode::from_flags(false, args.contains(&"--since-baseline")),
        cfg,
    )
}

/// The flags each step takes: (switches, flags with a value, flags whose
/// value is optional). Anything else fails the step instead of being
/// silently ignored.
fn step_flags(
    command: &str,
) -> Option<(
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
)> {
    Some(match command {
        "scan" => (
            &["--staged", "--history", "--since-baseline"],
            &["--changed-since", "--since"],
            &["--new-since"],
        ),
        "lint" => (&[], &["--dir"], &[]),
        "docker-lint" => (&[], &["--file"], &[]),
        "coverage" => (&[], &["--file", "--min"], &[]),
        "audit" => (&["--offline", "--since-baseline"], &[], &[]),
        "review" => (
            &["--staged", "--annotate"],
            &[
                "--base",
                "--coverage-file",
                "--min-coverage",
                "--complexity-budget",
                "--format",
            ],
            &[],
        ),
        "tia" => (&["--staged"], &["--base", "--format"], &[]),
        "sbom" => (&[], &["--output", "--lockfile"], &[]),
        "deps-check" => (&["--all"], &["--base"], &[]),
        "deps-review" => (&["--annotate"], &["--base"], &[]),
        "ci-lint" => (&[], &["--format", "--file"], &[]),
        _ => return None,
    })
}

fn check_step_flags(command: &str, args: &[&str]) -> Result<()> {
    let Some((switches, values, optional)) = step_flags(command) else {
        return Ok(()); // an unknown step fails in dispatch
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if values.contains(&a) {
            if args.get(i + 1).is_none_or(|v| v.starts_with("--")) {
                anyhow::bail!("step '{command}': {a} needs a value");
            }
            i += 1;
        } else if optional.contains(&a) {
            if args.get(i + 1).is_some_and(|v| !v.starts_with("--")) {
                i += 1;
            }
        } else if !switches.contains(&a) {
            anyhow::bail!(
                "step '{command}' does not take '{a}' (it takes: {})",
                switches
                    .iter()
                    .chain(values)
                    .chain(optional)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        i += 1;
    }
    Ok(())
}

/// The value of a flag whose value is optional: `Some("")` when it has none.
fn optional_value<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| *a == flag)?;
    Some(
        args.get(i + 1)
            .copied()
            .filter(|v| !v.starts_with("--"))
            .unwrap_or(""),
    )
}

fn dispatch(command: &str, args: &[&str], cfg: &config::Config) -> Result<Report> {
    check_step_flags(command, args)?;
    match command {
        "scan" => {
            let staged = args.contains(&"--staged");
            let since = flag_value(args, "--changed-since")
                .or_else(|| flag_value(args, "--since"))
                .map(str::to_string);
            let history = args.contains(&"--history");
            let new_since = optional_value(args, "--new-since");
            if new_since.is_some() && (staged || history || since.is_some()) {
                anyhow::bail!(
                    "step 'scan': --new-since cannot be combined with --staged, --history or --changed-since"
                );
            }
            let (diff, new_since) =
                crate::modules::scanner::select_diff(staged, history, since, new_since)?;
            crate::modules::scanner::run_scan(
                &ScanOpts {
                    format: OutputFormat::Text,
                    diff,
                    config: &cfg.scan,
                    sast_config: &cfg.sast,
                },
                baseline_policy(args, cfg),
                new_since.as_ref(),
            )
        }

        "lint" => {
            let dir = flag_value(args, "--dir")
                .unwrap_or(&cfg.lint.target_dir)
                .to_string();
            crate::modules::k8s_lint::run_lint(&dir)
        }

        "docker-lint" => {
            let dockerfile = flag_value(args, "--file")
                .unwrap_or(&cfg.docker.dockerfile)
                .to_string();
            crate::modules::docker_lint::run_docker_lint(&dockerfile)
        }

        "coverage" => {
            let file = flag_value(args, "--file")
                .unwrap_or(&cfg.coverage.file)
                .to_string();
            let min: f64 = parsed_flag(args, "--min")?.unwrap_or(cfg.coverage.min);
            crate::modules::coverage::run_coverage(&file, min)
        }

        "audit" => crate::modules::audit::run_audit(
            &cfg.audit,
            &cfg.deps.exclude_patterns,
            crate::report::Format::Text,
            args.contains(&"--offline"),
            baseline_policy(args, cfg),
        ),

        "lighthouse" | "reassure" => anyhow::bail!(
            "the '{command}' step was removed in greengate 0.4; take it out of [pipeline] steps \
             (use Lighthouse CI or Reassure's own reporting instead)"
        ),

        "review" => {
            let base = flag_value(args, "--base").unwrap_or("HEAD~1").to_string();
            let staged = args.contains(&"--staged");
            let coverage_file = flag_value(args, "--coverage-file").map(str::to_string);
            let min_coverage: f64 =
                parsed_flag(args, "--min-coverage")?.unwrap_or(cfg.review.min_new_code_coverage);
            let complexity_budget: u32 =
                parsed_flag(args, "--complexity-budget")?.unwrap_or(cfg.review.complexity_budget);
            let format = enum_flag(args, "--format")?.unwrap_or(ReportFormat::Text);
            let annotate = args.contains(&"--annotate");
            crate::modules::pr_review::run_review(crate::modules::pr_review::ReviewOpts {
                base,
                staged,
                coverage_file,
                min_coverage,
                complexity_budget,
                format,
                annotate,
            })
        }

        "tia" => {
            let base = flag_value(args, "--base").unwrap_or("HEAD~1").to_string();
            let staged = args.contains(&"--staged");
            let format = enum_flag(args, "--format")?.unwrap_or(TiaFormat::Newline);
            crate::modules::tia::run_tia(
                crate::modules::tia::TiaOpts {
                    base,
                    staged,
                    format,
                },
                &cfg.tia,
            )
            .map(|()| Report::new("tia"))
        }

        "sbom" => {
            let output = flag_value(args, "--output").map(str::to_string);
            crate::modules::sbom::run_sbom(crate::modules::sbom::SbomOpts {
                output: output.as_deref(),
                lockfile: flag_value(args, "--lockfile"),
                exclude: &cfg.deps.exclude_patterns,
            })
            .map(|()| Report::new("sbom"))
        }

        "deps-check" => {
            crate::modules::deps_check::run_deps_check(crate::modules::deps_check::CheckOpts {
                root: std::path::Path::new("."),
                base: flag_value(args, "--base"),
                all: args.contains(&"--all"),
                exclude: &cfg.deps.exclude_patterns,
                policy: &cfg.supply_chain,
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            })
        }

        "deps-review" => crate::modules::review::run_review(crate::modules::review::ReviewOpts {
            root: std::path::Path::new("."),
            base: flag_value(args, "--base"),
            cfg,
            format: crate::modules::review::ReviewFormat::Text,
            annotate: args.contains(&"--annotate"),
            policy: baseline_policy(&[], cfg),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }),

        "ci-lint" => {
            let format = enum_flag(args, "--format")?.unwrap_or(ReportFormat::Text);
            let file = flag_value(args, "--file").map(str::to_string);
            crate::modules::ci_lint::run_ci_lint(crate::modules::ci_lint::CiLintOpts {
                format,
                file,
                policy: baseline_policy(args, cfg),
            })
        }

        other => {
            anyhow::bail!(
                "Unknown pipeline step '{}'. Valid steps: scan, lint, docker-lint, coverage, audit, deps-check, deps-review, review, tia, sbom, ci-lint",
                other
            )
        }
    }
}

/// Extract the value following `--flag value` from an args slice.
fn flag_value<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1])
}

/// Parse the value of `--flag value`. A value that does not parse fails the
/// step rather than silently falling back to the configured default.
fn parsed_flag<T>(args: &[&str], flag: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    flag_value(args, flag)
        .map(|v| {
            v.parse()
                .map_err(|e| anyhow::anyhow!("invalid value '{v}' for {flag}: {e}"))
        })
        .transpose()
}

/// Parse the value of `--flag value` as one of a clap `ValueEnum`'s values.
fn enum_flag<T: clap::ValueEnum>(args: &[&str], flag: &str) -> Result<Option<T>> {
    flag_value(args, flag)
        .map(|v| T::from_str(v, false).map_err(|e| anyhow::anyhow!("invalid {flag}: {e}")))
        .transpose()
}
