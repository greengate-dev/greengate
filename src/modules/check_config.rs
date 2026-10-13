use crate::utils::{config::Config, terminal};
use anyhow::Result;

/// Validate and display the resolved `.greengate.toml` configuration.
///
/// - Exits with an error if the file exists but cannot be parsed.
/// - Prints all resolved values so users can verify overrides are applied correctly.
pub fn run_check_config() -> Result<()> {
    let path = std::path::Path::new(".greengate.toml");

    if !path.exists() {
        terminal::warn("No .greengate.toml found — all commands will use built-in defaults.");
        terminal::info("Run `greengate init` to generate a config file.");
        check_exceptions(&Config::default())?;
        print_defaults();
        return Ok(());
    }

    let content = std::fs::read_to_string(path)?;

    // Parse and report any TOML/serde errors with a clear message.
    let cfg: Config = toml::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            ".greengate.toml is invalid:\n\n  {}\n\nRun `greengate init --force` to regenerate it.",
            e
        )
    })?;

    terminal::success(".greengate.toml is valid.");
    check_exceptions(&cfg)?;
    eprintln!();
    eprintln!("Resolved configuration:");
    eprintln!();

    // ── Scan ──────────────────────────────────────────────────────────────────
    eprintln!("[scan]");
    eprintln!("  entropy             = {}", cfg.scan.entropy);
    eprintln!("  entropy_threshold   = {}", cfg.scan.entropy_threshold);
    eprintln!("  entropy_min_length  = {}", cfg.scan.entropy_min_length);
    eprintln!(
        "  extra_patterns      = {} custom pattern(s)",
        cfg.scan.extra_patterns.len()
    );
    for p in &cfg.scan.extra_patterns {
        eprintln!("    • {} = {}", p.name, p.regex);
    }
    eprintln!(
        "  exclude_patterns    = {} pattern(s)",
        cfg.scan.exclude_patterns.len()
    );
    for pat in &cfg.scan.exclude_patterns {
        eprintln!("    • {}", pat);
    }

    // ── SAST ──────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[sast]");
    eprintln!("  enabled             = {}", cfg.sast.enabled);
    eprintln!("  max_function_lines  = {}", cfg.sast.max_function_lines);
    eprintln!("  max_parameters      = {}", cfg.sast.max_parameters);
    eprintln!("  max_nesting_depth   = {}", cfg.sast.max_nesting_depth);
    eprintln!(
        "  disabled_rules      = {} rule(s)",
        cfg.sast.disabled_rules.len()
    );
    for r in &cfg.sast.disabled_rules {
        eprintln!("    • {}", r);
    }
    eprintln!(
        "  custom_rules        = {} rule(s)",
        cfg.sast.custom_rules.len()
    );
    for r in &cfg.sast.custom_rules {
        eprintln!("    • {}", r.id);
    }

    // ── Coverage ──────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[coverage]");
    eprintln!("  file                = {}", cfg.coverage.file);
    eprintln!("  min                 = {}%", cfg.coverage.min);

    // ── Lint ──────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[lint]");
    eprintln!("  target_dir          = {}", cfg.lint.target_dir);

    // ── Docker ────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[docker]");
    eprintln!("  dockerfile          = {}", cfg.docker.dockerfile);

    // ── Pipeline ──────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[pipeline]");
    eprintln!(
        "  steps               = {} step(s)",
        cfg.pipeline.steps.len()
    );
    for s in &cfg.pipeline.steps {
        eprintln!("    • {}", s);
    }

    eprintln!();
    terminal::success("Config check passed.");
    Ok(())
}

/// Validate `.greengate/exceptions.toml`, if there is one, and say how many
/// exceptions have expired or are about to.
fn check_exceptions(cfg: &Config) -> Result<()> {
    use crate::modules::exceptions::{self, EXCEPTIONS_FILE, WARN_DAYS};
    let today = crate::utils::dates::today();
    let Some(ex) = exceptions::load(
        std::path::Path::new("."),
        cfg.policy.max_exception_days,
        today,
    )?
    else {
        return Ok(());
    };
    let expired = ex.rules.iter().filter(|r| r.expired(today)).count();
    let soon = ex
        .rules
        .iter()
        .filter(|r| !r.expired(today) && r.expires - today < WARN_DAYS)
        .count();
    terminal::success(&format!(
        "{EXCEPTIONS_FILE} is valid: {} exception(s).",
        ex.rules.len()
    ));
    if expired > 0 {
        terminal::warn(&format!(
            "{expired} exception(s) have expired; their findings count again."
        ));
    }
    if soon > 0 {
        terminal::warn(&format!(
            "{soon} exception(s) expire within {WARN_DAYS} days."
        ));
    }
    if !cfg.audit.ignore_advisories.is_empty() {
        terminal::warn(
            "[audit] ignore_advisories is deprecated: run `greengate exceptions migrate`.",
        );
    }
    Ok(())
}

fn print_defaults() {
    eprintln!();
    eprintln!("Default values that will be used:");
    eprintln!("  [scan]     entropy=true, threshold=4.5, min_length=20");
    eprintln!(
        "  [sast]     enabled=true, max_function_lines=50, max_parameters=5, max_nesting_depth=4"
    );
    eprintln!("  [coverage] file=coverage/lcov.info, min=80%");
    eprintln!("  [lint]     target_dir=.");
    eprintln!("  [docker]   dockerfile=Dockerfile");
}
