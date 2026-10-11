use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use crate::utils::terminal;

// ── Config ────────────────────────────────────────────────────────────────────

pub struct ReassureOpts<'a> {
    pub current: &'a str,
    pub baseline: Option<&'a str>,
    /// Percentage of mean-time increase allowed before flagging a regression.
    pub threshold: f64,
}

// ── .perf JSON format ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PerfReport {
    results: HashMap<String, ComponentResult>,
}

#[derive(Deserialize)]
struct ComponentResult {
    #[serde(rename = "meanTime")]
    mean_time: f64,
    renders: f64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_reassure(opts: ReassureOpts<'_>) -> Result<()> {
    terminal::info(&format!("Parsing Reassure report: {}", opts.current));

    let current = load_report(opts.current)?;

    let baseline = match opts.baseline {
        Some(path) if std::path::Path::new(path).exists() => {
            terminal::info(&format!("Baseline found: {}", path));
            Some(load_report(path)?)
        }
        Some(_) => {
            terminal::warn("Baseline file not found — running in report-only mode.");
            None
        }
        None => None,
    };

    let Some(base) = baseline else {
        eprintln!();
        eprintln!(
            "  {:<40}  {:>10}  {:>8}",
            "Component", "Mean (ms)", "Renders"
        );
        eprintln!("  {}", "─".repeat(62));
        for (name, res) in &current.results {
            eprintln!(
                "  {:<40}  {:>10.1}  {:>8.1}",
                truncate(name, 40),
                res.mean_time,
                res.renders,
            );
        }
        eprintln!();
        terminal::info("No baseline provided — metrics reported above (no gating applied).");
        return Ok(());
    };

    let mut regressions = 0usize;

    eprintln!();
    eprintln!(
        "  {:<40}  {:>10}  {:>8}  {:>9}  {:>10}",
        "Component", "Mean (ms)", "Renders", "Δ Mean", "Δ Renders"
    );
    eprintln!("  {}", "─".repeat(84));

    // Sort by component name for stable output
    let mut names: Vec<&String> = current.results.keys().collect();
    names.sort();

    for name in &names {
        let cur = &current.results[*name];
        let (delta_mean_str, delta_renders_str) = match base.results.get(*name) {
            Some(base_res) => {
                let pct = (cur.mean_time - base_res.mean_time) / base_res.mean_time * 100.0;
                let renders_increased = cur.renders > base_res.renders;
                let is_regressed = pct > opts.threshold || renders_increased;
                if is_regressed {
                    regressions += 1;
                }
                let flag = if is_regressed { " ❌" } else { "" };

                let delta_mean = if pct >= 0.0 {
                    format!("+{:.1}%{}", pct, flag)
                } else {
                    format!("{:.1}%", pct)
                };
                let delta_renders = if renders_increased {
                    format!("+{:.1} ❌", cur.renders - base_res.renders)
                } else {
                    "─".to_string()
                };
                (delta_mean, delta_renders)
            }
            // New component — no baseline to compare
            None => ("new".to_string(), "─".to_string()),
        };

        eprintln!(
            "  {:<40}  {:>10.1}  {:>8.1}  {:>9}  {:>10}",
            truncate(name, 40),
            cur.mean_time,
            cur.renders,
            delta_mean_str,
            delta_renders_str,
        );
    }

    eprintln!();

    if regressions > 0 {
        anyhow::bail!(
            "Reassure failed: {} component(s) exceed the {:.1}% regression threshold.",
            regressions,
            opts.threshold,
        );
    }

    terminal::success(&format!(
        "Reassure passed: no regressions detected (threshold: {:.1}%)",
        opts.threshold
    ));
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_report(path: &str) -> Result<PerfReport> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read Reassure file: {}", path))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse Reassure file: {}", path))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
