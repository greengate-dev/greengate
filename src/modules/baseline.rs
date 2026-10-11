/// Scan baseline — save a snapshot of current findings and use it to suppress
/// known issues, so CI only fails on *new* findings introduced by a PR/commit.
///
/// Workflow:
///   1. `greengate scan --update-baseline`  → writes `.greengate-baseline.json`
///   2. `greengate scan --since-baseline`   → only fails on findings absent from baseline
use crate::modules::scanner::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_FILE: &str = ".greengate-baseline.json";

/// Stable fingerprint stored in the baseline.
/// Uses path + rule + line so individual line shifts don't invalidate the whole file.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct BaselineEntry {
    pub path: String,
    pub rule_id: String,
    pub line: usize,
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        Self {
            path: f.path.display().to_string(),
            rule_id: f.rule_id.clone(),
            line: f.line,
        }
    }
}

/// Persist findings to `.greengate-baseline.json`.
pub fn save_baseline(findings: &[Finding]) -> Result<()> {
    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from).collect();
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(BASELINE_FILE, json)?;
    eprintln!(
        "✅ Baseline saved: {} finding(s) written to {}",
        entries.len(),
        BASELINE_FILE
    );
    Ok(())
}

/// Load previously-saved baseline entries as a fingerprint set.
pub fn load_baseline() -> Result<HashSet<BaselineEntry>> {
    if !Path::new(BASELINE_FILE).exists() {
        return Ok(HashSet::new());
    }
    let content = std::fs::read_to_string(BASELINE_FILE)?;
    let entries: HashSet<BaselineEntry> = serde_json::from_str(&content)?;
    Ok(entries)
}

/// Drop findings already present in the baseline, keeping only new ones.
///
/// The (path, rule_id, line) comparison is line-exact intentionally — if the
/// same secret moves to a different line it should be reviewed again.
pub fn retain_new_findings(findings: &mut Vec<Finding>, baseline: &HashSet<BaselineEntry>) {
    findings.retain(|f| !baseline.contains(&BaselineEntry::from(f)));
}

/// Print a summary comparing current vs baseline.
pub fn print_baseline_summary(total: usize, new_count: usize, suppressed: usize) {
    if suppressed > 0 {
        eprintln!(
            "ℹ️  Baseline: {} total finding(s), {} suppressed by baseline, {} new",
            total, suppressed, new_count
        );
    }
}
