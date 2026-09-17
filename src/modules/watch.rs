/// `greengate watch` — re-runs scan on every file change.
///
/// Uses a simple polling loop (checks modification times every 2 s).
/// Intentionally keeps zero extra dependencies.
use crate::modules::scanner::{self, OutputFormat, ScanOpts};
use crate::utils::{config, terminal};
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

pub struct WatchOpts {
    /// Scan only staged files (passed through to scanner)
    pub staged: bool,
    /// Poll interval in milliseconds (default: 2000)
    pub interval_ms: u64,
}

pub fn run_watch(opts: WatchOpts) -> Result<()> {
    let interval = Duration::from_millis(opts.interval_ms);

    terminal::info(&format!(
        "Watching for changes (polling every {}ms). Press Ctrl-C to stop.",
        opts.interval_ms
    ));

    // Collect initial snapshot
    let mut snapshots = collect_snapshots(".")?;
    run_scan_once(opts.staged)?;

    loop {
        std::thread::sleep(interval);

        let current = collect_snapshots(".")?;
        let changed = diff_snapshots(&snapshots, &current);

        if !changed.is_empty() {
            eprintln!();
            terminal::info(&format!(
                "Detected {} changed file(s): {}",
                changed.len(),
                changed
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            run_scan_once(opts.staged)?;
            snapshots = current;
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns (path -> mtime) for all tracked files under `dir`.
fn collect_snapshots(dir: &str) -> Result<HashMap<PathBuf, SystemTime>> {
    let walker = ignore::WalkBuilder::new(dir)
        .hidden(true)
        .ignore(true)
        .git_ignore(true)
        .build();

    let mut map = HashMap::new();
    for entry in walker.flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            let path = entry.into_path();
            if let Ok(meta) = std::fs::metadata(&path)
                && let Ok(mtime) = meta.modified()
            {
                map.insert(path, mtime);
            }
        }
    }
    Ok(map)
}

/// Returns files that are new or have a newer mtime.
fn diff_snapshots(
    old: &HashMap<PathBuf, SystemTime>,
    new: &HashMap<PathBuf, SystemTime>,
) -> Vec<PathBuf> {
    new.iter()
        .filter(|(path, mtime)| old.get(*path).is_none_or(|prev| *mtime > prev))
        .map(|(path, _)| path.clone())
        .collect()
}

fn run_scan_once(staged: bool) -> Result<()> {
    let cfg = config::load()?;
    let diff = if staged {
        Some(scanner::DiffMode::Staged)
    } else {
        None
    };

    let result = scanner::run_scan(ScanOpts {
        format: OutputFormat::Text,
        diff,
        config: &cfg.scan,
        sast_config: &cfg.sast,
    });

    // In watch mode, don't bail on findings — just report and keep watching
    if let Err(e) = result {
        eprintln!("  {}", e);
    }

    Ok(())
}
