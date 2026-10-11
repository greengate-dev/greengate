//! `scan --new-since <ref>`: report only findings a change introduces.
//!
//! The base is the merge base of `<ref>` and `HEAD`. Files changed since then
//! (renames followed, uncommitted and untracked files included) are scanned
//! as they are now and as they were at the base, in memory; a finding counts
//! only if its fingerprint was not already there. Without a ref, a pull
//! request's base branch (`GITHUB_BASE_REF`) is used.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Diff {
    /// Describes the base, e.g. `merge base with origin/main (1a2b3c4d)`.
    pub label: String,
    /// Changed files that exist now, relative to the current directory.
    pub changed: Vec<PathBuf>,
    /// Their contents at the base, under their current path. Absent for
    /// files added since.
    pub base: HashMap<PathBuf, String>,
}

fn git(args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git") // greengate: ignore — fixed program, args from greengate
        .args(args)
        .output()
        .context("could not run git — is this a git repository?")?;
    if !out.status.success() {
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// The ref to compare against: the one given, else the pull request's base
/// branch.
fn target(reference: Option<&str>) -> Result<String> {
    if let Some(r) = reference.filter(|r| !r.is_empty()) {
        return Ok(r.to_string());
    }
    match std::env::var("GITHUB_BASE_REF") {
        Ok(b) if !b.is_empty() => Ok(format!("origin/{b}")),
        _ => Err(anyhow::anyhow!(
            "--new-since needs a ref outside a pull request, e.g. `--new-since origin/main`"
        ))
        .context(crate::utils::config::ConfigError("--new-since")),
    }
}

/// `git diff --name-status -z` output: (status, old path, new path).
fn parse_name_status(raw: &[u8]) -> Vec<(char, String, String)> {
    let mut fields = raw
        .split(|&b| b == 0)
        .map(|f| String::from_utf8_lossy(f).into_owned());
    let mut out = Vec::new();
    while let Some(status) = fields.next() {
        let Some(kind) = status.chars().next() else {
            continue;
        };
        let Some(first) = fields.next() else { break };
        if matches!(kind, 'R' | 'C') {
            let Some(second) = fields.next() else { break };
            out.push((kind, first, second));
        } else {
            out.push((kind, first.clone(), first));
        }
    }
    out
}

pub fn resolve(reference: Option<&str>) -> Result<Diff> {
    let target = target(reference)?;
    let base = String::from_utf8(git(&["merge-base", &target, "HEAD"])?)?
        .trim()
        .to_string();
    let label = format!("merge base with {target} ({})", &base[..base.len().min(8)]);

    // Working tree against the base: committed, staged and unstaged changes.
    let diff = git(&["diff", "-M", "--name-status", "-z", "--relative", &base])?;
    let mut changed = Vec::new();
    let mut base_files = HashMap::new();
    for (kind, old, new) in parse_name_status(&diff) {
        let path = PathBuf::from(&new);
        if kind == 'D' || !path.is_file() {
            continue;
        }
        if kind != 'A'
            && let Ok(content) = git(&["show", &format!("{base}:./{old}")])
        {
            base_files.insert(path.clone(), String::from_utf8_lossy(&content).into_owned());
        }
        changed.push(path);
    }
    // Untracked files are new in their entirety.
    let untracked = git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
    changed.extend(
        untracked
            .split(|&b| b == 0)
            .filter(|f| !f.is_empty())
            .map(|f| PathBuf::from(String::from_utf8_lossy(f).into_owned()))
            .filter(|p| Path::new(p).is_file()),
    );
    changed.sort();
    changed.dedup();
    Ok(Diff {
        label,
        changed,
        base: base_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_status_with_renames() {
        let raw = b"M\0a.rs\0R087\0old/b.rs\0new/b.rs\0A\0c.rs\0D\0d.rs\0";
        assert_eq!(
            parse_name_status(raw),
            vec![
                ('M', "a.rs".into(), "a.rs".into()),
                ('R', "old/b.rs".into(), "new/b.rs".into()),
                ('A', "c.rs".into(), "c.rs".into()),
                ('D', "d.rs".into(), "d.rs".into()),
            ]
        );
    }
}
