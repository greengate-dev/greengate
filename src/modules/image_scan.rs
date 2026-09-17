use crate::modules::scanner::{
    Finding, compile_patterns_for_scan, emit_findings, scan_text_content,
};
use crate::utils::config::ScanConfig;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// ── Output format re-export ───────────────────────────────────────────────────

use crate::modules::scanner::OutputFormat;

// ── Public entry point ────────────────────────────────────────────────────────

pub struct ImageScanOpts<'a> {
    /// Image reference: `nginx:latest`, `ghcr.io/owner/repo:sha-abc123`, etc.
    pub image: String,
    pub format: OutputFormat,
    pub no_fail: bool,
    pub scan_cfg: &'a ScanConfig,
}

/// Pull (if needed), extract, and scan an OCI image for secrets.
///
/// Workflow:
///   1. `docker save <image> -o <tmpdir>/image.tar`
///   2. `tar -xf image.tar -C <tmpdir>/outer/`
///   3. Find every `layer.tar` inside the extracted tree
///   4. For each layer: `tar -xf layer.tar -C <tmpdir>/layer-N/`
///   5. Walk text files and run regex + entropy scan
///   6. Report findings with path `<image>::layer:<digest>::<file>`
pub fn run_image_scan(opts: ImageScanOpts<'_>) -> Result<()> {
    require_docker()?;

    crate::utils::terminal::info(&format!(
        "Saving image {} — this may take a moment...",
        opts.image
    ));

    let tmp = TempDir::new("greengate-image")?;
    let image_tar = tmp.path.join("image.tar");
    let outer_dir = tmp.path.join("outer");
    std::fs::create_dir_all(&outer_dir)?;

    // Step 1 — docker save
    let save_status = std::process::Command::new("docker") // greengate: ignore
        .args(["save", &opts.image, "-o"])
        .arg(&image_tar)
        .status()
        .context("Failed to run docker save")?;

    if !save_status.success() {
        anyhow::bail!(
            "docker save failed for image '{}'. Is the image available locally or in a registry?",
            opts.image
        );
    }

    // Step 2 — extract outer tar
    let extract_status = std::process::Command::new("tar") // greengate: ignore
        .args(["-xf"])
        .arg(&image_tar)
        .args(["-C"])
        .arg(&outer_dir)
        .status()
        .context("Failed to run tar -xf on image archive")?;

    if !extract_status.success() {
        anyhow::bail!("Failed to extract image tar");
    }

    // Step 3 — find all layer.tar files
    let layer_tars = find_layer_tars(&outer_dir);

    if layer_tars.is_empty() {
        crate::utils::terminal::warn(
            "No layer.tar files found — image may use a different OCI layout.",
        );
        return Ok(());
    }

    crate::utils::terminal::info(&format!(
        "Scanning {} layer(s) in {}...",
        layer_tars.len(),
        opts.image
    ));

    let patterns = compile_patterns_for_scan(opts.scan_cfg)?;
    let mut all_findings: Vec<Finding> = Vec::new();

    for (idx, layer_tar) in layer_tars.iter().enumerate() {
        let layer_dir = tmp.path.join(format!("layer-{}", idx));
        std::fs::create_dir_all(&layer_dir)?;

        let layer_digest = layer_digest_label(layer_tar, &outer_dir);

        let ok = std::process::Command::new("tar") // greengate: ignore
            .args(["-xf"])
            .arg(layer_tar)
            .args(["-C"])
            .arg(&layer_dir)
            // Some layers have device files or other special entries — ignore errors
            // on individual entries but proceed with the rest.
            .args(["--ignore-command-error"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            // Retry without --ignore-command-error (macOS tar doesn't support it)
            std::process::Command::new("tar") // greengate: ignore
                .args(["-xf"])
                .arg(layer_tar)
                .args(["-C"])
                .arg(&layer_dir)
                .status()
                .ok();
        }

        let layer_findings = scan_layer_dir(
            &layer_dir,
            &layer_digest,
            &opts.image,
            &patterns,
            opts.scan_cfg,
        );
        all_findings.extend(layer_findings);
    }

    // Deduplicate: same content appears in multiple layers when a file is unchanged
    all_findings.dedup_by(|a, b| a.path == b.path && a.rule_id == b.rule_id && a.line == b.line);

    if all_findings.is_empty() {
        crate::utils::terminal::success(&format!(
            "No secrets found in {} ({} layer(s) scanned).",
            opts.image,
            layer_tars.len()
        ));
        return Ok(());
    }

    emit_findings(&all_findings, &opts.format)?;

    if !opts.no_fail {
        anyhow::bail!(
            "Image scan failed: {} finding(s) in {}",
            all_findings.len(),
            opts.image
        );
    }

    Ok(())
}

// ── Layer scanning ────────────────────────────────────────────────────────────

fn scan_layer_dir(
    layer_dir: &Path,
    layer_digest: &str,
    image: &str,
    patterns: &[(String, regex::Regex)],
    scan_cfg: &ScanConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    scan_dir_recursive(
        layer_dir,
        layer_dir,
        layer_digest,
        image,
        patterns,
        scan_cfg,
        &mut findings,
    );
    findings
}

fn scan_dir_recursive(
    base: &Path,
    dir: &Path,
    layer_digest: &str,
    image: &str,
    patterns: &[(String, regex::Regex)],
    scan_cfg: &ScanConfig,
    findings: &mut Vec<Finding>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.is_symlink() {
            continue;
        }

        if meta.is_dir() {
            // Skip .wh. whiteout directories (OCI layer deletion markers)
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(".wh."))
                .unwrap_or(false)
            {
                continue;
            }
            scan_dir_recursive(
                base,
                &path,
                layer_digest,
                image,
                patterns,
                scan_cfg,
                findings,
            );
            continue;
        }

        if !meta.is_file() {
            continue;
        }

        // Skip whiteout files, very large files (> 1 MB), and binary files
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename.starts_with(".wh.") || meta.len() > 1_048_576 {
            continue;
        }

        let Ok(content) = std::fs::read(&path) else {
            continue;
        };

        // Skip binary content (contains null bytes)
        if content.contains(&0u8) {
            continue;
        }

        let Ok(text) = std::str::from_utf8(&content) else {
            continue;
        };

        // Build a human-readable path label: image::layer:<digest>::/path/in/layer
        let rel = path.strip_prefix(base).unwrap_or(&path);
        let label_str = format!("{}::layer:{}::{}", image, layer_digest, rel.display());
        let label = PathBuf::from(&label_str);

        let mut file_findings = scan_text_content(&label, text, patterns, scan_cfg);

        // Prioritise interesting paths in the severity reporting
        if is_sensitive_path(rel) {
            for f in &mut file_findings {
                if f.severity == "medium" {
                    f.severity = "high".to_string();
                }
            }
        }

        findings.extend(file_findings);
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn require_docker() -> Result<()> {
    let result = std::process::Command::new("docker") // greengate: ignore
        .arg("info")
        .output();
    if result.is_err() {
        anyhow::bail!(
            "docker not found in PATH.\n\
             Install Docker Desktop: https://www.docker.com/products/docker-desktop\n\
             Or Docker Engine: https://docs.docker.com/engine/install/"
        );
    }
    Ok(())
}

fn find_layer_tars(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    find_layer_tars_recursive(dir, &mut result);
    result.sort();
    result
}

fn find_layer_tars_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_layer_tars_recursive(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("layer.tar") {
            out.push(path);
        }
    }
}

/// Produce a short digest label from the layer.tar path relative to the outer dir.
/// e.g. `a1b2c3d4` from `<outer>/a1b2c3d4.../layer.tar`
fn layer_digest_label(layer_tar: &Path, outer_dir: &Path) -> String {
    layer_tar
        .strip_prefix(outer_dir)
        .ok()
        .and_then(|rel| rel.components().next())
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.chars().take(12).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Returns true for paths that commonly contain credentials and should have
/// their findings promoted one severity level.
fn is_sensitive_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    matches!(
        true,
        _ if s.contains(".env")
            || s.contains(".aws/credentials")
            || s.contains(".ssh/")
            || s.contains("etc/environment")
            || s.ends_with(".pem")
            || s.ends_with(".key")
            || s.ends_with(".p12")
            || s.ends_with(".pfx")
            || s.contains("docker-compose")
    )
}

// ── RAII temp dir ─────────────────────────────────────────────────────────────

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Result<Self> {
        let base = std::env::temp_dir();
        let name = format!(
            "{}-{}",
            prefix,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = base.join(name);
        std::fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create temp dir: {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_digest_label_extracts_prefix() {
        let outer = PathBuf::from("/tmp/outer");
        let layer = PathBuf::from("/tmp/outer/a1b2c3d4e5f6deadbeef1234/layer.tar");
        let label = layer_digest_label(&layer, &outer);
        assert_eq!(label, "a1b2c3d4e5f6");
    }

    #[test]
    fn layer_digest_label_unknown_on_bad_path() {
        let outer = PathBuf::from("/tmp/outer");
        let layer = PathBuf::from("/other/layer.tar");
        let label = layer_digest_label(&layer, &outer);
        assert_eq!(label, "unknown");
    }

    #[test]
    fn is_sensitive_path_detects_env() {
        assert!(is_sensitive_path(Path::new("app/.env")));
        assert!(is_sensitive_path(Path::new("root/.ssh/id_rsa")));
        assert!(is_sensitive_path(Path::new("etc/environment")));
        assert!(is_sensitive_path(Path::new("certs/server.pem")));
        assert!(!is_sensitive_path(Path::new("app/main.go")));
    }

    #[test]
    fn temp_dir_creates_and_cleans_up() {
        let path = {
            let td = TempDir::new("greengate-test").unwrap();
            assert!(td.path.exists());
            td.path.clone()
        };
        assert!(!path.exists(), "TempDir should be removed on drop");
    }

    #[test]
    fn find_layer_tars_empty_dir() {
        let td = TempDir::new("greengate-test-layers").unwrap();
        let tars = find_layer_tars(&td.path);
        assert!(tars.is_empty());
    }

    #[test]
    fn find_layer_tars_finds_nested() {
        let td = TempDir::new("greengate-test-layers2").unwrap();
        let subdir = td.path.join("abc123");
        std::fs::create_dir_all(&subdir).unwrap();
        let layer = subdir.join("layer.tar");
        std::fs::write(&layer, b"fake").unwrap();
        let tars = find_layer_tars(&td.path);
        assert_eq!(tars.len(), 1);
        assert_eq!(tars[0], layer);
    }

    #[test]
    fn require_docker_does_not_panic() {
        // Just verify it returns a Result without panicking — docker may or may not be present
        let _ = require_docker();
    }
}
