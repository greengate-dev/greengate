use crate::utils::terminal;
use anyhow::{Context, Result};
use std::collections::HashMap;

struct FileRecord {
    path: String,
    hit: u64,
    found: u64,
}

// ── Format detection ──────────────────────────────────────────────────────────

enum CoverageFormat {
    Lcov,
    Cobertura,
}

fn detect_format(file: &str) -> CoverageFormat {
    let path = std::path::Path::new(file);
    match path.extension().and_then(|e| e.to_str()) {
        Some("xml") => return CoverageFormat::Cobertura,
        Some("info") => return CoverageFormat::Lcov,
        _ => {}
    }
    // Ambiguous extension: peek at the first 256 bytes for an XML signature.
    if let Ok(mut f) = std::fs::File::open(file) {
        use std::io::Read;
        let mut buf = [0u8; 256];
        let n = f.read(&mut buf).unwrap_or(0);
        if let Ok(head) = std::str::from_utf8(&buf[..n])
            && (head.contains("<coverage") || head.contains("<!DOCTYPE coverage"))
        {
            return CoverageFormat::Cobertura;
        }
    }
    CoverageFormat::Lcov
}

// ── LCOV parser ───────────────────────────────────────────────────────────────

fn parse_lcov(content: &str) -> Result<(u64, u64, Vec<FileRecord>)> {
    let mut records: Vec<FileRecord> = Vec::new();
    let mut current_path = String::new();
    let mut current_hit: u64 = 0;
    let mut current_found: u64 = 0;

    for line in content.lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            current_path = path.to_string();
            current_hit = 0;
            current_found = 0;
        } else if let Some(val) = line.strip_prefix("LH:") {
            current_hit = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("LF:") {
            current_found = val.trim().parse::<u64>().unwrap_or(0);
        } else if line == "end_of_record" && !current_path.is_empty() {
            records.push(FileRecord {
                path: current_path.clone(),
                hit: current_hit,
                found: current_found,
            });
        }
    }

    let total_hit: u64 = records.iter().map(|r| r.hit).sum();
    let total_found: u64 = records.iter().map(|r| r.found).sum();
    Ok((total_hit, total_found, records))
}

// ── Cobertura XML parser ──────────────────────────────────────────────────────

fn parse_cobertura(content: &str) -> Result<(u64, u64, Vec<FileRecord>)> {
    let doc =
        roxmltree::Document::parse(content).with_context(|| "Failed to parse Cobertura XML")?;

    let mut records: Vec<FileRecord> = Vec::new();

    for class_node in doc.descendants().filter(|n| n.has_tag_name("class")) {
        let filename = class_node.attribute("filename").unwrap_or("").to_string();

        let mut hit: u64 = 0;
        let mut found: u64 = 0;

        for line_node in class_node.descendants().filter(|n| n.has_tag_name("line")) {
            found += 1;
            let hits: u64 = line_node
                .attribute("hits")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if hits > 0 {
                hit += 1;
            }
        }

        if found > 0 {
            records.push(FileRecord {
                path: filename,
                hit,
                found,
            });
        }
    }

    let total_hit: u64 = records.iter().map(|r| r.hit).sum();
    let total_found: u64 = records.iter().map(|r| r.found).sum();
    Ok((total_hit, total_found, records))
}

// ── Public coverage map (used by pr_review) ───────────────────────────────────

/// Parse a coverage file and return a map of `file_path → { line_number → hit_count }`.
/// Line numbers are 1-based. Only lines explicitly listed in the coverage report are present.
pub fn parse_coverage_map(file: &str) -> Result<HashMap<String, HashMap<u32, u64>>> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Cannot read coverage file: {}", file))?;
    match detect_format(file) {
        CoverageFormat::Lcov => lcov_to_line_map(&content),
        CoverageFormat::Cobertura => cobertura_to_line_map(&content),
    }
}

fn lcov_to_line_map(content: &str) -> Result<HashMap<String, HashMap<u32, u64>>> {
    let mut map: HashMap<String, HashMap<u32, u64>> = HashMap::new();
    let mut current_path = String::new();
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            current_path = path.to_string();
        } else if let Some(rest) = line.strip_prefix("DA:") {
            // DA:<line>,<hits>[,<checksum>]
            let mut parts = rest.splitn(3, ',');
            if let (Some(lineno_s), Some(hits_s)) = (parts.next(), parts.next())
                && let (Ok(lineno), Ok(hits)) =
                    (lineno_s.trim().parse::<u32>(), hits_s.trim().parse::<u64>())
                && !current_path.is_empty()
            {
                map.entry(current_path.clone())
                    .or_default()
                    .insert(lineno, hits);
            }
        } else if line == "end_of_record" {
            current_path.clear();
        }
    }
    Ok(map)
}

fn cobertura_to_line_map(content: &str) -> Result<HashMap<String, HashMap<u32, u64>>> {
    let doc =
        roxmltree::Document::parse(content).with_context(|| "Failed to parse Cobertura XML")?;
    let mut map: HashMap<String, HashMap<u32, u64>> = HashMap::new();
    for class_node in doc.descendants().filter(|n| n.has_tag_name("class")) {
        let filename = class_node.attribute("filename").unwrap_or("").to_string();
        if filename.is_empty() {
            continue;
        }
        let entry = map.entry(filename).or_default();
        for line_node in class_node.descendants().filter(|n| n.has_tag_name("line")) {
            if let Some(number_s) = line_node.attribute("number")
                && let Ok(lineno) = number_s.parse::<u32>()
            {
                let hits: u64 = line_node
                    .attribute("hits")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                entry.insert(lineno, hits);
            }
        }
    }
    Ok(map)
}

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run_coverage(file: &str, min: f64) -> Result<()> {
    terminal::info(&format!(
        "Analyzing coverage file: {} (threshold: {:.1}%)",
        file, min
    ));

    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Cannot read coverage file: {}", file))?;

    let (total_hit, total_found, records) = match detect_format(file) {
        CoverageFormat::Lcov => parse_lcov(&content)?,
        CoverageFormat::Cobertura => parse_cobertura(&content)?,
    };

    if records.is_empty() {
        anyhow::bail!("No coverage records found in '{}'", file);
    }

    if total_found == 0 {
        anyhow::bail!("Coverage file '{}' has no line data", file);
    }

    // Per-file breakdown: show files below threshold.
    let mut below: Vec<&FileRecord> = records
        .iter()
        .filter(|r| r.found > 0)
        .filter(|r| (r.hit as f64 / r.found as f64) * 100.0 < min)
        .collect();
    below.sort_by(|a, b| {
        let pct_a = a.hit as f64 / a.found as f64;
        let pct_b = b.hit as f64 / b.found as f64;
        pct_a.total_cmp(&pct_b)
    });

    if !below.is_empty() {
        eprintln!("\n  Files below threshold ({:.1}%):", min);
        for r in &below {
            let pct = (r.hit as f64 / r.found as f64) * 100.0;
            eprintln!("    {:.1}%  {}", pct, r.path);
        }
        eprintln!();
    }

    let coverage_pct = (total_hit as f64 / total_found as f64) * 100.0;
    let files_scanned = records.len();

    if coverage_pct < min {
        terminal::warn(&format!(
            "Coverage {:.1}% is below threshold {:.1}% ({} files, {}/{} lines covered)",
            coverage_pct, min, files_scanned, total_hit, total_found
        ));
        anyhow::bail!("Coverage gate failed: {:.1}% < {:.1}%", coverage_pct, min);
    }

    terminal::success(&format!(
        "Coverage {:.1}% meets threshold {:.1}% ({} files, {}/{} lines covered)",
        coverage_pct, min, files_scanned, total_hit, total_found
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::{Builder, NamedTempFile};

    fn write_lcov(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    fn write_cobertura(content: &str) -> NamedTempFile {
        let mut f = Builder::new().suffix(".xml").tempfile().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── LCOV (existing tests, unchanged) ──────────────────────────────────────

    #[test]
    fn test_passes_above_threshold() {
        let lcov = write_lcov("SF:src/main.rs\nLH:90\nLF:100\nend_of_record\n");
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_ok(), "expected pass at 90% with threshold 80%");
    }

    #[test]
    fn test_fails_below_threshold() {
        let lcov = write_lcov("SF:src/main.rs\nLH:50\nLF:100\nend_of_record\n");
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_err(), "expected fail at 50% with threshold 80%");
    }

    #[test]
    fn test_aggregates_multiple_files() {
        let lcov = write_lcov(
            "SF:src/a.rs\nLH:80\nLF:100\nend_of_record\nSF:src/b.rs\nLH:80\nLF:100\nend_of_record\n",
        );
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_errors_on_missing_file() {
        let result = super::run_coverage("/nonexistent/lcov.info", 80.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_errors_on_empty_lcov() {
        let lcov = write_lcov("# no data\n");
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_err());
    }

    // ── Cobertura ─────────────────────────────────────────────────────────────

    fn cobertura_xml(lines: &[(&str, u64, u64)]) -> String {
        // lines: [(filename, hit_count, total_count)]
        let classes: String = lines
            .iter()
            .map(|(name, hits, total)| {
                let line_els: String = (1..=*total)
                    .map(|i| {
                        format!(
                            r#"<line number="{}" hits="{}"/>"#,
                            i,
                            if i <= *hits { 1 } else { 0 }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(r#"<class filename="{name}"><lines>{line_els}</lines></class>"#,)
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            r#"<?xml version="1.0"?><coverage><packages><package><classes>{classes}</classes></package></packages></coverage>"#
        )
    }

    #[test]
    fn test_cobertura_passes_above_threshold() {
        // 4/5 lines hit = 80%
        let xml = cobertura_xml(&[("src/a.py", 4, 5)]);
        let f = write_cobertura(&xml);
        assert!(super::run_coverage(f.path().to_str().unwrap(), 70.0).is_ok());
    }

    #[test]
    fn test_cobertura_fails_below_threshold() {
        // 1/3 lines hit ≈ 33%
        let xml = cobertura_xml(&[("src/a.py", 1, 3)]);
        let f = write_cobertura(&xml);
        assert!(super::run_coverage(f.path().to_str().unwrap(), 80.0).is_err());
    }

    #[test]
    fn test_cobertura_aggregates_multiple_classes() {
        // 4/5 + 4/5 = 8/10 = 80%
        let xml = cobertura_xml(&[("src/a.py", 4, 5), ("src/b.py", 4, 5)]);
        let f = write_cobertura(&xml);
        assert!(super::run_coverage(f.path().to_str().unwrap(), 80.0).is_ok());
    }

    #[test]
    fn test_format_detection_by_extension() {
        assert!(matches!(
            super::detect_format("coverage.xml"),
            super::CoverageFormat::Cobertura
        ));
        assert!(matches!(
            super::detect_format("lcov.info"),
            super::CoverageFormat::Lcov
        ));
    }
}
