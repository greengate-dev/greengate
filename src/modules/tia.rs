/// `greengate tia` — Test Impact Analysis.
///
/// Determines which test files are affected by a given set of changed source
/// files by walking the repository, extracting import/require statements with
/// tree-sitter, and matching them against the changed file set.
///
/// Default output is newline-separated file paths for direct use in test runners:
///
///   pytest $(greengate tia --base main)
///   npx jest $(greengate tia --base main)
///   go test $(greengate tia --base main --format newline)
use crate::utils::{config::TiaConfig, terminal};
use anyhow::{Context, Result};
use globset::{Glob, GlobSetBuilder};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ── Public options ─────────────────────────────────────────────────────────────

pub struct TiaOpts {
    /// Git ref to diff against (commit / branch / tag). Default: "HEAD~1".
    pub base: String,
    /// Diff against staged files instead of committed diff.
    pub staged: bool,
    pub format: TiaFormat,
}

/// Output format for `greengate tia`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TiaFormat {
    /// One test path per line, ready to pass to a test runner (default)
    Newline,
    Text,
    Json,
}

// ── Output types ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TiaOutput {
    pub changed_source_files: Vec<String>,
    pub affected_tests: Vec<String>,
    pub total_test_files: usize,
    pub config_files_changed: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_tia(opts: TiaOpts, cfg: &TiaConfig) -> Result<()> {
    // 1. Get the set of files changed between base and HEAD
    let changed = changed_files(&opts.base, opts.staged)?;
    if changed.is_empty() {
        terminal::info("No changed files found.");
        return Ok(());
    }

    // 2. Partition into source files (parseable) and everything else
    let (source_files, config_files): (Vec<_>, Vec<_>) =
        changed.iter().partition(|p| is_source_file(p));

    if !config_files.is_empty() {
        terminal::warn(&format!(
            "{} config/data file(s) changed — consider running the full test suite:",
            config_files.len()
        ));
        for f in &config_files {
            eprintln!("    {}", f);
        }
        eprintln!();
    }

    if source_files.is_empty() {
        terminal::info("No source code changes detected; no tests selected.");
        return Ok(());
    }

    // Precompute all path stems for every changed source file
    let changed_stems: Vec<String> = source_files.iter().flat_map(|p| file_stems(p)).collect();

    // 3. Build a GlobSet from the configured test_patterns
    let test_glob = build_glob_set(&cfg.test_patterns)
        .context("Failed to compile [tia] test_patterns globs")?;

    // 4. Walk the repo and collect all matching test files
    let test_files = collect_test_files(".", &test_glob);

    // 5. For each test file, parse its imports and check against changed stems
    let mut affected: Vec<String> = test_files
        .iter()
        .filter(|path| file_imports_affected(path, &changed_stems))
        .map(|path| {
            path.to_str()
                .unwrap_or("")
                .trim_start_matches("./")
                .to_string()
        })
        .collect();

    affected.sort();
    affected.dedup();

    let output = TiaOutput {
        changed_source_files: source_files.iter().map(|s| s.to_string()).collect(),
        affected_tests: affected,
        total_test_files: test_files.len(),
        config_files_changed: config_files.iter().map(|s| s.to_string()).collect(),
    };

    match opts.format {
        TiaFormat::Json => emit_json(&output)?,
        TiaFormat::Text => emit_text(&output),
        TiaFormat::Newline => emit_newline(&output),
    }

    Ok(())
}

// ── Git diff ──────────────────────────────────────────────────────────────────

fn changed_files(base: &str, staged: bool) -> Result<Vec<String>> {
    let output = if staged {
        Command::new("git") // greengate: ignore — running git to compute the file diff for TIA
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .output()
            .context("Failed to run git diff --cached --name-only")?
    } else {
        let out = Command::new("git") // greengate: ignore
            .args([
                "diff",
                &format!("{}...HEAD", base),
                "--name-only",
                "--diff-filter=ACM",
            ])
            .output()
            .context("Failed to run git diff --name-only")?;

        if out.status.success() {
            out
        } else {
            Command::new("git") // greengate: ignore — fallback git diff for TIA
                .args(["diff", base, "HEAD", "--name-only", "--diff-filter=ACM"])
                .output()
                .context("Failed to run git diff (fallback)")?
        }
    };

    let raw = String::from_utf8_lossy(&output.stdout);
    Ok(raw
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

// ── Source file classification ────────────────────────────────────────────────

/// Returns true for source files that have tree-sitter support and contain
/// import statements we can analyse. Everything else (JSON, YAML, lock files,
/// Dockerfiles, …) is treated as a config/data change.
fn is_source_file(path: &str) -> bool {
    matches!(
        Path::new(path).extension().and_then(|e| e.to_str()),
        Some("ts" | "tsx" | "js" | "jsx" | "py" | "go")
    )
}

// ── Stem computation ──────────────────────────────────────────────────────────

/// Given a changed file path, generate all path stems an import could use to
/// refer to it. For `src/utils/helpers.ts` this produces:
///   `src/utils/helpers`, `utils/helpers`, `helpers`
///
/// For index files (`src/utils/index.ts`) we additionally emit:
///   `src/utils`, `utils`
fn file_stems(path: &str) -> Vec<String> {
    let without_ext = Path::new(path).with_extension("");
    let base = without_ext
        .to_str()
        .unwrap_or("")
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();

    let mut stems: Vec<String> = Vec::new();

    // Full path without extension, then each progressive suffix
    let mut remaining: &str = &base;
    loop {
        stems.push(remaining.to_string());
        match remaining.find('/') {
            Some(pos) => remaining = &remaining[pos + 1..],
            None => break,
        }
    }

    // Index-file shorthand: "src/utils/index" → also emit "src/utils", "utils"
    if base.ends_with("/index") {
        let dir = &base[..base.len() - 6];
        if !dir.is_empty() {
            let mut rem: &str = dir;
            loop {
                stems.push(rem.to_string());
                match rem.find('/') {
                    Some(pos) => rem = &rem[pos + 1..],
                    None => break,
                }
            }
        }
    }

    stems
}

// ── Glob set ──────────────────────────────────────────────────────────────────

fn build_glob_set(patterns: &[String]) -> Result<globset::GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob =
            Glob::new(pattern).with_context(|| format!("Invalid glob pattern: {}", pattern))?;
        builder.add(glob);
    }
    builder.build().context("Failed to build glob set")
}

// ── Test file walker ──────────────────────────────────────────────────────────

fn collect_test_files(root: &str, glob: &globset::GlobSet) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let walker = ignore::WalkBuilder::new(root).hidden(false).build();
    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_str().unwrap_or("").replace('\\', "/");
        if glob.is_match(&rel_str) {
            results.push(path.to_path_buf());
        }
    }
    results
}

// ── Import extraction + matching ──────────────────────────────────────────────

/// Returns true if any import in `test_path` resolves to one of `changed_stems`.
fn file_imports_affected(test_path: &Path, changed_stems: &[String]) -> bool {
    let source = match std::fs::read(test_path) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let Some(language) = language_for(test_path) else {
        return false;
    };
    let Some(query_str) = import_query_for(test_path) else {
        return false;
    };

    let imports = extract_imports(&source, language, query_str);
    let test_dir = test_path.parent().unwrap_or(Path::new("."));

    for import in &imports {
        let normalized = normalize_import(import, test_dir);
        for stem in changed_stems {
            if imports_overlap(&normalized, stem) {
                return true;
            }
        }
    }
    false
}

fn extract_imports(source: &[u8], language: Language, query_str: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let Ok(query) = Query::new(&language, query_str) else {
        return Vec::new();
    };

    let import_idx = match query.capture_names().iter().position(|n| *n == "import") {
        Some(i) => i as u32,
        None => return Vec::new(),
    };

    let mut cursor = QueryCursor::new();
    let mut imports = Vec::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source);

    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == import_idx) {
            if let Ok(text) = cap.node.utf8_text(source) {
                imports.push(text.to_string());
            }
        }
    }
    imports
}

/// Resolve an import specifier to a normalised, extension-free path string.
///
/// - Relative imports (`./foo`, `../bar`) are resolved against `test_dir`.
/// - Python dotted names (`utils.helpers`) are converted to `utils/helpers`.
/// - Package imports (Go, npm packages) are returned as-is for suffix matching.
fn normalize_import(import: &str, test_dir: &Path) -> String {
    let import = import.trim_matches('"').trim_matches('\'');

    if import.starts_with('.') {
        // Relative import — resolve manually without hitting the filesystem
        let dir_str = test_dir.to_str().unwrap_or("").replace('\\', "/");
        let mut components: Vec<String> = dir_str
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .map(|s| s.to_string())
            .collect();

        for part in import.split('/') {
            match part {
                "." | "" => {}
                ".." => {
                    components.pop();
                }
                p => components.push(p.to_string()),
            }
        }

        // Strip file extension from the last component if present
        let joined = components.join("/");
        strip_extension(&joined)
    } else if !import.contains('/') && import.contains('.') {
        // Python-style dotted module name: convert dots to path separators
        import.replace('.', "/")
    } else {
        // Package import (Go full path, npm package, scoped package, etc.)
        import.to_string()
    }
}

fn strip_extension(path: &str) -> String {
    match path.rfind('.') {
        Some(dot) if dot > path.rfind('/').unwrap_or(0) => path[..dot].to_string(),
        _ => path.to_string(),
    }
}

/// Returns true if an import specifier resolves to, or is contained by,
/// a changed source file.
///
/// Three checks are performed:
/// 1. Exact path match (most reliable)
/// 2. The import is a suffix of the changed stem — handles cases where the test
///    uses a shorter relative path than the full repo path (most common)
/// 3. The changed file lives inside the imported package — handles Go-style
///    package imports where the changed file is one file within the package dir
fn imports_overlap(import_normalized: &str, changed_stem: &str) -> bool {
    // 1. Exact
    if import_normalized == changed_stem {
        return true;
    }
    // 2. Import is a path-suffix of changed stem
    //    e.g. import "utils/helpers" ↔ changed "src/utils/helpers"
    if changed_stem.ends_with(&format!("/{}", import_normalized)) {
        return true;
    }
    // 3. Changed stem's directory matches the import path (Go package imports)
    //    e.g. import "github.com/org/repo/pkg/utils" ↔ changed "pkg/utils/helpers"
    let changed_dir = Path::new(changed_stem)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    if !changed_dir.is_empty()
        && (import_normalized == changed_dir
            || import_normalized.ends_with(&format!("/{}", changed_dir)))
    {
        return true;
    }
    false
}

// ── Language / query dispatch ─────────────────────────────────────────────────

fn language_for(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Some("js" | "jsx") => Some(tree_sitter_javascript::LANGUAGE.into()),
        Some("py") => Some(tree_sitter_python::LANGUAGE.into()),
        Some("go") => Some(tree_sitter_go::LANGUAGE.into()),
        _ => None,
    }
}

fn import_query_for(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts" | "tsx" | "js" | "jsx") => Some(JS_TS_IMPORT_QUERY),
        Some("py") => Some(PYTHON_IMPORT_QUERY),
        Some("go") => Some(GO_IMPORT_QUERY),
        _ => None,
    }
}

/// JS/TS: static `import`/`export … from`, and CommonJS `require()` calls.
const JS_TS_IMPORT_QUERY: &str = r#"
[
  (import_statement source: (string (string_fragment) @import))
  (export_statement source: (string (string_fragment) @import))
  (call_expression
    function: (identifier) @fn
    arguments: (arguments (string (string_fragment) @import))
    (#eq? @fn "require"))
]
"#;

/// Python: `import foo.bar` and `from foo.bar import …` statements.
const PYTHON_IMPORT_QUERY: &str = r#"
[
  (import_statement name: (dotted_name) @import)
  (import_from_statement module_name: (dotted_name) @import)
]
"#;

/// Go: the quoted import path inside an `import_spec`.
const GO_IMPORT_QUERY: &str = r#"
(import_spec
  path: (interpreted_string_literal
    (interpreted_string_literal_content) @import))
"#;

// ── Output formatters ─────────────────────────────────────────────────────────

/// Default: one path per line, no decorations. Pipe-friendly.
fn emit_newline(output: &TiaOutput) {
    for test in &output.affected_tests {
        println!("{}", test);
    }
}

fn emit_text(output: &TiaOutput) {
    eprintln!();
    eprintln!("╔══ Test Impact Analysis ══════════════════════════════╗");
    eprintln!(
        "  Changed source files : {}",
        output.changed_source_files.len()
    );
    eprintln!("  Total test files     : {}", output.total_test_files);
    eprintln!("  Affected tests       : {}", output.affected_tests.len());
    eprintln!("╚══════════════════════════════════════════════════════╝");

    if !output.config_files_changed.is_empty() {
        eprintln!();
        eprintln!("  Config/data files changed (consider running all tests):");
        for f in &output.config_files_changed {
            eprintln!("    {}", f);
        }
    }

    if output.affected_tests.is_empty() {
        eprintln!();
        terminal::info("No affected tests found.");
    } else {
        eprintln!();
        for test in &output.affected_tests {
            println!("{}", test);
        }
        eprintln!();
        terminal::success(&format!(
            "{}/{} tests selected.",
            output.affected_tests.len(),
            output.total_test_files,
        ));
    }
}

fn emit_json(output: &TiaOutput) -> Result<()> {
    let json =
        serde_json::to_string_pretty(output).context("Failed to serialize TIA output as JSON")?;
    println!("{}", json);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_stems_basic() {
        let stems = file_stems("src/utils/helpers.ts");
        assert!(stems.contains(&"src/utils/helpers".to_string()));
        assert!(stems.contains(&"utils/helpers".to_string()));
        assert!(stems.contains(&"helpers".to_string()));
    }

    #[test]
    fn file_stems_index() {
        let stems = file_stems("src/utils/index.ts");
        assert!(stems.contains(&"src/utils/index".to_string()));
        assert!(stems.contains(&"src/utils".to_string()));
        assert!(stems.contains(&"utils".to_string()));
    }

    #[test]
    fn normalize_import_relative_same_dir() {
        let dir = Path::new("src/components");
        let result = normalize_import("./utils/helpers", dir);
        assert_eq!(result, "src/components/utils/helpers");
    }

    #[test]
    fn normalize_import_parent_traversal() {
        let dir = Path::new("src/components/Button");
        let result = normalize_import("../../utils/helpers", dir);
        assert_eq!(result, "src/utils/helpers");
    }

    #[test]
    fn normalize_import_python_dotted() {
        let dir = Path::new("tests");
        let result = normalize_import("utils.helpers", dir);
        assert_eq!(result, "utils/helpers");
    }

    #[test]
    fn normalize_import_strips_extension() {
        let dir = Path::new("src");
        let result = normalize_import("./utils/helpers.ts", dir);
        assert_eq!(result, "src/utils/helpers");
    }

    #[test]
    fn imports_overlap_exact() {
        assert!(imports_overlap("src/utils/helpers", "src/utils/helpers"));
    }

    #[test]
    fn imports_overlap_suffix() {
        assert!(imports_overlap("utils/helpers", "src/utils/helpers"));
        assert!(!imports_overlap("utils/other", "src/utils/helpers"));
    }

    #[test]
    fn imports_overlap_go_package() {
        // Go import "github.com/org/repo/pkg/utils" ↔ changed "pkg/utils/helpers.go"
        assert!(imports_overlap(
            "github.com/org/repo/pkg/utils",
            "pkg/utils/helpers"
        ));
    }

    #[test]
    fn imports_overlap_no_false_positive() {
        assert!(!imports_overlap("other/module", "src/utils/helpers"));
    }

    #[test]
    fn strip_extension_ts() {
        assert_eq!(strip_extension("src/utils/helpers.ts"), "src/utils/helpers");
    }

    #[test]
    fn strip_extension_no_ext() {
        assert_eq!(strip_extension("src/utils/helpers"), "src/utils/helpers");
    }
}
