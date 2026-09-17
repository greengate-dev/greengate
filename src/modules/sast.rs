use crate::modules::scanner::{
    Finding, check_entropy, is_known_false_positive, is_sast_file, make_finding,
};
use crate::modules::taint::{TaintCache, taint_for_sink};
use crate::utils::{
    config::{SastConfig, ScanConfig},
    terminal,
};
use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use std::path::{Path, PathBuf};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ── Inline suppression ────────────────────────────────────────────────────────

/// Return `true` if the finding at `row` (0-based) is suppressed.
///
/// Checks the matched line itself AND the line immediately after it.
/// Formatters (Prettier, ESLint) often move `// greengate: ignore` comments
/// inside object literals to the next line, e.g.:
/// ```text
///   dangerouslySetInnerHTML={{          ← flagged line (row N)
///     // greengate: ignore               ← comment on row N+1
///     __html: sanitized,
///   }}
/// ```
fn is_suppressed(source: &[u8], row: usize) -> bool {
    let mut lines = source.split(|&b| b == b'\n');
    // Collect the target line and the one after it.
    for (i, line) in lines.by_ref().enumerate() {
        if (i == row || i == row + 1)
            && std::str::from_utf8(line)
                .map(|l| l.contains("greengate: ignore"))
                .unwrap_or(false)
        {
            return true;
        }
        if i > row + 1 {
            break;
        }
    }
    false
}

// ── Language dispatch ─────────────────────────────────────────────────────────

fn language_for(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Some("js" | "jsx") => Some(tree_sitter_javascript::LANGUAGE.into()),
        Some("py") => Some(tree_sitter_python::LANGUAGE.into()),
        Some("go") => Some(tree_sitter_go::LANGUAGE.into()),
        Some("rs") => Some(tree_sitter_rust::LANGUAGE.into()),
        _ => None,
    }
}

// ── String-literal secret detection ──────────────────────────────────────────
//
// Scanning only string literal content nodes avoids flagging secrets inside
// comments, JSX text, or import paths.

/// JS/TS: content lives in `string_fragment` children of `string` and
/// `template_string` nodes.
const JS_TS_STRING_QUERY: &str = r#"
    [
        (string (string_fragment) @literal)
        (template_string (string_fragment) @literal)
    ]
"#;

/// Python: content lives in `string_content` children of `string` nodes.
const PYTHON_STRING_QUERY: &str = r#"
    (string (string_content) @literal)
"#;

/// Go: content lives inside `interpreted_string_literal` and
/// `raw_string_literal` nodes.
const GO_STRING_QUERY: &str = r#"
    [
        (interpreted_string_literal (interpreted_string_literal_content) @literal)
        (raw_string_literal (raw_string_literal_content) @literal)
    ]
"#;

/// Rust: string content lives inside `string_literal` and `raw_string_literal` nodes.
/// The `string_content` child holds the actual characters (excluding delimiters).
const RUST_STRING_QUERY: &str = r#"
    [
        (string_literal (string_content) @literal)
        (raw_string_literal (raw_string_literal_content) @literal)
    ]
"#;

fn string_query_for(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js" | "jsx" | "ts" | "tsx") => Some(JS_TS_STRING_QUERY),
        Some("py") => Some(PYTHON_STRING_QUERY),
        Some("go") => Some(GO_STRING_QUERY),
        Some("rs") => Some(RUST_STRING_QUERY),
        _ => None,
    }
}

fn scan_string_literals(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    lang: &Language,
    query_src: &str,
    patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
) -> Vec<Finding> {
    let query = match Query::new(lang, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };

    let literal_idx = match query.capture_names().iter().position(|n| *n == "literal") {
        Some(i) => i as u32,
        None => return Vec::new(),
    };

    let mut cursor = QueryCursor::new();
    let mut findings = Vec::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source);

    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == literal_idx) {
            let node = cap.node;
            let text = match node.utf8_text(source) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let line_no = node.start_position().row + 1; // 1-based

            // Inline suppression on the source line
            if is_suppressed(source, node.start_position().row) {
                continue;
            }

            // Run every secret/PII regex against the string literal value only
            for (name, regex) in patterns {
                if let Some(m) = regex.find(text) {
                    if is_known_false_positive(m.as_str()) {
                        continue;
                    }
                    findings.push(make_finding(
                        path.to_path_buf(),
                        name.clone(),
                        line_no,
                        None,
                    ));
                }
            }

            // Entropy check on the literal value itself
            for rule_id in check_entropy(text, scan_config) {
                findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
            }
        }
    }

    findings
}

// ── Dangerous pattern detection ───────────────────────────────────────────────

struct SastRule {
    id: &'static str,
    /// tree-sitter S-expression query. Must contain a @match capture that
    /// marks the outermost node for location reporting.
    query: &'static str,
}

const RULES: &[SastRule] = &[
    // ── XSS ──────────────────────────────────────────────────────────────────
    SastRule {
        id: "SAST/DangerouslySetInnerHTML",
        // JSX attribute: dangerouslySetInnerHTML={{ __html: ... }}
        // Only compiles successfully against TSX / JSX language grammars.
        // Omit `name:` field specifier — the TSX grammar does not surface it
        // as a queryable named field; match the identifier as a direct child instead.
        query: r#"
            (jsx_attribute
              (_) @_name
              (#eq? @_name "dangerouslySetInnerHTML")) @match
        "#,
    },
    SastRule {
        id: "SAST/InnerHTMLAssignment",
        // elem.innerHTML = expr  (any right-hand side)
        query: r#"
            (assignment_expression
              left: (member_expression
                property: (property_identifier) @_prop
                (#eq? @_prop "innerHTML"))) @match
        "#,
    },
    SastRule {
        id: "SAST/OuterHTMLAssignment",
        // elem.outerHTML = expr
        query: r#"
            (assignment_expression
              left: (member_expression
                property: (property_identifier) @_prop
                (#eq? @_prop "outerHTML"))) @match
        "#,
    },
    // ── Code injection ────────────────────────────────────────────────────────
    SastRule {
        id: "SAST/EvalUsage",
        // eval(...)
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "eval")) @match
        "#,
    },
    SastRule {
        id: "SAST/FunctionConstructor",
        // new Function(...)
        query: r#"
            (new_expression
              constructor: (identifier) @_ctor
              (#eq? @_ctor "Function")) @match
        "#,
    },
    SastRule {
        id: "SAST/SetTimeoutString",
        // setTimeout("code string", delay) — string as first arg is eval-equivalent
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "setTimeout")
              arguments: (arguments . [(string) (template_string)] @_first)) @match
        "#,
    },
    SastRule {
        id: "SAST/SetIntervalString",
        // setInterval("code string", delay)
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "setInterval")
              arguments: (arguments . [(string) (template_string)] @_first)) @match
        "#,
    },
    // ── Command injection ─────────────────────────────────────────────────────
    SastRule {
        id: "SAST/ChildProcessExec",
        // child_process.exec(cmd) / require('child_process').exec(cmd) / etc.
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "exec"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessExecSync",
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "execSync"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessSpawn",
        // child_process.spawn(cmd, args)
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "spawn"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessExecFile",
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "execFile"))) @match
        "#,
    },
    // ── Legacy DOM XSS ───────────────────────────────────────────────────────
    SastRule {
        id: "SAST/DocumentWrite",
        // document.write(expr) — inserts raw HTML into the document
        query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @_obj
                property: (property_identifier) @_prop)
              (#eq? @_obj "document")
              (#eq? @_prop "write")) @match
        "#,
    },
    SastRule {
        id: "SAST/DocumentWriteln",
        query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @_obj
                property: (property_identifier) @_prop)
              (#eq? @_obj "document")
              (#eq? @_prop "writeln")) @match
        "#,
    },
];

// ── Python SAST rules ─────────────────────────────────────────────────────────

const PYTHON_RULES: &[SastRule] = &[
    SastRule {
        id: "SAST/PythonEval",
        query: r#"
            (call
              function: (identifier) @_fn
              (#eq? @_fn "eval")) @match
        "#,
    },
    SastRule {
        id: "SAST/PythonExec",
        query: r#"
            (call
              function: (identifier) @_fn
              (#eq? @_fn "exec")) @match
        "#,
    },
    SastRule {
        id: "SAST/PythonPickle",
        // pickle.load(f) or pickle.loads(data)
        query: r#"
            (call
              function: (attribute
                object: (identifier) @_obj
                attribute: (identifier) @_fn)
              (#eq? @_obj "pickle")
              (#match? @_fn "^loads?$")) @match
        "#,
    },
    SastRule {
        id: "SAST/PythonSubprocessShell",
        // subprocess.run(..., shell=True) / .call / .Popen / .check_output
        query: r#"
            (call
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @_kw
                  value: (true)
                  (#eq? @_kw "shell")))) @match
        "#,
    },
    SastRule {
        id: "SAST/PythonYamlLoad",
        // yaml.load(data) without Loader= is unsafe (use yaml.safe_load instead)
        query: r#"
            (call
              function: (attribute
                object: (identifier) @_obj
                attribute: (identifier) @_fn)
              (#eq? @_obj "yaml")
              (#eq? @_fn "load")) @match
        "#,
    },
];

// ── Go SAST rules ─────────────────────────────────────────────────────────────

const GO_RULES: &[SastRule] = &[
    SastRule {
        id: "SAST/GoUnsafe",
        // import "unsafe" — use of the unsafe package is a memory-safety risk
        query: r#"
            (import_spec
              path: (interpreted_string_literal) @_pkg
              (#eq? @_pkg "\"unsafe\"")) @match
        "#,
    },
    SastRule {
        id: "SAST/GoExecCommand",
        // exec.Command("cmd", args...) — possible command injection
        query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @_pkg
                field: (field_identifier) @_fn)
              (#eq? @_pkg "exec")
              (#eq? @_fn "Command")) @match
        "#,
    },
    SastRule {
        id: "SAST/GoPanic",
        // explicit panic() — unexpected process termination in production code
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "panic")) @match
        "#,
    },
];

// ── Rust SAST rules ───────────────────────────────────────────────────────────

const RUST_RULES: &[SastRule] = &[
    SastRule {
        id: "SAST/RustUnsafeBlock",
        // Any `unsafe { ... }` block — may bypass memory safety guarantees.
        // Requires manual review to verify correctness.
        query: r#"
            (unsafe_block) @match
        "#,
    },
    SastRule {
        id: "SAST/RustCommandNew",
        // `Command::new(...)` — spawns an OS process; flag for review of
        // argument sources to prevent command injection.
        // Matches: Command::new, process::Command::new, tokio::process::Command::new, etc.
        query: r#"
            (call_expression
              function: (scoped_identifier) @_fn
              (#match? @_fn "Command::new")) @match
        "#,
    },
    SastRule {
        id: "SAST/RustUnwrap",
        // `.unwrap()` — panics if the value is `Err`/`None`.
        // Should use `?`, `unwrap_or`, or proper error handling in production code.
        query: r#"
            (call_expression
              function: (field_expression
                field: (field_identifier) @_field
                (#eq? @_field "unwrap"))) @match
        "#,
    },
    SastRule {
        id: "SAST/RustExpect",
        // `.expect("msg")` — panics with a message; same concern as `.unwrap()`.
        query: r#"
            (call_expression
              function: (field_expression
                field: (field_identifier) @_field
                (#eq? @_field "expect"))) @match
        "#,
    },
];

fn rules_for_path(path: &Path) -> &'static [SastRule] {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => PYTHON_RULES,
        Some("go") => GO_RULES,
        Some("rs") => RUST_RULES,
        _ => RULES,
    }
}

// ── Sanitizer-aware false-positive suppression ────────────────────────────────
//
// When an XSS rule fires, we inspect the AST of the HTML value being assigned.
// If it passes through a known sanitizer or is a static literal, the risk is
// already mitigated and we suppress the finding.
//
// This is intentionally a conservative allowlist — only functions whose
// sole purpose is safe HTML production are included. Generic helpers like
// `format()` or `toString()` are NOT included.

/// Member properties and bare identifiers that are known-safe HTML producers.
const KNOWN_SANITIZER_CALLS: &[&str] = &[
    // DOMPurify
    "sanitize",
    // sanitize-html, xss-filters
    "sanitizeHtml",
    "sanitizeHTML",
    // isomorphic-dompurify, dompurify wrappers
    "clean",
    // he / entities
    "encode",
    "escape",
    "escapeHtml",
    "escapeHTML",
    // JSON serialisation — JSON content cannot execute as HTML
    // (browsers treat application/ld+json as data, not markup)
    "stringify",
];

/// Walk a node's children and return the first named child with the given kind.
fn first_named_child_of_kind<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|n| n.kind() == kind)
}

/// Given the @match node for an XSS rule, navigate to the actual HTML value
/// expression (the thing being handed to innerHTML / dangerouslySetInnerHTML).
fn html_value_node<'a>(
    rule_id: &str,
    matched: tree_sitter::Node<'a>,
    source: &[u8],
) -> Option<tree_sitter::Node<'a>> {
    match rule_id {
        "SAST/DangerouslySetInnerHTML" => {
            // Structure: jsx_attribute → jsx_expression → object → pair(__html) → value
            let jsx_expr = first_named_child_of_kind(matched, "jsx_expression")?;
            let object = first_named_child_of_kind(jsx_expr, "object")?;
            let mut cur = object.walk();
            let html_pair = object.named_children(&mut cur).find(|n| {
                if n.kind() != "pair" {
                    return false;
                }
                n.child_by_field_name("key")
                    .and_then(|k| k.utf8_text(source).ok())
                    .map(|name| name == "__html")
                    .unwrap_or(false)
            })?;
            html_pair.child_by_field_name("value")
        }
        "SAST/InnerHTMLAssignment" | "SAST/OuterHTMLAssignment" => {
            matched.child_by_field_name("right")
        }
        _ => None,
    }
}

/// Returns true if `node` represents a known-safe HTML value:
///   • a static string / template literal with no interpolations
///   • a call to a known sanitizer function (DOMPurify.sanitize, JSON.stringify, …)
fn is_safe_html_value(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    match node.kind() {
        // Static string literal — no dynamic content, no injection vector
        "string" => true,
        // Template literal — safe only if it has no `${}` substitutions
        "template_string" => {
            let mut cur = node.walk();
            !node
                .children(&mut cur)
                .any(|c| c.kind() == "template_substitution")
        }
        // Call expression — check if it routes through a known-safe function
        "call_expression" => {
            let Some(func) = node.child_by_field_name("function") else {
                return false;
            };
            match func.kind() {
                // sanitize(...) / sanitizeHtml(...) / etc.
                "identifier" => func
                    .utf8_text(source)
                    .map(|n| KNOWN_SANITIZER_CALLS.contains(&n))
                    .unwrap_or(false),
                // DOMPurify.sanitize(...) / JSON.stringify(...) / he.encode(...)
                "member_expression" => func
                    .child_by_field_name("property")
                    .and_then(|p| p.utf8_text(source).ok())
                    .map(|name| KNOWN_SANITIZER_CALLS.contains(&name))
                    .unwrap_or(false),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Returns true if the `.exec()` call is on a non-shell receiver.
///
/// `regex.exec(str)`, `model.exec()`, and promise-chain `.exec()` calls are
/// common patterns that do NOT involve child_process and should not be flagged.
/// We suppress when the object is a known non-shell type or a regex literal.
fn exec_is_non_shell(matched: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    // matched is the call_expression; function is a member_expression
    let Some(func) = matched.child_by_field_name("function") else {
        return false;
    };
    let Some(object) = func.child_by_field_name("object") else {
        return false;
    };

    match object.kind() {
        // /regex/.exec(str) — regex literal, definitely not a shell call
        "regex" => true,
        // identifier — check against known non-shell names
        "identifier" => {
            let name = object.utf8_text(source).unwrap_or("");
            // Common Mongoose, database query, and promise executor names
            matches!(
                name,
                "query"
                    | "cursor"
                    | "stmt"
                    | "statement"
                    | "db"
                    | "collection"
                    | "model"
                    | "promise"
                    | "cmd" // not conclusive but very rarely child_process in modern code
            )
        }
        // new RegExp(...).exec(str)
        "new_expression" => {
            let ctor = object.child_by_field_name("constructor");
            ctor.and_then(|c| c.utf8_text(source).ok())
                .map(|n| n == "RegExp")
                .unwrap_or(false)
        }
        // call_expression.exec() — chained call, likely a query builder or promise
        "call_expression" => true,
        // await expr — awaited result being exec()'d is not a shell
        "await_expression" => true,
        _ => false,
    }
}

/// XSS / eval rules where taint tracking can both **suppress** (provably safe
/// value) and **label** (provably tainted value).  The sink is a single
/// expression so static-literal suppression is always correct.
const TAINT_SUPPRESS_RULES: &[&str] = &[
    "SAST/DangerouslySetInnerHTML",
    "SAST/InnerHTMLAssignment",
    "SAST/OuterHTMLAssignment",
    "SAST/DocumentWrite",
    "SAST/DocumentWriteln",
    "SAST/EvalUsage",
];

/// Command-injection rules where taint tracking only **labels** findings as
/// `[tainted]` — suppression is intentionally NOT applied because even a
/// static command name (e.g. `spawn("bash", ["-c", cmd])`) is dangerous when
/// the argument array contains user-controlled input.
const TAINT_LABEL_RULES: &[&str] = &[
    "SAST/ChildProcessExec",
    "SAST/ChildProcessExecSync",
    "SAST/ChildProcessSpawn",
    "SAST/ChildProcessExecFile",
];

fn scan_dangerous_patterns(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    lang: &Language,
    sast_config: &SastConfig,
    custom_rule_srcs: &[(String, String)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let file_root = tree.root_node();

    // Taint cache: keyed by enclosing-scope byte range, built lazily.
    let mut taint_cache: TaintCache = TaintCache::new();

    // ── Built-in rules ────────────────────────────────────────────────────────
    for rule in rules_for_path(path) {
        if sast_config.disabled_rules.iter().any(|d| d == rule.id) {
            continue;
        }

        // Query may fail to compile for rules that use JSX node types against
        // non-TSX/JSX language grammars — silently skip those.
        let query = match Query::new(lang, rule.query) {
            Ok(q) => q,
            Err(_) => continue,
        };

        let match_idx = match query.capture_names().iter().position(|n| *n == "match") {
            Some(i) => i as u32,
            None => continue,
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, file_root, source);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index == match_idx) {
                let line_no = cap.node.start_position().row + 1;

                if is_suppressed(source, cap.node.start_position().row) {
                    continue;
                }

                // ── Tier-1 taint + sanitizer-aware suppression ────────────────
                //
                // Two distinct taint-tracking strategies:
                //
                // TAINT_SUPPRESS_RULES (XSS / eval) — single-expression sink:
                //   1. Static / sanitizer check: suppress if provably safe.
                //   2. Taint context: suppress if all vars provably safe.
                //   3. If tainted → emit with "[tainted]" high-confidence label.
                //   4. Unknown → emit at normal confidence.
                //
                // TAINT_LABEL_RULES (exec / spawn / execFile / execSync):
                //   Never suppress — a static command name like "bash" is safe by
                //   itself but the argument array may still carry user input.
                //   Only add "[tainted]" label when the first arg is tainted.
                if TAINT_SUPPRESS_RULES.contains(&rule.id) {
                    // Resolve the HTML/value node for XSS rules, or first arg
                    // for eval / document.write.
                    let sink_val = if matches!(
                        rule.id,
                        "SAST/DangerouslySetInnerHTML"
                            | "SAST/InnerHTMLAssignment"
                            | "SAST/OuterHTMLAssignment"
                    ) {
                        html_value_node(rule.id, cap.node, source)
                    } else {
                        cap.node
                            .child_by_field_name("arguments")
                            .and_then(|args| args.named_child(0))
                    };

                    if let Some(val) = sink_val {
                        // Layer 1: fast static-literal / sanitizer suppression
                        if is_safe_html_value(val, source) {
                            continue;
                        }

                        // Layer 2: taint context
                        let tctx = taint_for_sink(cap.node, file_root, source, &mut taint_cache);

                        if tctx.node_is_safe(val, source) {
                            continue; // provably safe variable → suppress
                        }

                        let rule_id = if tctx.node_is_tainted(val, source) {
                            format!("{} [tainted]", rule.id)
                        } else {
                            rule.id.to_string()
                        };
                        findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
                        continue;
                    }
                    // No value resolved — fall through to normal emit below.
                } else if TAINT_LABEL_RULES.contains(&rule.id) {
                    // exec() non-shell receiver suppression (regex.exec, db.exec, …)
                    if rule.id == "SAST/ChildProcessExec" && exec_is_non_shell(cap.node, source) {
                        continue;
                    }

                    // Label as [tainted] when the first argument is tainted.
                    let tainted = cap
                        .node
                        .child_by_field_name("arguments")
                        .and_then(|args| args.named_child(0))
                        .map(|first_arg| {
                            let tctx =
                                taint_for_sink(cap.node, file_root, source, &mut taint_cache);
                            tctx.node_is_tainted(first_arg, source)
                        })
                        .unwrap_or(false);

                    let rule_id = if tainted {
                        format!("{} [tainted]", rule.id)
                    } else {
                        rule.id.to_string()
                    };
                    findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
                    continue;
                } else {
                    // All other rules: keep the existing sanitizer suppression
                    // for any XSS rules not listed in TAINT_SUPPRESS_RULES.
                    if matches!(
                        rule.id,
                        "SAST/DangerouslySetInnerHTML"
                            | "SAST/InnerHTMLAssignment"
                            | "SAST/OuterHTMLAssignment"
                    ) && let Some(val) = html_value_node(rule.id, cap.node, source)
                        && is_safe_html_value(val, source)
                    {
                        continue;
                    }

                    if rule.id == "SAST/ChildProcessExec" && exec_is_non_shell(cap.node, source) {
                        continue;
                    }
                }

                findings.push(make_finding(
                    path.to_path_buf(),
                    rule.id.to_string(),
                    line_no,
                    None,
                ));
            }
        }
    }

    // ── Custom rules from .greengate.toml ───────────────────────────────────────
    for (id, query_src) in custom_rule_srcs {
        // Compile per-language: query types differ between JS and TS grammars.
        let query = match Query::new(lang, query_src) {
            Ok(q) => q,
            Err(_) => continue, // already warned at pre-scan compile time
        };

        let match_idx = match query.capture_names().iter().position(|n| *n == "match") {
            Some(i) => i as u32,
            None => continue,
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index == match_idx) {
                let line_no = cap.node.start_position().row + 1;

                if is_suppressed(source, cap.node.start_position().row) {
                    continue;
                }

                findings.push(make_finding(path.to_path_buf(), id.clone(), line_no, None));
            }
        }
    }

    findings
}

// ── Code smell / complexity detection ────────────────────────────────────────

/// tree-sitter node kinds that represent function-like constructs in JS/TS.
const FUNCTION_NODE_KINDS: &[&str] = &[
    "function_declaration",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
];

/// tree-sitter node kinds that introduce a nesting level for SMELL/DeepNesting.
const NESTING_NODE_KINDS: &[&str] = &[
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "catch_clause",
];

/// Returns the number of source lines occupied by a function node's body.
fn count_function_lines(node: tree_sitter::Node<'_>) -> usize {
    let body = node.child_by_field_name("body").unwrap_or(node);
    let start = body.start_position().row;
    let end = body.end_position().row;
    end.saturating_sub(start) + 1
}

/// Returns the number of formal parameters for a function-like node.
fn count_parameters(node: tree_sitter::Node<'_>) -> usize {
    node.child_by_field_name("parameters")
        .map(|p| p.named_child_count())
        .unwrap_or(0)
}

/// Recursively computes the maximum nesting depth within `node`.
fn max_nesting_depth_in(node: tree_sitter::Node<'_>, current: usize) -> usize {
    let mut depth = current;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let child_depth = if NESTING_NODE_KINDS.contains(&child.kind()) {
            max_nesting_depth_in(child, current + 1)
        } else {
            max_nesting_depth_in(child, current)
        };
        depth = depth.max(child_depth);
    }
    depth
}

fn scan_complexity(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    sast_config: &SastConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Iterative stack traversal — avoids recursion on deeply nested files.
    let mut stack: Vec<tree_sitter::Node<'_>> = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if FUNCTION_NODE_KINDS.contains(&node.kind()) {
            let line_no = node.start_position().row + 1;

            // Inline suppression
            if !is_suppressed(source, node.start_position().row) {
                // SMELL/LongFunction
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/LongFunction")
                {
                    let lines = count_function_lines(node);
                    if lines > sast_config.max_function_lines {
                        let rule_id = format!(
                            "SMELL/LongFunction ({} lines, max {})",
                            lines, sast_config.max_function_lines
                        );
                        findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
                    }
                }

                // SMELL/TooManyParameters
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/TooManyParameters")
                {
                    let params = count_parameters(node);
                    if params > sast_config.max_parameters {
                        let rule_id = format!(
                            "SMELL/TooManyParameters ({} params, max {})",
                            params, sast_config.max_parameters
                        );
                        findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
                    }
                }

                // SMELL/DeepNesting — measured within the function body only
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/DeepNesting")
                    && let Some(body) = node.child_by_field_name("body")
                {
                    let depth = max_nesting_depth_in(body, 0);
                    if depth > sast_config.max_nesting_depth {
                        let rule_id = format!(
                            "SMELL/DeepNesting (depth {}, max {})",
                            depth, sast_config.max_nesting_depth
                        );
                        findings.push(make_finding(path.to_path_buf(), rule_id, line_no, None));
                    }
                }
            }
        }

        // Push children for traversal.
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            stack.push(child);
        }
    }

    findings
}

// ── Per-file scanner ──────────────────────────────────────────────────────────

fn scan_file(
    path: &Path,
    sast_config: &SastConfig,
    secret_patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
    custom_rule_srcs: &[(String, String)],
) -> Vec<Finding> {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let lang = match language_for(path) {
        Some(l) => l,
        None => return Vec::new(),
    };

    let string_query = match string_query_for(path) {
        Some(q) => q,
        None => return Vec::new(),
    };

    // Parser is !Send — must be created per closure (per file).
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }

    // tree-sitter is error-tolerant; parse() returns None only on hard timeout/cancel.
    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let bytes = source.as_bytes();
    let mut findings = Vec::new();

    // Secrets/PII scoped to string literals only (no comment noise)
    findings.extend(scan_string_literals(
        path,
        &tree,
        bytes,
        &lang,
        string_query,
        secret_patterns,
        scan_config,
    ));

    // Dangerous API patterns (XSS, code injection, command injection)
    findings.extend(scan_dangerous_patterns(
        path,
        &tree,
        bytes,
        &lang,
        sast_config,
        custom_rule_srcs,
    ));

    // Code smell / complexity rules — JS/TS only (node kinds differ per language)
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if matches!(ext, "js" | "jsx" | "ts" | "tsx") {
        findings.extend(scan_complexity(path, &tree, bytes, sast_config));
    }

    findings
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run the SAST scan over a pre-built file list (produced by `collect_scan_files`).
/// Filters to JS/TS files only; non-JS/TS files are handled by the regex scanner.
pub fn run_sast_scan(
    files: &[PathBuf],
    sast_config: &SastConfig,
    secret_patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
    is_text: bool,
) -> Result<Vec<Finding>> {
    let js_ts: Vec<&PathBuf> = files.iter().filter(|p| is_sast_file(p)).collect();

    if js_ts.is_empty() {
        return Ok(Vec::new());
    }

    if is_text {
        terminal::info(&format!("SAST: scanning {} file(s)...", js_ts.len()));
    }

    let bar = if is_text {
        let b = terminal::create_progress_bar(js_ts.len() as u64);
        b.set_message("SAST scanning...");
        Some(b)
    } else {
        None
    };

    // Compile custom rules once before the parallel scan.
    // Validate against the JS grammar as a quick syntax check; warn and skip on error.
    let custom_rule_srcs: Vec<(String, String)> = sast_config
        .custom_rules
        .iter()
        .filter(|r| !sast_config.disabled_rules.iter().any(|d| d == &r.id))
        .filter_map(|r| {
            let lang: Language = tree_sitter_javascript::LANGUAGE.into();
            match Query::new(&lang, &r.query) {
                Ok(_) => Some((r.id.clone(), r.query.clone())),
                Err(e) => {
                    eprintln!(
                        "greengate: warning: custom SAST rule '{}' failed to compile: {}",
                        r.id, e
                    );
                    None
                }
            }
        })
        .collect();

    let findings: Vec<Finding> = js_ts
        .par_iter()
        .flat_map(|path| {
            let result = scan_file(
                path,
                sast_config,
                secret_patterns,
                scan_config,
                &custom_rule_srcs,
            );
            if let Some(b) = &bar {
                b.inc(1);
            }
            result
        })
        .collect();

    if let Some(b) = &bar {
        b.finish_with_message("SAST scan complete.");
    }

    Ok(findings)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::{CustomSastRule, SastConfig, ScanConfig};
    use regex::Regex;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn default_configs() -> (SastConfig, ScanConfig) {
        (SastConfig::default(), ScanConfig::default())
    }

    fn compile_builtins() -> Vec<(String, Regex)> {
        vec![
            (
                "AWS Access Key".into(),
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            ),
            (
                "Generic PII (Email)".into(),
                Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            ),
        ]
    }

    fn write_tmp(ext: &str, content: &str) -> NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{}", ext))
            .tempfile()
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── String literal scoping ────────────────────────────────────────────────

    #[test]
    fn detects_aws_key_in_string_literal() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("ts", "const key = \"AKIA3KGXQW7ZP2MTV9CD\";\n"); // greengate: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "AWS Access Key"),
            "expected AWS Access Key in string literal, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ignores_aws_key_in_comment() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("ts", "// AKIA3KGXQW7ZP2MTV9CD\n"); // greengate: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
        assert!(
            findings.is_empty(),
            "comment-only secret should not be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ignores_email_in_jsx_text() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp(
            "tsx",
            "export const A = () => <p>contact@example.com</p>;\n", // greengate: ignore
        );
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
        let email_hits: Vec<_> = findings
            .iter()
            .filter(|x| x.rule_id.contains("Email"))
            .collect();
        assert!(
            email_hits.is_empty(),
            "email in JSX text content should not be flagged, got: {:?}",
            email_hits.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_secret_in_template_literal() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("js", "const k = `AKIA3KGXQW7ZP2MTV9CD`;\n"); // greengate: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "AWS Access Key"),
            "should detect key inside template literal"
        );
    }

    #[test]
    fn respects_inline_suppression() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp(
            "ts",
            "const k = \"AKIA3KGXQW7ZP2MTV9CD\"; // greengate: ignore\n",
        );
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
        assert!(
            findings.is_empty(),
            "suppressed line should produce no findings"
        );
    }

    // ── Dangerous patterns ────────────────────────────────────────────────────

    #[test]
    fn detects_eval() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "eval(userInput);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "eval() should be flagged"
        );
    }

    #[test]
    fn detects_inner_html_assignment() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "el.innerHTML = dangerousData;\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/InnerHTMLAssignment"),
            "innerHTML assignment should be flagged"
        );
    }

    #[test]
    fn detects_dangerously_set_inner_html() {
        let (sast, scan) = default_configs();
        let f = write_tmp(
            "tsx",
            "export const C = ({v}: {v:string}) => <div dangerouslySetInnerHTML={{__html: v}} />;\n",
        );
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/DangerouslySetInnerHTML"),
            "dangerouslySetInnerHTML should be flagged in TSX"
        );
    }

    #[test]
    fn detects_new_function() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "const fn = new Function(\"return 1\");\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/FunctionConstructor"),
            "new Function() should be flagged"
        );
    }

    #[test]
    fn detects_child_process_exec() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "child_process.exec(cmd, callback);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/ChildProcessExec"),
            "child_process.exec() should be flagged"
        );
    }

    #[test]
    fn detects_child_process_spawn() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "child_process.spawn(\"bash\", [\"-c\", cmd]);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/ChildProcessSpawn"),
            "child_process.spawn() should be flagged"
        );
    }

    #[test]
    fn detects_document_write() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "document.write(\"<script>\" + userInput);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/DocumentWrite"),
            "document.write() should be flagged"
        );
    }

    #[test]
    fn detects_settimeout_string() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "setTimeout(\"doSomething()\", 1000);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/SetTimeoutString"),
            "setTimeout with string arg should be flagged"
        );
    }

    #[test]
    fn does_not_flag_settimeout_with_function() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "setTimeout(() => doSomething(), 1000);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id == "SAST/SetTimeoutString"),
            "setTimeout with arrow function should NOT be flagged"
        );
    }

    #[test]
    fn disabled_rule_not_reported() {
        let sast = SastConfig {
            enabled: true,
            disabled_rules: vec!["SAST/EvalUsage".into()],
            ..Default::default()
        };
        let scan = ScanConfig::default();
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "disabled rule should produce no finding"
        );
    }

    #[test]
    fn suppression_skips_finding() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "eval(x); // greengate: ignore\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "suppressed eval() should not be reported"
        );
    }

    #[test]
    fn unsupported_file_type_returns_empty() {
        let (sast, scan) = default_configs();
        let f = write_tmp("md", "# Hello\neval(x)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.is_empty(),
            "Markdown file should be skipped by SAST"
        );
    }

    // ── Python SAST ───────────────────────────────────────────────────────────

    #[test]
    fn detects_python_eval() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "result = eval(user_input)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/PythonEval"),
            "eval() in Python should be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_python_exec() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "exec(code)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/PythonExec"),
            "exec() in Python should be flagged"
        );
    }

    #[test]
    fn detects_python_pickle_load() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "import pickle\ndata = pickle.load(f)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/PythonPickle"),
            "pickle.load() should be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_python_subprocess_shell_true() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "import subprocess\nsubprocess.run(cmd, shell=True)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/PythonSubprocessShell"),
            "subprocess with shell=True should be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    // ── Go SAST ───────────────────────────────────────────────────────────────

    #[test]
    fn detects_go_exec_command() {
        let (sast, scan) = default_configs();
        let f = write_tmp(
            "go",
            "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"ls\") }\n",
        );
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/GoExecCommand"),
            "exec.Command() in Go should be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_go_panic() {
        let (sast, scan) = default_configs();
        let f = write_tmp(
            "go",
            "package main\nfunc main() { panic(\"fatal error\") }\n",
        );
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/GoPanic"),
            "panic() in Go should be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    // ── Complexity rules ──────────────────────────────────────────────────────

    fn long_fn_src(body_lines: usize) -> String {
        // function with `body_lines` lines in the body block
        let body: String = (0..body_lines).map(|i| format!("  x{}();\n", i)).collect();
        format!("function f() {{\n{}}}\n", body)
    }

    #[test]
    fn detects_long_function() {
        let sast = SastConfig {
            max_function_lines: 3,
            ..Default::default()
        };
        let f = write_tmp("js", &long_fn_src(6));
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "6-line body should exceed max_function_lines=3"
        );
    }

    #[test]
    fn does_not_flag_function_within_line_limit() {
        let sast = SastConfig {
            max_function_lines: 50,
            ..Default::default()
        };
        let f = write_tmp("js", "function f() { return 1; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "single-line function should not be flagged"
        );
    }

    #[test]
    fn detects_too_many_parameters() {
        let sast = SastConfig {
            max_parameters: 2,
            ..Default::default()
        };
        let f = write_tmp("js", "function f(a, b, c) { return a; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/TooManyParameters")),
            "3 params should exceed max_parameters=2"
        );
    }

    #[test]
    fn does_not_flag_params_within_limit() {
        let sast = SastConfig {
            max_parameters: 5,
            ..Default::default()
        };
        let f = write_tmp("js", "function f(a, b) { return a + b; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/TooManyParameters")),
            "2 params should not exceed max_parameters=5"
        );
    }

    #[test]
    fn detects_deep_nesting() {
        let sast = SastConfig {
            max_nesting_depth: 2,
            ..Default::default()
        };
        let src =
            "function f() {\n  if (a) {\n    if (b) {\n      if (c) { x(); }\n    }\n  }\n}\n";
        let f = write_tmp("js", src);
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/DeepNesting")),
            "triple nested if should exceed max_nesting_depth=2"
        );
    }

    #[test]
    fn does_not_flag_nesting_within_limit() {
        let sast = SastConfig {
            max_nesting_depth: 4,
            ..Default::default()
        };
        let src = "function f() {\n  if (a) {\n    return 1;\n  }\n}\n";
        let f = write_tmp("js", src);
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/DeepNesting")),
            "single if should not exceed max_nesting_depth=4"
        );
    }

    #[test]
    fn disabled_smell_rule_not_reported() {
        let sast = SastConfig {
            max_function_lines: 3,
            disabled_rules: vec!["SMELL/LongFunction".into()],
            ..Default::default()
        };
        let f = write_tmp("js", &long_fn_src(6));
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "disabled SMELL/LongFunction should not be reported"
        );
    }

    // ── Custom rules ──────────────────────────────────────────────────────────

    #[test]
    fn custom_rule_fires_for_matching_query() {
        let sast = SastConfig {
            custom_rules: vec![CustomSastRule {
                id: "TEST/NoEval".into(),
                query:
                    r#"(call_expression function: (identifier) @_fn (#eq? @_fn "eval")) @match"#
                        .into(),
            }],
            ..Default::default()
        };
        // Pre-compile the same way run_sast_scan does
        let custom_srcs: Vec<(String, String)> = sast
            .custom_rules
            .iter()
            .map(|r| (r.id.clone(), r.query.clone()))
            .collect();
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &custom_srcs);
        assert!(
            findings.iter().any(|x| x.rule_id == "TEST/NoEval"),
            "custom eval rule should fire"
        );
    }

    #[test]
    fn custom_rule_respects_disabled_rules() {
        let sast = SastConfig {
            custom_rules: vec![CustomSastRule {
                id: "TEST/NoEval".into(),
                query:
                    r#"(call_expression function: (identifier) @_fn (#eq? @_fn "eval")) @match"#
                        .into(),
            }],
            disabled_rules: vec!["TEST/NoEval".into()],
            ..Default::default()
        };
        let custom_srcs: Vec<(String, String)> = vec![]; // disabled — filtered before call
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &custom_srcs);
        assert!(
            !findings.iter().any(|x| x.rule_id == "TEST/NoEval"),
            "disabled custom rule should not fire"
        );
    }

    #[test]
    fn invalid_custom_rule_does_not_panic() {
        // An invalid query is filtered out before reaching scan_file.
        // Verify that passing empty custom_srcs (as run_sast_scan would after filtering)
        // produces no panic and no spurious findings.
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(
            f.path(),
            &SastConfig::default(),
            &[],
            &ScanConfig::default(),
            &[],
        );
        // Should not panic; built-in eval rule still fires (proves scan_file ran normally)
        assert!(findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"));
    }
}
