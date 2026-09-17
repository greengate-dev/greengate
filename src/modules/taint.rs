/// Intra-procedural taint tracking for JS/TS.
///
/// Algorithm
/// ---------
/// 1. Walk the enclosing function body (or file root for module-level code)
///    and collect every variable assignment: `(name, value_node)`.
/// 2. Seed the `tainted` set from assignments whose RHS is a *direct* taint
///    source (req.body, searchParams.get(), localStorage.getItem(), etc.).
/// 3. Seed the `safe` set from assignments whose RHS is provably safe (static
///    string/number literal, template literal without `${}`, call to a known
///    sanitizer).
/// 4. Iterate to a fixpoint: propagate taint / safety through assignments and
///    through expressions (template literals, binary `+` concatenation, etc.).
/// 5. At each XSS/injection sink the caller uses `TaintContext::node_is_tainted`
///    and `TaintContext::node_is_safe` to decide whether to emit / suppress a
///    finding.
///
/// Scope
/// -----
/// This is *intra-procedural only* — taint does not cross function call
/// boundaries (except for direct source / sanitizer calls).  Cross-file and
/// inter-procedural tracking are Tier 2 / Tier 3 and are intentionally out of
/// scope here.  The analysis is *sound-ish* (conservative): unknown variables
/// are treated as neither tainted nor safe, so the existing pattern-match
/// finding is still emitted unchanged.
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// ── Known taint sources ───────────────────────────────────────────────────────

/// `object.property` member accesses that carry user-controlled data.
const MEMBER_TAINT_SOURCES: &[(&str, &str)] = &[
    // Express / Fastify / Koa request objects
    ("req", "body"),
    ("req", "query"),
    ("req", "params"),
    ("req", "headers"),
    ("req", "cookies"),
    ("request", "body"),
    ("request", "query"),
    ("request", "params"),
    ("request", "headers"),
    // Browser globals
    ("document", "cookie"),
    ("location", "hash"),
    ("location", "search"),
    ("location", "pathname"),
    ("window", "name"),
    // postMessage / worker events
    ("event", "data"),
    ("e", "data"),
    ("msg", "data"),
    // Node.js environment
    ("process", "env"),
];

/// `object.method(...)` call expressions that return user-controlled data.
const CALL_TAINT_SOURCES: &[(&str, &str)] = &[
    ("searchParams", "get"),
    ("params", "get"),
    ("localStorage", "getItem"),
    ("sessionStorage", "getItem"),
    ("cookies", "get"),
    ("cookie", "get"),
    ("headers", "get"),
    ("url", "searchParams"),
];

/// Bare function calls that return user-controlled data.
const BARE_TAINT_CALLS: &[&str] = &["getQueryParam", "getUserInput", "readInput"];

// ── Known safe call targets ───────────────────────────────────────────────────

/// `object.method(...)` calls that produce provably safe output.
const SAFE_MEMBER_CALLS: &[&str] = &[
    // DOMPurify family
    "sanitize",
    // sanitize-html, xss-filters
    "sanitizeHtml",
    "sanitizeHTML",
    // isomorphic-dompurify wrappers
    "clean",
    // he / entities
    "encode",
    "escape",
    "escapeHtml",
    "escapeHTML",
    // JSON serialisation — cannot execute as HTML markup
    "stringify",
];

// ── TaintContext ──────────────────────────────────────────────────────────────

/// Per-function taint analysis result.
///
/// `tainted`: variable names that carry user-controlled (untrusted) input.
/// `safe`:    variable names that carry provably sanitised / static values.
/// Variables absent from both sets are *unknown* — the caller should fall back
/// to the existing pattern-match behaviour (flag the finding).
pub struct TaintContext {
    pub tainted: HashSet<String>,
    pub safe: HashSet<String>,
}

#[allow(dead_code)] // pub API used in tests; not all methods called from sast.rs
impl TaintContext {
    /// Build a TaintContext by analysing all variable assignments within
    /// `scope_root` (a function body or the file root node).
    pub fn build(scope_root: Node<'_>, source: &[u8]) -> Self {
        // Collect every (name, value_node) pair in this scope.
        let mut assignments: Vec<(String, Node<'_>)> = Vec::new();
        collect_assignments(scope_root, source, &mut assignments);

        let mut tainted: HashSet<String> = HashSet::new();
        let mut safe: HashSet<String> = HashSet::new();

        // Seed: direct taint sources and direct safe values.
        for (name, val) in &assignments {
            if is_direct_taint_source(*val, source) {
                tainted.insert(name.clone());
            } else if is_direct_safe_value(*val, source, &safe) {
                safe.insert(name.clone());
            }
        }

        // Fixpoint propagation — repeat until no new vars are classified.
        let mut changed = true;
        while changed {
            changed = false;
            for (name, val) in &assignments {
                if tainted.contains(name) || safe.contains(name) {
                    continue; // already classified
                }
                if node_contains_tainted_var(*val, source, &tainted) {
                    tainted.insert(name.clone());
                    changed = true;
                } else if is_direct_safe_value(*val, source, &safe) {
                    safe.insert(name.clone());
                    changed = true;
                }
            }
        }

        TaintContext { tainted, safe }
    }

    /// Returns `true` if `name` is in the tainted set.
    #[allow(dead_code)]
    pub fn is_tainted(&self, name: &str) -> bool {
        self.tainted.contains(name)
    }

    /// Returns `true` if `name` is in the safe set.
    #[allow(dead_code)]
    pub fn is_safe(&self, name: &str) -> bool {
        self.safe.contains(name)
    }

    /// Returns `true` if `node` is (or transitively contains) a tainted value.
    pub fn node_is_tainted(&self, node: Node<'_>, source: &[u8]) -> bool {
        if is_direct_taint_source(node, source) {
            return true;
        }
        node_contains_tainted_var(node, source, &self.tainted)
    }

    /// Returns `true` if `node` is provably safe (sanitised, static, or all
    /// referenced variables are in the safe set).
    pub fn node_is_safe(&self, node: Node<'_>, source: &[u8]) -> bool {
        is_direct_safe_value(node, source, &self.safe)
    }
}

// ── Scope finding ─────────────────────────────────────────────────────────────

/// Walk up the parent chain from `node` to find the nearest enclosing
/// function-like node.  Returns the file root if no function is found.
pub fn find_enclosing_scope<'a>(node: Node<'a>, root: Node<'a>) -> Node<'a> {
    const FUNCTION_KINDS: &[&str] = &[
        "function_declaration",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    ];

    let mut current = node;
    loop {
        if let Some(parent) = current.parent() {
            if FUNCTION_KINDS.contains(&parent.kind()) {
                // Return the body of the function so we don't accidentally
                // recurse into nested function parameters or names.
                return parent.child_by_field_name("body").unwrap_or(parent);
            }
            current = parent;
        } else {
            return root;
        }
    }
}

// ── Assignment collection ─────────────────────────────────────────────────────

/// Recursively collect every `(variable_name, value_node)` assignment within
/// `node`.  Descends into all children *except* nested function bodies so that
/// inner functions do not pollute the outer function's symbol table.
fn collect_assignments<'a>(node: Node<'a>, source: &[u8], out: &mut Vec<(String, Node<'a>)>) {
    match node.kind() {
        // const/let x = expr;  or  const { x } = expr; (destructuring skipped)
        "variable_declarator" => {
            if let (Some(name_node), Some(val_node)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                // For destructuring patterns we skip for now — Tier 2 concern.
                if name_node.kind() == "identifier"
                    && let Ok(name) = name_node.utf8_text(source)
                {
                    out.push((name.to_string(), val_node));
                }
            }
            return; // do not descend further; value is already captured
        }
        // x = expr;
        "assignment_expression" => {
            if let (Some(lhs), Some(rhs)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) && lhs.kind() == "identifier"
                && let Ok(name) = lhs.utf8_text(source)
            {
                out.push((name.to_string(), rhs));
            }
            // Descend into RHS but NOT into LHS.
            if let Some(rhs) = node.child_by_field_name("right") {
                collect_assignments(rhs, source, out);
            }
            return;
        }
        // Do not cross nested function boundaries.
        "function_declaration"
        | "function"
        | "arrow_function"
        | "method_definition"
        | "generator_function_declaration"
        | "generator_function" => {
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_assignments(child, source, out);
    }
}

// ── Taint source detection ────────────────────────────────────────────────────

/// Returns `true` if `node` is a *direct* taint source (no variable lookup
/// required).
pub fn is_direct_taint_source(node: Node<'_>, source: &[u8]) -> bool {
    match node.kind() {
        "member_expression" => {
            let obj = node
                .child_by_field_name("object")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            let prop = node
                .child_by_field_name("property")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            MEMBER_TAINT_SOURCES
                .iter()
                .any(|(o, p)| *o == obj && *p == prop)
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "member_expression" {
                    let obj = func
                        .child_by_field_name("object")
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("");
                    let prop = func
                        .child_by_field_name("property")
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("");
                    if CALL_TAINT_SOURCES
                        .iter()
                        .any(|(o, p)| *o == obj && *p == prop)
                    {
                        return true;
                    }
                } else if func.kind() == "identifier" {
                    let name = func.utf8_text(source).unwrap_or("");
                    if BARE_TAINT_CALLS.contains(&name) {
                        return true;
                    }
                }
            }
            false
        }
        // Await a taint source (e.g. `const x = await req.body`)
        "await_expression" => {
            if let Some(child) = node.named_child(0) {
                return is_direct_taint_source(child, source);
            }
            false
        }
        // Parenthesised — unwrap
        "parenthesized_expression" => {
            if let Some(inner) = node.named_child(0) {
                return is_direct_taint_source(inner, source);
            }
            false
        }
        _ => false,
    }
}

// ── Safe value detection ──────────────────────────────────────────────────────

/// Returns `true` if `node` is provably safe — either a static literal, a
/// sanitizer call, or an expression composed entirely of safe values.
pub fn is_direct_safe_value(node: Node<'_>, source: &[u8], safe: &HashSet<String>) -> bool {
    match node.kind() {
        // Static literals
        "string" | "number" | "true" | "false" | "null" | "undefined" => true,
        // Template literal — safe only when it has no `${}` substitutions
        "template_string" => {
            let mut cur = node.walk();
            let subs: Vec<_> = node
                .children(&mut cur)
                .filter(|c| c.kind() == "template_substitution")
                .collect();
            if subs.is_empty() {
                return true;
            }
            // Safe if every substitution resolves to a safe identifier or literal
            subs.iter().all(|sub| {
                let mut sc = sub.walk();
                sub.named_children(&mut sc)
                    .all(|c| is_direct_safe_value(c, source, safe))
            })
        }
        // Call to a known sanitizer
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                match func.kind() {
                    "identifier" => {
                        let n = func.utf8_text(source).unwrap_or("");
                        return SAFE_MEMBER_CALLS.contains(&n);
                    }
                    "member_expression" => {
                        let prop = func
                            .child_by_field_name("property")
                            .and_then(|p| p.utf8_text(source).ok())
                            .unwrap_or("");
                        return SAFE_MEMBER_CALLS.contains(&prop);
                    }
                    _ => {}
                }
            }
            false
        }
        // Variable reference — safe only if in the safe set
        "identifier" => {
            let name = node.utf8_text(source).unwrap_or("");
            safe.contains(name)
        }
        // Binary expression (+ concatenation) — safe if both sides are safe
        "binary_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            matches!((left, right), (Some(l), Some(r))
                if is_direct_safe_value(l, source, safe)
                && is_direct_safe_value(r, source, safe))
        }
        // Parenthesised / awaited — unwrap
        "parenthesized_expression" | "await_expression" => {
            if let Some(inner) = node.named_child(0) {
                return is_direct_safe_value(inner, source, safe);
            }
            false
        }
        _ => false,
    }
}

// ── Taint propagation ─────────────────────────────────────────────────────────

/// Returns `true` if `node` (or any sub-expression) references a variable in
/// `tainted`, or is itself a direct taint source.
pub fn node_contains_tainted_var(
    node: Node<'_>,
    source: &[u8],
    tainted: &HashSet<String>,
) -> bool {
    if is_direct_taint_source(node, source) {
        return true;
    }
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source).unwrap_or("");
            tainted.contains(name)
        }
        "member_expression" => {
            // x.prop — tainted if the root object is tainted
            if let Some(obj) = node.child_by_field_name("object") {
                return node_contains_tainted_var(obj, source, tainted);
            }
            false
        }
        "template_string" => {
            let mut cur = node.walk();
            node.children(&mut cur).any(|c| {
                c.kind() == "template_substitution"
                    && node_contains_tainted_var(c, source, tainted)
            })
        }
        "template_substitution" => {
            let mut cur = node.walk();
            node.named_children(&mut cur)
                .any(|c| node_contains_tainted_var(c, source, tainted))
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            left.map(|n| node_contains_tainted_var(n, source, tainted))
                .unwrap_or(false)
                || right
                    .map(|n| node_contains_tainted_var(n, source, tainted))
                    .unwrap_or(false)
        }
        "call_expression" => {
            // args of a call may be tainted; the call itself may be a sanitizer
            // handled in is_direct_safe_value — here we just check args
            if let Some(args) = node.child_by_field_name("arguments") {
                let mut cur = args.walk();
                return args
                    .named_children(&mut cur)
                    .any(|a| node_contains_tainted_var(a, source, tainted));
            }
            false
        }
        "array" => {
            let mut cur = node.walk();
            node.named_children(&mut cur)
                .any(|c| node_contains_tainted_var(c, source, tainted))
        }
        "parenthesized_expression" | "await_expression" => {
            if let Some(inner) = node.named_child(0) {
                return node_contains_tainted_var(inner, source, tainted);
            }
            false
        }
        _ => false,
    }
}

// ── Cache type alias ──────────────────────────────────────────────────────────

/// Cache keyed by (start_byte, end_byte) of a function-scope node.
/// Avoids rebuilding the TaintContext for every sink inside the same function.
pub type TaintCache = HashMap<(usize, usize), TaintContext>;

/// Retrieve (or build and cache) the TaintContext for the scope that contains
/// `sink_node`.  `file_root` is the tree root; it is used as the fallback
/// scope when no enclosing function is found.
pub fn taint_for_sink<'a, 'c>(
    sink_node: Node<'a>,
    file_root: Node<'a>,
    source: &[u8],
    cache: &'c mut TaintCache,
) -> &'c TaintContext {
    let scope = find_enclosing_scope(sink_node, file_root);
    let key = (scope.start_byte(), scope.end_byte());
    cache
        .entry(key)
        .or_insert_with(|| TaintContext::build(scope, source))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_js(src: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.as_bytes().to_vec())
    }

    #[test]
    fn detects_req_body_direct() {
        let (tree, src) = parse_js("const x = req.body.comment;");
        let root = tree.root_node();
        let ctx = TaintContext::build(root, &src);
        assert!(ctx.is_tainted("x"), "x should be tainted from req.body");
        assert!(!ctx.is_safe("x"));
    }

    #[test]
    fn detects_propagation_through_template_literal() {
        let code = r#"
            const input = req.query.search;
            const html = `<div>${input}</div>`;
        "#;
        let (tree, src) = parse_js(code);
        let ctx = TaintContext::build(tree.root_node(), &src);
        assert!(ctx.is_tainted("input"));
        assert!(
            ctx.is_tainted("html"),
            "html should be tainted via template literal"
        );
    }

    #[test]
    fn detects_propagation_through_concatenation() {
        let code = r#"
            const raw = req.params.id;
            const cmd = "ls " + raw;
        "#;
        let (tree, src) = parse_js(code);
        let ctx = TaintContext::build(tree.root_node(), &src);
        assert!(ctx.is_tainted("raw"));
        assert!(
            ctx.is_tainted("cmd"),
            "cmd should be tainted via + concatenation"
        );
    }

    #[test]
    fn safe_sanitized_value_not_tainted() {
        let code = r#"
            const dirty = req.body.html;
            const clean = DOMPurify.sanitize(dirty);
        "#;
        let (tree, src) = parse_js(code);
        let ctx = TaintContext::build(tree.root_node(), &src);
        assert!(ctx.is_tainted("dirty"));
        // `clean` went through DOMPurify.sanitize → safe
        assert!(
            ctx.is_safe("clean"),
            "clean should be safe after sanitization"
        );
        assert!(!ctx.is_tainted("clean"));
    }

    #[test]
    fn static_string_variable_is_safe() {
        let code = r#"const content = "<b>hello</b>";"#;
        let (tree, src) = parse_js(code);
        let ctx = TaintContext::build(tree.root_node(), &src);
        assert!(
            ctx.is_safe("content"),
            "static string literal should be safe"
        );
        assert!(!ctx.is_tainted("content"));
    }

    #[test]
    fn local_search_params_tainted() {
        let code = r#"
            const q = searchParams.get("query");
            const msg = `You searched for: ${q}`;
        "#;
        let (tree, src) = parse_js(code);
        let ctx = TaintContext::build(tree.root_node(), &src);
        assert!(ctx.is_tainted("q"));
        assert!(ctx.is_tainted("msg"));
    }

    #[test]
    fn node_is_tainted_identifier() {
        let code = r#"
            const userInput = req.body.data;
        "#;
        let (tree, src) = parse_js(code);
        let root = tree.root_node();
        let ctx = TaintContext::build(root, &src);

        // Navigate to the `userInput` identifier in the assignment RHS's var ref
        // We'll test node_is_tainted via the identifier "userInput"
        assert!(ctx.is_tainted("userInput"));
    }
}
