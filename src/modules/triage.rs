use crate::modules::scanner::Finding;
use crate::utils::config::TriageConfig;
use crate::utils::http;
use anyhow::{Context, Result};
use std::path::Path;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TriageVerdict {
    LikelyReal,
    LikelyFalsePositive,
    Uncertain,
}

#[derive(Debug, Clone)]
pub struct TriageResult {
    pub verdict: TriageVerdict,
    /// 0.0–1.0 confidence in the verdict.
    pub confidence: f64,
    /// One-sentence human-readable explanation from the LLM.
    pub reason: String,
}

impl TriageResult {
    pub fn label(&self) -> &'static str {
        match self.verdict {
            TriageVerdict::LikelyReal => "LIKELY REAL",
            TriageVerdict::LikelyFalsePositive => "LIKELY FALSE POSITIVE",
            TriageVerdict::Uncertain => "UNCERTAIN",
        }
    }

    pub fn confidence_pct(&self) -> u8 {
        (self.confidence * 100.0).round() as u8
    }
}

/// Returns true when a finding should be auto-suppressed based on config threshold.
pub fn should_auto_suppress(result: &TriageResult, threshold: f64) -> bool {
    threshold > 0.0
        && result.verdict == TriageVerdict::LikelyFalsePositive
        && result.confidence >= threshold
}

// ── Context extraction ────────────────────────────────────────────────────────

fn read_context(path: &Path, line: usize, window: usize) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    // `line` may point past the end of the file: `--history` findings carry a
    // line number from an old blob, while we read the current working tree.
    // Clamp both ends so a shrunk file yields an empty window, not a panic.
    let end = (line + window).min(total);
    let start = line.saturating_sub(window + 1).min(end);
    let Some(window_lines) = lines.get(start..end) else {
        return String::new();
    };
    window_lines
        .iter()
        .enumerate()
        .map(|(i, l)| format!("{:4} | {}", start + i + 1, l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Prompt construction ───────────────────────────────────────────────────────

fn build_prompt(finding: &Finding, context: &str) -> String {
    format!(
        "You are a security code reviewer. A static analysis scanner flagged the following.\n\
         \n\
         Rule: {rule}\n\
         Severity: {sev}\n\
         File: {path}:{line}\n\
         \n\
         Surrounding code:\n\
         ```\n\
         {ctx}\n\
         ```\n\
         \n\
         Is this a real security issue or a false positive?\n\
         Consider: test files, placeholder/example values (e.g. AKIAIOSFODNN7EXAMPLE), \
         dead code, whether user-controlled data actually reaches this code path.\n\
         \n\
         Respond with JSON only, no markdown fences:\n\
         {{\"verdict\": \"real\" | \"false_positive\" | \"uncertain\", \
         \"confidence\": 0.0-1.0, \
         \"reason\": \"one concise sentence\"}}",
        rule = finding.rule_id,
        sev = finding.severity,
        path = finding.path.display(),
        line = finding.line,
        ctx = context,
    )
}

// ── Response parsing ──────────────────────────────────────────────────────────

fn parse_response(text: &str) -> Result<TriageResult> {
    let start = text
        .find('{')
        .ok_or_else(|| anyhow::anyhow!("no JSON object in LLM response"))?;
    let end = text
        .rfind('}')
        .ok_or_else(|| anyhow::anyhow!("no closing brace in LLM response"))?
        + 1;
    let json_str = text
        .get(start..end)
        .ok_or_else(|| anyhow::anyhow!("malformed JSON object in LLM response"))?;
    let v: serde_json::Value = serde_json::from_str(json_str)
        .with_context(|| format!("bad triage JSON: {}", json_str))?;

    let verdict = match v["verdict"].as_str().unwrap_or("uncertain") {
        "real" => TriageVerdict::LikelyReal,
        "false_positive" => TriageVerdict::LikelyFalsePositive,
        _ => TriageVerdict::Uncertain,
    };
    let confidence = v["confidence"].as_f64().unwrap_or(0.5).clamp(0.0, 1.0);
    let reason = v["reason"]
        .as_str()
        .unwrap_or("No reason provided.")
        .to_string();

    Ok(TriageResult {
        verdict,
        confidence,
        reason,
    })
}

// ── API calls ─────────────────────────────────────────────────────────────────

fn call_anthropic(prompt: &str, cfg: &TriageConfig, api_key: &str) -> Result<String> {
    let endpoint = cfg
        .endpoint
        .as_deref()
        .unwrap_or("https://api.anthropic.com/v1/messages");

    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    });

    let resp = http::agent()
        .post(endpoint)
        .set("x-api-key", api_key)
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("Anthropic API error: {}", e))?;

    let json: serde_json::Value =
        http::read_json(resp).context("failed to parse Anthropic response")?;

    json["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("unexpected Anthropic response shape"))
}

fn call_openai_compat(prompt: &str, cfg: &TriageConfig, api_key: &str) -> Result<String> {
    let endpoint = cfg
        .endpoint
        .as_deref()
        .unwrap_or("https://api.openai.com/v1/chat/completions");

    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    });

    let resp = http::agent()
        .post(endpoint)
        .set("Authorization", &format!("Bearer {}", api_key))
        .set("content-type", "application/json")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("OpenAI-compatible API error: {}", e))?;

    let json: serde_json::Value =
        http::read_json(resp).context("failed to parse OpenAI response")?;

    json["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("unexpected OpenAI response shape"))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Call the LLM to triage a single finding. Returns an error if the API call or
/// response parsing fails — callers typically log the error and continue.
pub fn triage_one(finding: &Finding, cfg: &TriageConfig, api_key: &str) -> Result<TriageResult> {
    let context = read_context(&finding.path, finding.line, cfg.context_lines);
    let prompt = build_prompt(finding, &context);

    // Use Anthropic API format unless the endpoint looks like an OpenAI-compatible service.
    let endpoint = cfg.endpoint.as_deref().unwrap_or("");
    let text = if endpoint.is_empty() || endpoint.contains("anthropic") {
        call_anthropic(&prompt, cfg, api_key)?
    } else {
        call_openai_compat(&prompt, cfg, api_key)?
    };

    parse_response(&text)
}

/// Triage all findings sequentially. Returns one `Option<TriageResult>` per finding —
/// `None` means the LLM call failed for that finding (warning is printed; scan continues).
pub fn triage_findings(findings: &[Finding], cfg: &TriageConfig) -> Vec<Option<TriageResult>> {
    let api_key = match std::env::var(&cfg.api_key_env) {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!(
                "greengate: triage: {} is not set — skipping LLM triage",
                cfg.api_key_env
            );
            return vec![None; findings.len()];
        }
    };

    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            triage_one(f, cfg, &api_key)
                .map_err(|e| {
                    eprintln!(
                        "greengate: triage: finding {} ({}:{}): {}",
                        i + 1,
                        f.path.display(),
                        f.line,
                        e
                    )
                })
                .ok()
        })
        .collect()
}

// ── Output ────────────────────────────────────────────────────────────────────

/// Print findings with triage annotations. Returns the count of non-suppressed findings
/// so the caller can decide the exit code.
pub fn emit_triaged(
    findings: &[Finding],
    results: &[Option<TriageResult>],
    threshold: f64,
) -> usize {
    let total = findings.len();
    if total == 0 {
        crate::utils::terminal::success("No secrets or PII found.");
        return 0;
    }

    let auto_suppressed: usize = results
        .iter()
        .filter(|r| {
            r.as_ref()
                .map(|tr| should_auto_suppress(tr, threshold))
                .unwrap_or(false)
        })
        .count();
    let effective = total - auto_suppressed;

    // Summary header
    if auto_suppressed > 0 {
        crate::utils::terminal::warn(&format!(
            "Found {} potential issue(s) — {} triaged as false positive(s) and auto-suppressed, {} require attention:",
            total, auto_suppressed, effective
        ));
    } else {
        crate::utils::terminal::warn(&format!("Found {} potential issue(s):", total));
    }

    for (f, result) in findings.iter().zip(results.iter()) {
        let suppressed = result
            .as_ref()
            .map(|tr| should_auto_suppress(tr, threshold))
            .unwrap_or(false);

        let suppressed_tag = if suppressed { " [AUTO-SUPPRESSED]" } else { "" };

        eprintln!(
            "  - [{}] [{}] {}:{}{}",
            f.severity.to_uppercase(),
            f.rule_id,
            f.path.display(),
            f.line,
            suppressed_tag
        );

        match result {
            Some(tr) => {
                eprintln!(
                    "    → Triage: {} ({}%) — {}",
                    tr.label(),
                    tr.confidence_pct(),
                    tr.reason
                );
            }
            None => {
                eprintln!("    → Triage: unavailable (LLM call failed)");
            }
        }
    }

    // Triage summary footer
    let real = results
        .iter()
        .filter(|r| {
            r.as_ref()
                .map(|tr| tr.verdict == TriageVerdict::LikelyReal)
                .unwrap_or(false)
        })
        .count();
    let uncertain = results
        .iter()
        .filter(|r| {
            r.as_ref()
                .map(|tr| tr.verdict == TriageVerdict::Uncertain)
                .unwrap_or(false)
        })
        .count();
    let unavailable = results.iter().filter(|r| r.is_none()).count();

    eprintln!();
    eprintln!(
        "  Triage summary: {} likely real · {} uncertain · {} false positive (suppressed: {}) · {} unavailable",
        real, uncertain, auto_suppressed, auto_suppressed, unavailable
    );

    effective
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_real_verdict() {
        let json = r#"{"verdict": "real", "confidence": 0.92, "reason": "User input flows directly into exec()."}"#;
        let r = parse_response(json).unwrap();
        assert_eq!(r.verdict, TriageVerdict::LikelyReal);
        assert!((r.confidence - 0.92).abs() < 0.001);
        assert!(r.reason.contains("exec"));
    }

    #[test]
    fn parse_response_false_positive() {
        let json =
            r#"{"verdict": "false_positive", "confidence": 0.88, "reason": "Test fixture."}"#;
        let r = parse_response(json).unwrap();
        assert_eq!(r.verdict, TriageVerdict::LikelyFalsePositive);
        assert_eq!(r.confidence_pct(), 88);
    }

    #[test]
    fn parse_response_strips_surrounding_prose() {
        let text = r#"Here is my analysis: {"verdict": "uncertain", "confidence": 0.5, "reason": "Cannot determine."} Hope that helps!"#;
        let r = parse_response(text).unwrap();
        assert_eq!(r.verdict, TriageVerdict::Uncertain);
    }

    #[test]
    fn parse_response_unknown_verdict_defaults_to_uncertain() {
        let json = r#"{"verdict": "maybe", "confidence": 0.6, "reason": "Not sure."}"#;
        let r = parse_response(json).unwrap();
        assert_eq!(r.verdict, TriageVerdict::Uncertain);
    }

    #[test]
    fn parse_response_clamps_confidence() {
        let json = r#"{"verdict": "real", "confidence": 1.5, "reason": "Overconfident."}"#;
        let r = parse_response(json).unwrap();
        assert!(r.confidence <= 1.0);
    }

    #[test]
    fn parse_response_missing_json_errors() {
        assert!(parse_response("no json here").is_err());
    }

    #[test]
    fn should_auto_suppress_below_threshold() {
        let r = TriageResult {
            verdict: TriageVerdict::LikelyFalsePositive,
            confidence: 0.80,
            reason: "test".into(),
        };
        assert!(!should_auto_suppress(&r, 0.90));
    }

    #[test]
    fn should_auto_suppress_above_threshold() {
        let r = TriageResult {
            verdict: TriageVerdict::LikelyFalsePositive,
            confidence: 0.95,
            reason: "test".into(),
        };
        assert!(should_auto_suppress(&r, 0.90));
    }

    #[test]
    fn should_not_suppress_real_finding_even_above_threshold() {
        let r = TriageResult {
            verdict: TriageVerdict::LikelyReal,
            confidence: 0.99,
            reason: "test".into(),
        };
        assert!(!should_auto_suppress(&r, 0.90));
    }

    #[test]
    fn should_not_suppress_when_threshold_zero() {
        let r = TriageResult {
            verdict: TriageVerdict::LikelyFalsePositive,
            confidence: 1.0,
            reason: "test".into(),
        };
        assert!(!should_auto_suppress(&r, 0.0));
    }

    #[test]
    fn triage_findings_skips_when_api_key_missing() {
        use crate::utils::config::TriageConfig;
        // Use an env var name that is guaranteed to be unset
        let cfg = TriageConfig {
            enabled: true,
            model: "claude-haiku-4-5-20251001".into(),
            api_key_env: "__GREENGATE_TEST_NO_KEY__".into(),
            endpoint: None,
            auto_suppress_threshold: 0.0,
            context_lines: 5,
        };
        let results = triage_findings(&[], &cfg);
        assert!(results.is_empty());
    }

    // ── Regression: both of these used to panic ──────────────────────────────

    #[test]
    fn read_context_survives_line_past_end_of_file() {
        // A `--history` finding carries a line number from an old blob; the
        // working-tree file has since shrunk to 10 lines.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shrunk.txt");
        std::fs::write(&path, "a\n".repeat(10)).expect("write fixture");
        assert_eq!(read_context(&path, 100, 3), "");
    }

    #[test]
    fn read_context_clamps_window_to_file_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short.txt");
        std::fs::write(&path, "one\ntwo\nthree\n").expect("write fixture");
        let ctx = read_context(&path, 3, 5);
        assert!(ctx.contains("one"), "got: {ctx}");
        assert!(ctx.contains("three"), "got: {ctx}");
    }

    #[test]
    fn parse_response_errors_on_reversed_braces() {
        // Last `}` precedes the first `{` — both are present, so the old
        // existence-only checks passed and the slice panicked.
        let err = parse_response("} {").expect_err("should not panic, should error");
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }
}
