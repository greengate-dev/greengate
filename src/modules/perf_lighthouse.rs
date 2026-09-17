use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::utils::http;
use crate::utils::terminal;

// ── Config ───────────────────────────────────────────────────────────────────

pub struct LighthouseOpts<'a> {
    pub url: &'a str,
    pub strategy: &'a str,
    pub thresholds: LighthouseThresholds,
    pub api_key: Option<String>,
}

#[derive(Clone)]
pub struct LighthouseThresholds {
    pub performance: u8,
    pub accessibility: u8,
    pub best_practices: u8,
    pub seo: u8,
}

impl Default for LighthouseThresholds {
    fn default() -> Self {
        Self {
            performance: 80,
            accessibility: 90,
            best_practices: 80,
            seo: 80,
        }
    }
}

// ── PSI API response ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PsiResponse {
    #[serde(rename = "lighthouseResult")]
    lighthouse_result: LighthouseResult,
}

#[derive(Deserialize)]
struct LighthouseResult {
    categories: Categories,
}

#[derive(Deserialize)]
struct Categories {
    performance: Option<CategoryScore>,
    accessibility: Option<CategoryScore>,
    #[serde(rename = "best-practices")]
    best_practices: Option<CategoryScore>,
    seo: Option<CategoryScore>,
}

#[derive(Deserialize)]
struct CategoryScore {
    score: Option<f64>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const PSI_API: &str = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";

/// Percent-encode a string for use as a query parameter value (RFC 3986).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

fn score_to_u8(cat: Option<&CategoryScore>) -> u8 {
    cat.and_then(|c| c.score)
        .map(|s| (s * 100.0).round() as u8)
        .unwrap_or(0)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_lighthouse(opts: LighthouseOpts<'_>) -> Result<()> {
    terminal::info(&format!(
        "Running Lighthouse audit: {} ({})",
        opts.url, opts.strategy
    ));

    let mut request_url = format!(
        "{}?url={}&strategy={}&category=performance&category=accessibility&category=best-practices&category=seo",
        PSI_API,
        percent_encode(opts.url),
        opts.strategy,
    );

    // Resolve API key: CLI flag → PAGESPEED_API_KEY env var
    let key = opts
        .api_key
        .clone()
        .or_else(|| std::env::var("PAGESPEED_API_KEY").ok());
    if let Some(k) = &key {
        request_url.push_str(&format!("&key={}", k));
    }

    let response = http::agent()
        .get(&request_url)
        .call()
        .context("Failed to reach PageSpeed Insights API — check your network connection")?;

    let body: Value =
        http::read_json(response).context("Failed to parse PageSpeed Insights API response")?;

    // Surface human-readable API errors (e.g. invalid URL, quota exceeded)
    if let Some(err) = body.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown API error");
        anyhow::bail!("PageSpeed Insights API error: {}", msg);
    }

    let psi: PsiResponse =
        serde_json::from_value(body).context("Unexpected PageSpeed Insights response shape")?;

    let cats = &psi.lighthouse_result.categories;

    let results = [
        (
            "Performance",
            score_to_u8(cats.performance.as_ref()),
            opts.thresholds.performance,
        ),
        (
            "Accessibility",
            score_to_u8(cats.accessibility.as_ref()),
            opts.thresholds.accessibility,
        ),
        (
            "Best Practices",
            score_to_u8(cats.best_practices.as_ref()),
            opts.thresholds.best_practices,
        ),
        ("SEO", score_to_u8(cats.seo.as_ref()), opts.thresholds.seo),
    ];

    let mut failures = 0usize;

    eprintln!();
    for (name, score, min) in &results {
        let icon = if score >= min { "✅" } else { "❌" };
        eprintln!(
            "  {:<18} {:>3}  {}  (min: {})",
            format!("{}:", name),
            score,
            icon,
            min
        );
        if score < min {
            failures += 1;
        }
    }
    eprintln!();

    if failures > 0 {
        anyhow::bail!(
            "Lighthouse failed: {} category/-ies below threshold.",
            failures
        );
    }

    terminal::success(&format!(
        "Lighthouse passed: all categories meet their thresholds for {}",
        opts.url
    ));
    Ok(())
}
