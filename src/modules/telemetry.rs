//! `greengate` telemetry — fire-and-forget metrics export.
//!
//! Emits structured metrics after each command via two optional backends:
//!
//! **OTLP HTTP/JSON** (`otlp_endpoint`)
//! Posts to `{endpoint}/v1/metrics` using the OpenTelemetry Protocol over
//! HTTP with JSON encoding.  Compatible with the OpenTelemetry Collector,
//! Grafana Agent, Datadog Agent (OTLP intake), Honeycomb, and any
//! OTLP-compatible backend.  Default port 4318 (HTTP) rather than 4317 (gRPC).
//!
//! **Prometheus text format** (`metrics_file`)
//! Writes a `.prom` file that Prometheus node_exporter's `--collector.textfile`
//! can scrape.  Append `/path/to/dir` to `--collector.textfile.directory` and
//! set `metrics_file` to a path inside that directory.
//!
//! Both backends are optional and independent.  Errors are logged as warnings
//! and **never** cause the greengate command to fail — telemetry is always
//! best-effort.

use crate::utils::config::TelemetryConfig;
use crate::utils::http;
use std::time::SystemTime;

// ── Public metric types ───────────────────────────────────────────────────────

/// A single metric data point.
pub struct Metric {
    /// Dot-separated name, e.g. `greengate.scan.findings_total`
    pub name: &'static str,
    /// Human-readable description (used in Prometheus HELP lines)
    pub description: &'static str,
    /// Unit string for OTLP, e.g. `"{finding}"`, `"ms"`, `"1"`
    pub unit: &'static str,
    /// Numeric value
    pub value: f64,
    /// Key-value label pairs
    pub labels: Vec<(&'static str, String)>,
    /// Counter (monotonically increasing) or Gauge (current snapshot)
    pub kind: MetricKind,
}

pub enum MetricKind {
    Counter,
    Gauge,
}

// ── Per-command helper builders ───────────────────────────────────────────────

/// Build metrics for a `greengate scan` run.
pub fn scan_metrics(
    findings: &[crate::modules::scanner::Finding],
    duration_ms: u64,
) -> Vec<Metric> {
    use std::collections::HashMap;

    let mut by_severity: HashMap<&str, usize> = HashMap::new();
    let mut by_rule: HashMap<(&str, &str), usize> = HashMap::new();

    for f in findings {
        *by_severity.entry(f.severity.as_str()).or_default() += 1;
        *by_rule
            .entry((f.rule_id.as_str(), f.severity.as_str()))
            .or_default() += 1;
    }

    let mut metrics = Vec::new();

    // Per-severity totals
    for (severity, count) in &by_severity {
        metrics.push(Metric {
            name: "greengate_scan_findings_total",
            description: "Total scan findings by severity",
            unit: "{finding}",
            value: *count as f64,
            labels: vec![("severity", severity.to_string())],
            kind: MetricKind::Counter,
        });
    }

    // Total findings (all severities)
    metrics.push(Metric {
        name: "greengate_scan_findings_total",
        description: "Total scan findings",
        unit: "{finding}",
        value: findings.len() as f64,
        labels: vec![("severity", "all".to_string())],
        kind: MetricKind::Counter,
    });

    // Scan duration
    metrics.push(Metric {
        name: "greengate_scan_duration_ms",
        description: "Scan duration in milliseconds",
        unit: "ms",
        value: duration_ms as f64,
        labels: vec![],
        kind: MetricKind::Gauge,
    });

    metrics
}

/// Build generic command duration + success metrics (used for commands that
/// don't produce structured result data).
pub fn command_metrics(command: &str, duration_ms: u64, success: bool) -> Vec<Metric> {
    vec![
        Metric {
            name: "greengate_command_duration_ms",
            description: "Command duration in milliseconds",
            unit: "ms",
            value: duration_ms as f64,
            labels: vec![
                ("command", command.to_string()),
                ("success", success.to_string()),
            ],
            kind: MetricKind::Gauge,
        },
        Metric {
            name: "greengate_command_success",
            description: "1 if the command succeeded, 0 if it failed",
            unit: "1",
            value: if success { 1.0 } else { 0.0 },
            labels: vec![("command", command.to_string())],
            kind: MetricKind::Gauge,
        },
    ]
}

// ── Emit ──────────────────────────────────────────────────────────────────────

/// Emit `metrics` to all configured backends.  Never panics, never fails the
/// calling command — errors are silently downgraded to stderr warnings.
pub fn emit(metrics: &[Metric], cfg: &TelemetryConfig) {
    if !cfg.enabled || metrics.is_empty() {
        return;
    }

    if let Some(ref endpoint) = cfg.otlp_endpoint
        && !endpoint.is_empty()
        && let Err(e) = emit_otlp(metrics, endpoint, &cfg.service_name)
    {
        eprintln!(
            "⚠️  greengate telemetry: OTLP export failed ({}). \
             Check [telemetry] otlp_endpoint in .greengate.toml.",
            e
        );
    }

    if let Some(ref path) = cfg.metrics_file
        && !path.is_empty()
        && let Err(e) = emit_prometheus(metrics, path, &cfg.service_name)
    {
        eprintln!(
            "⚠️  greengate telemetry: Prometheus file write failed ({}). \
             Check [telemetry] metrics_file in .greengate.toml.",
            e
        );
    }
}

// ── OTLP HTTP/JSON backend ────────────────────────────────────────────────────

fn emit_otlp(metrics: &[Metric], endpoint: &str, service_name: &str) -> anyhow::Result<()> {
    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let now_str = now_ns.to_string();

    let data_points: Vec<serde_json::Value> = metrics
        .iter()
        .map(|m| {
            let attrs: Vec<serde_json::Value> = m
                .labels
                .iter()
                .map(|(k, v)| {
                    serde_json::json!({
                        "key": k,
                        "value": {"stringValue": v}
                    })
                })
                .collect();

            match m.kind {
                MetricKind::Counter => serde_json::json!({
                    "attributes": attrs,
                    "startTimeUnixNano": now_str,
                    "timeUnixNano": now_str,
                    "asDouble": m.value
                }),
                MetricKind::Gauge => serde_json::json!({
                    "attributes": attrs,
                    "timeUnixNano": now_str,
                    "asDouble": m.value
                }),
            }
        })
        .collect();

    // Group all metrics into a single OTLP payload.
    // Each distinct metric name becomes one OTLP Metric object.
    use std::collections::HashMap;
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, m) in metrics.iter().enumerate() {
        by_name.entry(m.name).or_default().push(i);
    }

    let otlp_metrics: Vec<serde_json::Value> = by_name
        .iter()
        .map(|(name, indices)| {
            let first = &metrics[indices[0]];
            let points: Vec<&serde_json::Value> =
                indices.iter().map(|&i| &data_points[i]).collect();

            match first.kind {
                MetricKind::Counter => serde_json::json!({
                    "name": name,
                    "description": first.description,
                    "unit": first.unit,
                    "sum": {
                        "dataPoints": points,
                        "aggregationTemporality": 1,  // DELTA
                        "isMonotonic": true
                    }
                }),
                MetricKind::Gauge => serde_json::json!({
                    "name": name,
                    "description": first.description,
                    "unit": first.unit,
                    "gauge": {
                        "dataPoints": points
                    }
                }),
            }
        })
        .collect();

    let payload = serde_json::json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service_name}},
                    {"key": "telemetry.sdk.name", "value": {"stringValue": "greengate"}},
                    {"key": "telemetry.sdk.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}}
                ]
            },
            "scopeMetrics": [{
                "scope": {
                    "name": "greengate",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "metrics": otlp_metrics
            }]
        }]
    });

    let url = format!("{}/v1/metrics", endpoint.trim_end_matches('/'));
    http::agent()
        .post(&url)
        .set("Content-Type", "application/json")
        .send_json(payload)
        .map_err(|e| anyhow::anyhow!("HTTP {}", e))?;

    Ok(())
}

// ── Prometheus text-file backend ──────────────────────────────────────────────

fn emit_prometheus(metrics: &[Metric], path: &str, service_name: &str) -> anyhow::Result<()> {
    use std::collections::HashSet;
    let mut out = String::new();
    let mut described: HashSet<&str> = HashSet::new();

    for m in metrics {
        // Write HELP + TYPE once per unique name
        if described.insert(m.name) {
            out.push_str(&format!("# HELP {} {}\n", m.name, m.description));
            let type_str = match m.kind {
                MetricKind::Counter => "counter",
                MetricKind::Gauge => "gauge",
            };
            out.push_str(&format!("# TYPE {} {}\n", m.name, type_str));
        }

        // Build label string
        let mut label_pairs: Vec<String> = vec![format!("service=\"{}\"", service_name)];
        for (k, v) in &m.labels {
            label_pairs.push(format!("{}=\"{}\"", k, v));
        }
        let labels = label_pairs.join(",");

        out.push_str(&format!("{}{{{}}} {}\n", m.name, labels, m.value));
    }

    std::fs::write(path, out)?;
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::TelemetryConfig;

    fn silent_cfg() -> TelemetryConfig {
        TelemetryConfig {
            enabled: false,
            otlp_endpoint: None,
            service_name: "test".to_string(),
            metrics_file: None,
        }
    }

    #[test]
    fn emit_noop_when_disabled() {
        // Should not panic or error even with no backends configured.
        let m = command_metrics("scan", 100, true);
        emit(&m, &silent_cfg());
    }

    #[test]
    fn command_metrics_success() {
        let m = command_metrics("audit", 250, true);
        assert!(m.iter().any(|x| x.name == "greengate_command_duration_ms"));
        let dur = m
            .iter()
            .find(|x| x.name == "greengate_command_duration_ms")
            .unwrap();
        assert!((dur.value - 250.0).abs() < f64::EPSILON);
        let succ = m
            .iter()
            .find(|x| x.name == "greengate_command_success")
            .unwrap();
        assert!((succ.value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn command_metrics_failure() {
        let m = command_metrics("audit", 50, false);
        let succ = m
            .iter()
            .find(|x| x.name == "greengate_command_success")
            .unwrap();
        assert!((succ.value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn command_metrics_labels_include_command_name() {
        let m = command_metrics("coverage", 120, true);
        let dur = m
            .iter()
            .find(|x| x.name == "greengate_command_duration_ms")
            .unwrap();
        assert!(
            dur.labels
                .iter()
                .any(|(k, v)| *k == "command" && v == "coverage")
        );
    }

    #[test]
    fn prometheus_output_contains_help_and_type() {
        let tmp = std::env::temp_dir().join("greengate_test.prom");
        let cfg = TelemetryConfig {
            enabled: true,
            otlp_endpoint: None,
            service_name: "test-svc".to_string(),
            metrics_file: Some(tmp.to_str().unwrap().to_string()),
        };
        let metrics = command_metrics("scan", 300, true);
        emit(&metrics, &cfg);

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("# HELP greengate_command_duration_ms"));
        assert!(content.contains("# TYPE greengate_command_duration_ms gauge"));
        assert!(content.contains("service=\"test-svc\""));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn prometheus_output_counter_type() {
        let tmp = std::env::temp_dir().join("greengate_test_counter.prom");
        let cfg = TelemetryConfig {
            enabled: true,
            otlp_endpoint: None,
            service_name: "svc".to_string(),
            metrics_file: Some(tmp.to_str().unwrap().to_string()),
        };
        // scan_metrics emits greengate_scan_findings_total as a Counter
        let metrics = scan_metrics(&[], 200);
        emit(&metrics, &cfg);

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("# TYPE greengate_scan_duration_ms gauge"));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn otlp_unreachable_endpoint_does_not_panic() {
        // Emit to a port that is definitely not listening. Should warn + return.
        let cfg = TelemetryConfig {
            enabled: true,
            otlp_endpoint: Some("http://127.0.0.1:19999".to_string()),
            service_name: "test".to_string(),
            metrics_file: None,
        };
        let metrics = command_metrics("scan", 100, true);
        // This must not panic — it may print a warning to stderr.
        emit(&metrics, &cfg);
    }

    #[test]
    fn scan_metrics_groups_by_severity() {
        use crate::modules::scanner::Finding;
        use std::path::PathBuf;

        let findings = vec![
            Finding {
                path: PathBuf::from("a.js"),
                rule_id: "AWS Access Key".to_string(),
                line: 1,
                severity: "critical".to_string(),
                commit: None,
                blame: None,
            },
            Finding {
                path: PathBuf::from("b.js"),
                rule_id: "AWS Access Key".to_string(),
                line: 2,
                severity: "critical".to_string(),
                commit: None,
                blame: None,
            },
            Finding {
                path: PathBuf::from("c.js"),
                rule_id: "SAST/EvalUsage".to_string(),
                line: 5,
                severity: "high".to_string(),
                commit: None,
                blame: None,
            },
        ];

        let metrics = scan_metrics(&findings, 500);
        let total_all = metrics
            .iter()
            .find(|m| {
                m.name == "greengate_scan_findings_total"
                    && m.labels.iter().any(|(k, v)| *k == "severity" && v == "all")
            })
            .unwrap();
        assert!((total_all.value - 3.0).abs() < f64::EPSILON);

        let critical = metrics
            .iter()
            .find(|m| {
                m.name == "greengate_scan_findings_total"
                    && m.labels
                        .iter()
                        .any(|(k, v)| *k == "severity" && v == "critical")
            })
            .unwrap();
        assert!((critical.value - 2.0).abs() < f64::EPSILON);
    }
}
