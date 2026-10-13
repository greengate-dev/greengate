---
title: 'Telemetry and metrics'
description: 'Configure best-effort OTLP HTTP/JSON export and Prometheus text-file output, with per-run metric limitations.'
---

# Telemetry and metrics

greengate can export metrics to an OTLP HTTP/JSON endpoint and write a Prometheus text file. Both are optional. Export failures produce warnings rather than failing the gate.

## Configure export

```toml
[telemetry]
enabled = true
service_name = "my-api"
otlp_endpoint = "http://localhost:4318"
# metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

No data is exported unless an endpoint or file is configured. `enabled = false` disables export. The parent directory for `metrics_file` must exist and be writable.

## OTLP

The exporter posts JSON to `{otlp_endpoint}/v1/metrics`. Use an HTTP receiver, not a gRPC endpoint. A collector can handle authentication and route data to your monitoring backend.

Command metrics are emitted when execution reaches command-result handling. Scan metrics are emitted separately. Configuration failures, argument-parsing failures, and the agent hook do not necessarily emit metrics.

## Prometheus text files

Point `node_exporter --collector.textfile.directory` at the directory containing `metrics_file`. The writer **overwrites** the file on each export; it is not a cumulative record of executions.

In `scan`, the scan-specific export is followed by command-metric export, which overwrites the same file. The final text file can therefore contain only the command metrics. Use OTLP or structured reports when you need scan finding history.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `greengate_scan_findings_total` | counter | Findings in one scan, by severity, plus an `all` total |
| `greengate_scan_duration_ms` | gauge | One scan's elapsed time |
| `greengate_command_duration_ms` | gauge | Elapsed command time, with command and success labels |
| `greengate_command_success` | gauge | `1` for a successful exit, `0` otherwise |

The Prometheus output adds a `service` label. Scan totals are per invocation, not persistent monotonically increasing counts across runs. A counter-rate query is not a reliable finding-rate calculation for these snapshots.

For the most recently exported command:

```text
greengate_command_success == 0
topk(5, greengate_command_duration_ms)
```

A successful exit can include policy-waived incomplete checks or findings. Use the [structured report status](/reference/report-schema) to distinguish those outcomes.
