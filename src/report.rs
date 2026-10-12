//! The outcome of a gate, in one shape for every command.
//!
//! A gate has four possible results, and a security gate must keep them apart:
//! it passed, it found something, it could not check everything, or it broke.
//! Folding "could not check" into "passed" is how a network blip turns into a
//! green build, so `Incomplete` is a first-class status with its own exit code.
//!
//! Commands build a [`Report`] instead of deciding exit codes themselves;
//! `main` turns the report's [`Status`] into the process exit code.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Version tag of the JSON report layout. Bump on any breaking change to it.
pub const SCHEMA: &str = "greengate.report/v1";

/// Overall result of a gate, ordered by precedence: when a run produced
/// several, the greatest one is reported.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Everything was checked and nothing violates policy.
    Passed,
    /// Some checks could not run; nothing that did run found a problem.
    Incomplete,
    /// greengate or a tool it wraps failed.
    Error,
    /// Policy was violated. Outranks the rest: it is definite and actionable.
    Findings,
}

impl Status {
    /// Process exit code. `1` keeps its pre-0.4 meaning so existing CI keeps
    /// failing on findings; `2` is left to clap for usage errors.
    pub fn exit_code(self) -> u8 {
        match self {
            Status::Passed => 0,
            Status::Findings => 1,
            Status::Incomplete => 3,
            Status::Error => 4,
        }
    }
}

/// What to do when a gate is [`Status::Incomplete`] (`[policy] on_incomplete`).
#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnIncomplete {
    /// Exit 3 — an unchecked dependency is not a safe dependency.
    #[default]
    Fail,
    /// Exit 0, but still say "incomplete" in every output.
    Warn,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Map the free-text severities used by advisory databases.
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

/// One unit of verification — a lockfile read, a database query — and
/// whether it actually ran.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Check {
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Where the data behind the check came from, and how fresh it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Check {
    pub fn with_source(mut self, source: impl Into<String>) -> Check {
        self.source = Some(source.into());
        self
    }

    pub fn passed(id: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Passed,
            reason: None,
            source: None,
        }
    }

    pub fn incomplete(id: impl Into<String>, reason: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Incomplete,
            reason: Some(reason.into()),
            source: None,
        }
    }

    pub fn error(id: impl Into<String>, reason: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Error,
            reason: Some(reason.into()),
            source: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    File {
        path: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        line: Option<usize>,
    },
    /// A deployed page, e.g. a Lighthouse audit target.
    Url { url: String },
    /// The change or repository as a whole (a complexity budget, an
    /// authorship ceiling) rather than any one file.
    Project,
    Package {
        ecosystem: String,
        name: String,
        /// Unknown for a package named on a command line, before resolution.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        /// The dependency file the package was read from, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<PathBuf>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub location: Location,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Why the finding is in `suppressed`. Set only there, or on a finding
    /// whose exception expired (`kind: exception`, `expired: true`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<Suppression>,
    /// `gg1:` fingerprint, keyed with the baseline's salt, for exceptions
    /// that name one finding. Absent when there is no baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// What suppressed a finding.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    /// A `greengate: ignore` comment in the source.
    Inline,
    /// An entry in `.greengate/exceptions.toml`.
    Exception,
    /// Present in the baseline, or already at the `--new-since` base.
    Baseline,
    /// `[audit] ignore_advisories` (deprecated).
    Config,
    /// Auto-suppressed by `scan --triage`.
    Triage,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Suppression {
    pub kind: SuppressionKind,
    /// The exception id, or the baseline entry's original location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// The exception has expired, so the finding counts again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
}

impl Suppression {
    pub fn new(kind: SuppressionKind, reason: Option<String>) -> Suppression {
        Suppression {
            kind,
            id: None,
            reason,
            owner: None,
            expires: None,
            expired: false,
        }
    }
}

impl Finding {
    /// A finding located in a source file. `line` 0 means the whole file.
    pub fn in_file(
        rule: impl Into<String>,
        severity: Severity,
        path: impl Into<PathBuf>,
        line: usize,
        message: impl Into<String>,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            severity,
            location: Location::File {
                path: path.into(),
                line: (line > 0).then_some(line),
            },
            message: message.into(),
            remediation: None,
            reference: None,
            suppression: None,
            fingerprint: None,
        }
    }
}

impl Finding {
    /// A finding about the change or repository as a whole.
    pub fn project(
        rule: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            severity,
            location: Location::Project,
            message: message.into(),
            remediation: None,
            reference: None,
            suppression: None,
            fingerprint: None,
        }
    }
}

impl Finding {
    /// A finding about a package, as named by `name` in `ecosystem`.
    pub fn package(
        rule: impl Into<String>,
        severity: Severity,
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        message: impl Into<String>,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            severity,
            location: Location::Package {
                ecosystem: ecosystem.into(),
                name: name.into(),
                version: None,
                source: None,
            },
            message: message.into(),
            remediation: None,
            reference: None,
            suppression: None,
            fingerprint: None,
        }
    }
}

impl From<crate::modules::scanner::Severity> for Severity {
    fn from(s: crate::modules::scanner::Severity) -> Severity {
        use crate::modules::scanner::Severity as S;
        match s {
            S::Low => Severity::Low,
            S::Medium => Severity::Medium,
            S::High => Severity::High,
            S::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug)]
pub struct Report {
    pub command: &'static str,
    pub checks: Vec<Check>,
    pub findings: Vec<Finding>,
    /// Findings matched by a suppression; reported, never counted.
    pub suppressed: Vec<Finding>,
    /// Below the blocking threshold (or allowlisted): always shown, never
    /// counted toward the status.
    pub warnings: Vec<Finding>,
    /// `--no-fail`: findings are reported (status stays `findings`) but do
    /// not fail the exit code. Incomplete and error results still do.
    pub no_fail: bool,
}

impl Report {
    pub fn new(command: &'static str) -> Report {
        Report {
            command,
            checks: Vec::new(),
            findings: Vec::new(),
            suppressed: Vec::new(),
            warnings: Vec::new(),
            no_fail: false,
        }
    }

    pub fn status(&self) -> Status {
        let checks = self.checks.iter().map(|c| c.status).max();
        if self.findings.is_empty() {
            checks.unwrap_or(Status::Passed)
        } else {
            Status::Findings
        }
    }

    /// Checks that did not run to completion.
    pub fn unfinished(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| c.status != Status::Passed)
    }

    /// The exit code for this report under `on_incomplete`.
    pub fn exit_code(&self, on_incomplete: OnIncomplete) -> u8 {
        let status = match self.status() {
            // With findings waived, what is left decides the exit code.
            Status::Findings if self.no_fail => self
                .checks
                .iter()
                .map(|c| c.status)
                .max()
                .unwrap_or(Status::Passed),
            status => status,
        };
        match (status, on_incomplete) {
            (Status::Incomplete, OnIncomplete::Warn) => 0,
            (status, _) => status.exit_code(),
        }
    }

    pub fn to_json(&self, duration_ms: u128) -> Value {
        json!({
            "schema": SCHEMA,
            "tool": { "name": "greengate", "version": env!("CARGO_PKG_VERSION") },
            "command": self.command,
            "status": self.status(),
            "duration_ms": duration_ms,
            "checks": self.checks,
            "findings": self.findings,
            "warnings": self.warnings,
            "suppressed": self.suppressed,
        })
    }

    /// The report as SARIF 2.1.0, for code-scanning uploads. Checks that did
    /// not finish become tool-execution notifications and mark the run as not
    /// successful, so a partial scan is never presented as a clean one.
    pub fn to_sarif(&self) -> Value {
        let mut rule_ids: Vec<&str> = self.findings.iter().map(|f| f.rule.as_str()).collect();
        rule_ids.sort_unstable();
        rule_ids.dedup();
        let rules: Vec<Value> = rule_ids
            .iter()
            .map(|id| {
                json!({
                    "id": id,
                    "shortDescription": { "text": id },
                    "helpUri": "https://github.com/greengate-dev/greengate"
                })
            })
            .collect();

        let results: Vec<Value> = self.findings.iter().map(sarif_result).collect();
        let notifications: Vec<Value> = self
            .unfinished()
            .map(|c| {
                json!({
                    "level": if c.status == Status::Error { "error" } else { "warning" },
                    "descriptor": { "id": c.id },
                    "message": {
                        "text": format!(
                            "{}: {}",
                            c.id,
                            c.reason.as_deref().unwrap_or("did not complete")
                        )
                    }
                })
            })
            .collect();

        json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "greengate",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/greengate-dev/greengate",
                        "rules": rules
                    }
                },
                "automationDetails": { "id": format!("greengate/{}/", self.command) },
                "invocations": [{
                    "executionSuccessful": notifications.is_empty(),
                    "toolExecutionNotifications": notifications
                }],
                "results": results
            }]
        })
    }

    /// Text summary of checks that did not finish, so "incomplete" is never
    /// mistaken for a pass in human-readable output either.
    pub fn print_unfinished(&self) {
        let unfinished: Vec<&Check> = self.unfinished().collect();
        if unfinished.is_empty() {
            return;
        }
        eprintln!();
        eprintln!(
            "⚠️  {}: {} check(s) did not complete — this is not a pass:",
            self.command,
            unfinished.len()
        );
        for c in unfinished {
            eprintln!(
                "  [{}] {} — {}",
                match c.status {
                    Status::Error => "ERROR",
                    _ => "INCOMPLETE",
                },
                c.id,
                c.reason.as_deref().unwrap_or("no reason recorded")
            );
        }
    }
}

fn sarif_result(f: &Finding) -> Value {
    let level = match f.severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    };
    // SARIF locations are files; other findings point at the file that best
    // explains them, or carry their subject in the message.
    let file = match &f.location {
        Location::File { path, line } => Some((path.as_path(), *line)),
        Location::Package {
            source: Some(source),
            ..
        } => Some((source.as_path(), None)),
        _ => None,
    };
    let subject = match &f.location {
        Location::Package { name, version, .. } => match version {
            Some(v) => format!("{name}@{v}: "),
            None => format!("{name}: "),
        },
        Location::Url { url } => format!("{url}: "),
        _ => String::new(),
    };
    let mut text = format!("{subject}{}", f.message);
    if let Some(fix) = &f.remediation {
        text.push_str(&format!(" — {fix}"));
    }
    let mut result = json!({
        "ruleId": f.rule,
        "level": level,
        "message": { "text": text },
    });
    if let Some((path, line)) = file {
        let uri = path.to_string_lossy();
        let mut physical = json!({
            "artifactLocation": {
                "uri": uri.strip_prefix("./").unwrap_or(&uri),
                "uriBaseId": "%SRCROOT%"
            }
        });
        if let Some(line) = line {
            physical["region"] = json!({ "startLine": line });
        }
        result["locations"] = json!([{ "physicalLocation": physical }]);
    }
    result
}

/// Output format for commands that emit a [`Report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> Finding {
        Finding {
            rule: "r".into(),
            severity: Severity::High,
            location: Location::File {
                path: "a".into(),
                line: None,
            },
            message: "m".into(),
            remediation: None,
            reference: None,
            suppression: None,
            fingerprint: None,
        }
    }

    #[test]
    fn empty_report_passes() {
        assert_eq!(Report::new("t").status(), Status::Passed);
        assert_eq!(Report::new("t").exit_code(OnIncomplete::Fail), 0);
    }

    #[test]
    fn an_unfinished_check_is_never_a_pass() {
        let mut r = Report::new("t");
        r.checks.push(Check::passed("a"));
        r.checks.push(Check::incomplete("b", "offline"));
        assert_eq!(r.status(), Status::Incomplete);
        assert_eq!(r.exit_code(OnIncomplete::Fail), 3);
        assert_eq!(r.exit_code(OnIncomplete::Warn), 0);
        // `warn` relaxes the exit code only — the status stays honest.
        assert_eq!(r.status(), Status::Incomplete);
    }

    #[test]
    fn precedence_is_findings_then_error_then_incomplete() {
        let mut r = Report::new("t");
        r.checks.push(Check::incomplete("a", "x"));
        r.checks.push(Check::error("b", "y"));
        assert_eq!(r.status(), Status::Error);
        assert_eq!(r.exit_code(OnIncomplete::Warn), 4);
        r.findings.push(finding());
        assert_eq!(r.status(), Status::Findings);
        assert_eq!(r.exit_code(OnIncomplete::Warn), 1);
    }

    #[test]
    fn no_fail_waives_findings_but_not_incomplete() {
        let mut r = Report::new("t");
        r.no_fail = true;
        r.findings.push(finding());
        assert_eq!(r.status(), Status::Findings, "status stays honest");
        assert_eq!(r.exit_code(OnIncomplete::Fail), 0);
        r.checks.push(Check::incomplete("a", "x"));
        assert_eq!(r.exit_code(OnIncomplete::Fail), 3);
    }

    #[test]
    fn suppressed_findings_do_not_fail() {
        let mut r = Report::new("t");
        r.suppressed.push(finding());
        assert_eq!(r.status(), Status::Passed);
    }

    #[test]
    fn json_carries_schema_and_status() {
        let mut r = Report::new("audit");
        r.checks.push(Check::incomplete("osv", "unreachable"));
        let v = r.to_json(5);
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["status"], "incomplete");
        assert_eq!(v["checks"][0]["reason"], "unreachable");
    }

    #[test]
    fn sarif_marks_incomplete_runs_unsuccessful() {
        let mut r = Report::new("audit");
        assert_eq!(
            r.to_sarif()["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        r.checks.push(Check::incomplete("osv", "unreachable"));
        r.findings
            .push(Finding::in_file("R1", Severity::High, "./src/a.rs", 3, "m"));
        let sarif = r.to_sarif();
        let run = &sarif["runs"][0];
        assert_eq!(run["invocations"][0]["executionSuccessful"], false);
        assert_eq!(
            run["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"],
            "osv"
        );
        let loc = &run["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/a.rs");
        assert_eq!(loc["region"]["startLine"], 3);
        assert_eq!(run["results"][0]["level"], "error");
    }

    #[test]
    fn json_matches_the_published_schema() {
        // Drift guard for docs/public/schema/report-v1.json: the top-level
        // keys, status values and location kinds the schema promises.
        let schema: Value =
            serde_json::from_str(include_str!("../docs/public/schema/report-v1.json")).unwrap();
        let mut r = Report::new("t");
        r.checks.push(Check::incomplete("c", "x"));
        let doc = r.to_json(0);
        let mut required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let mut actual: Vec<&str> = doc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        required.sort_unstable();
        actual.sort_unstable();
        assert_eq!(required, actual);
        assert_eq!(schema["properties"]["schema"]["const"], SCHEMA);

        let statuses = &schema["$defs"]["status"]["enum"];
        for s in [
            Status::Passed,
            Status::Findings,
            Status::Incomplete,
            Status::Error,
        ] {
            assert!(
                statuses
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::to_value(s).unwrap()),
                "{s:?}"
            );
        }
        let kinds: Vec<&Value> = schema["$defs"]["finding"]["properties"]["location"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| &v["properties"]["kind"]["const"])
            .collect();
        for loc in [
            Location::File {
                path: "a".into(),
                line: None,
            },
            Location::Url { url: "u".into() },
            Location::Project,
            Location::Package {
                ecosystem: "npm".into(),
                name: "n".into(),
                version: None,
                source: None,
            },
        ] {
            let kind = serde_json::to_value(&loc).unwrap()["kind"].clone();
            assert!(kinds.contains(&&kind), "{kind}");
        }
    }

    #[test]
    fn severity_parses_advisory_vocabulary() {
        assert_eq!(Severity::parse("moderate"), Severity::Medium);
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse(""), Severity::Unknown);
    }
}
