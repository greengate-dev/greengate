//! The outcome of a gate, in one shape for every command.
//!
//! A gate has four possible results, and a security gate must keep them apart:
//! it passed, it found something, it could not check everything, or it broke.
//! Folding "could not check" into "passed" is how a network blip turns into a
//! green build, so `Incomplete` is a first-class status with its own exit code.
//!
//! Commands build a [`Report`] instead of deciding exit codes themselves;
//! `main` turns the report's [`Status`] into the process exit code.

use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;

/// Version tag of the JSON report layout. Bump on any breaking change to it.
pub const SCHEMA: &str = "greengate.report/v1";

/// Overall result of a gate, ordered by precedence: when a run produced
/// several, the greatest one is reported.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Everything was checked and nothing violates policy.
    Passed,
    /// Some checks could not run; nothing that did run found a problem.
    Incomplete,
    /// greengate or a tool it wraps failed.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed as commands move onto Report")
    )]
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

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Serialize, Debug, Clone)]
pub struct Check {
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Check {
    pub fn passed(id: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Passed,
            reason: None,
        }
    }

    pub fn incomplete(id: impl Into<String>, reason: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Incomplete,
            reason: Some(reason.into()),
        }
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used as commands move onto Report")
    )]
    pub fn error(id: impl Into<String>, reason: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            status: Status::Error,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed as file-based gates move onto Report")
    )]
    File {
        path: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        line: Option<usize>,
    },
    Package {
        ecosystem: String,
        name: String,
        version: String,
        /// The dependency file the package was read from.
        source: PathBuf,
    },
}

#[derive(Serialize, Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub location: Location,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug)]
pub struct Report {
    pub command: &'static str,
    pub checks: Vec<Check>,
    pub findings: Vec<Finding>,
    /// Findings matched by a suppression; reported, never counted.
    pub suppressed: Vec<Finding>,
}

impl Report {
    pub fn new(command: &'static str) -> Report {
        Report {
            command,
            checks: Vec::new(),
            findings: Vec::new(),
            suppressed: Vec::new(),
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
        match (self.status(), on_incomplete) {
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
            "suppressed": self.suppressed,
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
    fn severity_parses_advisory_vocabulary() {
        assert_eq!(Severity::parse("moderate"), Severity::Medium);
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse(""), Severity::Unknown);
    }
}
