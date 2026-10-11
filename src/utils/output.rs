/// Output format for the report-style commands: `ci-lint`, `review` and
/// `provenance`. Parsed by clap, so an unknown value is rejected up front
/// instead of quietly falling back to text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Sarif,
}
