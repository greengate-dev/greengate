# Contributing to GreenGate

Thanks for your interest in contributing! GreenGate is a Rust CLI tool — contributions of all kinds are welcome: bug reports, new secret-detection patterns, SAST rules, documentation improvements, and new features.

## Getting Started

### Prerequisites

- Rust 1.85+ (`rustup update stable`)
- Git

### Build

```bash
git clone https://github.com/greengate-dev/greengate
cd greengate
cargo build
```

### Run tests

```bash
cargo test
```

All tests must pass before submitting a pull request.

## How to Contribute

### Reporting bugs

Open an issue at [github.com/greengate-dev/greengate/issues](https://github.com/greengate-dev/greengate/issues) and include:

- greengate version (`greengate --version`)
- OS and architecture
- The command you ran and the full output
- What you expected to happen

### Suggesting new secret patterns

GreenGate's built-in patterns live in `src/scanner.rs`. Each pattern is a named regex. To propose a new one:

1. Add the pattern to the `patterns()` function with a descriptive name (e.g. `"Twilio Auth Token"`)
2. Add a test in `tests/` that exercises the new pattern with both a true-positive and a true-negative fixture
3. Open a PR describing the secret type, the regex, and any false-positive risk

### Suggesting new SAST rules

SAST rules are tree-sitter S-expression queries in `src/sast.rs`. To add a rule:

1. Write and test the query using the [tree-sitter playground](https://tree-sitter.github.io/tree-sitter/playground)
2. Add it to the `rules()` function with a `SAST/<RuleId>` identifier
3. Add a fixture file and test case in `tests/`

### Submitting pull requests

1. Fork the repository and create a branch from `main`
2. Make your changes with clear, focused commits
3. Ensure `cargo test` and `cargo clippy -- -D warnings` both pass
4. Open a pull request against `main` with a clear description of what changed and why

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` and fix all warnings
- Keep unsafe code to zero (the codebase has none)
- Prefer `anyhow::Result` for error propagation at the top level

## Project Layout

```
src/
  main.rs          — CLI entry point (clap)
  scanner.rs       — Secret/PII regex scanner
  sast.rs          — AST-based SAST engine (tree-sitter)
  linter.rs        — Kubernetes manifest linter
  coverage.rs      — LCOV/Cobertura coverage gate
  auditor.rs       — OSV dependency auditor
tests/             — Integration tests
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
