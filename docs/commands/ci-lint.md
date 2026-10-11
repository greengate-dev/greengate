---
title: 'ci-lint — GitHub Actions Security Linting'
description: 'Lint GitHub Actions workflow files for security misconfigurations: unpinned action refs, pull_request_target misuse and expression injection in run steps. Emits SARIF for Code Scanning.'
---

# ci-lint — GitHub Actions Security Linting

Lints GitHub Actions workflow files under `.github/workflows/` for security misconfigurations that can lead to CI pipeline poisoning, secret exfiltration, and privilege escalation.

CI pipeline attacks have become a primary supply chain vector — the [tj-actions/changed-files compromise](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3), the [Codecov bash uploader incident](https://about.codecov.io/security-update/), and the [reviewdog action compromise](https://github.com/reviewdog/action-setup/security/advisories/GHSA-5rjg-fvgr-3xxf) all exploited misconfigurations that `ci-lint` would flag.

## Usage

```bash
greengate ci-lint [OPTIONS]

Options:
      --format <FORMAT>   Output format: text (default), json, sarif
      --file <FILE>       Lint one workflow file instead of .github/workflows/
      --update-baseline   Save current findings as the baseline
      --since-baseline    Only fail on findings not in the saved baseline
  -h, --help              Print help
```

## Examples

```bash
# Lint all .github/workflows/*.yml files
greengate ci-lint

# Output SARIF for GitHub Code Scanning
greengate ci-lint --format sarif > ci-lint.sarif
```

## Rules

### CI/UnpinnedAction — Unpinned action ref (MEDIUM)

Using a mutable tag like `@v4` or `@main` means anyone who can push to that repo can silently change what code runs in your CI.

```yaml
# BAD — mutable tag, can be changed by the action author at any time
- uses: actions/checkout@v4

# GOOD — pinned to an immutable commit SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Fix: pin every `uses:` to a full commit SHA and add a comment showing the version for human readability.

### CI/PullRequestTargetWithCheckout — Dangerous pull_request_target + checkout (CRITICAL)

`pull_request_target` runs with write permissions and access to repository secrets. If you check out PR code in this context, an attacker can send a pull request with a malicious workflow modification and steal your secrets.

```yaml
# BAD — checks out untrusted PR code with write permissions
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

Fix: never check out PR code in a `pull_request_target` workflow. If you need to run tests on PR code, use a separate `pull_request` workflow that has no write permissions or secret access.

### CI/ExpressionInjection — Expression injection in run step (CRITICAL)

GitHub Actions expressions (`${{ ... }}`) are expanded before the shell interprets the `run:` script. Injecting attacker-controlled values like `github.event.pull_request.title` or `github.event.issue.body` directly into a `run:` step allows arbitrary command execution.

```yaml
# BAD — attacker controls github.event.pull_request.title
- run: echo "Processing PR: ${{ github.event.pull_request.title }}"

# GOOD — pass through an intermediate env var (shell safely quotes it)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Processing PR: $PR_TITLE"
```

Flagged expression sources: `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label` and `.base.ref`; `github.event.issue.title` and `.body`; `github.event.comment.body`; `github.event.review.body`; `github.head_ref`; `github.base_ref`.

## Sample output

```
ℹ️  CI lint: scanning 3 workflow file(s)...

  🚨 CI lint: 2 issue(s) found:

  [MEDIUM] [CI/UnpinnedAction] .github/workflows/ci.yml:12
    Action `actions/checkout` is pinned to `v4` (a mutable ref). Pin to a full commit SHA to prevent supply-chain attacks: `actions/checkout@<40-char-sha>`.

  [CRITICAL] [CI/ExpressionInjection] .github/workflows/pr-check.yml:44
    …
```

## CI usage

```yaml
- name: Lint CI workflows
  run: greengate ci-lint

# Upload findings to GitHub Code Scanning
- name: CI lint (SARIF)
  run: greengate ci-lint --format sarif > ci-lint.sarif || true

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ci-lint.sarif
```

## Suppressing findings

Add `# greengate: ignore` on the flagged line, or on its own line directly
above it. A reason is optional and is listed in the report:

```yaml
# greengate: ignore reason="internal action; we control its tags"
- uses: our-org/deploy-action@v2
```

To waive a rule for a limited time, with an owner, add an exception to
`.greengate/exceptions.toml`:

```toml
[[exception]]
id = "EX-4"
match = { rule = "CI/UnpinnedAction", path = ".github/workflows/release.yml" }
reason = "Org-internal action; tags are protected"
owner = "@platform"
expires = "2026-12-31"
```

To accept every finding present today and fail only on new ones, use
`--update-baseline` once and `--since-baseline` in CI. See
[Baselines & Exceptions](/guide/baselines-and-exceptions).
