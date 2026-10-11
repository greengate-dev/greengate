---
title: 'CI/CD Integration — GreenGate'
description: 'Integrate GreenGate into GitHub Actions, GitLab CI, Bitbucket, and CircleCI. Examples for zero-trust supply chain install, test impact analysis, secret scanning, coverage gates, and PR review.'
---

# CI/CD Integration

## GitHub Actions — Full pipeline

```yaml
name: GreenGate Quality Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload and Check Runs
  checks: write            # required for --annotate (GitHub Check Runs)
  pull-requests: write     # required for --annotate (PR review comment)

jobs:
  greengate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history required for --base diff

      - name: Install GreenGate
        run: |
          curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
            -o /usr/local/bin/greengate
          chmod +x /usr/local/bin/greengate

      # Zero-trust supply chain gate: static script scan + runtime dropper detection
      - name: Zero-trust supply chain install
        run: greengate watch-install npm ci

      - name: Secret, PII & SAST Scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: greengate scan --annotate

      - name: Dependency Audit (OSV)
        run: greengate audit

      # What this PR does to the dependency tree: new advisories with the
      # smallest fix, licenses, release risk — one PR comment, updated in place
      - name: Dependency Review
        if: github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: greengate deps review --annotate

      # Test impact analysis — run only tests affected by this PR's diff
      - name: Test Impact Analysis
        if: github.event_name == 'pull_request'
        run: |
          TESTS=$(greengate tia --base "${{ github.event.pull_request.base.sha }}")
          if [ -n "$TESTS" ]; then
            pytest $TESTS
          else
            echo "No affected tests — skipping"
          fi

      - name: PR Review (Complexity + Coverage Gaps)
        if: github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_SHA: ${{ github.sha }}
        run: |
          greengate review \
            --base "${{ github.event.pull_request.base.sha }}" \
            --coverage-file coverage/lcov.info \
            --min-coverage 80 \
            --annotate
        continue-on-error: true   # informational until coverage is wired in

      - name: Kubernetes Lint
        run: greengate lint --dir ./k8s

      - name: Coverage Gate
        run: greengate coverage --file coverage/lcov.info --min 80
```

## GitHub Actions — SARIF upload (alternative)

If you prefer GitHub Advanced Security inline annotations over `--annotate`:

```yaml
- name: Scan (SARIF)
  run: greengate scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## GitLab CI

```yaml
stages:
  - security
  - quality

.install_greengate: &install_greengate
  before_script:
    - curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64
        -o /usr/local/bin/greengate
    - chmod +x /usr/local/bin/greengate

secret-scan:
  stage: security
  <<: *install_greengate
  script:
    - greengate scan

pr-review:
  stage: quality
  <<: *install_greengate
  only:
    - merge_requests
  script:
    - greengate review
        --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
        --coverage-file coverage/lcov.info
        --min-coverage 80
  allow_failure: true   # informational until coverage is wired in

k8s-lint:
  stage: security
  <<: *install_greengate
  script:
    - greengate lint --dir ./k8s

coverage-gate:
  stage: quality
  <<: *install_greengate
  script:
    - greengate coverage --file coverage/lcov.info --min 80

dependency-audit:
  stage: security
  <<: *install_greengate
  script:
    - greengate audit
```

## Git pre-commit hook

Install greengate as a local pre-commit hook to catch secrets before they ever leave your machine:

```bash
greengate install-hooks
```

This writes a `.git/hooks/pre-commit` script that runs `greengate scan --staged` on every `git commit`.
