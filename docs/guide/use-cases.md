---
title: 'Use Cases — GreenGate DevOps Security CLI'
description: 'Real-world GreenGate use cases: stopping npm supply chain attacks, secret leak prevention, Kubernetes security gates, test impact analysis in CI, and full DevOps security pipelines.'
---

# Use Cases & Scenarios

Real-world examples of how greengate fits into different team workflows.

---

## 1. Supply-chain attack defence — protecting npm installs

> **Context:** In early 2025, attackers targeting the axios npm ecosystem demonstrated the "phantom dropper" attack pattern: a malicious `postinstall` script downloads a binary, executes it to exfiltrate secrets or install persistence, then deletes the binary before `npm install` finishes. The installed `node_modules/` looks identical to a clean install. Lock-file diffing and CVE scanners cannot detect it because no known vulnerability is involved — just a malicious script that leaves no trace.

**What `greengate watch-install` catches:**

GreenGate monitors `node_modules/` every 250 ms while the package manager runs. Any file that is created and then deleted within the install window is flagged as a `PHANTOM`. The install is halted before the CI pipeline continues.

**Drop-in replacement for `npm ci`:**

```yaml
- name: Install GreenGate
  run: |
    curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Supply-chain safe install
  run: greengate watch-install npm ci
```

**With config for native build tools** (esbuild, prisma, swc legitimately create temp files):

```toml
# .greengate.toml
[supply_chain]
block_phantom_scripts = true
enforce_sandbox       = true
allow_postinstall     = ["esbuild", "prisma", "@swc/core"]
```

**Layered with `greengate audit`** for defence in depth:

```yaml
- run: greengate watch-install npm ci   # catches runtime dropper behaviour
- run: greengate audit                  # catches known CVEs in your lock file
```

| Layer | What it catches |
|---|---|
| `watch-install` | Postinstall scripts that write+execute+delete a binary |
| `watch-install` | New executables dropped in the project root |
| `audit` | Packages with known CVEs in the OSV database |

Neither replaces the other. A compromised package can be zero-day (not in OSV yet) but still exhibit dropper behaviour on the filesystem.

**What it does not catch:** Pure network exfiltration with no file written to disk. For that, combine with outbound network egress controls in your CI runner.

---

## 2. Preventing secrets from being committed

**Situation:** A developer accidentally hardcodes an API key and pushes it. You want to catch this before it ever reaches the remote.

**Two-layer approach — local + CI:**

```bash
# Layer 1: catch it locally before git push
greengate install-hooks
```

This installs a pre-commit hook that scans staged files on every `git commit`. It fails the commit if a secret is detected.

```yaml
# Layer 2: catch it in CI as a safety net
- name: Secret scan
  run: greengate scan
```

**What it catches:** AWS keys, Stripe secrets, GitHub tokens, GCP service account JSON, `.env` values, high-entropy strings — 26 built-in patterns.

---

## 3. Kubernetes team — manifest quality gate

**Situation:** Your team ships microservices with Kubernetes manifests. You want to block deployments that are missing resource limits, health probes, or use the `latest` image tag.

```yaml
- name: Lint Kubernetes manifests
  run: greengate lint --dir ./k8s
```

**With `.greengate.toml`:**

```toml
[lint]
target_dir = "./k8s"
```

```bash
greengate lint   # reads config automatically
```

**What it catches:** Missing `resources.limits`, missing `livenessProbe`/`readinessProbe`, `image: nginx:latest` (unpinned), containers running as root.

---

## 4. Full security pipeline — Next.js / React app

**Situation:** You run a React frontend with a Node.js backend. You want secrets, SAST, dependency CVEs, and coverage all gated in one pipeline.

```yaml
- name: Secret & SAST scan
  run: greengate scan --annotate   # annotates PRs via GitHub Check Runs

- name: Dependency audit (OSV)
  run: greengate audit             # checks Cargo.lock / package-lock.json

- name: Coverage gate
  run: greengate coverage --file coverage/lcov.info --min 80
```

**What it catches across the pipeline:**

| Step | Catches |
|---|---|
| `scan` | Hardcoded secrets, XSS, `eval()`, command injection in JS/TS |
| `audit` | Known CVEs in npm/Cargo dependencies |
| `coverage` | Test coverage silently dropping below threshold |

---

## 5. Solo developer — minimal setup

**Situation:** You're shipping solo, no staging environment. You want the basics without overhead.

**`.greengate.toml`:**
```toml
[scan]
entropy = true
entropy_threshold = 4.5

[coverage]
file = "coverage/lcov.info"
min = 70.0
```

**GitHub Actions:**
```yaml
- name: Install greengate
  run: |
    curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Scan
  run: greengate scan

- name: Audit
  run: greengate audit

- name: Coverage
  run: greengate coverage
```

**Locally:**
```bash
greengate install-hooks   # catch secrets before they leave your machine
```

---

## 6. Engineering team — PR review intelligence gate

**Situation:** PRs are going out with untested new code and no consistent estimate of review effort. You want instant feedback on every PR: exactly which newly added lines lack test coverage, and an estimated review time so reviewers can plan their load.

**What `greengate review` outputs:**
- **Complexity Score** — estimated review time based on lines added/removed, files touched, and cyclomatic complexity of added code
- **New-code coverage gaps** — cross-references the diff against your LCOV report and pinpoints exactly which added lines are not covered

```yaml
- name: Install greengate
  run: |
    curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

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
```

**Example output:**
```
╔══ PR Review ════════════════════════════════╗
  Complexity Score : 47  (Normal Review ~23 min)
  Files changed    : 5
  Lines added/del  : +120 / -34
  Cyclomatic nodes : 18
╚═════════════════════════════════════════════╝

New-Code Coverage: 73.3%  ✗ (target: 80%)

  src/engine.rs      12/15 added lines covered  (80.0%) ✓
  src/scanner.rs      6/11 added lines covered  (54.5%) ✗
    Uncovered lines: 88, 89, 92, 95, 101
```

With `--annotate`, results are posted as GitHub Check Run annotations directly on the diff lines and a summary comment is added to the PR.

**Without a coverage file:** `greengate review` still outputs the Complexity Score and exits 0 — useful when you just want review-time estimates without a coverage gate.

**`.greengate.toml` config:**
```toml
[review]
min_new_code_coverage = 80   # fail if new-code coverage drops below this
complexity_budget = 0         # 0 = warn only; >0 = fail when score exceeds budget
```

**What it catches:**

| | |
|---|---|
| New code with no tests | Exact uncovered line numbers in the diff |
| PR too large to review safely | Complexity Score > 100 → "Large PR — consider splitting" |
| Reviewer overload | Estimated review time in the PR comment |
