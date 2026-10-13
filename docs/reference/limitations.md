---
title: 'Limitations and protection boundaries'
description: 'Supported analysis, install-isolation boundaries, and checks that greengate 0.4.0 does not perform.'
---

# Limitations

greengate combines dependency policy, install-time controls, and static repository checks. A clean report means the checks that ran found no blocking issue; it does not prove that a dependency or application is safe.

## Install protection

| Boundary | Current behavior |
|---|---|
| OS isolation | Linux with working bubblewrap only. The default `auto` mode can fall back to unisolated execution; require isolation explicitly when needed. |
| Python planning | pip and uv may execute source-build backends to read metadata, including under `--plan`. `require_isolation = true` refuses these phases without isolation. |
| JavaScript network access | Dependency scripts run without networking under bubblewrap unless allowlisted in `script_network`. Resolution and fetching still need network access or manager caches. |
| Python network access | Metadata resolution and source builds use network access for build requirements, even when isolated. |
| Project code | JavaScript root lifecycle scripts and uv's final project installation run normally. They are outside dependency-script isolation. |
| pnpm and Yarn Berry | Manager bookkeeping needs project writes; root changes are checked afterward. Berry builds share a sandbox and are not isolated from one another. |
| Cargo | New build scripts and proc-macro sources are inspected when adding or updating dependencies. Later compilation runs outside this gate. |
| Credential files | Known names are masked, including nested and linked directories. Dependency/build trees and virtual environments are excluded from discovery; a directory limit can leave files unmasked, with a warning. Arbitrary secret-bearing files are not discovered automatically. |
| Unisolated execution | Environment reduction and filesystem monitoring do not prevent reads, networking, or all harmful side effects. Suspicious scripts may be held back; allowlists waive selected checks. |

`--plan` avoids applying the requested install, but its depth varies: JavaScript plans inspect fetched packages, Cargo plans inspect fetched sources, and uv plans stop before syncing or inspecting installed startup files. Package-manager caches can change.

Script inspection uses static signals and bounded helper traversal. pip reads Python helpers shipped in the same wheel; uv reads the `.pth` file's site-packages directory. Dynamic imports, native extensions, and every possible encoded payload are not covered.

The install gate checks advisory and release risk for packages added or changed. An unchanged `npm ci` lockfile does not trigger a full advisory re-audit. Use [`audit`](/commands/audit) for supported registry dependencies and [`deps review`](/commands/deps) for changes.

The name guard scores explicitly requested names using registry metadata. It does not score the full transitive tree or establish malicious intent. Agent checks recognize supported shell command shapes; installs hidden behind arbitrary scripts, aliases, or Makefile targets are not discovered. `npx`, `bunx`, and `pnpm dlx` are not intercepted.

See the [install reference](/commands/install) and the [install-gate benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_GATE_RESULTS.md) for tested scenarios.

## Legacy compatibility paths

Supported `watch-install`, `pip-install`, and `cargo-add` invocations route through `install` in 0.4.0. Unsupported routing cases retain older behavior with a deprecation notice. The legacy watcher uses polling and post-install checks, does not isolate the process, and can miss temporary files between observations. The [legacy benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_RESULTS.md) measures that older path.

## Static analysis

| Language | AST rules | Taint tracking | Code-smell rules |
|---|---|---|---|
| JavaScript / TypeScript | Yes | Within the current file/function analysis | Yes |
| Python | Yes | No | No |
| Go | Yes | No | No |
| Rust | Yes | No | No |
| Ruby, PHP, Java, C# | No | No | No |

JavaScript and TypeScript taint tracking recognizes selected source and sanitizer names. It does not follow arbitrary function calls, cross-file flows, TypeScript types, or every control-flow path. A tainted label is a signal for review, not a demonstrated exploit; name-based sanitizer recognition can suppress unsafe code as well as valid code.

Python, Go, and Rust rules match syntax and API names. Rust `unsafe`, `Command::new`, `.unwrap()`, and `.expect()` findings are review signals, not proof of a vulnerability. Comments and source strings are handled differently by AST rules and regex scanning; false positives and false negatives remain possible.

Custom rules cannot add full inter-procedural analysis. Use deeper analysis or runtime testing when the risk requires it.

## Secret scanning

Regex and entropy checks cannot recognize every credential or determine whether a matched value is active. Known example keys and common entropy noise are filtered, but new secret formats and unusual file layouts can be missed.

With SAST enabled, supported source files use string-literal scoping for secret checks. Other text files use regex and entropy scanning. Git ignores and configured exclusions affect coverage; binary files are skipped. History scanning does not read uncommitted credentials from past commits.

## Dependency audits and reviews

Audits match supported registry package names and versions against OSV. Git, URL, and local-path dependencies are not matched as registry releases. Maven, .NET/NuGet, Ruby, `Pipfile.lock`, and binary `bun.lockb` are unsupported; unresolved requirements can make the run incomplete.

OSV availability, supported version ordering, cache freshness, and registry metadata limit the result. Missing data is reported as incomplete where tracked. With `on_incomplete = "warn"` or `--allow-incomplete`, an incomplete report can exit `0`. Private registry releases do not receive the public-registry release checks.

License checks use registry metadata, not a legal review of package contents. Signing a CycloneDX SBOM proves file integrity and the verified signer identity; it does not certify build provenance or regulatory compliance.

## Test selection and coverage

TIA compares tests' direct static imports with changed source-path stems. It does not build a transitive graph, resolve all workspace aliases, or prove that unselected tests are unaffected. Config/data changes produce warnings rather than test selection. Go output is a list of test files, not `go test` package arguments.

`review` counts only changed lines present in the supplied coverage report. Missing files and unmeasured lines are excluded from the percentage. Generate coverage for the code you want to gate. Review-time estimates are scoring heuristics.

## Other boundaries

- `image-scan` scans text files from local Docker image layers, not image configuration metadata or running containers. Pull images before scanning. Binary and oversized files are skipped.
- Kubernetes and Dockerfile linting inspect supported syntax and rules; they do not validate all deployment behavior.
- Authorship reporting uses commit metadata and author identity; it cannot reliably attribute every AI-assisted change.
- Static checks do not replace dynamic application testing, fuzzing, or runtime access controls.
