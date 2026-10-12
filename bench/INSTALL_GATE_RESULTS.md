# greengate install gate — benchmark results

_Generated 2026-10-12 15:25 UTC · greengate 0.4.0 · 15 scenarios · 3 trial(s) per scenario and mode._

> `greengate install` driving real npm, pip and cargo against a local fixture registry. Payloads are inert but observable (a canary in $HOME, a request to the fixture server, a change to another package, a .pth left in site-packages); outcomes are judged by whether that effect happened. No internet access; no real malware.

## `--isolate bwrap`

| Measure | Result |
|---|---:|
| Attacks stopped before the payload could run (preflight) | 9 / 24 |
| Attacks without effect after fetch or a sandboxed run (prevented) | 15 / 24 |
| Attacks that had their effect but failed the install | 0 / 24 |
| Attacks missed | 0 / 24 |
| **Attack effects prevented** | **100%** |
| Benign installs permitted and working | 21 / 21 |
| Benign installs blocked (false blocks) | 0 / 21 |
| Benign installs passed but broken | 0 / 21 |
| Errors / skipped | 0 / 0 |

Added wall time over the same install without greengate (benign scenarios): median 0.3 s, max 0.9 s.

## `--isolate none`

| Measure | Result |
|---|---:|
| Attacks stopped before the payload could run (preflight) | 9 / 24 |
| Attacks without effect after fetch or a sandboxed run (prevented) | 9 / 24 |
| Attacks that had their effect but failed the install | 3 / 24 |
| Attacks missed | 3 / 24 |
| **Attack effects prevented** | **75%** |
| Benign installs permitted and working | 21 / 21 |
| Benign installs blocked (false blocks) | 0 / 21 |
| Benign installs passed but broken | 0 / 21 |
| Errors / skipped | 0 / 0 |

Added wall time over the same install without greengate (benign scenarios): median 0.3 s, max 1.0 s.

## Registry metadata and OSV unreachable

Every scenario again (`--isolate bwrap` when available), with release metadata and OSV pointed at a closed port. Acceptable results are *incomplete* (exit 3) or *blocked*; a pass would mean unchecked packages went in.

| Result | Trials |
|---|---:|
| incomplete | 10 |
| nothing to look up | 5 |

Of the 10 trial(s) that needed metadata, **0 passed unchecked** (10 incomplete, 0 blocked). Installs of an unchanged lockfile (`npm ci`) look nothing up: release checks cover what an install adds or changes.

## Scenarios

| Scenario | Ground truth | `bwrap` | `none` | Description |
|---|---|---|---|---|
| `npm-transitive-postinstall` | malicious | prevented 3/3 | prevented 3/3 (`INSTALL/SuspiciousScript`) | `npm ci`: a transitive dependency's postinstall steals $HOME and phones home; nothing is named on the command line |
| `npm-new-install-script` | malicious | preflight 3/3 (`RELEASE/NewInstallScript`) | preflight 3/3 (`RELEASE/NewInstallScript`) | An established package's new version adds a postinstall the previous one did not have |
| `npm-provenance-regression` | malicious | preflight 3/3 (`RELEASE/ProvenanceRegression`) | preflight 3/3 (`RELEASE/ProvenanceRegression`) | A new version without the publish provenance every earlier one had, carrying a payload |
| `npm-tamper-other-package` | malicious | prevented 3/3 | after 3/3 (`INSTALL/ForeignWrite`) | A postinstall rewrites another package's index.js |
| `npm-dependency-confusion` | malicious | preflight 3/3 (`REGISTRY/DependencyConfusion`) | preflight 3/3 (`REGISTRY/DependencyConfusion`) | A private-scope package (@acme/*) resolves from the public registry |
| `pip-pth-wheel` | malicious | prevented 3/3 (`INSTALL/StartupCode`) | prevented 3/3 (`INSTALL/StartupCode`) | A wheel ships an executable .pth file that runs at every Python start |
| `pip-sdist-backend` | malicious | prevented 3/3 | missed 3/3 | An sdist whose build backend steals $HOME and phones home while pip resolves it |
| `cargo-build-rs` | malicious | prevented 3/3 (`INSTALL/SuspiciousBuildScript`) | prevented 3/3 (`INSTALL/SuspiciousBuildScript`) | A crate whose build.rs shells out to download and run a payload |
| `npm-prebuilt-download` | benign | permitted 3/3 | permitted 3/3 | A postinstall downloads a prebuilt binary (esbuild-style), allowlisted via script_network |
| `npm-native-build` | benign | permitted 3/3 | permitted 3/3 | A postinstall compiles and runs a C helper with cc (node-gyp-style native build) |
| `npm-plain` | benign | permitted 3/3 | permitted 3/3 | A package with no install scripts |
| `pip-native-wheel` | benign | permitted 3/3 | permitted 3/3 | A wheel with a cc-compiled native library (loaded with ctypes) |
| `pip-sdist` | benign | permitted 3/3 | permitted 3/3 | An sdist with an ordinary in-tree build backend |
| `pip-setuptools-pth` | benign | permitted 3/3 | permitted 3/3 | A wheel shipping setuptools' distutils-precedence.pth startup file |
| `cargo-cc-build` | benign | permitted 3/3 | permitted 3/3 | A crate whose build.rs compiles C with the cc crate |

## Reproduction and limits

- `python3 bench/install/gate.py --greengate-bin target/release/greengate` (needs npm, python3 with venv, cargo, and optionally bwrap and cc).
- The fixture registry, wheelhouse and crates are built per run in `gate.py`; the `cc` and `shlex` crates come from the local cargo cache.
- The name guard (`slopsquat_check`) is off: it needs the public npm downloads API.
- `npm-prebuilt-download` uses the documented allowlists (`allow_postinstall`, `script_network`), as a real esbuild-style package would.
- These are a dozen curated scenarios, not a measure of real-world attack prevalence.

- Environment: Linux-7.2.8-200.fc44.x86_64-x86_64-with-glibc2.43; Python 3.14.7; binary SHA-256 `ad37ddc7f85e09c07b99cfe4400afe89430cc8c6d232b123e8b5fbaef836c116`.
