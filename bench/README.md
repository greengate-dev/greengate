# greengate benchmarks

Three reproducible suites measure secret detection, the `greengate install`
gate, and the legacy `watch-install` watcher. They publish misses and false
positives as well as successful checks.

The latest runs are in **[RESULTS.md](RESULTS.md)** (secret detection),
**[INSTALL_GATE_RESULTS.md](INSTALL_GATE_RESULTS.md)** (`greengate install`)
and **[INSTALL_RESULTS.md](INSTALL_RESULTS.md)** (`watch-install`). Raw trials,
including output and exit codes, are in the matching `.json` files.

```bash
python3 bench/run.py            # scan, score, write RESULTS.md
python3 bench/run.py --print    # also print the report to stdout
python3 bench/install/gate.py   # greengate install against a local fixture registry
python3 bench/install/run.py    # watch-install scenarios; uses target/release/greengate
```

Both harnesses use the Python 3 standard library. The install suite additionally
requires POSIX process groups/permissions and a C compiler for native scenarios;
missing compilers are reported as skips, never successes. The secret suite
runs with just greengate;
competing tools are included automatically **if they're on your `PATH`**, and
reported as _not installed_ otherwise. Nothing is fabricated.

---

## What this measures (and what it doesn't)

**In scope:** secret-detection **precision and recall** against a labeled
corpus — how many planted secrets a tool catches (recall) and how often it
false-alarms on secret-*looking* strings that aren't secrets (precision).

**Separate suite:** install protection is measured by `install/run.py`, described
below. It is not compared with secret/CVE scanners, whose scope differs. Tools
such as Socket Firewall also offer install-time protections; this suite does
not establish superiority over them. SAST is excluded from the secret scores.

## `greengate install` gate methodology

`install/gate.py` runs the real package managers (npm, pip, cargo) through
`greengate install` against a fixture registry it serves on 127.0.0.1: npm
packuments and tarballs, a PEP 503 simple index, a crates.io sparse index,
PyPI and crates.io metadata, and an OSV stand-in. No internet access is
needed; the `cc` and `shlex` crates come from the local cargo cache.

Attack fixtures carry inert payloads with observable effects: a canary file
in `$HOME`, a request to the fixture server's `/exfil` endpoint, a change to
another package's files, or startup code left in site-packages. A trial is
scored by whether that effect happened, not by greengate's exit code:
*preflight* (stopped at the plan, nothing fetched), *prevented* (no effect
after fetching, or after a sandboxed run), *after* (effect happened, install
failed) or *missed*. Benign fixtures must install **and work**; otherwise they
are *blocked* (a false block) or *broken*. A crash is an error, never a
detection.

Every scenario runs with `--isolate bwrap` (when bubblewrap is available) and
`--isolate none`, then once more with registry metadata and OSV unreachable,
where only *incomplete* or *blocked* are acceptable for installs that needed
metadata. Added wall time is measured against the same install without
greengate.

## `watch-install` methodology

`install/manifest.json` labels 17 scenarios: nine attack simulations and eight
benign installs/builds. Each runs three times by default in a fresh temporary
project. Registry checks are explicitly disabled, so the suite needs no network,
package registry, credentials, Node, or downloaded dependencies.

`watch-install` wraps a Python installer stand-in, matching the wrapper's
filesystem and lifecycle-metadata interfaces. Suspicious hook strings remain
inert; no actual download, exfiltration, or arbitrary hook execution occurs.
The native scenarios compile and link `install/native.c` with a real C compiler
and execute its harmless binary inside the package directory. They cover
persistent artifacts, temporary-object cleanup, subprocess hook metadata, and
explicit package allowlisting. These are not real esbuild/node-gyp installations.

The harness reports three observations independently:

- **Preflight block:** the wrapper fails with script-detection evidence and an
  installer-start marker confirms the installer never ran.
- **Detection after execution:** the installer ran and the wrapper then failed
  with script, phantom-file, or executable-drop evidence. This is not prevention.
- **Permitted:** the installer completed and the wrapper exited successfully.
  A permitted attack simulation is a miss; a blocked benign scenario is a false
  positive. Allowlisted warnings are reported but do not count as blocks.

Timeouts, crashes, compiler failures, and unrelated nonzero exits are execution
errors, not detections. Errors and skipped scenarios are excluded from rates;
an execution error makes the harness exit nonzero. The suite deliberately
includes known gaps (fast file deletion, nested executable drops, and helper
script indirection) and benign cleanup that can resemble a dropper. It does not
require perfect detection or hide those cases to make the results look better.

```bash
python3 bench/install/run.py --greengate-bin /absolute/path/to/greengate --repeats 3
python3 -m unittest discover -s bench/install -p 'test_*.py'
```

Run binaries/fixtures in a disposable OS sandbox without external networking,
ambient credentials, or write access to unrelated files. CI uses a fresh runner
with an empty benchmark environment. Slow temporary files live for 0.8 seconds
to span multiple 250 ms polls; fast files are deleted immediately, so outcomes
can vary with scheduling. Raw trials preserve every observation.

This suite covers `watch-install` script scanning and filesystem observation.
It does **not** establish real package-manager compatibility, registry/slopsquat
guard accuracy, `pip-install`/`cargo-add` coverage, network isolation, or resistance
to all supply-chain attacks. Registry and end-to-end package-manager benchmarks
remain future work.

We publish this benchmark knowing greengate does **not** win every cell. It
optimises for recall and zero-dependency breadth; a dedicated scanner with a
curated allowlist will usually score higher precision on trap files. Showing
that honestly is the point — see the FP list in RESULTS.md, which doubles as
greengate's precision to-do list.

---

## Corpus

`corpus/` is scanned as-is by every tool (each runs with the corpus as its
working directory, so reported paths line up).

```
corpus/
  positives/     one planted, synthetic secret per file — every tool SHOULD flag these
  negatives/     false-positive traps — secret-LOOKING strings that are NOT secrets
  .greengate.toml  pinned scan settings (entropy on @ 4.5, SAST off) for reproducibility
```

Ground truth lives in [`manifest.json`](manifest.json) (kept **outside** the
scanned dir so its example strings don't pollute results):

- **`positives`** — `{file, line, category}` for each planted secret. All values
  are synthetic and non-functional (fake-but-format-valid keys, the public
  jwt.io sample JWT, etc.).
- **`negatives`** — FP-trap files with a note on what they bait: documented AWS
  example key, npm `sha512` integrity hashes, a base64 PNG data URI, UUIDs, git
  SHAs, placeholder env values (`YOUR_API_KEY_HERE`, `changeme`), a **public**
  key, a Stripe `sk_test_` key, and a Mapbox `pk.` public token.

The traps are chosen to hit different tools' weak spots — entropy tuning,
allowlisting, live-vs-test key discrimination — not to flatter any one tool.

## Scoring

| Term | Definition |
|---|---|
| **TP** (true positive) | a planted secret with ≥1 finding within `line_tolerance` (±2) lines of it |
| **FN** (false negative) | a planted secret no tool finding came near — a miss |
| **FP** (false positive) | a finding **not** near any planted secret — i.e. a hit on a trap file |
| **Precision** | TP / (TP + FP) — of what it flagged, how much was real |
| **Recall** | TP / (TP + FN) — of the real secrets, how many it caught |
| **F1** | harmonic mean of precision and recall |

A finding adjacent to a genuine secret never counts against precision, so a
multi-line secret (e.g. a PEM key) isn't penalised for spanning several lines.
Each tool runs in its **default** configuration — this measures the
out-of-the-box experience a developer actually gets.

## Adding a competitor

Install it and re-run — the harness picks it up automatically:

```bash
# macOS
brew install gitleaks trufflehog
python3 bench/run.py
```

Adapters live in `run.py` (`run_gitleaks`, `run_trufflehog`). To add another
scanner, write a function returning `(available, [Finding(file, line, rule), …], note)`
and append it to the `ADAPTERS` list. Normalising each tool's output into the
shared `Finding` shape is all that's required.

## Extending the corpus

Add a fixture under `positives/` (one secret) or `negatives/` (a trap), then add
a matching entry to `manifest.json`. Keep positive files minimal — one planted
secret and nothing else secret-looking — so stray matches don't muddy scoring.

---

## Honesty & limitations

- **Small corpus.** This is a smoke-test-sized, curated set, not a statistical
  sample of real-world repos. Treat the numbers as directional.
- **Synthetic secrets.** Values are format-valid but non-functional; verification
  scanners (e.g. trufflehog with live verification) will treat all of them as
  unverified, which is expected and noted per-tool.
- **Defaults-based.** Every tool runs with default settings + the pinned
  `.greengate.toml`. Tuning any tool's config will move its numbers.
- **Roadmap:** a CI workflow that installs the competitors and regenerates
  RESULTS.md on every release is the natural next step, so the published numbers
  stay current and third-party-reproducible.
