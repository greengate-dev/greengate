#!/usr/bin/env python3
"""
greengate secret-detection benchmark.

Runs greengate and (if installed) competing secret scanners against a labeled
corpus, then scores each on precision / recall / F1 against the ground truth in
manifest.json.

Design goals:
  * Runs today with just greengate. Competitors that aren't on PATH are reported
    as "not installed" and skipped — never fabricated.
  * Honest, not rigged: the corpus contains FP-trap files that each tool
    (greengate included) can and does get wrong. The numbers are whatever they are.
  * Stdlib only. No pip install required.

Scope: SECRET detection precision/recall only. Install-protection behavior is
measured separately by bench/install/run.py; its results are not mixed into
secret-detection scores.

Usage:
    python3 bench/run.py                       # scan, score, write RESULTS.md
    python3 bench/run.py --greengate-bin PATH  # use a specific greengate binary
    python3 bench/run.py --print               # also print the report to stdout
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BENCH_DIR)


# ── helpers ────────────────────────────────────────────────────────────────────

def norm(path):
    """Normalize a reported file path to a corpus-relative POSIX path."""
    p = path.replace("\\", "/")
    for prefix in ("./", ".\\"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    # Drop any leading corpus dir if a tool reported it absolute-ish.
    p = os.path.normpath(p).replace("\\", "/")
    if p.startswith("corpus/"):
        p = p[len("corpus/"):]
    return p


class Finding:
    __slots__ = ("file", "line", "rule")

    def __init__(self, file, line, rule):
        self.file = norm(file)
        self.line = int(line) if line is not None else -1
        self.rule = rule or ""

    def key(self):
        return (self.file, self.line)


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    return out


def materialize_corpus(corpus, manifest):
    """Copy the corpus into a fresh temp dir, substituting the __GG_SECRET__
    placeholder in each templated fixture with its decoded synthetic secret.

    The repository never stores contiguous provider-format secrets (they would
    trip GitHub secret-scanning / push-protection); the real values live
    base64-encoded in the manifest and are only ever written to this ephemeral
    dir. Substitution is in-place on the same line, so ground-truth line numbers
    are preserved. Returns the temp corpus path (caller must clean it up).
    """
    work = tempfile.mkdtemp(prefix="gg-bench-")
    dest = os.path.join(work, "corpus")
    shutil.copytree(corpus, dest)

    placeholder = manifest.get("placeholder", "__GG_SECRET__")
    entries = manifest.get("positives", []) + manifest.get("negatives", [])
    for e in entries:
        b64 = e.get("secret_b64")
        if not b64:
            continue
        secret = base64.b64decode(b64).decode()
        path = os.path.join(dest, *e["file"].split("/"))
        with open(path, "r") as fh:
            content = fh.read()
        if placeholder not in content:
            raise SystemExit(f"bench: {e['file']} is missing the {placeholder} placeholder")
        with open(path, "w") as fh:
            fh.write(content.replace(placeholder, secret))
    return dest


# ── adapters ───────────────────────────────────────────────────────────────────
# Each returns (available: bool, findings: list[Finding], note: str).

def run_greengate(corpus, bin_path):
    if not bin_path or not os.path.exists(bin_path):
        which = shutil.which("greengate")
        if not which:
            return False, [], "not found (build with `cargo build --release` or install greengate)"
        bin_path = which
    try:
        proc = subprocess.run(
            [bin_path, "scan", "--format", "json"],
            cwd=corpus, capture_output=True, text=True, timeout=120,
        )
    except Exception as e:  # noqa: BLE001
        return False, [], f"invocation failed: {e}"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], f"could not parse JSON output (exit {proc.returncode}): {proc.stderr[:200]}"
    findings = [Finding(f.get("file"), f.get("line"), f.get("rule")) for f in data.get("findings", [])]
    return True, findings, f"greengate scan --format json (exit {proc.returncode})"


def run_gitleaks(corpus, _bin):
    bin_path = shutil.which("gitleaks")
    if not bin_path:
        return False, [], "not installed (https://github.com/gitleaks/gitleaks)"
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        report = tf.name
    try:
        proc = subprocess.run(
            [bin_path, "detect", "--no-git", "--source", ".", "-f", "json", "-r", report],
            cwd=corpus, capture_output=True, text=True, timeout=120,
        )
        try:
            with open(report) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, FileNotFoundError):
            return False, [], f"no JSON report (exit {proc.returncode}): {proc.stderr[:200]}"
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass
    findings = [Finding(r.get("File"), r.get("StartLine"), r.get("RuleID")) for r in data]
    return True, findings, f"gitleaks detect --no-git (exit {proc.returncode})"


def run_trufflehog(corpus, _bin):
    bin_path = shutil.which("trufflehog")
    if not bin_path:
        return False, [], "not installed (https://github.com/trufflesecurity/trufflehog)"
    try:
        proc = subprocess.run(
            [bin_path, "filesystem", ".", "--json", "--no-update"],
            cwd=corpus, capture_output=True, text=True, timeout=180,
        )
    except Exception as e:  # noqa: BLE001
        return False, [], f"invocation failed: {e}"
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = (obj.get("SourceMetadata") or {}).get("Data") or {}
        fs = meta.get("Filesystem") or {}
        f = fs.get("file")
        if f:
            findings.append(Finding(f, fs.get("line", -1), obj.get("DetectorName")))
    return True, findings, "trufflehog filesystem --json"


ADAPTERS = [
    ("greengate", run_greengate),
    ("gitleaks", run_gitleaks),
    ("trufflehog", run_trufflehog),
]


# ── scoring ────────────────────────────────────────────────────────────────────

def score(findings, positives, tolerance):
    """Score findings against ground truth. Returns (tp, fp, fn, matched_categories, fp_files).

    A positive is a true positive if the tool reports at least one finding within
    `tolerance` lines of it. A finding is a false positive only if it is not near
    ANY positive — so a multi-line secret (e.g. a PEM key spanning several lines)
    that yields several findings is not penalised for the extra lines; only
    findings on the trap/negative files count against precision.
    """
    findings = dedupe(findings)
    matched_categories = set()
    matched_pos_count = 0

    def near_a_positive(f):
        return any(f.file == p["file"] and abs(f.line - p["line"]) <= tolerance for p in positives)

    for pos in positives:
        if any(f.file == pos["file"] and abs(f.line - pos["line"]) <= tolerance for f in findings):
            matched_pos_count += 1
            matched_categories.add(pos["category"])

    tp = matched_pos_count
    fn = len(positives) - tp
    fp_findings = [f for f in findings if not near_a_positive(f)]
    fp = len(fp_findings)
    fp_files = sorted({f.file for f in fp_findings})
    return tp, fp, fn, matched_categories, fp_files


def prf(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision and recall and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0 if (precision is not None and recall is not None) else None
    return precision, recall, f1


def pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


# ── report ─────────────────────────────────────────────────────────────────────

def build_report(results, positives, negatives, tolerance, gg_version):
    cats = sorted({p["category"] for p in positives})
    lines = []
    add = lines.append

    add("# greengate secret-detection benchmark — results\n")
    add(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"greengate {gg_version} · {len(positives)} planted secrets across "
        f"{len({p['file'] for p in positives})} files · {len(negatives)} false-positive-trap files · "
        f"line tolerance ±{tolerance}._\n")
    add("> This measures **secret detection** precision/recall only. It is generated by "
        "`bench/run.py` against the labeled corpus in `bench/corpus/`. Competing tools that "
        "are not installed on the runner are shown as _not installed_ and excluded from scoring — "
        "no numbers are fabricated. See [README.md](README.md) for methodology. "
        "Install-protection scenarios and native-build false positives are reported "
        "separately in [INSTALL_RESULTS.md](INSTALL_RESULTS.md).\n")

    # Summary table
    add("## Precision / recall / F1\n")
    add("| Tool | TP | FP | FN | Precision | Recall | F1 |")
    add("|---|---:|---:|---:|---:|---:|---:|")
    for name, r in results.items():
        if not r["available"]:
            add(f"| {name} | — | — | — | _not installed_ | | |")
            continue
        p, rc, f1 = r["prf"]
        add(f"| **{name}** | {r['tp']} | {r['fp']} | {r['fn']} | {pct(p)} | {pct(rc)} | {pct(f1)} |")
    add("")
    add("- **Recall** = of the planted secrets, how many the tool caught (higher = fewer misses).")
    add("- **Precision** = of what the tool flagged, how much was a real planted secret "
        "(higher = fewer false alarms on the trap files).")
    add("")

    # Per-category detection matrix
    avail = [n for n, r in results.items() if r["available"]]
    if avail:
        add("## Detection by secret type (recall detail)\n")
        add("| Secret type | " + " | ".join(avail) + " |")
        add("|---|" + "|".join([":--:"] * len(avail)) + "|")
        for c in cats:
            row = [c]
            for n in avail:
                row.append("✓" if c in results[n]["categories"] else "✗")
            add("| " + " | ".join(row) + " |")
        add("")

    # False-positive detail
    if avail:
        add("## False positives (trap files each tool flagged)\n")
        for n in avail:
            fpf = results[n]["fp_files"]
            if fpf:
                add(f"- **{n}** ({len(fpf)}): " + ", ".join(f"`{x}`" for x in fpf))
            else:
                add(f"- **{n}**: none 🎉")
        add("")

    add("## Runner notes\n")
    for name, r in results.items():
        add(f"- `{name}`: {r['note']}")
    add("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="greengate secret-detection benchmark")
    ap.add_argument("--greengate-bin",
                    default=os.path.join(REPO_ROOT, "target", "release", "greengate"),
                    help="path to greengate binary (default: target/release/greengate)")
    ap.add_argument("--corpus", default=os.path.join(BENCH_DIR, "corpus"))
    ap.add_argument("--manifest", default=os.path.join(BENCH_DIR, "manifest.json"))
    ap.add_argument("--out", default=os.path.join(BENCH_DIR, "RESULTS.md"))
    ap.add_argument("--print", dest="do_print", action="store_true")
    args = ap.parse_args()

    with open(args.manifest) as fh:
        manifest = json.load(fh)
    positives = manifest["positives"]
    negatives = manifest["negatives"]
    tolerance = manifest.get("line_tolerance", 2)

    # greengate version (best effort)
    gg_version = "unknown"
    gg_bin = args.greengate_bin if os.path.exists(args.greengate_bin) else shutil.which("greengate")
    if gg_bin:
        try:
            out = subprocess.run([gg_bin, "--version"], capture_output=True, text=True,
                                 timeout=15).stdout.strip()
            # Normalise "greengate 0.3.3" → "0.3.3"; the report adds the name itself.
            gg_version = out.split()[-1] if out else "unknown"
        except Exception:  # noqa: BLE001
            pass
    if gg_version in ("", "unknown"):
        # Fallback for older binaries without --version.
        try:
            with open(os.path.join(REPO_ROOT, "Cargo.toml")) as fh:
                for ln in fh:
                    if ln.strip().startswith("version"):
                        gg_version = ln.split('"')[1]
                        break
        except Exception:  # noqa: BLE001
            pass

    # Materialize the corpus (placeholder → decoded synthetic secret) into a
    # temp dir; every tool scans that, never the repo's placeholder fixtures.
    work = materialize_corpus(args.corpus, manifest)
    try:
        results = {}
        for name, fn in ADAPTERS:
            bin_arg = args.greengate_bin if name == "greengate" else None
            available, findings, note = fn(work, bin_arg)
            if available:
                tp, fp, fnc, cats, fp_files = score(findings, positives, tolerance)
                results[name] = {
                    "available": True, "tp": tp, "fp": fp, "fn": fnc,
                    "prf": prf(tp, fp, fnc), "categories": cats, "fp_files": fp_files, "note": note,
                }
            else:
                results[name] = {"available": False, "note": note}
    finally:
        shutil.rmtree(work, ignore_errors=True)

    report = build_report(results, positives, negatives, tolerance, gg_version)
    with open(args.out, "w") as fh:
        fh.write(report)

    # Console summary
    print(f"\nBenchmark complete → {os.path.relpath(args.out, REPO_ROOT)}\n")
    for name, r in results.items():
        if not r["available"]:
            print(f"  {name:12s} not installed — skipped")
            continue
        p, rc, f1 = r["prf"]
        print(f"  {name:12s} TP={r['tp']:2d} FP={r['fp']:2d} FN={r['fn']:2d}  "
              f"precision={pct(p)}  recall={pct(rc)}  F1={pct(f1)}")
    print()
    if args.do_print:
        print(report)


if __name__ == "__main__":
    sys.exit(main())
