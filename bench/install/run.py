#!/usr/bin/env python3
"""Offline behavioral benchmark for watch-install; Python stdlib only.

Run untrusted binaries only in a disposable OS sandbox. Fixtures do not download
packages or execute malware. Nonzero harness exit means an execution error,
not a scanner miss or false positive: those remain visible in the report.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO = BENCH.parent


def classify(returncode, output, ran, native_built, case, completed=True):
    """A crash or failed fixture must never count as a security detection."""
    evidence = any(text in output for text in (
        "pre-existing package(s) with suspicious", "newly installed package(s) with suspicious",
        "[PHANTOM", "[EXEC_DROP",
    ))
    if returncode not in (0, 1) or (returncode == 1 and not evidence):
        return "error"
    if not ran:
        return "preflight" if returncode == 1 and evidence else "error"
    if not completed:
        return "error"
    if case.get("compiler") and not native_built:
        return "error"
    return "after execution" if returncode == 1 else "permitted"


def invoke(command, cwd, timeout):
    # A timeout terminates the whole process group, including the installer.
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RuntimeError(f"fixture exceeded {timeout}s timeout")
    return process.returncode, output


def run_case(case, binary, compiler, timeout):
    if case.get("compiler") and not compiler:
        return {"outcome": "skipped", "note": "C compiler unavailable"}
    with tempfile.TemporaryDirectory(prefix="gg-install-") as directory:
        root = Path(directory)
        package = root / "node_modules/trusted-builder"
        config = "[supply_chain]\nslopsquat_check = false\n"
        if case.get("allow"):
            config += 'allow_postinstall = ["trusted-builder"]\n'
        (root / ".greengate.toml").write_text(config, encoding="utf-8")
        if case["id"].startswith("existing-") or case["id"].startswith("native-spawn"):
            package.mkdir(parents=True)
            if "script" in case:
                (package / "package.json").write_text(json.dumps({
                    "name": "trusted-builder", "scripts": {"postinstall": case["script"]},
                }), encoding="utf-8")
            if case["id"] == "existing-cleanup":
                (package / "old.tmp").write_text("existing build artifact", encoding="utf-8")
        command = [str(binary), "watch-install", sys.executable, str(HERE / "worker.py"),
                   json.dumps(case), compiler or ""]
        try:
            code, output = invoke(command, root, timeout)
        except (OSError, RuntimeError) as error:
            return {"outcome": "error", "note": str(error)}
        ran = (root / "installer-ran").exists()
        native_built = (root / "native-built").exists()
        completed = (root / "installer-completed").exists()
        outcome = classify(code, output, ran, native_built, case, completed)
        return {"outcome": outcome, "exit_code": code, "installer_ran": ran,
                "installer_completed": completed,
                "native_built": native_built, "output": output,
                "note": "" if outcome != "error" else "unexpected exit or incomplete fixture"}


def totals(results):
    counts = Counter()
    for case in results:
        for trial in case["trials"]:
            outcome = trial["outcome"]
            if outcome in ("error", "skipped"):
                counts[outcome] += 1
            elif case["label"] == "malicious":
                counts["fn" if outcome == "permitted" else "tp"] += 1
                if outcome == "preflight":
                    counts["preflight"] += 1
            else:
                counts["tn" if outcome == "permitted" else "fp"] += 1
    return counts


def percentage(numerator, denominator):
    return f"{100 * numerator / denominator:.1f}%" if denominator else "n/a"


def build_report(results, version, repeats, compiler, metadata=None):
    counts = totals(results)
    lines = ["# greengate install-protection benchmark — results", "",
             f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · greengate {version} · "
             f"{len(results)} scenarios · {repeats} trials per scenario._", "",
             "> Local `watch-install` behavioral fixtures with an installer stand-in and real C builds. "
             "No registry requests, package downloads, live credentials, or malware execution. "
             "This does not benchmark npm/pip/Cargo compatibility or registry guards.", "",
             "## Trial-level results", "",
             "| Measure | Result |", "|---|---:|",
             f"| Attack trials detected (TP) | {counts['tp']} |",
             f"| Attack trials missed (FN) | {counts['fn']} |",
             f"| Attack trials blocked before installer execution | {counts['preflight']} |",
             f"| Attack trials detected after installer execution | {counts['tp'] - counts['preflight']} |",
             f"| Benign trials blocked (FP) | {counts['fp']} |",
             f"| Benign trials permitted (TN) | {counts['tn']} |",
             f"| Detection recall | {percentage(counts['tp'], counts['tp'] + counts['fn'])} |",
             f"| Preflight prevention rate | {percentage(counts['preflight'], counts['tp'] + counts['fn'])} |",
             f"| Benign block rate | {percentage(counts['fp'], counts['fp'] + counts['tn'])} |",
             f"| Execution errors / skipped trials | {counts['error']} / {counts['skipped']} |", "",
             "A detection after execution fails the gate but is not evidence that the simulated "
             "attack was prevented. Allowlisted events may still warn; they count as permitted "
             "when the command exits successfully. Errors and skipped trials are excluded from rates.", "",
             "## Scenario observations", "",
             "| Scenario | Ground truth | Observed outcomes | Fixture |",
             "|---|---|---|---|"]
    for case in results:
        outcomes = Counter(trial["outcome"] for trial in case["trials"])
        summary = ", ".join(f"{key}: {value}/{repeats}" for key, value in sorted(outcomes.items()))
        lines.append(f"| `{case['id']}` | {case['label']} | {summary} | {case['description']} |")
    lines += ["", "## Reproduction and limits", "",
              "- Run `python3 bench/install/run.py --greengate-bin /absolute/path/to/greengate --repeats 3`.",
              f"- C compiler: `{compiler or 'unavailable'}`. Native fixtures compile, link, and run `install/native.c` "
              "when the installer is permitted to start. Compiler failures are execution errors.",
              "- Labels are in `install/manifest.json`; raw per-trial output is in `INSTALL_RESULTS.json`.",
              "- Slow temporary files live for 0.8 s; fast ones are deleted immediately. "
              "Polling and machine load can change observations, so every trial is retained.",
              "- Suspicious inline hook/helper text is inert. The stand-in creates only harmless files. "
              "These cases measure metadata scanning and filesystem signals, not successful exploitation.",
              "- Native scenarios are controlled C builds, not installations of actual esbuild, node-gyp, or swc packages.",
              "- This small curated suite is not a real-world attack prevalence estimate or a competitor comparison.", ""]
    if metadata:
        lines += [f"- Environment: {metadata['platform']}; Python {metadata['python']}.",
                  f"- Binary SHA-256: `{metadata['binary_sha256']}`.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--greengate-bin", type=Path, default=REPO / "target/release/greengate")
    parser.add_argument("--manifest", type=Path, default=HERE / "manifest.json")
    parser.add_argument("--out", type=Path, default=BENCH / "INSTALL_RESULTS.md")
    parser.add_argument("--json-out", type=Path, default=BENCH / "INSTALL_RESULTS.json")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--cc", help="C compiler executable (default: cc on PATH)")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this suite requires POSIX executable permissions and process groups")
    if args.repeats < 1 or args.timeout <= 0:
        parser.error("repeats and timeout must be positive")
    binary = args.greengate_bin.resolve()
    if not binary.is_file():
        parser.error(f"greengate binary not found: {binary}")
    compiler = shutil.which(args.cc or "cc")
    if args.cc and not compiler:
        parser.error(f"C compiler not found: {args.cc}")
    version = subprocess.run([str(binary), "--version"], capture_output=True,
                             text=True, check=True, timeout=15).stdout.strip()
    if not version.startswith("greengate "):
        parser.error("unexpected greengate version output")
    with binary.open("rb") as executable:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            hasher.update(chunk)
        digest = hasher.hexdigest()
    metadata = {"platform": platform.platform(), "python": platform.python_version(),
                "binary_sha256": digest}
    cases = json.loads(args.manifest.read_text(encoding="utf-8"))["cases"]
    ids = [case["id"] for case in cases]
    if not cases or len(set(ids)) != len(ids) or any(case["label"] not in ("malicious", "benign") for case in cases):
        parser.error("manifest must contain unique scenarios labeled malicious or benign")
    results = []
    for case in cases:
        trials = [run_case(case, binary, compiler, args.timeout) for _ in range(args.repeats)]
        results.append({**case, "trials": trials})
        print(f"{case['id']}: " + ", ".join(trial["outcome"] for trial in trials), flush=True)
    args.out.write_text(build_report(results, version.split()[-1], args.repeats, compiler, metadata), encoding="utf-8")
    args.json_out.write_text(json.dumps({"version": version, "repeats": args.repeats,
                                      **metadata,
                                      "compiler": compiler, "results": results}, indent=2) + "\n", encoding="utf-8")
    counts = totals(results)
    print(f"Report: {args.out}; raw trials: {args.json_out}")
    return 1 if counts["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
