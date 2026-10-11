# greengate install-protection benchmark — results

_Generated 2026-10-11 11:40 UTC · greengate 0.3.4 · 17 scenarios · 3 trials per scenario._

> Local `watch-install` behavioral fixtures with an installer stand-in and real C builds. No registry requests, package downloads, live credentials, or malware execution. This does not benchmark npm/pip/Cargo compatibility or registry guards.

## Trial-level results

| Measure | Result |
|---|---:|
| Attack trials detected (TP) | 18 |
| Attack trials missed (FN) | 9 |
| Attack trials blocked before installer execution | 9 |
| Attack trials detected after installer execution | 9 |
| Benign trials blocked (FP) | 6 |
| Benign trials permitted (TN) | 18 |
| Detection recall | 66.7% |
| Preflight prevention rate | 33.3% |
| Benign block rate | 25.0% |
| Execution errors / skipped trials | 0 / 0 |

A detection after execution fails the gate but is not evidence that the simulated attack was prevented. Allowlisted events may still warn; they count as permitted when the command exits successfully. Errors and skipped trials are excluded from rates.

## Scenario observations

| Scenario | Ground truth | Observed outcomes | Fixture |
|---|---|---|---|
| `existing-network` | malicious | preflight: 3/3 | Existing inline network/environment hook |
| `existing-eval` | malicious | preflight: 3/3 | Existing inline dynamic-code hook |
| `existing-shell` | malicious | preflight: 3/3 | Existing shell download hook |
| `fresh-inline` | malicious | after execution: 3/3 | New inline suspicious hook, visible only after install |
| `slow-phantom` | malicious | after execution: 3/3 | Package file created, held for 0.8 s, then deleted |
| `root-executable` | malicious | after execution: 3/3 | Executable persisted directly in project root |
| `fast-phantom` | malicious | permitted: 3/3 | Package file created and immediately deleted between polls |
| `nested-executable` | malicious | permitted: 3/3 | Executable persisted in a project subdirectory |
| `helper-script` | malicious | permitted: 3/3 | New hook invokes a helper containing inert suspicious source |
| `clean` | benign | permitted: 3/3 | No filesystem changes |
| `persistent-package` | benign | permitted: 3/3 | Ordinary package files persist in node_modules |
| `existing-cleanup` | benign | permitted: 3/3 | Installer removes a file that predates the install |
| `native-persistent` | benign | permitted: 3/3 | Real C compilation leaves its executable inside the package |
| `native-temp` | benign | after execution: 3/3 | Real C compilation cleans a temporary object after 0.8 s |
| `native-temp-allowed` | benign | permitted: 3/3 | Same C build cleanup with explicit package allowlisting |
| `native-spawn` | benign | preflight: 3/3 | Legitimate native-build hook references child_process |
| `native-spawn-allowed` | benign | permitted: 3/3 | Same native-build hook with explicit package allowlisting |

## Reproduction and limits

- Run `python3 bench/install/run.py --greengate-bin /absolute/path/to/greengate --repeats 3`.
- C compiler: `/usr/bin/gcc`. Native fixtures compile, link, and run `install/native.c` when the installer is permitted to start. Compiler failures are execution errors.
- Labels are in `install/manifest.json`; raw per-trial output is in `INSTALL_RESULTS.json`.
- Slow temporary files live for 0.8 s; fast ones are deleted immediately. Polling and machine load can change observations, so every trial is retained.
- Suspicious inline hook/helper text is inert. The stand-in creates only harmless files. These cases measure metadata scanning and filesystem signals, not successful exploitation.
- Native scenarios are controlled C builds, not installations of actual esbuild, node-gyp, or swc packages.
- This small curated suite is not a real-world attack prevalence estimate or a competitor comparison.

- Environment: Linux-7.2.8-200.fc44.x86_64-x86_64-with-glibc2.43; Python 3.14.7.
- Binary SHA-256: `1441672c8edd99d9441154e68ccae0b9c164b5c70d447cfa06498bb181201770`.
