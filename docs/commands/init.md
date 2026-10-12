---
title: 'init — Config Wizard'
description: 'Interactive wizard that generates a .greengate.toml configuration file for your project with sensible defaults.'
---

# init — Config Wizard

Interactive wizard that generates a `.greengate.toml` configuration file for your project.

## Usage

```bash
greengate init [--force]
```

## Options

| Flag | Description |
|---|---|
| `--force` | Overwrite an existing `.greengate.toml` without prompting |

## What it does

Asks a series of short questions about your project and writes a tailored `.greengate.toml`. Press Enter to accept the default shown in `[brackets]`.

```
greengate init — generating .greengate.toml

[ Secret & SAST Scanning ]
  Enable entropy-based secret detection? [Y/n]:
  Entropy threshold (higher = fewer false positives) [4.5]:

[ Coverage Gate ]
  LCOV file path [coverage/lcov.info]:
  Minimum coverage % [80]:

[ Kubernetes Lint ]
  Kubernetes manifests directory [./k8s]:

[ Docker Lint ]
  Dockerfile path (leave blank to skip) []:

[ Pipeline Runner ]
  Generate a default pipeline (greengate run)? [Y/n]:

✅ .greengate.toml written successfully.
```

## Generated config

```toml
[scan]
entropy = true
entropy_threshold = 4.5
entropy_min_length = 20

[coverage]
file = "coverage/lcov.info"
min = 80

[lint]
target_dir = "./k8s"

[pipeline]
steps = [
  "scan",
  "audit",
  "coverage",
]
```

## Updating an existing config

```bash
# Will fail if .greengate.toml already exists
greengate init

# Overwrite without prompting
greengate init --force
```

## Next steps after init

Once `.greengate.toml` exists, every subsequent `greengate` invocation reads it automatically. Run the full pipeline with:

```bash
greengate run
```
