---
title: 'watch-install — Zero-Trust Supply Chain Gate'
description: 'npm/yarn/pnpm/bun install gate with lifecycle-script checks, polled phantom-file detection, and post-install executable-drop checks. Does not isolate the installer.'
---

# watch-install — Zero-Trust Supply Chain Quality Gate

> **Observe install-time script and filesystem signals.**

`greengate watch-install` wraps a package manager with lifecycle-script checks,
polled phantom-file detection, and post-install executable-drop checks. It does
not query CVE databases or isolate the installer. Existing scripts can be
blocked before execution; newly installed scripts and runtime events are
reported after the package manager runs.

---

## Usage

```bash
greengate watch-install <PACKAGE_MANAGER> [ARGS...]
```

All arguments after the package manager name are forwarded verbatim:

```bash
# Drop-in for npm install
greengate watch-install npm install

# Frozen lockfile (CI)
greengate watch-install npm ci

# pnpm with flags
greengate watch-install pnpm install --frozen-lockfile

# yarn
greengate watch-install yarn install --immutable

# bun
greengate watch-install bun install
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--no-fail` | — | Report findings to stderr but exit 0. Useful for audit-only pipelines not yet blocking. |

---

## Three-layer architecture

### Layer 1 — Pre-flight static script scan

Before the install runs, `watch-install` checks `preinstall`, `install`, and
`postinstall` strings in existing top-level packages and scoped packages under
`node_modules`. The same pass runs after installation for newly present packages.
It does not recursively inspect every nested package or the source of helper
files invoked by a hook. Signals may also occur in legitimate build tooling.

**Signals detected:**

| Category | Patterns |
|---|---|
| Dynamic code execution | `eval()`, `new Function()`, `vm.runInContext()`, `vm.runInNewContext()` |
| Obfuscation / Base64 | `Buffer.from(`, `atob()`, `btoa()` |
| Raw networking | `require('http')`, `require('https')`, `require('net')`, `require('dns')`, `require('tls')` |
| HTTP client libraries | `fetch(`, `axios`, `got(`, `request(`, `superagent` |
| Process / shell spawn | `child_process`, `execSync(`, `spawnSync(`, `exec(`, `spawn(`, `curl `, `wget ` |
| Env exfiltration | `process.env` |
| **High entropy** | Shannon entropy > 4.8 over a 64-char window — may indicate obfuscation or benign minified code |

Finding any signal, or exceeding the entropy threshold, produces a `SCRIPT_THREAT` finding.

### Layer 2 — Runtime phantom-file detection

A 250 ms polling thread watches `node_modules/` while the package manager runs.
A file observed as newly created and later deleted is flagged as a `PHANTOM`.
Files created and deleted between observations can be missed. The watcher
cannot establish which process created a file or whether it was executed;
legitimate native-build cleanup can trigger the same signal.

```
postinstall → write binary → execute → unlink to hide evidence
```

The [install benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_RESULTS.md)
measures controlled examples of this pattern and benign native-build cleanup.

### Layer 3 — Post-install executable-drop detection

After the install completes, a new executable file directly in the project root
is flagged as an `EXEC_DROP`. This check is non-recursive: executables in project
subdirectories are not covered. Legitimate tooling can also create executables,
so findings require review. Neither this check nor phantom-file detection
prevents the wrapped process from executing first.

---

## Example output

**Script threat detected (Layer 1):**

```
⚠️  Zero-Trust Supply Chain Gate: 1 package(s) with suspicious lifecycle scripts:

  [SCRIPT_THREAT] malicious-utils (postinstall)
    Signals   : fetch(, process.env, eval()
    Entropy   : 5.91  (threshold 4.80 — likely obfuscated)

  Tip: inspect each flagged script manually. If the package is a known
  native build tool, add it to [supply_chain] allow_postinstall in .greengate.toml.

Error: Zero-Trust Supply Chain Gate: 1 newly installed package(s) with suspicious
lifecycle scripts detected — halting.
```

**Phantom detected (Layer 2):**

```
🚨 greengate watch-install: 1 suspicious event(s) detected:

  [PHANTOM   ] evil-pkg
               path: node_modules/evil-pkg/.postinstall

  Tip: if this package is a known native build tool (e.g. esbuild, swc),
  add it to [supply_chain] allow_postinstall in .greengate.toml to suppress.

Error: Zero-Trust Supply Chain Gate: 1 blocking runtime event(s) detected — halting.
```

**Clean install:**

```
✅ Zero-Trust Supply Chain Gate: clean — no phantom files, executable drops,
   or suspicious scripts detected.
```

---

## Configuration

All options live under `[supply_chain]` in `.greengate.toml`:

```toml
[supply_chain]
# Halt the install when any layer detects a threat (default: true).
block_phantom_scripts = true

# Also monitor the project root for new executables (Layer 3, default: true).
enforce_sandbox = true

# Packages whose postinstall scripts legitimately create temp files or make
# network calls (e.g. native build tools that compile .node addons).
# Findings from these packages are downgraded to warnings — they still appear
# in output for full audit trail but do not cause a non-zero exit.
allow_postinstall = ["esbuild", "prisma", "@swc/core"]
```

### allow_postinstall behaviour

Allowlisted packages still appear in output with `[allowlisted — warning only]`, providing a full audit trail. They do not trigger `block_phantom_scripts` failure across any of the three layers.

---

## CI usage

Replace your existing `npm install` / `npm ci` step:

```yaml
- name: Install GreenGate
  run: |
    curl -sL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Zero-Trust supply chain install
  run: greengate watch-install npm ci
```

For teams not yet ready to block on findings, start in audit-only mode:

```yaml
- name: Supply-chain audit (non-blocking)
  run: greengate watch-install --no-fail npm ci
```

---

## Layered defence with `audit`

`watch-install` and `greengate audit` are complementary, not redundant:

| Tool | When it runs | What it catches |
|---|---|---|
| `greengate audit` | Pre/post install | Known CVEs in the OSV database for your lock file |
| `greengate watch-install` | During and after install | Runtime dropper behaviour, obfuscated scripts, and exec-drops that CVE databases cannot see |

Run both to combine filesystem/script signals with known-advisory checks:

```yaml
- run: greengate watch-install npm ci   # zero-trust gate: behaviour + static scan
- run: greengate audit                  # known CVE database check
```

---

## Background

An installer can create a payload, execute it, then delete it. A final snapshot
or lock-file diff alone does not show that temporary file. The watcher attempts
to observe creation and deletion during installation; the benchmark uses
harmless fixtures to measure this behavior and its polling limitations.

Lifecycle script strings can also contain networking, environment access, or
dynamic-code operations. Static scanning flags those signals for review, but
does not establish that they are malicious or inspect invoked helper-file code.

---

## Limitations

- **Pure network exfiltration without file writes** — there is no filesystem event for Layer 2 to observe. Layer 1 may flag network patterns in the lifecycle script string, but does not inspect network traffic or helper-file source.
- **Windows** — phantom detection works on Windows via `std::fs` polling, but exec-drop detection uses file-extension heuristics (`.exe`, `.bat`, `.cmd`, `.ps1`) rather than the execute bit.
- **Very fast droppers** — files created and deleted within a single 250 ms poll window may be missed by Layer 2. Layer 1 static scanning of the postinstall script provides a second line of defence for these cases.
- **Obfuscation at install time** — if a package downloads and decodes its malicious payload at runtime (not in the static script text), Layer 1 will not see it. Layer 2 runtime detection still applies.

See also: [Roadmap](/reference/roadmap) for planned `sandbox-install` with full network isolation.
