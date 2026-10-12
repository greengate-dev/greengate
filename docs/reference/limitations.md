---
title: 'Known Limitations — GreenGate'
description: 'Known boundaries of GreenGate: supported language coverage, taint tracking scope, what the zero-trust supply chain gate cannot detect, and Lighthouse API requirements.'
---

# Limitations

This page documents the known boundaries of GreenGate's analysis. Understanding these limitations helps you set accurate expectations and decide where additional tooling may be warranted.

---

## SAST — taint tracking scope

GreenGate implements **Tier-1 intra-procedural taint tracking** for JS/TS. This means:

### What IS covered

| Scenario | Example |
|---|---|
| Direct source → sink (same statement) | `el.innerHTML = req.body.html` |
| Single-hop variable assignment | `const x = req.body.data; el.innerHTML = x` |
| Template literal propagation | `` const h = `<b>${x}</b>`; el.innerHTML = h `` |
| String concatenation propagation | `const cmd = "ls " + x; exec(cmd)` |
| Member access on tainted object | `const id = req.params.id; exec("cmd " + id)` |
| Sanitizer-through-variable suppression | `const s = DOMPurify.sanitize(x); el.innerHTML = s` |
| Static variable suppression | `const label = "Hello"; el.innerHTML = label` |

### What is NOT covered (Tier 2 / Tier 3)

| Gap | Reason | Workaround |
|---|---|---|
| **Inter-procedural taint** — taint flowing through a user-defined function call | Requires building a call graph across functions, which is Tier 2 | Add `// greengate: ignore` on the call site, or use a purpose-built SAST tool (Semgrep, Snyk Code) for this pattern |
| **Cross-file taint** — taint flowing through `import`/`require` across modules | Requires a whole-project analysis pass; not practical in a single-file scanner | Same as above |
| **Object/array destructuring propagation** | `const { name } = req.body` — destructured properties are not yet tracked | Assign to an intermediate variable before the sink |
| **Conditional taint** — value is tainted only on certain branches | Flow-sensitive analysis (not implemented) | Unlikely to matter in practice for most XSS/injection sinks |
| **Prototype chain / dynamic dispatch** | `this.input` or `obj[key]` | Use explicit variable assignments |

### Practical false negative risk

Because Tier-2 (inter-procedural) taint is not tracked, a pattern like:

```js
function getInput() {
  return req.body.data;   // taint source inside a helper
}

el.innerHTML = getInput();  // greengate sees an unknown call — flags normally
```

…is **still flagged** at normal confidence because GreenGate does not know `getInput()` is safe. The false negative scenario is the opposite: a sanitizer wrapped in a function will NOT suppress the finding:

```js
function safeHtml(input) {
  return DOMPurify.sanitize(input);  // safe inside function
}

el.innerHTML = safeHtml(raw);  // greengate does not know safeHtml() is safe
                               // → flagged (false positive)
```

For this case, use `// greengate: ignore` on the assignment line, or add `safeHtml` to a custom-safe list via a custom SAST rule.

---

## SAST — language coverage

| Language | AST-based SAST | Taint tracking | Code smells |
|---|---|---|---|
| JavaScript (`.js`, `.jsx`) | ✅ | ✅ | ✅ |
| TypeScript (`.ts`, `.tsx`) | ✅ | ✅ | ✅ |
| Python (`.py`) | ✅ | ❌ | ❌ |
| Go (`.go`) | ✅ | ❌ | ❌ |
| Rust (`.rs`) | ✅ | ❌ | ❌ |
| Ruby, PHP, Java, C# | ❌ | ❌ | ❌ |

Python, Go, and Rust use AST query rules without taint tracking. Rust rules
flag `unsafe` blocks, `Command::new(...)`, `.unwrap()`, and `.expect()` for
review; these constructs are not necessarily vulnerabilities. Rust analysis
does not establish whether command arguments are attacker-controlled.
Taint tracking is JS/TS only.

---

## SAST — no TypeScript type information

GreenGate uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) for AST parsing. tree-sitter is a syntax parser — it does **not** have access to TypeScript's type checker. This means:

- The engine cannot know the declared type of a variable (e.g. it cannot tell whether a `string` came from `HTMLElement.innerHTML` or a user-defined getter).
- Generic suppression decisions (is this `exec()` a child_process call or a DB query builder call?) are made by inspecting the receiver's **name** and AST shape, not its type.

For higher-fidelity type-aware analysis, Semgrep Pro or a dedicated type-aware linter would be needed.

---

## Dependency audit — data sources

`greengate audit` queries the [OSV database](https://osv.dev), or an offline
snapshot from `greengate db update` (`[audit] source`). Results are cached for
24 hours. When neither can answer, the run is **incomplete** (exit `3`),
never a pass; `[policy] on_incomplete = "warn"` makes that exit `0` while
still reporting it. Advisory ids that are aliases of one another (a
`RUSTSEC-…` and its `GHSA-…`) are merged in `deps review` but listed
separately by `audit`. Waive accepted advisories with exceptions
(`.greengate/exceptions.toml`); `[audit] ignore_advisories` is deprecated.

---

## Secret scanning — entropy tuning

Shannon entropy detection (`entropy = true`) may produce false positives on:

- **Lock file integrity hashes** (e.g. `pnpm-lock.yaml` sha512 checksums) — add `"pnpm-lock.yaml"` to `exclude_patterns`.
- **Base64-encoded binary assets** embedded in source (SVGs, fonts) — exclude `**/public/**` or the specific asset directory.
- **Minified JavaScript** — exclude `**/*.min.js`.

Raising `entropy_threshold` (e.g. to `5.0`) reduces false positives but may miss shorter secrets. Lowering it (e.g. to `3.5`) via `--profile strict` increases sensitivity.

---

## Baseline mode

`--since-baseline` compares findings against `.greengate-baseline.json` by fingerprint: the rule, the file, the matched text and the lines around it. A finding stays known when lines are inserted above it, the code around it changes, or its file is renamed. It becomes new when the matched text itself changes (a rotated secret is a different secret), or when a moved file's finding is ambiguous: several baseline entries share its rule and matched text, and none is in the same file. The baseline stores keyed hashes, not secrets, but its salt is in the same file, so a reader can test guesses at weak secrets. See [Baselines & Exceptions](/guide/baselines-and-exceptions).

---

## `greengate install` boundaries

- **Isolation is Linux-only.** Install scripts and sdist builds run in
  bubblewrap when it is installed. On macOS and Windows, and on Linux without
  bubblewrap, scripts run unisolated: suspicious ones are held back unless
  allowlisted, and changes outside a package are detected afterwards rather
  than refused. `require_isolation = true` refuses to run scripts at all
  without a sandbox.
- **pip and uv without isolation run sdist build backends unconfined while
  planning**, because resolving an sdist runs its build code. greengate warns
  (`INSTALL/SourceBuild`) but cannot stop it; the
  [benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_GATE_RESULTS.md)
  records this as a miss. With bubblewrap the same payload has no effect.
- **Release checks and advisories cover what an install adds or changes.**
  `npm ci` of an unchanged lockfile looks nothing up; review lockfile changes
  where they are made, with `greengate deps review`.
- **Yarn Berry** builds every package in one step, so a suspicious build is
  held back even with isolation.
- **Cargo** installs run no crate code; build scripts and proc-macros of new
  crates are inspected, and run later at `cargo build`.
- The name guard needs the public registries' download statistics;
  `npx`/`bunx`/`pnpm dlx` are not intercepted.
- The [agent hook](/guide/agents) recognises common install commands; an
  install hidden behind a script (`./setup.sh`), an alias or a Makefile target
  is not seen.

---

## Runtime analysis boundaries

Code and secret scanning are static. `watch-install` (deprecated in favour
of `greengate install`) additionally observes
filesystem changes during the wrapped command, but does not isolate the
process or inspect network traffic. Its 250 ms polling can miss files created
and deleted between observations. Preflight checks inspect existing packages;
newly installed lifecycle scripts are checked after execution. The slopsquat
guard checks explicitly supplied package names, not the full resolved tree
(`npm ci` and `pip-install -r requirements.txt` do not supply names to it).

The [watch-install benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_RESULTS.md)
reports detection timing, misses, and native-build false positives separately.

GreenGate cannot:

- Detect secrets injected at runtime via environment variables (those are generally safe — use env vars instead of hardcoding).
- Detect vulnerabilities that only manifest under specific runtime conditions (race conditions, logic bugs, SSRF depending on user-controlled URLs at runtime).
- Replace dynamic analysis tools (DAST, fuzzing, penetration testing).
