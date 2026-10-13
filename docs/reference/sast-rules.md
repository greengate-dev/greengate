---
title: 'SAST Rules Reference — greengate'
description: 'All built-in greengate SAST rules for JavaScript, TypeScript, Python, Go, and Rust: eval injection, XSS sinks, SQL injection, command injection, dangerous deserialization, and taint-tracked flows.'
---

# SAST Rules Reference

SAST runs automatically when `greengate scan` encounters a supported source file. It uses tree-sitter to parse each file into a real AST before running any checks.

**Supported languages:**

| Language | Extensions | Features |
|---|---|---|
| JavaScript | `.js`, `.jsx` | String-literal scoping, dangerous patterns, code smells, taint tracking |
| TypeScript | `.ts`, `.tsx` | String-literal scoping, dangerous patterns, code smells, taint tracking |
| Python | `.py` | String-literal scoping, dangerous patterns |
| Go | `.go` | String-literal scoping, dangerous patterns |
| Rust | `.rs` | String-literal scoping and review signals for unsafe code, process construction, and panic-prone calls |

## Tier-1 intra-procedural taint tracking

greengate performs **intra-procedural taint tracking** for JS/TS to reduce both false positives and false negatives. For every XSS and command-injection sink, the engine resolves where the value came from within the enclosing function body.

### How it works

1. **Source seeding** — variables assigned from known user-controlled sources are marked tainted:

   | Source pattern | Example |
   |---|---|
   | `req.body.*`, `req.query.*`, `req.params.*` | Express route handlers |
   | `request.body.*`, `request.headers.*` | Fastify / Koa |
   | `searchParams.get(...)` | URL search parameters |
   | `localStorage.getItem(...)`, `sessionStorage.getItem(...)` | Browser storage |
   | `document.cookie`, `location.hash`, `location.search` | Browser globals |
   | `event.data` | `postMessage` / worker events |
   | `process.env` | Node.js environment variables |

2. **Fixpoint propagation** — taint flows through assignments, template literals, and `+` concatenation until no new variables are classified.

3. **Safe set** — variables assigned from static string/number literals or calls to known sanitizers (`DOMPurify.sanitize`, `JSON.stringify`, `he.encode`, `sanitizeHtml`, etc.) are marked safe.

### Effect on findings

| Sink value | Result |
|---|---|
| Variable in **tainted** set | Rule ID gains a `[tainted]` label — e.g. `SAST/InnerHTMLAssignment [tainted]` — indicating a recognized taint flow that needs review |
| Variable in **safe** set | Finding is **suppressed** — value is classified as a recognized sanitizer result or static value |
| Unknown variable | Finding emitted at normal confidence (unchanged behaviour) |
| Static string literal (inline) | Finding is **suppressed** |
| Call to known sanitizer (inline) | Finding is **suppressed** |

### Suppression rules vs. label-only rules

| Strategy | Rules |
|---|---|
| **Suppress if safe, label if tainted** | `SAST/DangerouslySetInnerHTML`, `SAST/InnerHTMLAssignment`, `SAST/OuterHTMLAssignment`, `SAST/DocumentWrite`, `SAST/DocumentWriteln`, `SAST/EvalUsage` |
| **Label if tainted, never suppress** | `SAST/ChildProcessExec`, `SAST/ChildProcessExecSync`, `SAST/ChildProcessSpawn`, `SAST/ChildProcessExecFile` — a static command name like `"bash"` is safe by itself but the arguments array may still carry user input |

### Example

```js
// Multi-hop taint chain — detected even across intermediate variables
const raw   = req.body.comment;           // taint source
const html  = `<div>${raw}</div>`;        // propagated: html is tainted
el.innerHTML = html;
// → SAST/InnerHTMLAssignment [tainted]  (high confidence)

// Sanitizer suppresses the finding
const clean = DOMPurify.sanitize(raw);    // clean is marked safe
el.innerHTML = clean;
// → suppressed (classified as safe by the heuristic)

// Static variable suppresses the finding
const label = "Enter your name:";
el.innerHTML = label;
// → suppressed (classified as safe by the heuristic)
```

> **Scope:** Tier-1 tracking is intra-procedural only — taint does not follow calls into other functions. See [Limitations](/reference/limitations) for details.

## Dangerous pattern rules

These rules match supported syntax and API names. Selected JS/TS sinks also apply the taint and suppression heuristics above:

| Rule ID | What it flags |
|---|---|
| `SAST/DangerouslySetInnerHTML` | `dangerouslySetInnerHTML` prop with `__html` value in TSX/JSX |
| `SAST/InnerHTMLAssignment` | `element.innerHTML = expr` |
| `SAST/OuterHTMLAssignment` | `element.outerHTML = expr` |
| `SAST/EvalUsage` | `eval(expr)` |
| `SAST/FunctionConstructor` | `new Function(...)` |
| `SAST/SetTimeoutString` | `setTimeout("code", delay)` — string as first argument |
| `SAST/SetIntervalString` | `setInterval("code", delay)` — string as first argument |
| `SAST/ChildProcessExec` | `child_process.exec(cmd)` |
| `SAST/ChildProcessExecSync` | `child_process.execSync(cmd)` |
| `SAST/ChildProcessSpawn` | `child_process.spawn(cmd, args)` |
| `SAST/ChildProcessExecFile` | `child_process.execFile(cmd)` |
| `SAST/DocumentWrite` | `document.write(expr)` |
| `SAST/DocumentWriteln` | `document.writeln(expr)` |

## Python rules

| Rule ID | What it flags | Severity |
|---|---|---|
| `SAST/PythonEval` | `eval(expr)` — arbitrary code execution | critical |
| `SAST/PythonExec` | `exec(code)` — arbitrary code execution | critical |
| `SAST/PythonPickle` | `pickle.load(f)` / `pickle.loads(data)` — unsafe deserialization | high |
| `SAST/PythonSubprocessShell` | Any call with `shell=True` keyword argument — command injection | high |
| `SAST/PythonYamlLoad` | `yaml.load(data)` without a `Loader=` — use `yaml.safe_load` instead | high |

## Go rules

| Rule ID | What it flags | Severity |
|---|---|---|
| `SAST/GoUnsafe` | `import "unsafe"` — direct memory manipulation bypasses type safety | high |
| `SAST/GoExecCommand` | `exec.Command(cmd, ...)` — possible command injection | high |
| `SAST/GoPanic` | `panic(...)` — unexpected process termination in production code | medium |

## Rust rules

| Rule ID | What it flags |
|---|---|
| `SAST/RustUnsafeBlock` | `unsafe` blocks |
| `SAST/RustCommandNew` | Calls whose scoped function name matches `Command::new` |
| `SAST/RustUnwrap` | `.unwrap()` calls |
| `SAST/RustExpect` | `.expect()` calls |

These rules apply to matching syntax in Rust files, including applications; they are not limited to library code. They do not establish attacker control or prove that a construct is unsafe in context.

## Code smell rules

| Rule ID | Trigger | Default threshold |
|---|---|---|
| `SMELL/LongFunction` | Function body exceeds N lines | 50 lines |
| `SMELL/TooManyParameters` | Function has more than N parameters | 5 params |
| `SMELL/DeepNesting` | Control-flow depth exceeds N levels inside a function | 4 levels |

Rule IDs embed the measured value — e.g. `SMELL/LongFunction (63 lines, max 50)` — for immediate context. Thresholds are configurable in `.greengate.toml`.

## Suppressing findings in Python / Go

Use a same-line comment to suppress a specific finding:

```python
data = pickle.load(f)  # greengate: ignore
```

```go
panic("fatal: unrecoverable state")  // greengate: ignore
```

## Custom rules

Define project-specific rules using [tree-sitter S-expression queries](https://tree-sitter.github.io/tree-sitter/using-parsers/queries/). Each rule must include a `@match` capture marking the outermost node to report:

```toml
[sast]
custom_rules = [
  { id = "CUSTOM/EvalCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"eval\") arguments: (_) @match)" },
  { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]
```

Custom rules are validated at startup — invalid queries are skipped with a warning and never cause greengate to crash.

## Disabling rules

```toml
[sast]
disabled_rules = [
  "SAST/ChildProcessExec",
  "SAST/DocumentWrite",
  "SMELL/LongFunction",
]
```

Or disable SAST entirely:

```toml
[sast]
enabled = false
```
