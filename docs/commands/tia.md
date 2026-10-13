---
title: 'tia: suggest tests from direct imports'
description: 'Compare changed source paths with tests’ static imports. Understand selection limits before using the output to narrow a test run.'
---

# tia

`greengate tia` suggests test files whose direct static imports match changed source paths. It parses supported imports with tree-sitter and compares normalized names and path suffixes. It does not build a complete transitive dependency graph or prove that omitted tests are unaffected.

## Usage

```bash
greengate tia --base origin/main --format json
greengate tia --staged --format text
```

| Flag | Default | Purpose |
|---|---|---|
| `--base <ref>` | `HEAD~1` | Compare the merge base with HEAD |
| `--staged` | off | Use staged changes |
| `--format` | `newline` | Print paths, text summary, or JSON |

The JSON output includes changed source files, selected tests, total test-file count, and config/data changes when source changes are present. With no changed source files, the command exits successfully after a message and may emit no JSON document.

## Supported files

| Language | Extensions and imports |
|---|---|
| JavaScript / TypeScript | `.js`, `.jsx`, `.ts`, `.tsx`; supported `import`, re-export, and `require` syntax |
| Python | `.py`; supported `import` and `from` syntax |
| Go | `.go`; package import paths |

A source change produces extension-free path stems and suffixes. Test imports are matched against those stems, with package-directory matching for Go. Unreadable or unsupported test files do not contribute matches.

## Use the suggestions

```bash
greengate tia --base origin/main
```

Review the list before passing it to pytest or Jest. Empty selections require an explicit decision: invoking a test runner with no filenames can run the full suite. Go test filenames are not package selectors; convert the selection to package directories before using `go test`.

For a Python project, a policy that runs the full suite when no tests are selected can use:

```bash
mapfile -t tests < <(greengate tia --base origin/main)
if [ "${#tests[@]}" -gt 0 ]; then
  pytest "${tests[@]}"
else
  pytest
fi
```

This Bash example handles only the empty-selection case. It does not make a nonempty selection complete. Run the full suite for config changes, indirect dependencies, or required assurance.

## Configuration

Configure test-file globs under `[tia]`:

```toml
[tia]
test_patterns = ["**/*.test.ts", "**/test_*.py", "**/*_test.go"]
```

This overrides the defaults. The defaults also include JavaScript/TypeScript spec files, JSX/TSX tests, Python `_test.py` files, and Python files under `tests/`.

## Limitations

- Transitive imports and indirect re-exports do not select tests automatically
- Dynamic module paths and workspace aliases may not resolve to source files
- Config/data changes warn but do not drive selection
- A changed test file is not necessarily selected solely because it changed

## Exit codes

`0` means the analysis completed, possibly with no selected tests. `4` means a runtime failure. See [exit codes](/reference/exit-codes).
