---
title: 'tia — Test Impact Analysis'
description: 'AST-based test selection for CI: determines which test files are affected by a diff and pipes results into pytest, jest, or go test. Cut CI runtime without skipping relevant tests.'
---

# tia — Test Impact Analysis

> **Run only the tests that matter for a given diff.**

`greengate tia` analyses which source files changed between two commits, parses the import statements of every test file in the repository using tree-sitter, and outputs only the test files whose dependency graph overlaps with the changed set.

The default output is newline-separated file paths — designed to be piped directly into your test runner.

---

## Usage

```bash
greengate tia [OPTIONS]
```

```
Options:
      --base <REF>     Diff base: commit, branch, or tag [default: HEAD~1]
      --staged         Diff staged changes instead of committed diff
      --format <FMT>   Output format: newline (default) | text | json
  -h, --help           Print help
```

---

## Pipe-friendly output (default)

```bash
# Run only affected pytest tests
pytest $(greengate tia --base main)

# Run only affected Jest tests
npx jest $(greengate tia --base main)

# Run only affected Go tests
go test $(greengate tia --base main --format newline)

# Staged changes (before committing)
pytest $(greengate tia --staged)
```

When no tests are affected the command exits 0 with empty output — the test runner receives no arguments and will typically exit cleanly or with a "no tests selected" message.

---

## How it works

1. **Diff** — Runs `git diff <base>...HEAD --name-only` to get the list of changed files.
2. **Partition** — Splits changed files into *source files* (`.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.go`) and *config/data files* (everything else). Config changes produce a warning to consider running the full suite.
3. **Walk** — Traverses the repository (respecting `.gitignore`) and collects all files matching the configured `test_patterns` globs.
4. **Parse** — For each test file, uses tree-sitter to extract all `import`/`require`/`from … import` statements.
5. **Match** — Resolves each import to an extension-free path and checks whether it overlaps with any changed source file (exact match, path-suffix match, or package-directory match for Go).
6. **Output** — Prints the affected test file paths.

### Supported languages

| Language | Import syntax detected |
|---|---|
| TypeScript / TSX | `import … from '…'`, `export … from '…'`, `require('…')` |
| JavaScript / JSX | `import … from '…'`, `export … from '…'`, `require('…')` |
| Python | `import foo.bar`, `from foo.bar import …` |
| Go | `import "pkg/path"` |

### Path matching

Three overlap checks are applied (first match wins):

| Check | Example |
|---|---|
| Exact | import `src/utils/helpers` ↔ changed `src/utils/helpers.ts` |
| Suffix | import `utils/helpers` ↔ changed `src/utils/helpers.ts` |
| Package dir (Go) | import `github.com/org/repo/pkg/utils` ↔ changed `pkg/utils/helpers.go` |

---

## Text output

```bash
greengate tia --base main --format text
```

```
╔══ Test Impact Analysis ══════════════════════════════╗
  Changed source files : 3
  Total test files     : 48
  Affected tests       : 7
╚══════════════════════════════════════════════════════╝

src/utils/__tests__/helpers.test.ts
src/components/__tests__/Button.test.tsx
src/api/__tests__/client.test.ts
tests/test_helpers.py
tests/test_client.py
pkg/utils/helpers_test.go
pkg/api/client_test.go

✅ 7/48 tests selected.
```

---

## JSON output

```bash
greengate tia --base main --format json
```

```json
{
  "changed_source_files": [
    "src/utils/helpers.ts",
    "src/api/client.ts"
  ],
  "affected_tests": [
    "src/utils/__tests__/helpers.test.ts",
    "src/api/__tests__/client.test.ts"
  ],
  "total_test_files": 48,
  "config_files_changed": []
}
```

---

## Configuration

Configure test file detection under `[tia]` in `.greengate.toml`:

```toml
[tia]
test_patterns = [
  "**/*.test.ts",
  "**/*.test.tsx",
  "**/*.test.js",
  "**/*.test.jsx",
  "**/*.spec.ts",
  "**/*.spec.tsx",
  "**/*.spec.js",
  "**/*.spec.jsx",
  "**/test_*.py",
  "**/*_test.py",
  "tests/**/*.py",
  "**/*_test.go",
]
```

All patterns use standard glob syntax with `**` for recursive matching. The defaults above cover the standard conventions for TypeScript/JavaScript, Python, and Go projects. Override to match your project layout.

---

## CI usage

Use `tia` to speed up PR pipelines without sacrificing correctness:

```yaml
- name: Run affected tests only
  run: |
    TESTS=$(greengate tia --base "${{ github.event.pull_request.base.sha }}")
    if [ -n "$TESTS" ]; then
      pytest $TESTS
    else
      echo "No affected tests — skipping"
    fi
```

For Jest:

```yaml
- name: Run affected tests only
  run: |
    TESTS=$(greengate tia --base "${{ github.event.pull_request.base.sha }}")
    if [ -n "$TESTS" ]; then
      npx jest $TESTS
    else
      echo "No affected tests — skipping"
    fi
```

---

## Limitations

- **Static imports only** — dynamic `import()` calls with non-literal paths (e.g. `import(someVariable)`) cannot be statically resolved and are not detected.
- **Re-exports** — if module A re-exports module B, and a test imports A, changes to B will not automatically surface that test. Direct imports only.
- **Non-source changes** — changes to `package.json`, `Cargo.toml`, `.env`, YAML configs, or other non-source files are reported as warnings but do not drive test selection. If a config change could affect test outcomes, run the full suite manually.
- **Monorepo package boundaries** — cross-package imports using workspace aliases (e.g. `@myorg/shared`) are matched on the alias string rather than resolved to a file path. Ensure your alias paths overlap with the actual file paths for best results.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Command ran successfully (may output zero affected tests) |
| `4` | Git diff failed, glob compilation error, or other runtime error |
