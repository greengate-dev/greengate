---
title: 'AI Agents — Check Dependency Installs Before They Run'
description: 'Stop coding agents (Claude Code, Cursor, Codex, Gemini CLI) from installing vulnerable or risky packages: greengate plans every dependency install an agent is about to run, without running package code, and denies, asks or stays out of the way.'
---

# AI Agents

A coding agent that runs `npm install some-package` runs that package's
install scripts with your credentials, and it picks packages from memory,
which can be outdated, vulnerable or [hallucinated](../commands/install.md).
greengate can check every dependency install before the agent runs it.

It finds the installs in the shell command (`npm i x`, `pnpm add y`,
`uv add z`, `pip install …`, `cargo add …`, including `cd web && …` and
`bash -c '…'`), and plans each one with
[`greengate install --plan`](../commands/install.md). The plan resolves the
full tree in a scratch copy, checks every package the install adds or
changes for known advisories and release risk, and inspects install scripts.
It installs nothing and runs no package code.

## Claude Code

Add a `PreToolUse` hook to `.claude/settings.json` (project) or
`~/.claude/settings.json` (all projects):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "greengate hook claude-code", "timeout": 90 }
        ]
      }
    ]
  }
}
```

For each Bash command Claude is about to run:

| Result | Decision | Who sees the reason |
|---|---|---|
| Not a dependency install | nothing: your normal permissions apply | — |
| A blocking finding (e.g. an advisory at or above `fail_on_severity`, a new install script, a dependency-confusion match) | **deny** | Claude, with the finding and the version to use instead, so it can correct course |
| Warnings, a check that could not finish (registry unreachable, out of time), or an install greengate cannot plan (Poetry, `cargo install`, `npm i -g`, arguments built with `$(…)`) | **ask** | you, in the permission prompt |
| Clean | nothing: your normal permissions apply | — |

A clean result does not approve the command, because the same command line
can do other things too (`npm i x && curl … | sh`). To approve clean installs
anyway, add `--allow-on-pass`. Claude Code's deny rules still apply when you
do.

The hook always exits `0`. A hook that exits `2` blocks the command, and a
broken `.greengate.toml` must not block every command Claude runs. Problems
surface as an *ask* instead.

**Time.** With warm caches, a plan takes about a second (npm; measured on
`npm i lodash`). The hook spends at most `--budget-secs` (default 60). After
that it asks rather than allows. Set the hook's `timeout` above the budget.

Policy comes from the project's `.greengate.toml`: `[supply_chain]` for
release risk and sources, `[dependency_review] fail_on_severity` for which
advisories block. Exceptions in `.greengate/exceptions.toml` apply.

## Other agents and editors

`greengate check-command` takes the shell command and prints a
[`greengate.report/v1`](../reference/report-schema.md) document, with the
usual exit codes (`0` passed, `1` blocking findings, `3` could not check
everything):

```bash
$ greengate check-command -- "npm i lodash@4.17.20"
{
  "schema": "greengate.report/v1",
  "command": "check-command",
  "status": "findings",
  "findings": [
    {
      "rule": "OSV/GHSA-35jh-r3h4-6jhm",
      "severity": "high",
      "location": { "kind": "package", "name": "lodash", "version": "4.17.20", … },
      "message": "Command Injection in lodash",
      "remediation": "use lodash 4.18.0 or later"
    }
  ],
  …
}
```

Any tool that can run a command before a shell call can use it. Common
setups:

- **Cursor, Gemini CLI, Codex and others with command hooks:** run
  `greengate check-command --cwd "$DIR" -- "$COMMAND"` and block when the exit
  code is `1`. Ask the user on `3`.
- **Your own agent loop:** call it before executing a shell tool call, and
  feed `findings[].message` and `remediation` back to the model.

Options: `--cwd <dir>` (where the command would run), `--budget-secs <n>`
(default 120).

## What is detected

| Command | Planned as |
|---|---|
| `npm install/i/add/ci …` | `greengate install npm …` |
| `pnpm add/install …`, `yarn [add/install] …`, `bun add/install …` | `greengate install pnpm/yarn/bun …` |
| `pip install …`, `pip3 install …`, `python -m pip install …`, `uv pip install …` | `greengate install pip …` |
| `uv add/sync …` | `greengate install uv …` |
| `cargo add …` | `greengate install cargo …` |
| `poetry add/install`, `cargo install`, `uv tool install`, global npm/pnpm/yarn/bun installs, installs with `$(…)` or `$VAR` arguments | not planned: reported as needing review |

Commands are split on `&&`, `||`, `;`, `|` and newlines; quotes, `cd`,
`VAR=value` prefixes, `sudo`/`env` wrappers and `bash -c` bodies are
followed. `npx`, `bunx` and `pnpm dlx` are not treated as installs.
