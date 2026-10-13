---
title: 'watch-install: deprecated compatibility command'
description: 'Migrate npm-family installs from watch-install to the 0.4.0 install gate.'
---

# watch-install

`watch-install` is deprecated in 0.4.0 and scheduled for removal in 0.5. Supported npm, pnpm, Yarn, and Bun install commands route through [`greengate install`](/commands/install), including its dependency policies, script inspection, and isolation behavior.

## Migrate

```bash
# Compatibility command
greengate watch-install npm ci

# Preferred command
greengate install npm ci
```

Use `install --isolate bwrap` or `[supply_chain] require_isolation = true` when isolation is required. The default `auto` mode can fall back to unisolated execution.

## Compatibility behavior

Commands that cannot route through the install gate retain the older watcher with a deprecation notice. That path checks lifecycle-script strings, polls filesystem changes, and reports executable drops after execution. It does not isolate the process or inspect network traffic. Files created and deleted between polls can be missed.

`--no-fail` permits findings, but tool failures and incomplete checks still follow the [exit-code policy](/reference/exit-codes). Legacy watcher settings such as `enforce_sandbox` do not enable OS isolation.

The [legacy benchmark](https://github.com/greengate-dev/greengate/blob/main/bench/INSTALL_RESULTS.md) describes the old watcher; use the [install reference](/commands/install) for the routed 0.4.0 behavior.
