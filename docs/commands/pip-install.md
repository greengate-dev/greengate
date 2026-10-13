---
title: 'pip-install: deprecated compatibility command'
description: 'Migrate Python installs from pip-install to the 0.4.0 install gate.'
---

# pip-install

`pip-install` is deprecated in 0.4.0 and scheduled for removal in 0.5. With pip 22.2 or later, it routes through [`greengate install pip`](/commands/install), using pip reports, artifact inspection, and sandboxed source builds when isolation is available.

## Migrate

```bash
# Compatibility command
greengate pip-install --pip .venv/bin/pip -r requirements.txt

# Preferred command
greengate install --pip .venv/bin/pip pip install -r requirements.txt
```

Python metadata resolution can execute build code during planning. Set `[supply_chain] require_isolation = true` to refuse those phases without isolation, or use `--isolate bwrap` on Linux.

## Compatibility behavior

Older pip versions retain the legacy path with a deprecation notice: package-name checks run before installation, while installed Python source and executable-drop checks run afterward. Those post-install checks do not prevent package code from executing first.

`--no-fail` permits findings; it does not hide tool errors or incomplete checks. See [exit codes](/reference/exit-codes) and the [install reference](/commands/install) for policy and supported install arguments.
