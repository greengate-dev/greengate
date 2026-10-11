---
title: 'check-config — Validate Configuration'
description: 'Validate .greengate.toml and print all resolved configuration values, including profile overrides. Useful for debugging config issues in CI.'
---

# check-config — Validate Configuration

Reads `.greengate.toml`, validates it, and prints all resolved configuration values. Useful for verifying that overrides are applied correctly and that the file has no syntax errors. Also validates `.greengate/exceptions.toml` when there is one.

## Usage

```
greengate check-config
```

## Behaviour

- If `.greengate.toml` exists and is valid, prints every resolved value and exits 0.
- If the file contains a TOML syntax or type error, prints a descriptive error and exits 2.
- If no config file is found, prints the built-in defaults that will be used and exits 0.
- If `.greengate/exceptions.toml` is invalid (a missing field, a bad date, an expiry beyond `[policy] max_exception_days`), lists every problem and exits 2. Expired exceptions, and ones expiring within 14 days, are reported as warnings.

## Examples

```bash
# Verify your config file before running the pipeline
greengate check-config

# Combine with a profile to preview merged values
greengate --profile strict check-config
```

## Sample output (valid config)

```
✅ .greengate.toml is valid.

Resolved configuration:

[scan]
  entropy             = true
  entropy_threshold   = 4.5
  entropy_min_length  = 20
  extra_patterns      = 1 custom pattern(s)
    • Internal API Token = myapp_[a-z0-9]{32}
  exclude_patterns    = 2 pattern(s)
    • tests/**
    • vendor/**

[sast]
  enabled             = true
  max_function_lines  = 50
  max_parameters      = 5
  max_nesting_depth   = 4
  disabled_rules      = 0 rule(s)
  custom_rules        = 0 rule(s)

[coverage]
  file                = coverage/lcov.info
  min                 = 80%

[lint]
  target_dir          = .

[docker]
  dockerfile          = Dockerfile

[lighthouse]
  url                 = (not set)
  strategy            = mobile
  min_performance     = 80
  min_accessibility   = 90
  min_best_practices  = 80
  min_seo             = 80

[reassure]
  current             = output/current.perf
  baseline            = output/baseline.perf
  threshold           = 15%

[pipeline]
  steps               = 0 step(s)

✅ Config check passed.
```

## Sample output (no config file)

```
⚠️  No .greengate.toml found — all commands will use built-in defaults.
ℹ️  Run `greengate init` to generate a config file.

Default values that will be used:
  [scan]     entropy=true, threshold=4.5, min_length=20
  [sast]     enabled=true, max_function_lines=50, max_parameters=5, max_nesting_depth=4
  [coverage] file=coverage/lcov.info, min=80%
  [lint]     target_dir=.
  [docker]   dockerfile=Dockerfile
  [lighthouse] strategy=mobile, min_performance=80, min_accessibility=90
  [reassure] threshold=15%
```
