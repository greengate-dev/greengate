---
title: 'cargo-add: deprecated compatibility command'
description: 'Migrate Rust dependency additions from cargo-add to the 0.4.0 install gate.'
---

# cargo-add

`cargo-add` is deprecated in 0.4.0 and scheduled for removal in 0.5. In a directory containing `Cargo.toml`, it routes through [`greengate install cargo`](/commands/install), applying dependency policy and inspecting new crates' build scripts and proc-macro sources.

## Migrate

```bash
# Compatibility command
greengate cargo-add serde --features derive

# Preferred command
greengate install cargo add serde --features derive
```

Cargo fetches dependencies without compiling them. Build scripts and proc-macros execute later at `cargo build`; greengate does not sandbox that later build.

Without `Cargo.toml`, the compatibility command uses its older implementation and reports any failure. `--no-fail` permits findings, but runtime errors and incomplete checks retain their [exit-code behavior](/reference/exit-codes).
