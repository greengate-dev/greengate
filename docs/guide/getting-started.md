---
title: 'Getting started with greengate'
description: 'Install greengate, then run dependency checks and repository scans.'
---

# Getting started

greengate is a Rust CLI for dependency checks, install protection, and repository gates.

## Install a binary

The release workflow builds Linux x64, macOS Intel and Apple Silicon, and Windows x64 binaries. Choose the asset for your platform from the [releases page](https://github.com/greengate-dev/greengate/releases).

For Linux x64:

```bash
curl -fsSL https://github.com/greengate-dev/greengate/releases/download/v0.4.0/greengate-linux-amd64 -o greengate
sudo install -m 755 greengate /usr/local/bin/greengate
```

For macOS, replace the asset name with `greengate-macos-arm64` or `greengate-macos-amd64`. For a local installation without root:

```bash
mkdir -p ~/.local/bin
install -m 755 greengate ~/.local/bin/greengate
```

Add `~/.local/bin` to your `PATH`.

For Windows PowerShell:

```powershell
$install_dir = Join-Path $env:USERPROFILE '.local\bin'
New-Item -ItemType Directory -Force -Path $install_dir | Out-Null
Invoke-WebRequest -Uri 'https://github.com/greengate-dev/greengate/releases/download/v0.4.0/greengate-windows-amd64.exe' -OutFile (Join-Path $install_dir 'greengate.exe')
```

Add that directory to your `PATH`, then run `greengate --version`.

### Verify a release

Release assets have `.sig` and `.pem` companions. Download the binary, signature, and certificate for the **same release tag**, then verify with cosign:

```bash
cosign verify-blob \
  --certificate greengate-linux-amd64.pem \
  --signature greengate-linux-amd64.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/greengate-dev/greengate/.github/workflows/release.yml@refs/tags/' \
  greengate-linux-amd64
```

## Build from source

From a source checkout, use a Rust toolchain that supports edition 2024:

```bash
cargo install --path . --locked
greengate --version
```

To obtain the 0.4.0 source checkout first:

```bash
git clone --branch v0.4.0 https://github.com/greengate-dev/greengate.git
cd greengate
cargo install --path . --locked
```

## Tools needed by optional features

The CLI does not need Node.js or Python to run its core scans. Other features need:

| Feature | Requirements |
|---|---|
| Wrapped dependency installs | The package manager, language runtime, and required build tools |
| OS-isolated install scripts | Linux with working bubblewrap; `--isolate bwrap` requires it |
| Git diff and history checks | Git and the relevant repository history |
| Online dependency checks | Network access; offline audits need downloaded OSV snapshots |
| Container image scanning | Docker, tar, and a locally available image |
| SBOM signing or verification | cosign |

## Run your first checks

From your project's root:

```bash
greengate deps list
greengate audit
greengate scan
greengate install --plan npm ci
```

Use `greengate install --isolate bwrap npm ci` to apply an npm install with required Linux isolation. Python planning can run source-build code, even with `--plan`; see [install](/commands/install).

Set `[supply_chain] require_isolation = true` to refuse supported package-code phases without isolation. The default `auto` mode otherwise permits an unisolated fallback.

## Next steps

- Configure [dependency policy](/commands/deps) and review changes on pull requests
- Add [CI reporting](/guide/ci-integration) and [coding-agent checks](/guide/agents)
- Manage [baselines and exceptions](/guide/baselines-and-exceptions)
- Read [limitations](/reference/limitations) before relying on a gate
