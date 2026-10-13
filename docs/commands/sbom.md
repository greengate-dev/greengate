---
title: 'sbom — SBOM Generation & Sigstore Attestation'
description: 'Generate a CycloneDX 1.5 SBOM — components, dependency graph, scopes and hashes — from your lockfiles, and optionally sign it with Sigstore keyless signing to establish file integrity and signer identity. No private key required.'
---

# sbom — SBOM Generation & Sigstore Attestation

Generates a [CycloneDX 1.5](https://cyclonedx.org/specification/overview/) Software Bill of Materials (SBOM) from your project's dependency files. No internet access required — the lockfiles are parsed locally, and the output validates against the CycloneDX 1.5 JSON Schema.

Optionally signs the SBOM using [Sigstore](https://sigstore.dev) keyless signing (`--attest`) and verifies signed SBOMs (`--verify`). Signing and verification establish the file's integrity and the expected signer identity; they do not certify build provenance or regulatory compliance.

## Usage

```
greengate sbom [OPTIONS]

Options:
      --lockfile <FILE>                  Read only this dependency file
  -o, --output <FILE>                    Write SBOM to a file instead of stdout
                                         (default when --attest is set: sbom.json)
      --attest                           Sign the generated SBOM with Sigstore
                                         keyless signing via cosign
      --bundle <FILE>                    Path for the cosign bundle file
                                         (default: <output>.bundle.json)
      --verify <SBOM_FILE>               Verify an existing SBOM against a cosign bundle
      --certificate-oidc-issuer <ISSUER> Expected OIDC issuer for --verify
      --certificate-identity <IDENTITY>  Expected signer identity for --verify
  -h, --help                             Print help
```

## What goes in

Every supported dependency file under the current directory, or just one
with `--lockfile <file>`:

| Ecosystem | Dependency files |
|---|---|
| Node.js | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (Yarn 1 and Berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` |
| Python | `uv.lock`, `poetry.lock`, `pylock.toml` (PEP 751), `requirements.txt` (`==` pins) |
| Rust | `Cargo.lock` |
| Go | `go.mod` (Go 1.17+, with `replace` directives), else `go.sum` |

Two lockfiles for one ecosystem in one directory are an error — an SBOM
states what ships, so greengate will not guess which one is installed. Pick
one with `--lockfile`, or exclude the other with `[deps] exclude_patterns`.

Each component carries:

| Field | From |
|---|---|
| `purl` (also the `bom-ref`) | `pkg:npm/%40scope/name@1.0.0`, `pkg:pypi/…`, `pkg:cargo/…`, `pkg:golang/…`; a `repository_url`, `vcs_url` or `download_url` qualifier when the package does not come from the default registry |
| `scope` | `required` for runtime, `optional`, or `excluded` for development-only dependencies |
| `hashes` | the lockfile's integrity value (SRI `sha512-…` or `sha256:…`) |

The `dependencies` section records the graph: which component depends on
which, with the project itself (`bom-ref: root`) depending on the direct
dependencies.

## Examples

```bash
# Print SBOM to stdout
greengate sbom

# Write SBOM to a file
greengate sbom --output sbom.json

# Only one dependency file
greengate sbom --lockfile frontend/pnpm-lock.yaml --output sbom.json

# Generate and sign (writes sbom.json + sbom.json.bundle.json)
greengate sbom --attest

# Custom paths
greengate sbom --attest --output dist/sbom.json --bundle dist/sbom.bundle.json

# Verify the signature only. Any valid Sigstore identity is accepted, so the
# signer is not checked: the run is reported as incomplete (exit 3).
greengate sbom --verify sbom.json

# Verify with strict policy (exact issuer + identity)
greengate sbom --verify sbom.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

## Sigstore attestation (`--attest`)

`--attest` uses [cosign](https://github.com/sigstore/cosign) `sign-blob` to sign the SBOM with **keyless signing** — no private key to manage or rotate. The signing identity comes from the OIDC token issued by your CI provider at build time.

### What the bundle contains

The bundle file (`sbom.json.bundle.json`) contains three things:

| Field | What it is |
|---|---|
| Signing certificate | Your CI identity, e.g. `https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main` |
| ECDSA signature | Signature over the SHA-256 hash of the SBOM content |
| Rekor log entry | Inclusion proof in the public Rekor transparency log — anyone can verify this independently |

Distribute both `sbom.json` and `sbom.json.bundle.json` alongside your release artifacts.

### Requirements

Install cosign once:

```bash
# macOS
brew install sigstore/tap/cosign

# Linux (download binary)
# https://github.com/sigstore/cosign/releases

# GitHub Actions (add before the greengate step)
- uses: sigstore/cosign-installer@v3
```

### GitHub Actions: signing steps

Install greengate using the [CI setup guide](/guide/ci-integration) before these steps.

```yaml
permissions:
  contents: read
  id-token: write   # required for Sigstore keyless signing

steps:
  - uses: actions/checkout@v4

  - uses: sigstore/cosign-installer@v3

  - name: Generate and attest SBOM
    run: greengate sbom --attest --output sbom.json

  - name: Upload SBOM and bundle as release assets
    uses: softprops/action-gh-release@v2
    with:
      files: |
        sbom.json
        sbom.json.bundle.json
```

In GitHub Actions with `id-token: write`, cosign is fully non-interactive. Locally it opens a browser for a one-time OAuth flow.

## Verification (`--verify`)

```bash
# Basic — validates the certificate chain and Rekor log entry
greengate sbom --verify sbom.json --bundle sbom.json.bundle.json

# Strict — pin to your exact workflow identity
greengate sbom --verify sbom.json \
  --bundle sbom.json.bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

Without an expected signer identity, a valid signature is reported as incomplete (exit `3` by default). An issuer alone does not satisfy the identity check. Set both an expected issuer and identity to restrict the signer.

### Setting defaults in config

```toml
[sbom]
default_output    = "sbom.json"
expected_issuer   = "https://token.actions.githubusercontent.com"
expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
```

With these set, `greengate sbom --verify sbom.json` applies the policy without repeating the flags.

## Output format

The output is a CycloneDX 1.5 JSON document:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:12345678-1234-4123-8123-123456789012",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-06T12:00:00Z",
    "tools": [{ "vendor": "greengate-dev", "name": "greengate", "version": "0.4.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "serde",
      "version": "1.0.210",
      "purl": "pkg:cargo/serde@1.0.210",
      "scope": "required"
    }
  ]
}
```

## What signing establishes

A verified signature can bind the SBOM file to an expected signer identity and detect modification. The SBOM describes dependencies read from supported files; it does not attest that a particular build used those dependencies, assess their safety, or certify compliance.

Verify required fields and coverage against the requirements of the system consuming your SBOM.
