# image-scan

Scan a Docker/OCI container image for secrets and credentials baked into its filesystem layers.

```bash
greengate image-scan <image> [OPTIONS]
```

## Why scan image layers?

Build pipelines often copy secrets into images inadvertently:

- `COPY .env /app/` — the `.env` file (with its `DATABASE_URL`, `STRIPE_SECRET_KEY`, etc.) is now in the image.
- `ARG` values written to config files — `ARG API_KEY` followed by `RUN echo "key=$API_KEY" > /etc/app/config` bakes the key into a layer.
- Build tools that write credentials to `~/.aws/credentials` or `~/.ssh/` during the build stage and are then `COPY`-ed into the final image.
- Credentials left in earlier filesystem layers can remain in the archive after a later layer deletes the file. Image-configuration `ENV` values are not scanned by this command.

Layer scanning can find text-file credentials absent from the current source tree, including deleted files retained in earlier layers.

## How it works

```
docker save <image> -o /tmp/greengate-image-<nanos>.tar
    │
    ▼
Unpack outer tar → manifest.json + <hash>/layer.tar files
    │
    ▼  (per layer)
Unpack each layer.tar → files added or changed in that layer
    │
    ▼
Walk all text files (skip binary, > 1 MB, whiteout files)
    │
    ▼
Run built-in secret patterns + Shannon entropy scan
    │
    ▼
Deduplicate across layers → emit findings
    │
    ▼
RAII cleanup — temp directory removed on exit
```

Findings include the layer digest and path inside the layer:

```
nginx:latest::layer:a1b2c3d4e5f6::etc/environment:3  HIGH  AWS_ACCESS_KEY_ID
```

## Options

| Flag | Default | Description |
|---|---|---|
| `<image>` | _(required)_ | Image reference: `nginx:latest`, `ghcr.io/org/app:sha-abc123`, etc. |
| `--format` | `text` | Output format: `text`, `json`, `sarif`, `junit`, `gitlab` |
| `--no-fail` | `false` | Report findings but exit 0 (audit mode) |
| `--profile` | _(none)_ | Apply a preset: `strict`, `relaxed`, `ci` |

## Sensitive path promotion

Files in paths that commonly contain credentials have their finding severity automatically promoted one level (medium → high):

| Path pattern | Common contents |
|---|---|
| `*.env`, `.env.*` | Application secrets, API keys |
| `.aws/credentials` | AWS access keys |
| `.ssh/` | SSH private keys |
| `etc/environment` | System-wide environment variables |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | TLS/code signing certificates |
| `docker-compose*.yml` | Service credentials, bind mounts |

## Examples

```bash
# Scan a public image
greengate image-scan nginx:latest

# Scan a private registry image
greengate image-scan ghcr.io/my-org/my-app:sha-abc123

# JSON output for downstream tooling
greengate image-scan my-app:v1.2.3 --format json

# Audit mode — report but don't fail
greengate image-scan my-app:v1.2.3 --no-fail

# Strict profile — lower entropy threshold
greengate image-scan my-app:v1.2.3 --profile strict
```

## GitHub Actions

Scan the built image before pushing it to the registry:

```yaml
jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download published greengate
        run: |
          curl -fsSL https://github.com/greengate-dev/greengate/releases/latest/download/greengate-linux-amd64 \
            -o greengate
          sudo install -m 755 greengate /usr/local/bin/greengate

      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Scan image layers for secrets
        run: greengate image-scan my-app:${{ github.sha }}

      - name: Push image
        if: success()
        run: docker push my-app:${{ github.sha }}
```

The `if: success()` guard ensures the image is only pushed when the scan passes.

### SARIF output for Code Scanning

```yaml
- name: Scan image (SARIF)
  run: greengate image-scan my-app:${{ github.sha }} --format sarif > image-scan.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: image-scan.sarif
```

## Requirements

- **Docker** must be running and `docker` must be in `PATH`. greengate prints an error with installation instructions if Docker is not found.
- The image must be present locally: greengate calls `docker save`, not `docker pull`. Pull it yourself before scanning if needed. The external `tar` command must also be available.
- The process needs permission to access your Docker daemon.

## Performance

Scanning cost depends on the number, size, and contents of the layers.

The extracted layer data is written to a temporary directory and removed automatically when the command exits — even if the scan fails mid-way.

## Deduplication

OCI images use a layered filesystem: unchanged files from earlier layers are copied forward into later layers. Without deduplication, a secret in `/app/.env` that was present since layer 2 would be reported once per remaining layer.

greengate deduplicates findings by `(path, rule_id, line_number)` before reporting, so each unique finding is shown exactly once regardless of how many layers it appears in.

## Skipped files

The following are silently skipped to keep scan output noise-free:

| Skip condition | Reason |
|---|---|
| Files > 1 MB | Likely build artifacts, compiled binaries, or data files |
| Binary files (contain null bytes) | Binary scanning is unsupported; credentials embedded in binaries may be missed |
| Whiteout files (`.wh.` prefix) | OCI layer deletion markers, not real files |
| Symlinks | Not followed by the scanning walk |
