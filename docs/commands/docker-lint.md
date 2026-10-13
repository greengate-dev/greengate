---
title: 'docker-lint — Dockerfile Linting'
description: 'Lint a Dockerfile for security issues and best-practice violations: unpinned base images, ADD instead of COPY, missing USER or HEALTHCHECK, and more.'
---

# docker-lint — Dockerfile Linting

Lint a `Dockerfile` for best-practice violations that cause security issues, bloated images, or unreliable container behaviour.

## Usage

```bash
greengate docker-lint [--file <path>]
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--file` | `Dockerfile` | Path to the Dockerfile to lint (overrides config) |

## What it checks

| Rule | What it catches |
|---|---|
| `no-latest-image` | `FROM node:latest` or `FROM node` (no tag) — unpinned images break reproducibility |
| `prefer-copy-over-add` | `ADD . /app` — prefer `COPY` unless you need URL fetch or tar extraction |
| `no-user-directive` | No `USER` instruction — container runs as root by default |
| `no-root-user` | `USER root` or `USER 0` — explicit root switch |
| `no-healthcheck` | Missing `HEALTHCHECK` instruction — orchestrators can't detect unhealthy containers |
| `secret-in-env` | `ENV API_KEY=...` or `ENV PASSWORD=...` — secrets baked into the image layer |
| `apt-no-recommends` | `apt-get install` without `--no-install-recommends` — installs unnecessary packages |
| `apt-stale-cache` | `apt-get update` and `apt-get install` in separate `RUN` layers — stale cache risk |

## Configuration

```toml
# .greengate.toml
[docker]
dockerfile = "Dockerfile"   # default
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues found |
| `1` | One or more lint violations found |
| `4` | The Dockerfile could not be read |

## Examples

```bash
# Lint the default Dockerfile
greengate docker-lint

# Lint a specific Dockerfile
greengate docker-lint --file docker/Dockerfile.prod

# In GitHub Actions
- name: Lint Dockerfile
  run: greengate docker-lint --file Dockerfile
```

## Example output

```
⚠️  Found 3 issue(s):
  [no-latest-image] Dockerfile:1 — FROM 'node:latest' uses an unpinned or :latest tag
  [secret-in-env] Dockerfile:4 — ENV 'API_KEY' may expose a secret — use ARG, runtime secrets, or a secrets manager instead
  [no-healthcheck] Dockerfile — No HEALTHCHECK defined — add one for container health monitoring
Error: Docker lint failed: 3 issue(s) found.
```

## Writing a clean Dockerfile

```dockerfile
# Pin the exact digest or a specific version tag
FROM node:20.11.0

WORKDIR /app
COPY package*.json ./
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN npm ci --only=production

# Run as a non-root user
USER node

# Define a healthcheck
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["node", "server.js"]
```
