---
title: 'db — Offline Vulnerability Data'
description: 'Download OSV vulnerability snapshots so greengate audit can run offline, in air-gapped CI, or keep working when the OSV API is down. Reports snapshot age as evidence.'
---

# db — Offline Vulnerability Data

Downloads [OSV](https://osv.dev)'s per-ecosystem vulnerability snapshots and
indexes them locally, so [`audit`](audit.md) can match dependencies without
calling the OSV API.

Use it to:

- run `audit` in air-gapped or egress-restricted CI (`audit --offline`)
- keep `audit` working when the OSV API is unreachable — by default `audit`
  falls back to a fresh-enough snapshot instead of reporting the run
  incomplete
- make results reproducible within a CI run, with the snapshot's age recorded
  in the report

## Usage

```
greengate db update [--ecosystem <ECOSYSTEM>]... [--all]
greengate db status [--format text|json]
```

`db update` downloads the ecosystems used by the dependency files in the
current directory (`Cargo.lock` → crates.io, `package-lock.json` /
`yarn.lock` / `pnpm-lock.yaml` → npm, `requirements.txt` → PyPI, `go.sum` →
Go). Pass `--ecosystem` (repeatable) or `--all` to choose explicitly.

Re-running `db update` revalidates each snapshot with the server's ETag, so an
unchanged snapshot is not downloaded again; it is only marked as checked.

| Ecosystem | Download (Oct 2026) | Index on disk |
|---|---|---|
| npm | ~220 MB | ~41 MB |
| PyPI | ~36 MB | ~21 MB |
| Go | ~12 MB | ~5 MB |
| crates.io | ~4 MB | ~2 MB |

The npm archive is large mostly because it lists malicious packages (`MAL-`
advisories), which `audit` reports like any other advisory.

## Where data is stored

`~/.cache/greengate/osv-db/<ecosystem>/`, or `$GREENGATE_CACHE_DIR/osv-db/`
when that variable is set. Set `GREENGATE_OSV_DB_URL` to download snapshots
from a mirror of `https://osv-vulnerabilities.storage.googleapis.com`.

## Freshness

`audit` refuses snapshots older than `[audit] max_db_age_hours` (default 24)
and reports the run as incomplete instead. Every check that used a snapshot
records its age in the report's `source` field.

```toml
[audit]
source = "auto"          # auto (default) | online | offline
max_db_age_hours = 24
```

## In CI

Cache the snapshots between runs and refresh them once per job:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/greengate/osv-db
    key: osv-db-${{ runner.os }}-${{ github.run_id }}
    restore-keys: osv-db-${{ runner.os }}-

- run: greengate db update
- run: greengate audit
```

`db update` exits `4` if a download fails; `audit` then still uses the
cached snapshot if it is within `max_db_age_hours`.
