---
title: 'Secret and PII patterns'
description: 'The built-in credential and PII patterns in the 0.4.0 scanner, plus entropy checks and custom patterns.'
---

# Secret and PII patterns

greengate has 25 built-in regex patterns, plus configurable entropy detection. Some patterns match identifiers or credential-file markers rather than secret values. Findings require context; a match does not prove that a credential is active.

With SAST enabled, supported JS/TS, Python, Go, and Rust files use string-literal scoping. Other text files use line-based scanning. Known example credentials and common entropy noise are filtered.

## Built-in patterns

| Reported name | Match |
|---|---|
| AWS Access Key | `AKIA` access-key identifiers |
| AWS Secret Key | `aws_secret_access_key` assignments |
| Azure Storage Connection String | Connection strings containing `AccountKey` |
| Azure SAS Token | SAS URL parameters containing a signature |
| Google API Key | `AIza` API keys |
| GCP Service Account Key | JSON containing the `service_account` type marker |
| GCP OAuth2 Token | `ya29.` access tokens |
| DigitalOcean PAT | `dop_v1_` tokens |
| Alibaba Cloud Access Key ID | `LTAI` identifiers |
| GitHub PAT (classic) | `ghp_` tokens |
| GitHub PAT (fine-grained) | `github_pat_` tokens |
| Slack Webhook | Slack incoming-webhook URLs |
| Stripe Secret Key | `sk_live_` keys |
| Stripe Publishable Key | `pk_live_` identifiers; these may intentionally be public |
| SendGrid API Key | `SG.` API keys |
| Mailgun API Key | `key-` API keys |
| Twilio Account SID | `AC` account identifiers |
| HashiCorp Vault Token | `hvs.` service tokens |
| Expo Access Token | `expa_` tokens |
| Sentry DSN | Supported Sentry ingest URLs |
| Mapbox Secret Token | `sk.eyJ` secret tokens |
| PEM Private Key | Supported private-key headers |
| JWT Token | Three-part tokens matching the supported shape |
| Generic PII (SSN) | US-style Social Security number shapes |
| Generic PII (Email) | Email-like addresses |

The names above match the current code's report identifiers. The patterns are format-specific, not comprehensive provider credential inventories or full email-address validation.

## Custom patterns

```toml
[scan]
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
]
```

Custom patterns supplement the built-ins and use the same scanning scope.

## Entropy detection

```toml
[scan]
entropy = true
entropy_threshold = 4.5
entropy_min_length = 20
```

Entropy is a heuristic for unrecognized high-entropy tokens. Raising the threshold reduces sensitivity; lowering it can increase false positives. It cannot identify every secret or distinguish all credentials from hashes and data.

## Exclusions and suppressions

Use `[scan] exclude_patterns` for paths that should not be scanned. A `greengate: ignore` comment or an expiring exception can suppress a reviewed finding while keeping it visible in the shared report. See [baselines and exceptions](/guide/baselines-and-exceptions).
