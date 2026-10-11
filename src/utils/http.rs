//! Shared outbound HTTP client.
//!
//! Every request greengate makes goes through [`agent`], and every response body
//! it parses goes through [`read_json`]. Both exist to bound what a remote server
//! can do to a CI gate:
//!
//! * **Timeouts.** `ureq` applies none by default, so an unresponsive registry
//!   would stall the gate until the CI job's own limit killed it.
//! * **A body cap.** `Response::into_reader` is uncapped (only `into_string` has
//!   `ureq`'s built-in 10 MB limit). Registry "packument" documents for popular
//!   npm packages genuinely run to tens of megabytes, so an unbounded read is a
//!   memory-exhaustion risk in the ordinary case, not just a hostile one.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use std::io::Read;

/// Hard cap on a response body we will buffer and parse.
///
/// A body larger than this fails the parse rather than being truncated
/// silently: callers treat that as "registry unavailable" and fail open, which
/// is the same outcome as any other transport error.
pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on a whole call, so a server that trickles bytes forever still ends.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// The process-wide agent: timeouts applied, connections pooled across calls.
///
/// `ureq::Agent` is internally reference-counted, so cloning it is cheap.
pub fn agent() -> ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout_read(READ_TIMEOUT)
                .timeout_write(WRITE_TIMEOUT)
                .timeout(CALL_TIMEOUT)
                .build()
        })
        .clone()
}

/// Deserialize a response body, reading at most [`MAX_BODY_BYTES`].
///
/// # Errors
/// Returns an error if the body is not valid JSON for `T`, or if it exceeds the
/// cap (which truncates the stream and therefore fails the parse).
pub fn read_json<T: serde::de::DeserializeOwned>(resp: ureq::Response) -> Result<T> {
    // `into_reader` hands back a boxed trait object, so take a `&mut` borrow of
    // it to get a `Sized` reader that `Read::take` will accept.
    let mut body = resp.into_reader();
    serde_json::from_reader(body.by_ref().take(MAX_BODY_BYTES))
        .context("failed to read response body (or body exceeded the size cap)")
}

/// Agent for large downloads: same connect/read timeouts, but no whole-call
/// ceiling — a 200 MB archive on a slow link legitimately takes minutes. A
/// stalled transfer still ends via the read timeout.
fn download_agent() -> ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout_read(READ_TIMEOUT)
                .timeout_write(WRITE_TIMEOUT)
                .build()
        })
        .clone()
}

/// Result of [`download`].
pub enum Download {
    /// The body was written to the destination.
    Fetched { etag: Option<String> },
    /// The server confirmed the copy matching the sent ETag is current.
    NotModified,
}

/// Stream `url` into `dest`, failing past `max_bytes`. With `etag`, sends
/// `If-None-Match` and returns [`Download::NotModified`] on a 304.
pub fn download(
    url: &str,
    dest: &std::path::Path,
    max_bytes: u64,
    etag: Option<&str>,
) -> Result<Download> {
    let mut req = download_agent().get(url);
    if let Some(tag) = etag {
        req = req.set("If-None-Match", tag);
    }
    let resp = req.call().with_context(|| format!("GET {url}"))?;
    if resp.status() == 304 {
        return Ok(Download::NotModified);
    }
    let etag = resp.header("ETag").map(str::to_string);
    let mut file = std::fs::File::create(dest)
        .with_context(|| format!("could not create {}", dest.display()))?;
    // Read one byte past the cap so an oversized body is detected, not cut.
    let written = std::io::copy(&mut resp.into_reader().take(max_bytes + 1), &mut file)
        .with_context(|| format!("download of {url} failed"))?;
    anyhow::ensure!(
        written <= max_bytes,
        "{url} is larger than the {} MB limit",
        max_bytes / (1024 * 1024)
    );
    Ok(Download::Fetched { etag })
}

/// Outcome of fetching a JSON document that may legitimately not exist.
pub enum Fetched<T> {
    Json(T),
    /// HTTP 404 / 410: the registry says the thing does not exist.
    NotFound,
    /// Anything else — transport error, other status, oversized or invalid
    /// body. The answer is unknown.
    Unavailable(String),
}

/// GET `url` and deserialize at most `max_bytes` of the body into `T`.
/// Registry documents (an npm packument runs to 30 MB) can exceed
/// [`MAX_BODY_BYTES`]; a typed `T` keeps only the fields it names.
pub fn get_json_capped<T: serde::de::DeserializeOwned>(
    url: &str,
    max_bytes: u64,
    user_agent: &str,
) -> Fetched<T> {
    match agent()
        .get(url)
        .set("User-Agent", user_agent)
        .set("Accept", "application/json")
        .call()
    {
        Ok(resp) => {
            let mut body = resp.into_reader();
            match serde_json::from_reader(std::io::BufReader::new(body.by_ref().take(max_bytes))) {
                Ok(v) => Fetched::Json(v),
                Err(e) => Fetched::Unavailable(format!("unreadable response from {url}: {e}")),
            }
        }
        Err(ureq::Error::Status(404 | 410, _)) => Fetched::NotFound,
        Err(ureq::Error::Status(code, _)) => {
            Fetched::Unavailable(format!("{url} returned HTTP {code}"))
        }
        Err(e) => Fetched::Unavailable(format!("{url}: {e}")),
    }
}

/// GET `url` as text, reading at most `max_bytes`.
pub fn get_text_capped(url: &str, max_bytes: u64, user_agent: &str) -> Fetched<String> {
    match agent().get(url).set("User-Agent", user_agent).call() {
        Ok(resp) => {
            let mut text = String::new();
            match resp.into_reader().take(max_bytes).read_to_string(&mut text) {
                Ok(_) => Fetched::Json(text),
                Err(e) => Fetched::Unavailable(format!("unreadable response from {url}: {e}")),
            }
        }
        Err(ureq::Error::Status(404 | 410, _)) => Fetched::NotFound,
        Err(ureq::Error::Status(code, _)) => {
            Fetched::Unavailable(format!("{url} returned HTTP {code}"))
        }
        Err(e) => Fetched::Unavailable(format!("{url}: {e}")),
    }
}

/// HTTP status of a GET to `url` (for existence probes), or `None` on a
/// transport failure.
pub fn status_of(url: &str, user_agent: &str) -> Option<u16> {
    match agent().get(url).set("User-Agent", user_agent).call() {
        Ok(resp) => Some(resp.status()),
        Err(ureq::Error::Status(code, _)) => Some(code),
        Err(_) => None,
    }
}
