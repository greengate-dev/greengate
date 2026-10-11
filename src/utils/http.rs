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
