use ignore::{Walk, WalkBuilder};
use std::io;
use std::path::Path;

/// Root of greengate's on-disk cache: `$GREENGATE_CACHE_DIR`, else
/// `~/.cache/greengate` (`%USERPROFILE%\.cache\greengate` on Windows).
pub fn cache_root() -> Option<std::path::PathBuf> {
    if let Some(dir) = std::env::var_os("GREENGATE_CACHE_DIR").filter(|d| !d.is_empty()) {
        return Some(dir.into());
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| std::path::PathBuf::from(home).join(".cache/greengate"))
}

pub fn get_walker<P: AsRef<Path>>(dir: P) -> Walk {
    // Respects .gitignore rules; hidden(false) ensures dotfiles like .env are included
    WalkBuilder::new(dir).hidden(false).build()
}

/// How far into a file to look for a NUL byte when deciding it is binary — the
/// same window git uses.
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Read a file as text for content scanning.
///
/// Returns `Ok(None)` when there is nothing to scan: the file is binary, or it
/// was removed between being listed and being read.
///
/// Valid UTF-8 is returned as-is. Anything else is decoded lossily unless it
/// looks binary. Rejecting non-UTF-8 outright would let one Latin-1 byte in a
/// config file hide every secret in it, and every pattern greengate matches is
/// ASCII, so the U+FFFD substitutions cannot create or break a match.
///
/// # Errors
/// Any I/O error other than `NotFound` (permission denied, a directory, …).
pub fn read_text(path: &Path) -> io::Result<Option<String>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(text)),
        Err(e) if looks_binary(e.as_bytes()) => Ok(None),
        Err(e) => Ok(Some(String::from_utf8_lossy(e.as_bytes()).into_owned())),
    }
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(BINARY_SNIFF_BYTES).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_with(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp dir is writable");
        f.write_all(bytes).expect("temp file is writable");
        f
    }

    #[test]
    fn utf8_is_returned_unchanged() {
        let f = temp_with("key = \"héllo\"\n".as_bytes());
        assert_eq!(
            read_text(f.path()).unwrap().as_deref(),
            Some("key = \"héllo\"\n")
        );
    }

    #[test]
    fn latin1_is_decoded_lossily_not_skipped() {
        let f = temp_with(b"# caf\xe9\nAWS_KEY=AKIAQWERTYUIOPASDFGH\n");
        let text = read_text(f.path())
            .unwrap()
            .expect("Latin-1 text is still text");
        assert!(text.contains("AKIAQWERTYUIOPASDFGH"));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn invalid_utf8_with_nul_is_binary() {
        let f = temp_with(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff");
        assert_eq!(read_text(f.path()).unwrap(), None);
    }

    #[test]
    fn missing_file_is_nothing_to_scan() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_text(&dir.path().join("gone")).unwrap(), None);
    }

    #[test]
    fn other_io_errors_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_text(dir.path()).is_err(),
            "reading a directory must not pass silently"
        );
    }
}
