//! Does a version requirement, as written in an ecosystem's manifests, allow
//! a version? `None` when it cannot be told: a git or path spec, a dist-tag,
//! a syntax this does not understand.

use crate::deps::Ecosystem;
use std::str::FromStr;

pub fn allows(eco: Ecosystem, req: &str, version: &str) -> Option<bool> {
    match eco {
        Ecosystem::Npm => npm_allows(req, version),
        Ecosystem::Cargo => {
            let req = if req.trim().is_empty() { "*" } else { req };
            let r = semver::VersionReq::parse(req).ok()?;
            Some(r.matches(&semver::Version::parse(version).ok()?))
        }
        Ecosystem::PyPI => pep440_allows(req, version),
        // A go.mod `require` is a minimum: any later version satisfies it.
        Ecosystem::Go => Some(true),
    }
}

/// PEP 440 specifiers (`>=1.0,<2`); empty allows everything.
pub fn pep440_allows(req: &str, version: &str) -> Option<bool> {
    let v = pep440_rs::Version::from_str(version).ok()?;
    if req.trim().is_empty() {
        return Some(true);
    }
    let specs = pep440_rs::VersionSpecifiers::from_str(req).ok()?;
    Some(specs.contains(&v))
}

/// Poetry's dependency syntax: `^1.2`, `~1.2`, `1.2.*`, `*`, a bare version
/// (exact), or PEP 440 specifiers.
pub fn poetry_allows(req: &str, version: &str) -> Option<bool> {
    let req = req.trim();
    if req.is_empty() || req == "*" {
        return Some(true);
    }
    let parts =
        |s: &str| -> Option<Vec<u64>> { s.split('.').map(|p| p.parse::<u64>().ok()).collect() };
    if let Some(rest) = req.strip_prefix('^') {
        let p = parts(rest.trim())?;
        // Bump the first non-zero component (or the last one given).
        let idx = p.iter().position(|&x| x != 0).unwrap_or(p.len() - 1);
        let mut upper: Vec<u64> = p[..=idx].to_vec();
        upper[idx] += 1;
        let upper = upper
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        return pep440_allows(&format!(">={},<{upper}", rest.trim()), version);
    }
    if let Some(rest) = req.strip_prefix('~').filter(|r| !r.starts_with('=')) {
        let p = parts(rest.trim())?;
        let upper = if p.len() == 1 {
            format!("{}", p[0] + 1)
        } else {
            format!("{}.{}", p[0], p[1] + 1)
        };
        return pep440_allows(&format!(">={},<{upper}", rest.trim()), version);
    }
    if req.chars().next().is_some_and(|c| c.is_ascii_digit()) && !req.contains(',') {
        return pep440_allows(&format!("=={req}"), version);
    }
    pep440_allows(req, version)
}

/// npm's range syntax (node-semver), as a set of alternatives the `semver`
/// crate can evaluate.
fn npm_allows(req: &str, version: &str) -> Option<bool> {
    let v = semver::Version::parse(version.strip_prefix('v').unwrap_or(version)).ok()?;
    let req = req.trim();
    let req = req.strip_prefix("workspace:").unwrap_or(req);
    if req.is_empty() || req == "*" || req == "x" {
        return Some(true);
    }
    if req.contains(':') || req.contains('/') {
        return None; // git, file:, link:, URLs, tags of forks
    }
    let mut any_parsed = false;
    for alt in req.split("||") {
        let Some(r) = npm_alternative(alt.trim()) else {
            continue;
        };
        any_parsed = true;
        if r.matches(&v) {
            return Some(true);
        }
    }
    any_parsed.then_some(false)
}

fn npm_alternative(alt: &str) -> Option<semver::VersionReq> {
    if alt.is_empty() || alt == "*" {
        return semver::VersionReq::parse("*").ok();
    }
    // Hyphen range: `1.2 - 2.3.4` → `>=1.2.0 <=2.3.4`; a partial upper bound
    // excludes the next increment (`- 2.3` → `<2.4.0`).
    if let Some((lo, hi)) = alt.split_once(" - ") {
        let lo = pad(lo.trim())?;
        let hi_parts: Vec<&str> = hi.trim().trim_start_matches('v').split('.').collect();
        let upper = match hi_parts.len() {
            1 => format!("<{}.0.0", hi_parts[0].parse::<u64>().ok()? + 1),
            2 => format!(
                "<{}.{}.0",
                hi_parts[0],
                hi_parts[1].parse::<u64>().ok()? + 1
            ),
            _ => format!("<={}", hi.trim().trim_start_matches('v')),
        };
        return semver::VersionReq::parse(&format!(">={lo}, {upper}")).ok();
    }
    // Join an operator to its version (`>= 1.2` → `>=1.2`), then turn each
    // whitespace-separated comparator into the `semver` crate's syntax.
    let mut tokens: Vec<String> = Vec::new();
    let mut pending = String::new();
    for t in alt.split_whitespace() {
        if matches!(t, ">" | ">=" | "<" | "<=" | "=" | "^" | "~") {
            pending = t.to_string();
            continue;
        }
        tokens.push(format!("{pending}{t}"));
        pending.clear();
    }
    let comparators: Option<Vec<String>> = tokens.iter().map(|t| npm_comparator(t)).collect();
    semver::VersionReq::parse(&comparators?.join(", ")).ok()
}

fn npm_comparator(t: &str) -> Option<String> {
    let op_len = t
        .find(|c: char| c.is_ascii_digit() || matches!(c, 'x' | 'X' | '*' | 'v'))
        .unwrap_or(t.len());
    let (op, ver) = t.split_at(op_len);
    let ver = ver.trim_start_matches('v').replace(['x', 'X'], "*");
    if ver.is_empty() {
        return None;
    }
    let full = ver.split('.').count() >= 3 && !ver.contains('*');
    Some(match op {
        // A bare full version is exact in npm, a caret in Cargo.
        "" if full => format!("={ver}"),
        "" => ver,
        "=" | ">" | ">=" | "<" | "<=" | "^" | "~" => format!("{op}{ver}"),
        _ => return None,
    })
}

/// `1.2` → `1.2.0`, for hyphen-range lower bounds.
fn pad(v: &str) -> Option<String> {
    let v = v.trim_start_matches('v');
    let mut parts: Vec<&str> = v.split('.').collect();
    if parts.iter().take(3).any(|p| p.parse::<u64>().is_err()) && parts.len() <= 3 {
        return None;
    }
    while parts.len() < 3 {
        parts.push("0");
    }
    Some(parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm(req: &str, v: &str) -> Option<bool> {
        allows(Ecosystem::Npm, req, v)
    }

    #[test]
    fn npm_ranges() {
        assert_eq!(npm("^4.17.0", "4.17.21"), Some(true));
        assert_eq!(npm("^4.17.0", "5.0.0"), Some(false));
        assert_eq!(npm("~1.2.3", "1.2.9"), Some(true));
        assert_eq!(npm("~1.2.3", "1.3.0"), Some(false));
        assert_eq!(npm("1.2.3", "1.2.4"), Some(false), "bare version is exact");
        assert_eq!(npm("1.2", "1.2.9"), Some(true), "partial is a wildcard");
        assert_eq!(npm("1.x", "1.9.0"), Some(true));
        assert_eq!(npm(">= 2.1.2 < 3.0.0", "2.5.0"), Some(true));
        assert_eq!(npm(">=2.1.2 <3", "3.0.0"), Some(false));
        assert_eq!(npm("^1.0.0 || ^2.0.0", "2.3.0"), Some(true));
        assert_eq!(npm("1.2 - 2.3", "2.3.9"), Some(true));
        assert_eq!(npm("1.2 - 2.3", "2.4.0"), Some(false));
        assert_eq!(npm("*", "9.9.9"), Some(true));
        assert_eq!(npm("", "9.9.9"), Some(true));
        assert_eq!(npm("workspace:^1.0.0", "1.4.0"), Some(true));
        assert_eq!(npm("github:user/repo#v1", "1.0.0"), None);
        assert_eq!(npm("latest", "1.0.0"), None);
    }

    #[test]
    fn cargo_requirements() {
        let c = |r, v| allows(Ecosystem::Cargo, r, v);
        assert_eq!(c("1.0", "1.9.3"), Some(true));
        assert_eq!(c("0.3", "0.4.0"), Some(false));
        assert_eq!(c("=0.3.1", "0.3.2"), Some(false));
        assert_eq!(c(">=1.2, <1.5", "1.4.0"), Some(true));
        assert_eq!(c("", "1.0.0"), Some(true));
    }

    #[test]
    fn python_requirements() {
        assert_eq!(pep440_allows(">=2.0,<3", "2.31.0"), Some(true));
        assert_eq!(pep440_allows("<2.2", "2.2.0"), Some(false));
        assert_eq!(pep440_allows("~=1.4", "1.9"), Some(true));
        assert_eq!(pep440_allows("", "1.0"), Some(true));
        assert_eq!(poetry_allows("^1.2", "1.9.0"), Some(true));
        assert_eq!(poetry_allows("^1.2", "2.0.0"), Some(false));
        assert_eq!(poetry_allows("^0.3.1", "0.4.0"), Some(false));
        assert_eq!(poetry_allows("~1.2", "1.2.7"), Some(true));
        assert_eq!(poetry_allows("~1.2", "1.3.0"), Some(false));
        assert_eq!(poetry_allows("2.0.1", "2.0.2"), Some(false));
        assert_eq!(poetry_allows(">=1,<3", "2.5"), Some(true));
    }
}
