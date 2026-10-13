//! Licenses as SPDX expressions, and whether an expression is acceptable
//! under `deny_licenses` / `allow_licenses`.
//!
//! An `OR` expression is acceptable when any alternative is (the user picks
//! one); an `AND` expression only when every part is.

/// The registry's license field as an SPDX expression, or `None` when it is
/// missing or not recognisable (a URL, "SEE LICENSE IN …", free text).
pub fn normalize(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Old crates.io style: `MIT/Apache-2.0`.
    let raw = if raw.contains('/') && !raw.contains("://") {
        raw.split('/')
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" OR ")
    } else {
        raw.to_string()
    };
    let alternatives: Vec<&str> = raw.split(" OR ").collect();
    if alternatives.len() > 1 && alternatives.iter().all(|a| known_name(a).is_some()) {
        return Some(
            alternatives
                .iter()
                .filter_map(|a| known_name(a))
                .collect::<Vec<_>>()
                .join(" OR "),
        );
    }
    if let Some(id) = known_name(&raw) {
        return Some(id.to_string());
    }
    (is_spdx_expression(&raw) && parse(&raw).is_some()).then_some(raw)
}

/// Common non-SPDX spellings (PyPI classifiers, free text) of SPDX ids.
fn known_name(s: &str) -> Option<&'static str> {
    let k = s.trim().to_ascii_lowercase();
    Some(match k.as_str() {
        "mit" | "mit license" | "the mit license" | "mit-license" => "MIT",
        "isc" | "isc license" | "isc license (iscl)" => "ISC",
        "apache-2.0"
        | "apache 2.0"
        | "apache 2"
        | "apache license 2.0"
        | "apache license, version 2.0"
        | "apache software license"
        | "apache-2" => "Apache-2.0",
        "bsd-2-clause" | "bsd 2-clause" | "simplified bsd" => "BSD-2-Clause",
        "bsd-3-clause" | "bsd 3-clause" | "new bsd" | "new bsd license" => "BSD-3-Clause",
        "mozilla public license 2.0 (mpl 2.0)" | "mpl 2.0" | "mpl-2.0" => "MPL-2.0",
        "python software foundation license" | "psf" | "psf-2.0" => "PSF-2.0",
        "the unlicense (unlicense)" | "unlicense" => "Unlicense",
        "zlib" | "zlib/libpng license" => "Zlib",
        "gnu general public license v2 (gplv2)" => "GPL-2.0",
        "gnu general public license v3 (gplv3)" => "GPL-3.0",
        "gnu lesser general public license v3 (lgplv3)" => "LGPL-3.0",
        "gnu affero general public license v3" => "AGPL-3.0",
        _ => return None,
    })
}

fn is_spdx_expression(s: &str) -> bool {
    !s.is_empty()
        && s.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter(|t| !t.is_empty())
            .all(|t| {
                matches!(t, "AND" | "OR" | "WITH")
                    || t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | ':'))
                        && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            })
}

#[derive(Debug, PartialEq)]
enum Expr {
    Id(String),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

fn parse(s: &str) -> Option<Expr> {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut pos = 0;
    let e = parse_or(&tokens, &mut pos)?;
    (pos == tokens.len()).then_some(e)
}

fn parse_or(t: &[&str], pos: &mut usize) -> Option<Expr> {
    let mut parts = vec![parse_and(t, pos)?];
    while t.get(*pos) == Some(&"OR") {
        *pos += 1;
        parts.push(parse_and(t, pos)?);
    }
    Some(if parts.len() == 1 {
        parts.remove(0)
    } else {
        Expr::Or(parts)
    })
}

fn parse_and(t: &[&str], pos: &mut usize) -> Option<Expr> {
    let mut parts = vec![parse_atom(t, pos)?];
    while t.get(*pos) == Some(&"AND") {
        *pos += 1;
        parts.push(parse_atom(t, pos)?);
    }
    Some(if parts.len() == 1 {
        parts.remove(0)
    } else {
        Expr::And(parts)
    })
}

fn parse_atom(t: &[&str], pos: &mut usize) -> Option<Expr> {
    let tok = *t.get(*pos)?;
    *pos += 1;
    if tok == "(" {
        let e = parse_or(t, pos)?;
        (t.get(*pos) == Some(&")")).then_some(())?;
        *pos += 1;
        return Some(e);
    }
    if matches!(tok, ")" | "AND" | "OR" | "WITH") {
        return None;
    }
    // `GPL-2.0 WITH Classpath-exception-2.0`: judged by the license.
    if t.get(*pos) == Some(&"WITH") {
        *pos += 2;
    }
    Some(Expr::Id(tok.to_string()))
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Allowed,
    /// The ids that made it unacceptable.
    Denied(Vec<String>),
    /// No license, or one that could not be read.
    Unknown,
}

/// The base of an id, without `-only` / `-or-later` / `+`, so that denying
/// `GPL-3.0-only` also catches the ambiguous `GPL-3.0`.
fn base(id: &str) -> String {
    let id = id.to_ascii_lowercase();
    let id = id.trim_end_matches('+');
    id.strip_suffix("-only")
        .or_else(|| id.strip_suffix("-or-later"))
        .unwrap_or(id)
        .to_string()
}

fn listed(id: &str, list: &[String]) -> bool {
    list.iter().any(|l| {
        l.eq_ignore_ascii_case(id) || {
            // An unqualified id matches either qualified form, both ways.
            let unqualified = |s: &str| !s.contains("-only") && !s.contains("-or-later");
            (unqualified(id) || unqualified(l)) && base(l) == base(id)
        }
    })
}

pub fn verdict(license: Option<&str>, deny: &[String], allow: &[String]) -> Verdict {
    let Some(expr) = license.and_then(parse) else {
        return Verdict::Unknown;
    };
    let bad_id = |id: &str| listed(id, deny) || (!allow.is_empty() && !listed(id, allow));
    fn denied(e: &Expr, bad: &dyn Fn(&str) -> bool, out: &mut Vec<String>) -> bool {
        match e {
            Expr::Id(id) => {
                let b = bad(id);
                if b {
                    out.push(id.clone());
                }
                b
            }
            Expr::And(parts) => {
                let mut any = false;
                for p in parts {
                    any |= denied(p, bad, out);
                }
                any
            }
            Expr::Or(parts) => {
                let mut tmp = Vec::new();
                let all = parts.iter().all(|p| denied(p, bad, &mut tmp));
                if all {
                    out.extend(tmp);
                }
                all
            }
        }
    }
    let mut ids = Vec::new();
    if denied(&expr, &bad_id, &mut ids) {
        ids.dedup();
        Verdict::Denied(ids)
    } else {
        Verdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn normalizes_common_forms() {
        assert_eq!(normalize("MIT").as_deref(), Some("MIT"));
        assert_eq!(
            normalize("MIT/Apache-2.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(normalize("MIT License").as_deref(), Some("MIT"));
        assert_eq!(
            normalize("Apache Software License OR MIT License").as_deref(),
            Some("Apache-2.0 OR MIT")
        );
        assert_eq!(
            normalize("(MIT OR CC0-1.0)").as_deref(),
            Some("(MIT OR CC0-1.0)")
        );
        assert_eq!(normalize("SEE LICENSE IN LICENSE.md"), None);
        assert_eq!(normalize("https://example.com/license"), None);
        assert_eq!(normalize(""), None);
    }

    #[test]
    fn deny_and_allow() {
        let deny = list(&["AGPL-3.0-only", "GPL-3.0-only"]);
        assert_eq!(verdict(Some("MIT"), &deny, &[]), Verdict::Allowed);
        assert_eq!(
            verdict(Some("AGPL-3.0-only"), &deny, &[]),
            Verdict::Denied(list(&["AGPL-3.0-only"]))
        );
        // A choice that includes an acceptable license is acceptable.
        assert_eq!(
            verdict(Some("(MIT OR GPL-3.0-only)"), &deny, &[]),
            Verdict::Allowed
        );
        assert_eq!(
            verdict(
                Some("MIT AND GPL-3.0-or-later"),
                &list(&["GPL-3.0-or-later"]),
                &[]
            ),
            Verdict::Denied(list(&["GPL-3.0-or-later"]))
        );
        // The ambiguous old id is caught by a qualified deny entry.
        assert_eq!(
            verdict(Some("GPL-3.0"), &deny, &[]),
            Verdict::Denied(list(&["GPL-3.0"]))
        );
        assert_eq!(verdict(None, &deny, &[]), Verdict::Unknown);
        let allow = list(&["MIT", "Apache-2.0"]);
        assert_eq!(
            verdict(Some("Apache-2.0 OR MIT"), &[], &allow),
            Verdict::Allowed
        );
        assert_eq!(
            verdict(Some("BSD-3-Clause"), &[], &allow),
            Verdict::Denied(list(&["BSD-3-Clause"]))
        );
        assert_eq!(
            verdict(Some("Apache-2.0 WITH LLVM-exception"), &[], &allow),
            Verdict::Allowed
        );
    }
}
