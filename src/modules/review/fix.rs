//! How to get a vulnerable dependency to a fixed version.
//!
//! For `X@v` with a fix in `F`:
//! 1. If everything that depends on X already allows F, a refresh of X is
//!    enough.
//! 2. Otherwise, for each dependent whose requirement excludes F: if it is
//!    the project itself, raise the project's requirement; if it is a direct
//!    dependency D, find the lowest release of D that allows `X >= F` and say
//!    whether it is within the project's current requirement on D.
//! 3. When no release allows it (or the blocker is deeper in the tree), force
//!    X with the package manager's override mechanism, where there is one.

use super::manifest::{self, Req};
use crate::deps::{Ecosystem, Format, Lockfile, Source, normalize_python};
use crate::modules::audit::Advisory;
use crate::registry::requirements::{self, VersionReqs};
use crate::utils::http::Fetched;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Everything that depends on the package allows the fix: re-resolve it.
    Refresh { command: String },
    /// The project's own requirement excludes the fix.
    RaiseRequirement {
        requirement: String,
        command: String,
    },
    /// A direct dependency's requirement excludes the fix; a newer release
    /// of it does not. `compatible`: within the project's current requirement.
    UpgradeParent {
        parent: String,
        from: String,
        to: String,
        compatible: bool,
        command: String,
    },
    /// Force the version with the package manager's override mechanism.
    Override { file: String, snippet: String },
    /// Change a pin by hand.
    Edit { file: String, change: String },
}

#[derive(Serialize, Debug, Clone)]
pub struct Guidance {
    pub package: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    pub steps: Vec<Step>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

type Requires = HashMap<String, Vec<String>>;

/// Registry answers, fetched once per run.
#[derive(Default)]
pub struct Ctx {
    versions: HashMap<(Ecosystem, String), Option<Vec<VersionReqs>>>,
    pypi: HashMap<(String, String), Option<Requires>>,
    /// Lookups that failed, for an incomplete check.
    pub unavailable: Vec<String>,
}

impl Ctx {
    fn all_versions(&mut self, eco: Ecosystem, name: &str) -> Option<&Vec<VersionReqs>> {
        let unavailable = &mut self.unavailable;
        self.versions
            .entry((eco, name.to_string()))
            .or_insert_with(|| match requirements::all_versions(eco, name) {
                Fetched::Json(v) => Some(v),
                Fetched::NotFound => None,
                Fetched::Unavailable(e) => {
                    unavailable.push(e);
                    None
                }
            })
            .as_ref()
    }

    /// What `name@version` requires of `dep`: `Some(reqs)` (empty when it no
    /// longer depends on it), `None` when unknown.
    fn requires(
        &mut self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        dep: &str,
    ) -> Option<Vec<String>> {
        let key = |d: &str| match eco {
            Ecosystem::PyPI => normalize_python(d),
            _ => d.to_string(),
        };
        let reqs: HashMap<String, Vec<String>> = if eco == Ecosystem::PyPI {
            let unavailable = &mut self.unavailable;
            self.pypi
                .entry((name.to_string(), version.to_string()))
                .or_insert_with(|| match requirements::of_version(eco, name, version) {
                    Fetched::Json(r) => Some(r),
                    Fetched::NotFound => None,
                    Fetched::Unavailable(e) => {
                        unavailable.push(e);
                        None
                    }
                })
                .clone()?
        } else {
            self.all_versions(eco, name)?
                .iter()
                .find(|v| v.version == version)?
                .requires
                .clone()
        };
        let want = key(dep);
        Some(
            reqs.into_iter()
                .filter(|(k, _)| key(k) == want)
                .flat_map(|(_, v)| v)
                .collect(),
        )
    }

    /// Whether `name@version` lets `dep` be at one of `targets`. `None` when
    /// unknown.
    fn parent_allows(
        &mut self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        dep: &str,
        targets: &[String],
    ) -> Option<bool> {
        let reqs = ParentReq::Registry(self.requires(eco, name, version, dep)?);
        any_target(targets, |t| reqs.allows(eco, t))
    }

    /// The lowest release of `parent` above `from` that lets `dep` be at one
    /// of `targets`. PyPI needs a request per version, so it is binary-searched
    /// (newer releases are assumed not to go back to older requirements).
    fn lowest_parent(
        &mut self,
        eco: Ecosystem,
        parent: &str,
        from: &str,
        dep: &str,
        targets: &[String],
    ) -> Option<String> {
        let pre_ok = requirements::is_prerelease(eco, from);
        let candidates: Vec<String> = self
            .all_versions(eco, parent)?
            .iter()
            .filter(|v| !v.withdrawn)
            .filter(|v| pre_ok || !requirements::is_prerelease(eco, &v.version))
            .filter(|v| requirements::less(eco, from, &v.version) == Some(true))
            .map(|v| v.version.clone())
            .collect();
        if eco != Ecosystem::PyPI {
            return candidates
                .into_iter()
                .find(|v| self.parent_allows(eco, parent, v, dep, targets) == Some(true));
        }
        let ok =
            |ctx: &mut Ctx, v: &str| ctx.parent_allows(eco, parent, v, dep, targets) == Some(true);
        let last = candidates.last()?.clone();
        if !ok(self, &last) {
            return None;
        }
        let (mut lo, mut hi) = (0usize, candidates.len() - 1);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if ok(self, &candidates[mid]) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Some(candidates[lo].clone())
    }
}

/// What a dependent requires of the package.
enum ParentReq {
    Manifest(Req),
    /// Every requirement a registry release declares (empty: none).
    Registry(Vec<String>),
}

impl ParentReq {
    fn allows(&self, eco: Ecosystem, version: &str) -> Option<bool> {
        match self {
            ParentReq::Manifest(r) => r.allows(eco, version),
            ParentReq::Registry(reqs) => {
                let mut all = Some(true);
                for r in reqs {
                    match super::ranges::allows(eco, r, version) {
                        Some(true) => {}
                        Some(false) => return Some(false),
                        None => all = None,
                    }
                }
                all
            }
        }
    }

    fn text(&self) -> String {
        match self {
            ParentReq::Manifest(r) => r.text().to_string(),
            ParentReq::Registry(reqs) => reqs.join(" and "),
        }
    }
}

/// `Some(true)` when `f` allows any target, `Some(false)` when it rules
/// them all out, `None` when it cannot tell.
fn any_target(targets: &[String], mut f: impl FnMut(&str) -> Option<bool>) -> Option<bool> {
    let mut unknown = false;
    for t in targets {
        match f(t) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown { None } else { Some(false) }
}

/// Versions above `version` that none of the (fixable) advisories affect:
/// every fixed version they name, on any release line, lowest first. A
/// requirement that allows any of them can be satisfied safely. Without
/// range data, the highest of the per-line fixes.
fn safe_targets(eco: Ecosystem, version: &str, advisories: &[Advisory]) -> Vec<String> {
    use crate::modules::osv_db::{Event, affects};
    let fixable: Vec<&Advisory> = advisories.iter().filter(|a| a.fixed_in.is_some()).collect();
    if fixable.iter().any(|a| a.entries.is_empty()) {
        return fixable
            .iter()
            .filter_map(|a| a.fixed_in.clone())
            .reduce(|a, b| {
                if requirements::less(eco, &a, &b) == Some(true) {
                    b
                } else {
                    a
                }
            })
            .into_iter()
            .collect();
    }
    let mut candidates: Vec<String> = fixable
        .iter()
        .flat_map(|a| &a.entries)
        .flat_map(|e| &e.ranges)
        .flat_map(|r| &r.events)
        .filter_map(|e| match e {
            Event::Fixed(v) => Some(v.clone()),
            _ => None,
        })
        .filter(|v| requirements::less(eco, version, v) == Some(true))
        .collect();
    candidates.sort_by(|a, b| match requirements::less(eco, a, b) {
        Some(true) => std::cmp::Ordering::Less,
        Some(false) if a != b => std::cmp::Ordering::Greater,
        _ => std::cmp::Ordering::Equal,
    });
    candidates.dedup();
    candidates.retain(|t| {
        fixable
            .iter()
            .flat_map(|a| &a.entries)
            .all(|e| affects(eco.osv(), e, t) != Some(true))
    });
    candidates
}

pub fn guidance(lock: &Lockfile, x: usize, advisories: &[Advisory], ctx: &mut Ctx) -> Guidance {
    let pkg = &lock.packages[x];
    let eco = lock.ecosystem;
    let mut g = Guidance {
        package: pkg.name.clone(),
        version: pkg.version.clone(),
        fixed_in: None,
        steps: Vec::new(),
        notes: Vec::new(),
    };
    let unfixed: Vec<&str> = advisories
        .iter()
        .filter(|a| a.fixed_in.is_none())
        .map(|a| a.id.as_str())
        .collect();
    if !unfixed.is_empty() {
        g.notes.push(format!(
            "no fixed release is known for {}",
            unfixed.join(", ")
        ));
    }
    let targets = safe_targets(eco, &pkg.version, advisories);
    g.fixed_in = targets.first().cloned();
    let Some(fix) = g.fixed_in.clone() else {
        return g;
    };
    let file = lock
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cmd = Commands::new(lock);

    if lock.format == Format::Requirements {
        g.steps.push(Step::Edit {
            file,
            change: format!("{}=={fix}", pkg.name),
        });
        return g;
    }
    if eco == Ecosystem::Go {
        g.steps.push(Step::Refresh {
            command: cmd.wrap(format!("go get {}@{}", pkg.name, go_version(&fix))),
        });
        return g;
    }
    if !lock.edges_known {
        g.steps.push(Step::Refresh {
            command: cmd.refresh(&pkg.name, &pkg.version, &fix),
        });
        g.notes.push(format!(
            "{file} records no dependency edges, so what else requires {} is unknown",
            pkg.name
        ));
        return g;
    }

    let parents: Vec<usize> = (0..lock.packages.len())
        .filter(|&p| lock.edges[p].iter().any(|(t, _)| *t == x))
        .collect();
    let direct = lock.direct();
    let mut blocked: Vec<(usize, String)> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut known: Vec<ParentReq> = Vec::new();
    for &p in &parents {
        let parent = &lock.packages[p];
        let req: Option<ParentReq> = if parent.member {
            manifest::requirement(lock, parent, &pkg.name).map(ParentReq::Manifest)
        } else if matches!(parent.source, Source::Registry { url: None }) {
            ctx.requires(eco, &parent.name, &parent.version, &pkg.name)
                .map(ParentReq::Registry)
        } else {
            None
        };
        match req
            .as_ref()
            .and_then(|r| any_target(&targets, |t| r.allows(eco, t)))
        {
            Some(true) => known.extend(req),
            Some(false) => blocked.push((p, req.map(|r| r.text()).unwrap_or_default())),
            None => unknown.push(parent.id()),
        }
    }

    if blocked.is_empty() {
        // The lowest safe version every dependent allows.
        let to = targets
            .iter()
            .find(|t| known.iter().all(|r| r.allows(eco, t) == Some(true)))
            .unwrap_or(&fix);
        g.steps.push(Step::Refresh {
            command: cmd.refresh(&pkg.name, &pkg.version, to),
        });
        if !unknown.is_empty() {
            g.notes.push(format!(
                "could not read what {} require(s) of {}; the refresh may stop below {fix}",
                unknown.join(", "),
                pkg.name
            ));
        }
        return g;
    }

    let mut forced: Vec<String> = Vec::new();
    for (p, req) in blocked {
        let parent = &lock.packages[p];
        if parent.member {
            g.steps.push(Step::RaiseRequirement {
                requirement: format!("{} requires {} {req}", parent.name, pkg.name),
                command: cmd.raise(&pkg.name, &fix),
            });
            continue;
        }
        if direct.contains(&p) && matches!(parent.source, Source::Registry { url: None }) {
            if let Some(to) =
                ctx.lowest_parent(eco, &parent.name, &parent.version, &pkg.name, &targets)
            {
                // Within every member's requirement on the parent?
                let members: Vec<Req> = (0..lock.packages.len())
                    .filter(|&m| {
                        lock.packages[m].member && lock.edges[m].iter().any(|(t, _)| *t == p)
                    })
                    .filter_map(|m| manifest::requirement(lock, &lock.packages[m], &parent.name))
                    .collect();
                let compatible = !members.is_empty()
                    && members.iter().all(|r| r.allows(eco, &to) == Some(true));
                g.steps.push(Step::UpgradeParent {
                    parent: parent.name.clone(),
                    from: parent.version.clone(),
                    command: cmd.upgrade(&parent.name, &parent.version, &to, compatible),
                    to,
                    compatible,
                });
                continue;
            }
            g.notes.push(format!(
                "no release of {} allows {} {fix} yet",
                parent.name, pkg.name
            ));
        } else {
            g.notes
                .push(format!("{} requires {} {req}", parent.id(), pkg.name));
        }
        forced.push(parent.name.clone());
    }
    if !forced.is_empty() {
        match cmd.force(&pkg.name, &fix, &forced) {
            Some(step) => g.steps.push(step),
            None => g.notes.push(cmd.no_override(&pkg.name, &forced)),
        }
    }
    g
}

fn go_version(v: &str) -> String {
    if v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{v}")
    }
}

/// Package-manager commands for one lockfile, run in its directory.
struct Commands<'a> {
    format: Format,
    dir: Option<&'a Path>,
    file: String,
}

impl<'a> Commands<'a> {
    fn new(lock: &'a Lockfile) -> Commands<'a> {
        let dir = lock
            .path
            .parent()
            .filter(|d| !d.as_os_str().is_empty() && *d != Path::new("."));
        Commands {
            format: lock.format,
            dir,
            file: lock
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }

    fn wrap(&self, cmd: String) -> String {
        match self.dir {
            Some(d) => format!(
                "cd {} && {cmd}",
                d.to_string_lossy().trim_start_matches("./")
            ),
            None => cmd,
        }
    }

    /// Re-resolve `name` to the newest version its dependents allow.
    fn refresh(&self, name: &str, version: &str, fix: &str) -> String {
        self.wrap(match self.format {
            Format::PackageLock => format!("npm update {name}"),
            Format::Pnpm => format!("pnpm update {name}"),
            // `yarn upgrade` only moves direct dependencies.
            Format::Yarn1 => format!(
                "delete the {name}@… entries from {}, then run yarn install",
                self.file
            ),
            Format::YarnBerry => format!("yarn up -R {name}"),
            Format::Bun => format!("bun update {name}"),
            Format::CargoLock => format!("cargo update -p {name}@{version} --precise {fix}"),
            Format::UvLock => format!("uv lock -P {name}"),
            Format::PoetryLock => format!("poetry update {name}"),
            Format::Pylock => format!("re-lock {} so that {name} >= {fix}", self.file),
            Format::Requirements => format!("set {name}=={fix} in {}", self.file),
            Format::GoMod | Format::GoSum => format!("go get {name}@{}", go_version(fix)),
        })
    }

    /// Raise the project's own requirement on `name` to `fix`.
    fn raise(&self, name: &str, fix: &str) -> String {
        self.wrap(match self.format {
            Format::PackageLock => format!("npm install {name}@^{fix}"),
            Format::Pnpm => format!("pnpm add {name}@^{fix}"),
            Format::Yarn1 => format!("yarn add {name}@^{fix}"),
            Format::YarnBerry => format!("yarn up {name}@^{fix}"),
            Format::Bun => format!("bun add {name}@^{fix}"),
            Format::CargoLock => format!("cargo add {name}@{fix}"),
            Format::UvLock => format!("uv add '{name}>={fix}'"),
            Format::PoetryLock => format!("poetry add '{name}>={fix}'"),
            Format::Pylock | Format::Requirements => {
                format!("require {name}>={fix} and re-lock {}", self.file)
            }
            Format::GoMod | Format::GoSum => format!("go get {name}@{}", go_version(fix)),
        })
    }

    /// Move the direct dependency `name` from `from` to at least `to`.
    fn upgrade(&self, name: &str, from: &str, to: &str, compatible: bool) -> String {
        self.wrap(match (self.format, compatible) {
            (Format::PackageLock, true) => format!("npm update {name}"),
            (Format::PackageLock, false) => format!("npm install {name}@^{to}"),
            (Format::Pnpm, true) => format!("pnpm update {name}"),
            (Format::Pnpm, false) => format!("pnpm add {name}@^{to}"),
            (Format::Yarn1, true) => format!("yarn upgrade {name}"),
            (Format::Yarn1, false) => format!("yarn add {name}@^{to}"),
            (Format::YarnBerry, true) => format!("yarn up -R {name}"),
            (Format::YarnBerry, false) => format!("yarn up {name}@^{to}"),
            (Format::Bun, true) => format!("bun update {name}"),
            (Format::Bun, false) => format!("bun add {name}@^{to}"),
            (Format::CargoLock, true) => format!("cargo update -p {name}@{from} --precise {to}"),
            (Format::CargoLock, false) => format!("cargo add {name}@{to}"),
            (Format::UvLock, true) => format!("uv lock -P {name}"),
            (Format::UvLock, false) => format!("uv add '{name}>={to}'"),
            (Format::PoetryLock, true) => format!("poetry update {name}"),
            (Format::PoetryLock, false) => format!("poetry add '{name}>={to}'"),
            (Format::Pylock | Format::Requirements, _) => {
                format!("require {name}>={to} and re-lock {}", self.file)
            }
            (Format::GoMod | Format::GoSum, _) => format!("go get {name}@{}", go_version(to)),
        })
    }

    /// Force `name` to `fix` under the blocking `parents`, where the package
    /// manager can.
    fn force(&self, name: &str, fix: &str, parents: &[String]) -> Option<Step> {
        let json = |pairs: Vec<String>| pairs.join(", ");
        let (file, snippet) = match self.format {
            Format::PackageLock => (
                "package.json",
                format!(
                    "\"overrides\": {{ {} }}",
                    json(
                        parents
                            .iter()
                            .map(|p| format!("\"{p}\": {{ \"{name}\": \"^{fix}\" }}"))
                            .collect()
                    )
                ),
            ),
            Format::Pnpm => (
                "package.json",
                format!(
                    "\"pnpm\": {{ \"overrides\": {{ {} }} }}",
                    json(
                        parents
                            .iter()
                            .map(|p| format!("\"{p}>{name}\": \"^{fix}\""))
                            .collect()
                    )
                ),
            ),
            Format::Yarn1 | Format::YarnBerry => (
                "package.json",
                format!(
                    "\"resolutions\": {{ {} }}",
                    json(
                        parents
                            .iter()
                            .map(|p| format!("\"{p}/{name}\": \"^{fix}\""))
                            .collect()
                    )
                ),
            ),
            // Bun's overrides are top-level only.
            Format::Bun => (
                "package.json",
                format!("\"overrides\": {{ \"{name}\": \"^{fix}\" }}"),
            ),
            Format::UvLock => (
                "pyproject.toml",
                format!("[tool.uv]\noverride-dependencies = [\"{name}>={fix}\"]"),
            ),
            _ => return None,
        };
        let file = match self.dir {
            Some(d) => d
                .join(file)
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string(),
            None => file.to_string(),
        };
        Some(Step::Override { file, snippet })
    }

    fn no_override(&self, name: &str, parents: &[String]) -> String {
        match self.format {
            Format::CargoLock => format!(
                "Cargo cannot force {name} past what {} require(s): upgrade or patch {}",
                parents.join(", "),
                if parents.len() == 1 { "it" } else { "them" }
            ),
            Format::PoetryLock => format!(
                "Poetry has no overrides: {} must allow the fixed {name} first",
                parents.join(", ")
            ),
            _ => format!("{} must allow the fixed {name} first", parents.join(", ")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{EdgeKind, Package, Scope};
    use crate::report::Severity;

    fn adv(id: &str, fixed: Option<&str>) -> Advisory {
        Advisory {
            id: id.into(),
            summary: String::new(),
            severity: Severity::High,
            fixed_in: fixed.map(str::to_string),
            reference: None,
            entries: Vec::new(),
            aliases: Vec::new(),
        }
    }

    #[test]
    fn without_ranges_the_target_is_the_highest_fix() {
        let a = [
            adv("A", Some("1.2.5")),
            adv("B", Some("1.10.0")),
            adv("C", None),
        ];
        assert_eq!(safe_targets(Ecosystem::Npm, "1.2.0", &a), ["1.10.0"]);
    }

    #[test]
    fn safe_targets_span_release_lines() {
        use crate::modules::osv_db::{Entry, Event, Range};
        let ranges = |spans: &[(&str, &str)]| Entry {
            id: "X".into(),
            summary: String::new(),
            severity: None,
            reference: None,
            versions: Vec::new(),
            ranges: vec![Range {
                kind: "SEMVER".into(),
                events: spans
                    .iter()
                    .flat_map(|(i, f)| {
                        [
                            Event::Introduced(i.to_string()),
                            Event::Fixed(f.to_string()),
                        ]
                    })
                    .collect(),
            }],
        };
        // minimist: GHSA-vh95 (<0.2.1, 1.0.0–1.2.3) and GHSA-xvch (<0.2.4, 1.0.0–1.2.6).
        let mut a = adv("GHSA-vh95", Some("0.2.1"));
        a.entries = vec![ranges(&[("0", "0.2.1"), ("1.0.0", "1.2.3")])];
        let mut b = adv("GHSA-xvch", Some("0.2.4"));
        b.entries = vec![ranges(&[("0", "0.2.4"), ("1.0.0", "1.2.6")])];
        assert_eq!(
            safe_targets(Ecosystem::Npm, "0.0.8", &[a, b]),
            ["0.2.4", "1.2.6"]
        );
    }

    /// app → lodash (direct, manifest `^4.17.0`); app → old-lib → minimist.
    fn npm_project(dir: &Path, lodash_req: &str) -> Lockfile {
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"dependencies": {{"lodash": "{lodash_req}"}}}}"#),
        )
        .unwrap();
        let mut lock = Lockfile::new_for_tests();
        lock.path = dir.join("package-lock.json");
        lock.format = Format::PackageLock;
        let app = lock.add(Package::member("app", "1.0.0", "."));
        let mut lodash = Package::new("lodash", "4.17.20", Source::registry());
        lodash.scope = Scope::Prod;
        let lodash = lock.add(lodash);
        lock.link(app, lodash);
        let _ = EdgeKind::Normal;
        lock
    }

    #[test]
    fn direct_dependency_within_range_is_a_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let lock = npm_project(dir.path(), "^4.17.0");
        let g = guidance(
            &lock,
            1,
            &[adv("GHSA-1", Some("4.17.21"))],
            &mut Ctx::default(),
        );
        assert_eq!(g.fixed_in.as_deref(), Some("4.17.21"));
        assert!(
            matches!(&g.steps[..], [Step::Refresh { command }] if command.ends_with("npm update lodash"))
        );
    }

    #[test]
    fn direct_dependency_pinned_below_the_fix_raises_the_requirement() {
        let dir = tempfile::tempdir().unwrap();
        let lock = npm_project(dir.path(), "4.17.20");
        let g = guidance(
            &lock,
            1,
            &[adv("GHSA-1", Some("4.17.21"))],
            &mut Ctx::default(),
        );
        assert!(
            matches!(&g.steps[..], [Step::RaiseRequirement { command, .. }] if command.ends_with("npm install lodash@^4.17.21")),
            "{:?}",
            g.steps
        );
    }

    #[test]
    fn no_fix_no_steps() {
        let dir = tempfile::tempdir().unwrap();
        let lock = npm_project(dir.path(), "^4.17.0");
        let g = guidance(&lock, 1, &[adv("GHSA-1", None)], &mut Ctx::default());
        assert!(g.steps.is_empty());
        assert!(g.notes[0].contains("no fixed release"));
    }

    #[test]
    fn override_snippets() {
        let lock = |f: Format| {
            let mut l = Lockfile::new_for_tests();
            l.path = "web/package-lock.json".into();
            l.format = f;
            l
        };
        let pnpm = lock(Format::Pnpm);
        let step = Commands::new(&pnpm).force("minimist", "1.2.6", &["old-lib".into()]);
        assert_eq!(
            step,
            Some(Step::Override {
                file: "web/package.json".into(),
                snippet: "\"pnpm\": { \"overrides\": { \"old-lib>minimist\": \"^1.2.6\" } }"
                    .into()
            })
        );
        let cargo = lock(Format::CargoLock);
        assert_eq!(
            Commands::new(&cargo).force("x", "1.0.0", &["p".into()]),
            None
        );
        assert_eq!(
            Commands::new(&cargo).refresh("x", "0.9.1", "0.9.3"),
            "cd web && cargo update -p x@0.9.1 --precise 0.9.3"
        );
    }
}
