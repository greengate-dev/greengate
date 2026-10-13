//! Parser tests against lockfiles written by the real package managers
//! (tests/fixtures/deps). Every JS fixture installs the same project:
//! dependencies debug@2.6.9 (→ ms@2.0.0), ms@2.1.3, @sindresorhus/is@4.6.0;
//! devDependencies is-number@7.0.0.

use super::*;

fn fixture(rel: &str) -> Lockfile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/deps")
        .join(rel);
    load(&path).unwrap_or_else(|e| panic!("{rel}: {e:#}"))
}

fn ids(lock: &Lockfile, idx: &[usize]) -> Vec<String> {
    let mut v: Vec<String> = idx.iter().map(|&i| lock.packages[i].id()).collect();
    v.sort();
    v
}

fn find(lock: &Lockfile, id: &str) -> usize {
    lock.packages
        .iter()
        .position(|p| p.id() == id)
        .unwrap_or_else(|| {
            panic!(
                "{id} not in {:?}",
                lock.packages.iter().map(Package::id).collect::<Vec<_>>()
            )
        })
}

fn chain(lock: &Lockfile, id: &str) -> Vec<String> {
    lock.why(find(lock, id))
        .unwrap_or_default()
        .iter()
        .skip(1) // the member
        .map(|&i| lock.packages[i].id())
        .collect()
}

/// The shared JS fixture, whatever wrote it.
fn assert_js_fixture(rel: &str) {
    let lock = fixture(rel);
    let deps: Vec<String> = {
        let mut d: Vec<String> = lock.dependencies().map(Package::id).collect();
        d.sort();
        d
    };
    assert_eq!(
        deps,
        [
            "@sindresorhus/is@4.6.0",
            "debug@2.6.9",
            "is-number@7.0.0",
            "ms@2.0.0",
            "ms@2.1.3"
        ],
        "{rel}"
    );
    assert_eq!(
        ids(&lock, &lock.direct()),
        [
            "@sindresorhus/is@4.6.0",
            "debug@2.6.9",
            "is-number@7.0.0",
            "ms@2.1.3"
        ],
        "{rel}: direct"
    );
    assert_eq!(
        chain(&lock, "ms@2.0.0"),
        ["debug@2.6.9", "ms@2.0.0"],
        "{rel}: why ms@2.0.0"
    );
    assert_eq!(
        lock.packages[find(&lock, "is-number@7.0.0")].scope,
        Scope::Dev,
        "{rel}"
    );
    assert_eq!(
        lock.packages[find(&lock, "ms@2.0.0")].scope,
        Scope::Prod,
        "{rel}"
    );
    assert!(
        lock.dependencies().all(|p| p.source == Source::registry()),
        "{rel}"
    );
}

#[test]
fn npm_package_lock() {
    assert_js_fixture("npm/package-lock.json");
    let lock = fixture("npm/package-lock.json");
    let ms = &lock.packages[find(&lock, "ms@2.0.0")];
    assert!(
        ms.integrity
            .as_deref()
            .is_some_and(|i| i.starts_with("sha512-"))
    );
}

#[test]
fn pnpm_v9() {
    assert_js_fixture("pnpm/pnpm-lock.yaml");
}

#[test]
fn yarn_v1() {
    assert_js_fixture("yarn1/yarn.lock");
}

#[test]
fn yarn_berry() {
    assert_js_fixture("berry/yarn.lock");
    assert_eq!(fixture("berry/yarn.lock").format, Format::YarnBerry);
}

#[test]
fn bun_text_lockfile() {
    assert_js_fixture("bun/bun.lock");
}

#[test]
fn cargo_lock() {
    let lock = fixture("cargo/Cargo.lock");
    assert_eq!(
        ids(&lock, &lock.direct()),
        ["cfg-if@1.0.5", "itoa@1.0.18", "once_cell@1.21.4"]
    );
    // Cargo.lock has no dev marker; the sibling Cargo.toml lists cfg-if there.
    assert_eq!(lock.packages[find(&lock, "cfg-if@1.0.5")].scope, Scope::Dev);
    assert_eq!(lock.packages[find(&lock, "itoa@1.0.18")].scope, Scope::Prod);
    let member = lock.packages.iter().find(|p| p.member).unwrap();
    assert_eq!(member.name, "fixture");
    let itoa = &lock.packages[find(&lock, "itoa@1.0.18")];
    assert!(
        itoa.integrity
            .as_deref()
            .is_some_and(|i| i.starts_with("sha256:"))
    );
}

/// requests@2.31.0 → certifi, charset-normalizer, idna, urllib3; dev iniconfig.
#[test]
fn uv_lock() {
    let lock = fixture("uv/uv.lock");
    assert_eq!(
        ids(&lock, &lock.direct()),
        ["iniconfig@2.0.0", "requests@2.31.0"]
    );
    // Two urllib3 versions, each behind its own environment marker.
    assert_eq!(
        chain(&lock, "urllib3@2.6.3"),
        ["requests@2.31.0", "urllib3@2.6.3"]
    );
    assert_eq!(
        chain(&lock, "urllib3@2.8.0"),
        ["requests@2.31.0", "urllib3@2.8.0"]
    );
    assert_eq!(
        lock.packages[find(&lock, "iniconfig@2.0.0")].scope,
        Scope::Dev
    );
    assert_eq!(lock.packages[find(&lock, "idna@3.20")].scope, Scope::Prod);
}

#[test]
fn poetry_lock() {
    let lock = fixture("poetry/poetry.lock");
    assert_eq!(
        ids(&lock, &lock.direct()),
        ["iniconfig@2.0.0", "requests@2.31.0"]
    );
    assert_eq!(chain(&lock, "idna@3.20"), ["requests@2.31.0", "idna@3.20"]);
    assert_eq!(
        lock.packages[find(&lock, "iniconfig@2.0.0")].scope,
        Scope::Dev
    );
    assert_eq!(
        lock.packages[find(&lock, "certifi@2026.7.22")].scope,
        Scope::Prod
    );
}

#[test]
fn pylock_without_edges() {
    let lock = fixture("pylock/pylock.toml");
    assert!(!lock.edges_known);
    assert_eq!(lock.dependencies().count(), 7);
    assert!(lock.why(0).is_none());
}

#[test]
fn requirements_exported_by_uv() {
    let lock = fixture("requirements/requirements.txt");
    let mut names: Vec<String> = lock.dependencies().map(Package::id).collect();
    names.sort();
    assert!(names.contains(&"requests@2.31.0".to_string()), "{names:?}");
    assert!(lock.unresolved.is_empty(), "{:?}", lock.unresolved);
    assert!(lock.dependencies().all(|p| p.integrity.is_some()));
}

#[test]
fn go_mod_with_replace() {
    let lock = fixture("go/go.mod");
    assert_eq!(lock.format, Format::GoMod);
    assert_eq!(
        ids(&lock, &lock.direct()),
        [
            "github.com/gin-gonic/gin@v1.9.0",
            "golang.org/x/net@v0.23.0"
        ],
        "replace directives apply"
    );
    assert_eq!(
        lock.dependencies().count(),
        4,
        "indirect modules are listed too"
    );
}

#[test]
fn discovery_flags_ambiguous_lockfiles() {
    let dir = tempfile::tempdir().unwrap();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deps");
    std::fs::copy(
        base.join("npm/package-lock.json"),
        dir.path().join("package-lock.json"),
    )
    .unwrap();
    std::fs::copy(base.join("yarn1/yarn.lock"), dir.path().join("yarn.lock")).unwrap();
    std::fs::write(dir.path().join("bun.lockb"), b"\0binary").unwrap();
    let found = discover(dir.path(), &[]);
    assert_eq!(found.lockfiles.len(), 3);
    assert_eq!(found.ambiguous().len(), 1);
    let bun = found
        .lockfiles
        .iter()
        .find(|l| l.format == Format::Bun)
        .unwrap();
    assert!(bun.unresolved[0].contains("--save-text-lockfile"));

    let found = discover(dir.path(), &["yarn.lock".to_string()]);
    assert_eq!(found.lockfiles.len(), 2, "excluded by pattern");
}

/// Parse `content` written to a temp dir as `name` (with optional extra files).
fn inline(name: &str, content: &str, extra: &[(&str, &str)]) -> Lockfile {
    let dir = tempfile::tempdir().unwrap();
    for (n, c) in extra {
        std::fs::write(dir.path().join(n), c).unwrap();
    }
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    load(&path).unwrap()
}

fn sorted_deps(lock: &Lockfile) -> Vec<String> {
    let mut d: Vec<String> = lock.dependencies().map(Package::id).collect();
    d.sort();
    d
}

#[test]
fn pnpm_v6_single_project_with_peer_variants() {
    let lock = inline(
        "pnpm-lock.yaml",
        "lockfileVersion: '6.0'
dependencies:
  react:
    specifier: ^18
    version: 18.2.0
  react-dom:
    specifier: ^18
    version: 18.2.0(react@18.2.0)
packages:
  /loose-envify@1.4.0:
    resolution: {integrity: sha512-a}
    dev: false
  /react@18.2.0:
    resolution: {integrity: sha512-b}
    dependencies:
      loose-envify: 1.4.0
    dev: false
  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-c}
    dependencies:
      react: 18.2.0
      scheduler: 0.23.0
    dev: false
  /scheduler@0.23.0:
    resolution: {integrity: sha512-d}
    dev: false
",
        &[],
    );
    assert_eq!(
        sorted_deps(&lock),
        [
            "loose-envify@1.4.0",
            "react-dom@18.2.0",
            "react@18.2.0",
            "scheduler@0.23.0"
        ]
    );
    assert_eq!(
        chain(&lock, "scheduler@0.23.0"),
        ["react-dom@18.2.0", "scheduler@0.23.0"]
    );
}

#[test]
fn pnpm_v5_slash_keys() {
    let lock = inline(
        "pnpm-lock.yaml",
        "lockfileVersion: 5.4
dependencies:
  react-dom: 18.0.0_react@18.0.0
  react: 18.0.0
packages:
  /react/18.0.0:
    resolution: {integrity: sha512-a}
    dev: false
  /react-dom/18.0.0_react@18.0.0:
    resolution: {integrity: sha512-b}
    dependencies:
      react: 18.0.0
    dev: false
",
        &[],
    );
    assert_eq!(sorted_deps(&lock), ["react-dom@18.0.0", "react@18.0.0"]);
    assert_eq!(
        ids(&lock, &lock.direct()),
        ["react-dom@18.0.0", "react@18.0.0"]
    );
}

#[test]
fn yarn1_entry_with_several_descriptors() {
    let lock = inline(
        "yarn.lock",
        "# yarn lockfile v1\n\n\"ms@^2.1.1\", ms@2.1.3:\n  version \"2.1.3\"\n  resolved \"https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#x\"\n",
        &[(
            "package.json",
            r#"{"name":"r","dependencies":{"ms":"^2.1.1"}}"#,
        )],
    );
    assert_eq!(ids(&lock, &lock.direct()), ["ms@2.1.3"]);
}

#[test]
fn yarn1_without_package_json_lists_packages_with_a_note() {
    let lock = inline(
        "yarn.lock",
        "# yarn lockfile v1\n\nms@2.1.3:\n  version \"2.1.3\"\n",
        &[],
    );
    assert_eq!(sorted_deps(&lock), ["ms@2.1.3"]);
    assert!(lock.unresolved.is_empty(), "every package is still listed");
    assert_eq!(lock.notes.len(), 1);
}

#[test]
fn npm_workspaces_resolve_links_to_members() {
    let lock = inline(
        "package-lock.json",
        r#"{"lockfileVersion": 3, "packages": {
            "": {"name": "root", "workspaces": ["packages/*"], "dependencies": {"app": "*"}},
            "packages/app": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
            "node_modules/app": {"resolved": "packages/app", "link": true},
            "node_modules/left-pad": {"version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
        }}"#,
        &[],
    );
    assert_eq!(
        sorted_deps(&lock),
        ["left-pad@1.3.0"],
        "workspace members are not dependencies"
    );
    assert_eq!(ids(&lock, &lock.direct()), ["left-pad@1.3.0"]);
    assert_eq!(lock.packages.iter().filter(|p| p.member).count(), 2);
}

#[test]
fn npm_lockfile_v1_nested_tree() {
    let lock = inline(
        "package-lock.json",
        r#"{"name": "r", "lockfileVersion": 1, "dependencies": {
            "debug": {"version": "2.6.9", "requires": {"ms": "2.0.0"},
                "dependencies": {"ms": {"version": "2.0.0"}}},
            "ms": {"version": "2.1.3"}
        }}"#,
        &[],
    );
    assert_eq!(sorted_deps(&lock), ["debug@2.6.9", "ms@2.0.0", "ms@2.1.3"]);
    assert_eq!(chain(&lock, "ms@2.0.0"), ["debug@2.6.9", "ms@2.0.0"]);
}

#[test]
fn requirements_pip_compile_output() {
    // Hash continuations, markers, extras and pip options are all normal in a
    // compiled requirements file; none of them is an unresolved dependency.
    let lock = inline(
        "requirements.txt",
        "--index-url https://pypi.org/simple\n\
         --require-hashes\n\
         requests[security]==2.31.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n\
         pywin32==306 ; sys_platform == \"win32\"  # via foo\n\
         black===23.1.0\n",
        &[],
    );
    assert_eq!(
        sorted_deps(&lock),
        ["black@23.1.0", "pywin32@306", "requests@2.31.0"]
    );
    assert!(lock.unresolved.is_empty(), "{:?}", lock.unresolved);
    let requests = &lock.packages[find(&lock, "requests@2.31.0")];
    assert_eq!(requests.integrity.as_deref(), Some("sha256:aaa"));
}

#[test]
fn requirements_report_what_they_cannot_pin() {
    let lock = inline(
        "requirements.txt",
        "-r base.txt\n-e .\ngit+https://github.com/a/b.git==1.0\nflask>=2\nDjango==4.2.0\n",
        &[],
    );
    assert_eq!(sorted_deps(&lock), ["django@4.2.0"]);
    assert_eq!(lock.unresolved.len(), 4);
}

#[test]
fn private_index_is_recorded_as_the_registry() {
    let lock = inline(
        "requirements.txt",
        "--index-url https://pypi.acme.dev/simple\nacme-utils==1.0\n",
        &[],
    );
    assert_eq!(
        lock.packages[0].source,
        Source::Registry {
            url: Some("https://pypi.acme.dev/simple".into())
        }
    );
}

#[test]
fn bun_local_tarballs_are_path_sources() {
    let lock = inline(
        "bun.lock",
        r#"{"lockfileVersion": 1, "workspaces": {"": {"name": "app", "dependencies": {"a": "file:a-1.0.0.tgz", "b": "file:./b-1.0.0.tgz"}}},
            "packages": {"a": ["a@a-1.0.0.tgz", {}, "sha512-x"], "b": ["b@./b-1.0.0.tgz", {}, "sha512-y"], "c": ["c@2.0.0", "", {}, "sha512-z"]}}"#,
        &[],
    );
    let src = |n: &str| {
        lock.packages
            .iter()
            .find(|p| p.name == n)
            .unwrap()
            .source
            .clone()
    };
    assert!(matches!(src("a"), Source::Path { .. }));
    assert!(matches!(src("b"), Source::Path { .. }));
    assert_eq!(src("c"), Source::registry());
}
