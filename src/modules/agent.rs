//! Agent integration: check a shell command before an AI agent runs it.
//!
//! An agent that installs dependencies runs package code with the
//! developer's credentials. `check-command` finds the dependency installs in
//! a shell command (`npm i x`, `uv add y`, `cd web && pnpm add z`…), plans
//! each with `greengate install --plan` — nothing is installed, no package
//! code runs — and reports the result as `greengate.report/v1`.
//!
//! `hook claude-code` wraps the same check as a Claude Code `PreToolUse`
//! hook: a blocking finding denies the command (the reason goes to Claude),
//! warnings or an unfinished check ask the user (the reason is shown in the
//! permission prompt), and a clean result says nothing, leaving the normal
//! permission flow in charge — unless `--allow-on-pass`.

use crate::report::{Check, Finding, Report, Status};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── Shell parsing ─────────────────────────────────────────────────────────────

/// One simple command: its words, and whether any word was built by command
/// substitution or a variable (so its real value is unknown).
#[derive(Debug, PartialEq)]
struct Simple {
    words: Vec<String>,
    dynamic: bool,
}

/// Split a shell command into simple commands, following quotes and escapes;
/// `&&`, `||`, `;`, `|`, `&`, parentheses and newlines separate them.
fn simple_commands(cmd: &str) -> Vec<Simple> {
    let mut out: Vec<Simple> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut dynamic = false;
    let mut chars = cmd.chars().peekable();
    let end_word = |words: &mut Vec<String>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                word.push(n);
                            }
                        }
                        '$' | '`' => {
                            dynamic = true;
                            word.push(q);
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next()
                    && n != '\n'
                {
                    word.push(n);
                }
            }
            '$' | '`' => {
                dynamic = true;
                in_word = true;
                word.push(c);
            }
            '#' if !in_word => {
                // A comment runs to the end of the line.
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                end_word(&mut words, &mut word, &mut in_word);
                if !words.is_empty() {
                    out.push(Simple {
                        words: std::mem::take(&mut words),
                        dynamic,
                    });
                }
                dynamic = false;
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                end_word(&mut words, &mut word, &mut in_word);
                if !words.is_empty() {
                    out.push(Simple {
                        words: std::mem::take(&mut words),
                        dynamic,
                    });
                }
                dynamic = false;
            }
            c if c.is_whitespace() => end_word(&mut words, &mut word, &mut in_word),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    end_word(&mut words, &mut word, &mut in_word);
    if !words.is_empty() {
        out.push(Simple { words, dynamic });
    }
    out
}

// ── Detection ─────────────────────────────────────────────────────────────────

/// A dependency install found in a command.
#[derive(Debug, PartialEq)]
pub enum Detected {
    /// Plannable with `greengate install <manager> --plan`.
    Plan {
        dir: PathBuf,
        manager: &'static str,
        pip: Option<String>,
        args: Vec<String>,
        text: String,
    },
    /// An install greengate cannot plan; `why` says what it is.
    Unchecked { why: String, text: String },
}

/// Commands that run another command, with the options of each that take a
/// value (short letters, long names) and those that change directory.
struct Wrapper {
    name: &'static str,
    short_values: &'static str,
    long_values: &'static [&'static str],
    chdir: &'static [&'static str],
    /// Positional words before the command (`timeout DURATION cmd`).
    positionals: usize,
}

const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        name: "sudo",
        short_values: "ugpCDrtTU",
        long_values: &[
            "user",
            "group",
            "prompt",
            "close-from",
            "chdir",
            "role",
            "type",
            "command-timeout",
            "other-user",
            "host",
        ],
        chdir: &["-D", "--chdir"],
        positionals: 0,
    },
    Wrapper {
        name: "doas",
        short_values: "uC",
        long_values: &[],
        chdir: &[],
        positionals: 0,
    },
    Wrapper {
        name: "env",
        short_values: "uCS",
        long_values: &["unset", "chdir", "split-string"],
        chdir: &["-C", "--chdir"],
        positionals: 0,
    },
    Wrapper {
        name: "nice",
        short_values: "n",
        long_values: &["adjustment"],
        chdir: &[],
        positionals: 0,
    },
    Wrapper {
        name: "time",
        short_values: "fo",
        long_values: &["format", "output"],
        chdir: &[],
        positionals: 0,
    },
    Wrapper {
        name: "timeout",
        short_values: "sk",
        long_values: &["signal", "kill-after"],
        chdir: &[],
        positionals: 1,
    },
    Wrapper {
        name: "exec",
        short_values: "a",
        long_values: &[],
        chdir: &[],
        positionals: 0,
    },
    Wrapper {
        name: "nohup",
        short_values: "",
        long_values: &[],
        chdir: &[],
        positionals: 0,
    },
    Wrapper {
        name: "command",
        short_values: "",
        long_values: &[],
        chdir: &[],
        positionals: 0,
    },
];

/// Strip one wrapper's options from `words` (which start after its name),
/// following `--chdir`-style options into `dir`. `Err` when the wrapped
/// command cannot be told apart from its options.
fn strip_wrapper<'a>(
    w: &Wrapper,
    mut words: &'a [String],
    dir: &mut PathBuf,
) -> Result<&'a [String], String> {
    while let Some(first) = words.first() {
        let f = first.as_str();
        if f == "--" {
            words = &words[1..];
            break;
        }
        if let Some(long) = f.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if name == "split-string" {
                return Err(format!(
                    "`{} --split-string` builds the command from a string",
                    w.name
                ));
            }
            let value = if w.long_values.contains(&name) {
                match inline {
                    Some(v) => Some(v.to_string()),
                    None => {
                        let v = words.get(1).ok_or_else(|| format!("`{f}` has no value"))?;
                        words = &words[1..];
                        Some(v.clone())
                    }
                }
            } else {
                None
            };
            if let Some(v) = value.filter(|_| w.chdir.contains(&format!("--{name}").as_str())) {
                *dir = dir.join(v);
            }
            words = &words[1..];
            continue;
        }
        if f.len() > 1 && f.starts_with('-') {
            // A cluster of short options; one taking a value ends it.
            for (i, c) in f.char_indices().skip(1) {
                if !w.short_values.contains(c) {
                    continue;
                }
                if c == 'S' && w.name == "env" {
                    return Err("`env -S` builds the command from a string".into());
                }
                let rest = &f[i + c.len_utf8()..];
                let v = if rest.is_empty() {
                    let v = words.get(1).ok_or_else(|| format!("`{f}` has no value"))?;
                    words = &words[1..];
                    v.clone()
                } else {
                    rest.to_string()
                };
                if w.chdir.contains(&format!("-{c}").as_str()) {
                    *dir = dir.join(v);
                }
                break;
            }
            words = &words[1..];
            continue;
        }
        break;
    }
    if words.len() < w.positionals {
        return Err(format!("`{}` has no command", w.name));
    }
    Ok(&words[w.positionals..])
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// The first non-flag word and everything after it.
fn subcommand(rest: &[String]) -> Option<(&str, &[String])> {
    let i = rest.iter().position(|w| !w.starts_with('-'))?;
    Some((rest[i].as_str(), &rest[i + 1..]))
}

/// A JavaScript package manager's options before its subcommand.
struct Globals {
    /// Options that take a value (without dashes; short ones as one letter).
    values: &'static [&'static str],
    /// Options that never take one.
    flags: &'static [&'static str],
    /// Options that run the command in another directory.
    chdir: &'static [&'static str],
}

const NPM_GLOBALS: Globals = Globals {
    values: &[
        "prefix",
        "C",
        "workspace",
        "w",
        "userconfig",
        "globalconfig",
        "cache",
        "registry",
        "loglevel",
        "location",
        "tag",
        "omit",
        "include",
        "install-strategy",
        "before",
        "script-shell",
        "otp",
        "scope",
        "cpu",
        "os",
        "libc",
    ],
    flags: &[
        "g",
        "global",
        "D",
        "save-dev",
        "S",
        "save",
        "E",
        "save-exact",
        "O",
        "save-optional",
        "P",
        "save-prod",
        "B",
        "save-bundle",
        "f",
        "force",
        "offline",
        "prefer-offline",
        "prefer-online",
        "ignore-scripts",
        "silent",
        "s",
        "q",
        "quiet",
        "d",
        "dd",
        "ddd",
        "verbose",
        "legacy-peer-deps",
        "strict-peer-deps",
        "dry-run",
        "workspaces",
        "ws",
        "include-workspace-root",
        "foreground-scripts",
        "y",
        "yes",
        "audit",
        "fund",
        "production",
        "package-lock-only",
    ],
    chdir: &["prefix", "C"],
};

const PNPM_GLOBALS: Globals = Globals {
    values: &[
        "dir",
        "C",
        "filter",
        "F",
        "workspace-dir",
        "reporter",
        "loglevel",
        "registry",
    ],
    flags: &[
        "r",
        "recursive",
        "w",
        "workspace-root",
        "s",
        "silent",
        "g",
        "global",
        "D",
        "save-dev",
        "P",
        "save-prod",
        "O",
        "save-optional",
        "E",
        "save-exact",
        "offline",
        "prefer-offline",
        "ignore-scripts",
        "frozen-lockfile",
        "stream",
        "aggregate-output",
    ],
    chdir: &["dir", "C"],
};

const YARN_GLOBALS: Globals = Globals {
    values: &[
        "cwd",
        "registry",
        "modules-folder",
        "cache-folder",
        "network-timeout",
    ],
    flags: &[
        "silent",
        "s",
        "offline",
        "prefer-offline",
        "ignore-scripts",
        "frozen-lockfile",
        "immutable",
        "production",
        "non-interactive",
        "verbose",
        "W",
        "ignore-workspace-root-check",
    ],
    chdir: &["cwd"],
};

const BUN_GLOBALS: Globals = Globals {
    values: &["cwd", "config", "c", "registry", "backend", "cache-dir"],
    flags: &[
        "g",
        "global",
        "d",
        "D",
        "dev",
        "production",
        "p",
        "silent",
        "verbose",
        "frozen-lockfile",
        "ignore-scripts",
        "no-save",
        "dry-run",
        "f",
        "force",
        "exact",
        "E",
        "optional",
    ],
    chdir: &["cwd"],
};

/// Where a JavaScript package manager's subcommand is, past options that
/// take values; options before it are moved after it (they hold anywhere),
/// except those naming another directory, which go into `dir`.
enum Sub<'a> {
    /// The subcommand, then its arguments with the leading options appended.
    Found(&'a str, Vec<String>),
    /// No subcommand at all.
    None,
    /// An unknown option before a word that may be its value or the
    /// subcommand.
    Unclear(String),
}

fn js_subcommand<'a>(rest: &'a [String], g: &Globals, dir: &mut PathBuf) -> Sub<'a> {
    let mut leading: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i].as_str();
        let Some(opt) = w.strip_prefix('-') else {
            let mut args = rest[i + 1..].to_vec();
            args.extend(leading);
            return Sub::Found(w, args);
        };
        let opt = opt.strip_prefix('-').unwrap_or(opt);
        let (name, inline) = match opt.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (opt, None),
        };
        let value = if inline.is_some() {
            inline
        } else if g.values.contains(&name) {
            i += 1;
            rest.get(i).cloned()
        } else if g.flags.contains(&name) || name.starts_with("no-") {
            None
        } else if rest.get(i + 1).is_some_and(|n| !n.starts_with('-')) {
            return Sub::Unclear(w.to_string());
        } else {
            None
        };
        if g.chdir.contains(&name) {
            if let Some(v) = value {
                *dir = dir.join(v);
            }
        } else {
            leading.push(w.to_string());
            if let Some(v) = value.filter(|_| !w.contains('=')) {
                leading.push(v);
            }
        }
        i += 1;
    }
    Sub::None
}

fn with(sub: &str, rest: &[String]) -> Vec<String> {
    std::iter::once(sub.to_string())
        .chain(rest.iter().cloned())
        .collect()
}

pub fn detect(cmd: &str, cwd: &Path) -> Vec<Detected> {
    let mut out = Vec::new();
    let mut dir = cwd.to_path_buf();
    for simple in simple_commands(cmd) {
        let mut words: &[String] = &simple.words;
        // `sudo -u x env -C web FOO=1 npm …`: wrappers, their options and
        // assignments, in any order. A wrapper's directory option holds for
        // this command only.
        let mut here = dir.clone();
        let mut unclear: Option<String> = None;
        while let Some(first) = words.first() {
            let base = first.rsplit('/').next().unwrap_or(first);
            if is_assignment(first) {
                words = &words[1..];
            } else if let Some(w) = WRAPPERS.iter().find(|w| w.name == base) {
                match strip_wrapper(w, &words[1..], &mut here) {
                    Ok(rest) => words = rest,
                    Err(why) => {
                        unclear = Some(why);
                        break;
                    }
                }
            } else {
                break;
            }
        }
        if let Some(why) = unclear {
            let text = simple.words.join(" ");
            if INSTALLERS.iter().any(|i| text.contains(i)) {
                out.push(Detected::Unchecked {
                    why: format!("{why}, so what it runs is unknown"),
                    text,
                });
            }
            continue;
        }
        let Some((program, rest)) = words.split_first() else {
            continue;
        };
        let text = words.join(" ");
        let program = program.rsplit('/').next().unwrap_or(program);
        if matches!(program, "cd" | "pushd") {
            if let Some(target) = rest.first().filter(|t| !t.starts_with('-')) {
                dir = dir.join(target);
            }
            continue;
        }
        if matches!(program, "bash" | "sh" | "zsh" | "dash")
            && let Some(i) = rest.iter().position(|w| w == "-c")
            && let Some(body) = rest.get(i + 1)
        {
            out.extend(detect(body, &here));
            continue;
        }
        let found = recognise(program, rest, &here, &text);
        if let Some(d) = found {
            if simple.dynamic {
                out.push(Detected::Unchecked {
                    why: "its arguments are computed by the shell ($… or `…`), so what it installs is unknown".into(),
                    text,
                });
            } else {
                out.push(d);
            }
        }
    }
    out
}

/// Package managers whose name in an unparseable command makes it worth a look.
const INSTALLERS: &[&str] = &["npm", "pnpm", "yarn", "bun", "pip", "uv", "cargo", "poetry"];

fn recognise(program: &str, rest: &[String], dir: &Path, text: &str) -> Option<Detected> {
    let mut dir = dir.to_path_buf();
    let globals = match program {
        "npm" => Some(&NPM_GLOBALS),
        "pnpm" => Some(&PNPM_GLOBALS),
        "yarn" => Some(&YARN_GLOBALS),
        "bun" => Some(&BUN_GLOBALS),
        _ => None,
    };
    // For the JavaScript managers, `rest` becomes subcommand-first.
    let js_rest: Vec<String>;
    let rest: &[String] = match globals.map(|g| js_subcommand(rest, g, &mut dir)) {
        None => rest,
        Some(Sub::Found(sub, args)) => {
            js_rest = std::iter::once(sub.to_string()).chain(args).collect();
            &js_rest
        }
        Some(Sub::None) if program == "yarn" => &[],
        Some(Sub::None) => return None,
        Some(Sub::Unclear(opt)) => {
            let installs = rest.iter().any(|w| {
                matches!(
                    w.as_str(),
                    "install" | "i" | "add" | "ci" | "clean-install" | "a"
                )
            });
            return installs.then(|| Detected::Unchecked {
                why: format!(
                    "a {program} command where `{opt}` may take a value, so its subcommand is unclear"
                ),
                text: text.to_string(),
            });
        }
    };
    let dir = dir.as_path();
    let plan = |manager: &'static str, pip: Option<String>, args: Vec<String>| Detected::Plan {
        dir: dir.to_path_buf(),
        manager,
        pip,
        args,
        text: text.to_string(),
    };
    let unchecked = |why: &str| Detected::Unchecked {
        why: why.to_string(),
        text: text.to_string(),
    };
    let global = rest
        .iter()
        .any(|a| a == "-g" || a == "--global" || a.starts_with("--location=global"));
    match program {
        "npm" => {
            let (sub, args) = subcommand(rest)?;
            let sub = match sub {
                "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt"
                | "isnta" | "isntal" | "isntall" | "add" => "install",
                "ci" | "clean-install" | "ic" | "install-clean" | "isntall-clean" => "ci",
                _ => return None,
            };
            if global {
                return Some(unchecked(
                    "a global npm install, which greengate install does not plan",
                ));
            }
            Some(plan("npm", None, with(sub, args)))
        }
        "pnpm" => {
            let (sub, args) = subcommand(rest)?;
            let sub = match sub {
                "add" => "add",
                "install" | "i" => "install",
                _ => return None,
            };
            if global {
                return Some(unchecked(
                    "a global pnpm install, which greengate install does not plan",
                ));
            }
            Some(plan("pnpm", None, with(sub, args)))
        }
        "yarn" => match subcommand(rest) {
            None => Some(plan("yarn", None, vec!["install".into()])),
            Some(("add", args)) => Some(plan("yarn", None, with("add", args))),
            Some(("install", args)) => Some(plan("yarn", None, with("install", args))),
            Some(("global", _)) => Some(unchecked(
                "a global yarn install, which greengate install does not plan",
            )),
            _ => None,
        },
        "bun" => {
            let (sub, args) = subcommand(rest)?;
            let sub = match sub {
                "add" | "a" => "add",
                "install" | "i" => "install",
                _ => return None,
            };
            if global {
                return Some(unchecked(
                    "a global bun install, which greengate install does not plan",
                ));
            }
            Some(plan("bun", None, with(sub, args)))
        }
        p if p == "pip" || p.starts_with("pip3") => match subcommand(rest)? {
            ("install", args) => Some(plan("pip", Some(p.to_string()), with("install", args))),
            _ => None,
        },
        p if p == "python" || p.starts_with("python3") => {
            let i = rest.iter().position(|w| w == "-m")?;
            if rest.get(i + 1).map(String::as_str) != Some("pip") {
                return None;
            }
            match subcommand(&rest[i + 2..])? {
                ("install", args) => Some(plan("pip", None, with("install", args))),
                _ => None,
            }
        }
        "uv" => match subcommand(rest)? {
            ("add", args) => Some(plan("uv", None, with("add", args))),
            ("sync", args) => Some(plan("uv", None, with("sync", args))),
            ("pip", args) => match subcommand(args)? {
                ("install", args) => Some(plan("pip", None, with("install", args))),
                _ => None,
            },
            ("tool", args) if subcommand(args).is_some_and(|(s, _)| s == "install") => Some(
                unchecked("`uv tool install`, which greengate install does not plan"),
            ),
            _ => None,
        },
        "poetry" => match subcommand(rest)? {
            ("add" | "install", _) => {
                Some(unchecked("Poetry, which greengate install does not plan"))
            }
            _ => None,
        },
        "cargo" => match subcommand(rest)? {
            ("add", args) => Some(plan("cargo", None, with("add", args))),
            ("install", _) => Some(unchecked(
                "`cargo install`, which builds crates (running their build scripts) and greengate install does not plan",
            )),
            _ => None,
        },
        _ => None,
    }
}

// ── Checking ──────────────────────────────────────────────────────────────────

pub struct Outcome {
    pub report: Report,
    /// How many dependency installs the command contains.
    pub installs: usize,
    /// One line per install, for messages.
    pub commands: Vec<String>,
}

fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The plan runs the package manager below greengate: end the group.
        let _ = Command::new("kill") // greengate: ignore — ends the plan's process group
            .args(["-KILL", &format!("-{}", child.id())])
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Plan one install in a child greengate, within `budget`.
fn plan_one(
    dir: &Path,
    manager: &str,
    pip: Option<&str>,
    args: &[String],
    budget: Duration,
    report: &mut Report,
) -> Result<()> {
    let scratch = std::env::temp_dir().join(format!(
        "greengate-check-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch)?;
    let out_path = scratch.join("report.json");
    let exe = std::env::current_exe().context("cannot find the greengate binary")?;
    let mut cmd = Command::new(exe); // greengate: ignore — greengate itself
    cmd.arg("--report")
        .arg(&out_path)
        .args(["install", "--plan"]);
    if let Some(p) = pip {
        cmd.args(["--pip", p]);
    }
    cmd.arg(manager)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let id = format!("plan:{manager}");
    let mut child = cmd
        .spawn()
        .context("could not start greengate install --plan")?;
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if start.elapsed() >= budget {
            kill_tree(&mut child);
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        use std::io::Read;
        let _ = e.read_to_string(&mut stderr);
    }
    let parsed: Option<Value> = std::fs::read_to_string(&out_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let _ = std::fs::remove_dir_all(&scratch);
    let Some(status) = status else {
        report.checks.push(Check::incomplete(
            id,
            format!("the check did not finish within {} s", budget.as_secs()),
        ));
        return Ok(());
    };
    let Some(sub) = parsed.filter(|_| status.code() != Some(2)) else {
        let last = stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no output")
            .trim()
            .to_string();
        report.checks.push(Check::error(
            id,
            format!("greengate install --plan failed ({status}): {last}"),
        ));
        return Ok(());
    };
    let list = |key: &str| -> Vec<Finding> {
        serde_json::from_value(sub[key].clone()).unwrap_or_default()
    };
    let checks: Vec<Check> = serde_json::from_value(sub["checks"].clone()).unwrap_or_default();
    report.checks.extend(checks.into_iter().map(|mut c| {
        c.id = format!("{manager}/{}", c.id);
        c
    }));
    if !report
        .checks
        .iter()
        .any(|c| c.id.starts_with(&format!("{manager}/")))
    {
        report.checks.push(Check::passed(id));
    }
    report.findings.extend(list("findings"));
    report.warnings.extend(list("warnings"));
    report.suppressed.extend(list("suppressed"));
    Ok(())
}

/// Check every dependency install in `command`, run from `cwd`, spending at
/// most `budget` in total.
pub fn check(command: &str, cwd: &Path, budget: Duration) -> Outcome {
    let mut report = Report::new("check-command");
    let detected = detect(command, cwd);
    let start = Instant::now();
    let mut commands = Vec::new();
    for d in &detected {
        match d {
            Detected::Plan {
                dir,
                manager,
                pip,
                args,
                text,
            } => {
                commands.push(text.clone());
                let left = budget.saturating_sub(start.elapsed());
                if left.is_zero() {
                    report.checks.push(Check::incomplete(
                        format!("plan:{manager}"),
                        format!("not checked: the {} s budget was used up", budget.as_secs()),
                    ));
                    continue;
                }
                if let Err(e) = plan_one(dir, manager, pip.as_deref(), args, left, &mut report) {
                    report
                        .checks
                        .push(Check::error(format!("plan:{manager}"), format!("{e:#}")));
                }
            }
            Detected::Unchecked { why, text } => {
                commands.push(text.clone());
                report.checks.push(Check::incomplete(
                    "command",
                    format!("`{text}` is {why}; review it before running"),
                ));
            }
        }
    }
    if detected.is_empty() {
        report
            .checks
            .push(Check::passed("command").with_source("no dependency install in the command"));
    }
    Outcome {
        report,
        installs: detected.len(),
        commands,
    }
}

// ── Claude Code hook ──────────────────────────────────────────────────────────

fn summary(f: &Finding) -> String {
    let what = match &f.location {
        crate::report::Location::Package { name, version, .. } => match version {
            Some(v) => format!("{name}@{v}"),
            None => name.clone(),
        },
        crate::report::Location::File { path, .. } => path.display().to_string(),
        _ => String::new(),
    };
    match &f.remediation {
        // The fix is what lets the agent correct course on its own.
        Some(fix) => format!("{} {what}: {} ({fix})", f.rule, f.message),
        None => format!("{} {what}: {}", f.rule, f.message),
    }
}

fn listed(items: Vec<String>) -> String {
    let n = items.len();
    let mut s: Vec<String> = items.into_iter().take(4).collect();
    if n > 4 {
        s.push(format!("…and {} more", n - 4));
    }
    s.join("; ")
}

/// The hook's answer to one `PreToolUse` event, as the JSON to print —
/// `None` to print nothing and leave the decision to the normal flow.
pub fn claude_code_hook(input: &str, budget: Duration, allow_on_pass: bool) -> Option<Value> {
    let event: Value = serde_json::from_str(input).ok()?;
    if event["tool_name"].as_str() != Some("Bash") {
        return None;
    }
    let command = event["tool_input"]["command"].as_str()?;
    let cwd = event["cwd"]
        .as_str()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let outcome = check(command, &cwd, budget);
    if outcome.installs == 0 {
        return None;
    }
    let r = &outcome.report;
    let rerun = format!(
        "Details: greengate check-command -- {}",
        outcome.commands.join(" && ")
    );
    let (decision, reason) = if !r.findings.is_empty() {
        (
            "deny",
            format!(
                "greengate blocked this dependency install: {}. {rerun}",
                listed(r.findings.iter().map(summary).collect())
            ),
        )
    } else if r.status() != Status::Passed || !r.warnings.is_empty() {
        let mut items: Vec<String> = r
            .unfinished()
            .map(|c| {
                format!(
                    "{}: {}",
                    c.id,
                    c.reason.as_deref().unwrap_or("did not complete")
                )
            })
            .collect();
        items.extend(r.warnings.iter().map(summary));
        ("ask", format!("greengate: {}. {rerun}", listed(items)))
    } else if allow_on_pass {
        (
            "allow",
            format!(
                "greengate checked {} install(s): no issues",
                outcome.installs
            ),
        )
    } else {
        return None;
    };
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(cmd: &str) -> Vec<Vec<String>> {
        simple_commands(cmd).into_iter().map(|s| s.words).collect()
    }

    #[test]
    fn splits_shell_commands() {
        assert_eq!(
            words("cd web && npm i 'left pad' ; echo \"a;b\" | tee x # npm i evil"),
            vec![
                vec!["cd", "web"],
                vec!["npm", "i", "left pad"],
                vec!["echo", "a;b"],
                vec!["tee", "x"],
            ]
        );
        assert!(simple_commands("npm i $(cat list)")[0].dynamic);
        assert!(!simple_commands("npm i 'x$y'")[0].dynamic);
    }

    fn plans(cmd: &str) -> Vec<(String, &'static str, Vec<String>)> {
        detect(cmd, Path::new("/p"))
            .into_iter()
            .filter_map(|d| match d {
                Detected::Plan {
                    dir, manager, args, ..
                } => Some((dir.display().to_string(), manager, args)),
                Detected::Unchecked { .. } => None,
            })
            .collect()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn detects_installs() {
        assert_eq!(
            plans("npm i lodash"),
            [("/p".into(), "npm", s(&["install", "lodash"]))]
        );
        assert_eq!(
            plans("cd web && pnpm add -D vite"),
            [("/p/web".into(), "pnpm", s(&["add", "-D", "vite"]))]
        );
        assert_eq!(
            plans("CI=1 sudo -E npm ci"),
            [("/p".into(), "npm", s(&["ci"]))]
        );
        assert_eq!(plans("yarn"), [("/p".into(), "yarn", s(&["install"]))]);
        assert_eq!(
            plans("python3 -m pip install requests"),
            [("/p".into(), "pip", s(&["install", "requests"]))]
        );
        assert_eq!(
            plans("uv pip install httpx"),
            [("/p".into(), "pip", s(&["install", "httpx"]))]
        );
        assert_eq!(
            plans("uv add 'fastapi>=0.110'"),
            [("/p".into(), "uv", s(&["add", "fastapi>=0.110"]))]
        );
        assert_eq!(
            plans("bash -c 'cargo add serde'"),
            [("/p".into(), "cargo", s(&["add", "serde"]))]
        );
        assert_eq!(
            plans("/usr/bin/bun i"),
            [("/p".into(), "bun", s(&["install"]))]
        );
        // Not installs.
        assert!(
            detect(
                "npm test && npm run build && pip list && cargo build",
                Path::new("/p")
            )
            .is_empty()
        );
        assert!(detect("echo npm install x", Path::new("/p")).is_empty());
    }

    #[test]
    fn option_values_are_not_subcommands() {
        assert_eq!(
            plans("npm --prefix packages/app install review-fixture"),
            [(
                "/p/packages/app".into(),
                "npm",
                s(&["install", "review-fixture"])
            )]
        );
        assert_eq!(
            plans("sudo -u dummy npm install review-fixture"),
            [("/p".into(), "npm", s(&["install", "review-fixture"]))]
        );
        assert_eq!(
            plans("npm --registry https://r.example ci"),
            [(
                "/p".into(),
                "npm",
                s(&["ci", "--registry", "https://r.example"])
            )]
        );
        assert_eq!(
            plans("env -C web FOO=1 nice -n 5 timeout 60 pnpm --filter app add vite"),
            [(
                "/p/web".into(),
                "pnpm",
                s(&["add", "vite", "--filter", "app"])
            )]
        );
        assert_eq!(
            plans("sudo -D web --user=dummy yarn --cwd app add x"),
            [("/p/web/app".into(), "yarn", s(&["add", "x"]))]
        );
        assert_eq!(
            plans("bun --cwd=site i"),
            [("/p/site".into(), "bun", s(&["install"]))]
        );
        // A wrapper's directory holds for its command only.
        assert_eq!(
            plans("env -C web npm ci && npm ci"),
            [
                ("/p/web".into(), "npm", s(&["ci"])),
                ("/p".into(), "npm", s(&["ci"]))
            ]
        );
    }

    #[test]
    fn unclear_install_forms_are_unchecked() {
        let unchecked = |cmd: &str| {
            detect(cmd, Path::new("/p"))
                .iter()
                .any(|d| matches!(d, Detected::Unchecked { .. }))
        };
        assert!(unchecked("npm --some-new-option value install x"));
        assert!(unchecked("env -S 'npm install x'"));
        assert!(detect("npm --some-new-option value test", Path::new("/p")).is_empty());
    }

    #[test]
    fn unplannable_installs_are_flagged() {
        let unchecked = |cmd: &str| {
            detect(cmd, Path::new("/p"))
                .iter()
                .any(|d| matches!(d, Detected::Unchecked { .. }))
        };
        assert!(unchecked("npm install -g typescript"));
        assert!(unchecked("poetry add requests"));
        assert!(unchecked("cargo install ripgrep"));
        assert!(unchecked("npm i $(cat deps.txt)"));
        assert!(!unchecked("npm i lodash"));
    }

    #[test]
    fn hook_ignores_other_tools_and_commands() {
        let b = Duration::from_secs(1);
        assert_eq!(
            claude_code_hook(r#"{"tool_name":"Read","tool_input":{}}"#, b, false),
            None
        );
        assert_eq!(
            claude_code_hook(
                r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/"}"#,
                b,
                true
            ),
            None
        );
        assert_eq!(claude_code_hook("not json", b, false), None);
    }

    #[test]
    fn hook_asks_about_unplannable_installs() {
        let out = claude_code_hook(
            r#"{"tool_name":"Bash","tool_input":{"command":"poetry add requests"},"cwd":"/"}"#,
            Duration::from_secs(1),
            false,
        )
        .unwrap();
        let o = &out["hookSpecificOutput"];
        assert_eq!(o["hookEventName"], "PreToolUse");
        assert_eq!(o["permissionDecision"], "ask");
        assert!(
            o["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("Poetry")
        );
    }
}
