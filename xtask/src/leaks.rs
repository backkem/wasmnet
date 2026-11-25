//! `check-tree`: nothing local in the tree or in new commits.
//!
//! This repository is public, so the files it tracks and the commits it gains must not carry
//! what only made sense on one machine: an absolute path into a user's home or projects
//! directory (Windows drive paths, the same paths as Git Bash or WSL spell them, Unix and macOS
//! home directories), a link to an AI coding tool's session or the trailer such a tool adds
//! to a commit message, or a merge conflict marker left behind.
//!
//! The patterns are generic: they name no person and no project. A line that must show such a
//! path (a placeholder in an example) says so on the same line with the marker [`ALLOW`],
//! in a comment of its language.

use std::path::Path;
use std::process::Command;

use crate::Result;

/// The marker that exempts its line.
pub const ALLOW: &str = "tree-check: allow";

/// What was found on one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The line, from 1.
    pub line: usize,
    /// What it is.
    pub what: &'static str,
}

/// Directories under which a path names a user or a checkout on one machine.
const PRIVATE_DIRS: &[&str] = &["users", "projects", "documents and settings"];

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

/// After a run of separators at `at`, whether one of [`PRIVATE_DIRS`] follows, then a separator.
fn private_dir_after_seps(line: &[u8], mut at: usize) -> bool {
    let start = at;
    while at < line.len() && is_sep(line[at]) {
        at += 1;
    }
    at > start && private_dir_at(line, at)
}

fn private_dir_at(line: &[u8], at: usize) -> bool {
    PRIVATE_DIRS.iter().any(|dir| {
        let end = at + dir.len();
        line.get(at..end) == Some(dir.as_bytes()) && line.get(end).is_some_and(|&b| is_sep(b))
    })
}

/// A drive path into a users or projects directory, with either separator, escaped or not.
fn windows_path(line: &[u8]) -> bool {
    (0..line.len().saturating_sub(1)).any(|i| {
        line[i].is_ascii_alphabetic()
            && line[i + 1] == b':'
            && (i == 0 || !is_word(line[i - 1]))
            && private_dir_after_seps(line, i + 2)
    })
}

/// The same directories as Git Bash (`/<drive>/...`) and WSL (`/mnt/<drive>/...`) spell them.
fn drive_mount_path(line: &[u8]) -> bool {
    (0..line.len().saturating_sub(3)).any(|i| {
        let mount = i >= 4 && &line[i - 4..i] == b"/mnt";
        line[i] == b'/'
            && line[i + 1].is_ascii_alphabetic()
            && line[i + 2] == b'/'
            && (i == 0 || mount || !is_word(line[i - 1]))
            && private_dir_at(line, i + 3)
    })
}

/// A Unix or macOS home directory with a user name in it: `/home/<name>/`, `/Users/<name>/`.
fn home_path(line: &[u8]) -> bool {
    ["/home/", "/users/"].iter().any(|prefix| {
        let p = prefix.as_bytes();
        (0..line.len()).any(|i| {
            if line.get(i..i + p.len()) != Some(p) || (i > 0 && is_word(line[i - 1])) {
                return false;
            }
            let name: usize = line[i + p.len()..]
                .iter()
                .take_while(|&&b| is_word(b) || matches!(b, b'.' | b'_' | b'-'))
                .count();
            name > 0 && line.get(i + p.len() + name) == Some(&b'/')
        })
    })
}

/// A session link or session trailer of an AI coding tool.
fn session(line: &str) -> bool {
    // Spelled in pieces so that this file does not match itself.
    const NEEDLES: &[&str] = &[
        concat!("claude", "-session:"),
        concat!("claude", ".ai/code/session"),
    ];
    NEEDLES.iter().any(|n| line.contains(n))
}

/// The lines of `text` that carry something local, with what it is. Lines with [`ALLOW`] are
/// skipped.
pub fn scan(text: &str) -> Vec<Finding> {
    let open = "<".repeat(7);
    let close = ">".repeat(7);
    let base = "|".repeat(7);
    let middle = "=".repeat(7);
    let mut findings = Vec::new();
    let mut seen_open = false;
    for (i, raw) in text.lines().enumerate() {
        if raw.contains(ALLOW) {
            continue;
        }
        let line = raw.to_ascii_lowercase();
        let bytes = line.as_bytes();
        let what = if windows_path(bytes) || drive_mount_path(bytes) || home_path(bytes) {
            Some("a local path")
        } else if session(&line) {
            Some("an AI coding tool's session link or trailer")
        } else {
            let marker = |m: &str| {
                raw.strip_prefix(m)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
            };
            if marker(&open) {
                seen_open = true;
            }
            (marker(&open)
                || marker(&close)
                || marker(&base)
                || (seen_open && raw.trim_end() == middle))
                .then_some("a merge conflict marker")
        };
        if let Some(what) = what {
            findings.push(Finding { line: i + 1, what });
        }
    }
    findings
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").current_dir(root).args(args).output()?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Every tracked file, and every untracked one that is not ignored.
fn tree(root: &Path) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let list = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    for name in list.split('\0').filter(|n| !n.is_empty()) {
        let Ok(bytes) = std::fs::read(root.join(name)) else {
            continue; // deleted in the working tree
        };
        if bytes.iter().take(8192).any(|&b| b == 0) {
            continue; // binary
        }
        for f in scan(&String::from_utf8_lossy(&bytes)) {
            problems.push(format!("{name}:{}: {}", f.line, f.what));
        }
    }
    Ok(problems)
}

/// The messages and the added lines of the commits in `range` (`<base>..<head>`).
fn commits(root: &Path, range: &str) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for commit in git(root, &["rev-list", "--reverse", range])?.lines() {
        let short = &commit[..commit.len().min(12)];
        let message = git(root, &["log", "-1", "--format=%B", commit])?;
        for f in scan(&message) {
            problems.push(format!(
                "commit {short}, message line {}: {}",
                f.line, f.what
            ));
        }
        let diff = git(
            root,
            &[
                "show",
                "--format=",
                "--no-color",
                "--no-ext-diff",
                "--unified=0",
                commit,
            ],
        )?;
        let (mut file, mut in_header) = (String::new(), false);
        let mut added = String::new();
        let mut where_: Vec<String> = Vec::new();
        for line in diff.lines() {
            if let Some(rest) = line.strip_prefix("diff --git ") {
                in_header = true;
                file = rest.rsplit(" b/").next().unwrap_or(rest).to_owned();
            } else if line.starts_with("@@") {
                in_header = false;
            } else if !in_header && let Some(text) = line.strip_prefix('+') {
                added.push_str(text);
                added.push('\n');
                where_.push(file.clone());
            }
        }
        for f in scan(&added) {
            let file = where_.get(f.line - 1).map_or("?", String::as_str);
            problems.push(format!(
                "commit {short}, a line it adds to {file}: {}",
                f.what
            ));
        }
    }
    Ok(problems)
}

/// `check-tree [--commits <base>..<head>]`.
pub fn command(args: &[String]) -> Result<()> {
    let mut range = None;
    let mut args = args.iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--commits" => range = Some(args.next().ok_or("check-tree: --commits needs a range")?),
            other => return Err(format!("check-tree: unknown option {other}").into()),
        }
    }
    let root = crate::root();
    let mut problems = tree(&root)?;
    if let Some(range) = range {
        if !range.contains("..") {
            return Err(format!(
                "check-tree: `{range}` is not a range (<base>..<head>): history before the base \
                 is not checked"
            )
            .into());
        }
        problems.extend(commits(&root, range)?);
    }
    for p in &problems {
        println!("  {p}");
    }
    if problems.is_empty() {
        println!("xtask check-tree: nothing local found");
        Ok(())
    } else {
        Err(format!(
            "{} finding(s); a line that must keep one (a placeholder) carries `{ALLOW}`",
            problems.len()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kinds found in `text`.
    fn found(text: &str) -> Vec<&'static str> {
        scan(text).iter().map(|f| f.what).collect()
    }

    const PATH: &str = "a local path";

    #[test]
    fn local_paths_in_every_spelling() {
        // Built from pieces, so that this file passes its own check.
        let (users, projects, home) = ("Users", "projects", "home");
        for text in [
            format!("see C:\\{users}\\someone\\x"),
            format!("\"d:\\\\{projects}\\\\thing\""),
            format!("(C:/{users}/someone)"),
            format!("cd /c/{users}/someone"),
            format!("/mnt/c/{projects}/thing"),
            format!("cd /{home}/someone/src"),
            format!("open /{users}/someone/x"),
            format!("`~` is not, but this is: /{home}/a.b-c/x"),
        ] {
            assert_eq!(found(&text), [PATH], "{text}");
        }
        for text in [
            format!("https://example.com/{home}/a/b"),
            format!("{projects}/ and {users}/ alone"),
            "~/.cargo/registry".to_owned(),
            format!("/{home}/ alone"),
            format!("C:\\Program Files\\{projects}x\\"),
            format!("cd /c/{users}/someone # {ALLOW}"),
        ] {
            assert!(found(&text).is_empty(), "{text}");
        }
    }

    #[test]
    fn session_links_and_trailers() {
        let trailer = format!("{}-Session: https://example", "Claude");
        assert_eq!(
            found(&trailer),
            ["an AI coding tool's session link or trailer"]
        );
        let link = format!("see https://{}.ai/code/session_01abc", "claude");
        assert_eq!(
            found(&link),
            ["an AI coding tool's session link or trailer"]
        );
        assert!(found("Co-Authored-By: someone <a@b>").is_empty());
    }

    #[test]
    fn conflict_markers_but_not_headings() {
        let marker = "a merge conflict marker";
        let (open, mid, close) = ("<".repeat(7), "=".repeat(7), ">".repeat(7));
        let text = format!("a\n{open} HEAD\nb\n{mid}\nc\n{close} branch\n");
        assert_eq!(found(&text), [marker, marker, marker]);
        let lines: Vec<usize> = scan(&text).iter().map(|f| f.line).collect();
        assert_eq!(lines, [2, 4, 6]);
        // A Markdown heading underline is not a marker without an opening one.
        assert!(found(&format!("Title\n{mid}\n")).is_empty());
        assert!(found(&format!("{open}<<< not one\n")).is_empty());
    }

    #[test]
    fn the_tree_is_clean() {
        let problems = tree(&crate::root()).unwrap();
        assert!(problems.is_empty(), "{problems:#?}");
    }
}
