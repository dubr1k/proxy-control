//! The command-line skeleton of `proxy-control-installer` (`installer/cli.py:88-135`).
//!
//! **Host WP3 owns the commands**: this module only parses the global part the way argparse
//! does (`--root` with prefix abbreviations, the required subcommand, usage errors on stderr
//! with exit 2) and answers `--version`. Every subcommand is recognised and reported as not
//! available in this build yet.

use std::path::PathBuf;

/// The program name argparse prints.
pub const PROG: &str = "proxy-control-installer";
/// The release version, compiled in from the tree (no timestamp, no `git describe`).
pub const VERSION: &str = include_str!("../../VERSION");

/// The subcommands of the Python parser, in its order.
pub const COMMANDS: &[&str] =
    &["wizard", "plan", "install", "status", "resume", "repair", "report", "uninstall", "reconcile-panel-update"];

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// `-h`/`--help`.
    Help,
    /// `--version`.
    Version,
    /// A subcommand with the remaining arguments.
    Command { root: PathBuf, command: String, arguments: Vec<String> },
}

/// A usage error: argparse prints the usage line and `prog: error: <message>`, exit 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

/// argparse's usage line for the top-level parser.
pub fn usage() -> String {
    format!("usage: {PROG} [-h] {{{}}} ...", COMMANDS.join(","))
}

/// The `--help` text (summary only; the subcommands document themselves in WP3).
pub fn help() -> String {
    let mut text = format!("{}\n\nTyped Proxy Control release installer\n\npositional arguments:\n", usage());
    text.push_str(&format!(
        "  {{{}}}\n\noptions:\n  -h, --help            show this help message and exit\n",
        COMMANDS.join(",")
    ));
    text
}

/// Parses the global options and the subcommand (`--root` may be abbreviated to any unique
/// prefix of at least `--r`, and given as `--root=X` or `--root X`).
pub fn parse(arguments: &[String]) -> Result<Invocation, UsageError> {
    let mut root = PathBuf::from("/");
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-h" || argument == "--help" {
            return Ok(Invocation::Help);
        }
        if argument == "--version" {
            return Ok(Invocation::Version);
        }
        if argument == "--" {
            index += 1;
            break;
        }
        if let Some(option) = argument.strip_prefix("--") {
            let (name, inline) = match option.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (option, None),
            };
            if name.is_empty() || !"root".starts_with(name) {
                return Err(UsageError(format!("unrecognized arguments: {argument}")));
            }
            let value = match inline {
                Some(value) => value,
                None => {
                    index += 1;
                    match arguments.get(index) {
                        Some(value) if !value.starts_with('-') || value == "-" => value.clone(),
                        _ => return Err(UsageError("argument --root: expected one argument".into())),
                    }
                }
            };
            root = PathBuf::from(value);
            index += 1;
            continue;
        }
        if argument.starts_with('-') && argument != "-" {
            return Err(UsageError(format!("unrecognized arguments: {argument}")));
        }
        break;
    }
    let Some(command) = arguments.get(index) else {
        return Err(UsageError("the following arguments are required: command".into()));
    };
    if !COMMANDS.contains(&command.as_str()) {
        let choices: Vec<String> = COMMANDS.iter().map(|name| format!("'{name}'")).collect();
        return Err(UsageError(format!(
            "argument command: invalid choice: '{command}' (choose from {})",
            choices.join(", ")
        )));
    }
    Ok(Invocation::Command { root, command: command.clone(), arguments: arguments[index + 1..].to_vec() })
}

/// Runs the command line; returns the exit status and writes to the given streams.
pub fn run(arguments: &[String], stdout: &mut dyn std::io::Write, stderr: &mut dyn std::io::Write) -> i32 {
    match parse(arguments) {
        Ok(Invocation::Help) => {
            let _ = write!(stdout, "{}", help());
            0
        }
        Ok(Invocation::Version) => {
            let _ = writeln!(stdout, "{PROG} {}", VERSION.trim());
            0
        }
        Ok(Invocation::Command { command, .. }) => {
            let _ = writeln!(
                stderr,
                "{}\n{PROG}: error: the {command} command is not available in this build yet",
                usage()
            );
            2
        }
        Err(UsageError(message)) => {
            let _ = writeln!(stderr, "{}\n{PROG}: error: {message}", usage());
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn run_args(values: &[&str]) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args(values), &mut out, &mut err);
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    #[test]
    fn version_names_the_release() {
        let (code, out, _) = run_args(&["--version"]);
        assert_eq!(code, 0);
        assert_eq!(out, format!("proxy-control-installer {}\n", VERSION.trim()));
        assert!(!VERSION.trim().is_empty());
    }

    #[test]
    fn root_is_parsed_like_argparse() {
        for form in [&["--root", "/tmp/x", "status"][..], &["--root=/tmp/x", "status"], &["--ro", "/tmp/x", "status"]] {
            assert_eq!(
                parse(&args(form)).unwrap(),
                Invocation::Command { root: "/tmp/x".into(), command: "status".into(), arguments: vec![] }
            );
        }
        assert_eq!(
            parse(&args(&["resume", "--json"])).unwrap(),
            Invocation::Command { root: "/".into(), command: "resume".into(), arguments: args(&["--json"]) }
        );
    }

    #[test]
    fn usage_errors_exit_2() {
        let (code, _, err) = run_args(&[]);
        assert_eq!(code, 2);
        assert!(
            err.ends_with("proxy-control-installer: error: the following arguments are required: command\n"),
            "{err}"
        );
        assert!(err.starts_with("usage: proxy-control-installer [-h] {wizard,plan,"));
        assert_eq!(run_args(&["frobnicate"]).0, 2);
        assert!(run_args(&["frobnicate"]).2.contains("invalid choice: 'frobnicate'"));
        assert_eq!(run_args(&["--bogus", "status"]).0, 2);
        assert_eq!(run_args(&["--root"]).0, 2);
        assert_eq!(run_args(&["status"]).0, 2);
        assert_eq!(run_args(&["-h"]).0, 0);
    }
}
