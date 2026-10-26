//! A port of the parts of Python 3.12's `argparse` the installer's command lines use, so that
//! operators, scripts and README commands see the same behaviour and bytes:
//!
//! - unambiguous prefixes of long options (`--conf` → `--config`), `--opt=value`, `--`;
//! - `-h/--help` (help on stdout, exit 0) and usage errors (`usage: …` and
//!   `<prog>: error: <message>` on stderr, exit 2) with argparse's exact texts;
//! - subcommands (`nargs=PARSER`), required options and positionals, `choices`, `type=Path`
//!   (stored as `str(Path(value))`, so `""` becomes `.`);
//! - argparse's usage wrapping and help layout (`HelpFormatter`, `textwrap`) for a given width
//!   (`shutil.get_terminal_size().columns - 2`, see [`terminal_width`]).
//!
//! Only the actions the installer needs exist: store, store_true, help and subparsers.

use std::collections::BTreeMap;

use crate::pystr::{py_path_str, py_repr};

/// How many command-line strings an action consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nargs {
    /// Flags (`store_true`, `help`).
    Zero,
    /// `nargs=None`: exactly one.
    One,
    /// A subcommand and everything after it (`argparse.PARSER`).
    Parser,
}

/// `help=`: absent, `argparse.SUPPRESS`, or a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Help {
    None,
    Suppress,
    Text(String),
}

/// What taking the action does.
#[derive(Debug, Clone)]
pub enum Kind {
    Store,
    StoreTrue,
    Help,
    Subparsers(Vec<SubCommand>),
}

/// `choices=`: the accepted strings, how `repr()` shows each in an error, and how `str()` shows
/// each in the metavar (an enum's members differ in the two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    pub values: Vec<String>,
    pub reprs: Vec<String>,
    pub strs: Vec<String>,
}

impl Choices {
    /// Plain string choices: `repr` is the quoted string.
    pub fn strings(values: &[&str]) -> Choices {
        Choices {
            values: values.iter().map(|v| v.to_string()).collect(),
            reprs: values.iter().map(|v| py_repr(v)).collect(),
            strs: values.iter().map(|v| v.to_string()).collect(),
        }
    }
}

/// One argument (`parser.add_argument(...)`).
#[derive(Debug, Clone)]
pub struct Action {
    /// Empty for a positional.
    pub option_strings: Vec<String>,
    pub dest: String,
    pub nargs: Nargs,
    pub required: bool,
    pub help: Help,
    pub metavar: Option<String>,
    pub choices: Option<Choices>,
    pub kind: Kind,
    /// `type=Path`.
    pub path: bool,
    /// The default put into the namespace (`None` for `argparse.SUPPRESS`).
    pub default: Option<Arg>,
}

/// A parsed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    None,
    Bool(bool),
    Str(String),
}

/// One `add_parser(name, help=…)`.
#[derive(Debug, Clone)]
pub struct SubCommand {
    pub name: String,
    pub help: Option<String>,
    pub parser: Parser,
}

/// An `ArgumentParser`.
#[derive(Debug, Clone)]
pub struct Parser {
    pub prog: String,
    pub description: Option<String>,
    pub actions: Vec<Action>,
}

/// The parsed namespace: `dest` → value.
pub type Namespace = BTreeMap<String, Arg>;

/// What a parse ended with when it did not produce a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Parser {
    /// `ArgumentParser(prog=…, description=…)` with its `-h/--help`.
    pub fn new(prog: &str, description: Option<&str>) -> Parser {
        let mut parser =
            Parser { prog: prog.into(), description: description.map(str::to_string), actions: Vec::new() };
        parser.actions.push(Action {
            option_strings: vec!["-h".into(), "--help".into()],
            dest: "help".into(),
            nargs: Nargs::Zero,
            required: false,
            help: Help::Text("show this help message and exit".into()),
            metavar: None,
            choices: None,
            kind: Kind::Help,
            path: false,
            default: None,
        });
        parser
    }

    /// `add_argument(*strings, ...)` storing one value; `dest` from the first long option.
    pub fn add_option(
        &mut self,
        strings: &[&str],
        required: bool,
        help: Help,
        path: bool,
        default: Arg,
    ) -> &mut Action {
        let dest = strings
            .iter()
            .find(|s| s.starts_with("--"))
            .unwrap_or(&strings[0])
            .trim_start_matches('-')
            .replace('-', "_");
        self.actions.push(Action {
            option_strings: strings.iter().map(|s| s.to_string()).collect(),
            dest,
            nargs: Nargs::One,
            required,
            help,
            metavar: None,
            choices: None,
            kind: Kind::Store,
            path,
            default: Some(default),
        });
        self.actions.last_mut().expect("just pushed")
    }

    /// `add_argument(flag, action="store_true")`.
    pub fn add_flag(&mut self, strings: &[&str], help: Help) {
        self.add_option(strings, false, help, false, Arg::Bool(false));
        let action = self.actions.last_mut().expect("just pushed");
        action.nargs = Nargs::Zero;
        action.kind = Kind::StoreTrue;
    }

    /// `add_argument(dest)` (a positional).
    pub fn add_positional(&mut self, dest: &str, help: Help, path: bool, choices: Option<Choices>) {
        self.actions.push(Action {
            option_strings: Vec::new(),
            dest: dest.into(),
            nargs: Nargs::One,
            required: true,
            help,
            metavar: None,
            choices,
            kind: Kind::Store,
            path,
            default: Some(Arg::None),
        });
    }

    /// `add_subparsers(dest=…, required=…)` followed by `add_parser` for each command.
    pub fn add_subparsers(&mut self, dest: &str, required: bool, commands: Vec<SubCommand>) {
        let names: Vec<&str> = commands.iter().map(|c| c.name.as_str()).collect();
        let choices = Choices::strings(&names);
        self.actions.push(Action {
            option_strings: Vec::new(),
            dest: dest.into(),
            nargs: Nargs::Parser,
            required,
            help: Help::None,
            metavar: None,
            choices: Some(choices),
            kind: Kind::Subparsers(commands),
            path: false,
            default: Some(Arg::None),
        });
    }

    /// `"%s %s" % (prog_prefix, name)`: the prog of a subcommand added to this parser.
    pub fn sub_prog(&self, name: &str) -> String {
        let mut parts = vec![self.prog.clone()];
        for action in self.actions.iter().filter(|a| a.option_strings.is_empty()) {
            parts.push(format_args_usage(action, &action.dest));
        }
        format!("{} {name}", parts.join(" "))
    }

    fn option_string_actions(&self) -> Vec<(&str, usize)> {
        let mut out = Vec::new();
        for (index, action) in self.actions.iter().enumerate() {
            for option in &action.option_strings {
                out.push((option.as_str(), index));
            }
        }
        out
    }

    fn lookup(&self, option: &str) -> Option<usize> {
        self.option_string_actions().into_iter().find(|(name, _)| *name == option).map(|(_, index)| index)
    }

    /// `parse_args(args)`.
    pub fn parse_args(&self, args: &[String], width: usize) -> Result<Namespace, Exit> {
        let (namespace, extras) = self.parse_known_args(args, width)?;
        if !extras.is_empty() {
            return Err(self.error(&format!("unrecognized arguments: {}", extras.join(" ")), width));
        }
        Ok(namespace)
    }

    /// `parse_known_args(args)`: the namespace and the unrecognised strings.
    pub fn parse_known_args(&self, args: &[String], width: usize) -> Result<(Namespace, Vec<String>), Exit> {
        let mut namespace = Namespace::new();
        for action in &self.actions {
            if let Some(default) = &action.default {
                namespace.entry(action.dest.clone()).or_insert_with(|| default.clone());
            }
        }
        let mut state = State { parser: self, width, namespace, extras: Vec::new(), unrecognized: Vec::new() };
        match state.run(args) {
            Ok(()) => {}
            Err(Failure::Exit(exit)) => return Err(exit),
            Err(Failure::Argument(message)) => return Err(self.error(&message, width)),
        }
        let mut extras = state.extras;
        extras.extend(state.unrecognized);
        Ok((state.namespace, extras))
    }

    /// `error(message)`: usage and `<prog>: error: <message>` on stderr, exit 2.
    pub fn error(&self, message: &str, width: usize) -> Exit {
        Exit {
            status: 2,
            stdout: String::new(),
            stderr: format!("{}{}: error: {message}\n", self.format_usage(width), self.prog),
        }
    }

    /// `format_usage()`.
    pub fn format_usage(&self, width: usize) -> String {
        let mut formatter = Formatter::new(&self.prog, width);
        let usage = formatter.format_usage_text(&self.actions);
        finish(&usage)
    }

    /// `format_help()`.
    pub fn format_help(&self, width: usize) -> String {
        let mut formatter = Formatter::new(&self.prog, width);
        let mut out = formatter.format_usage_text(&self.actions);
        if let Some(description) = &self.description {
            out.push_str(&formatter.format_text(description));
        }
        let positionals: Vec<&Action> = self.actions.iter().filter(|a| a.option_strings.is_empty()).collect();
        let optionals: Vec<&Action> = self.actions.iter().filter(|a| !a.option_strings.is_empty()).collect();
        formatter.measure(&positionals);
        formatter.measure(&optionals);
        out.push_str(&formatter.section("positional arguments", &positionals));
        out.push_str(&formatter.section("options", &optionals));
        finish(&out)
    }
}

/// `format_help`'s tail: `\n\n\n+` → `\n\n`, then `strip("\n") + "\n"`.
fn finish(text: &str) -> String {
    let mut collapsed = String::with_capacity(text.len());
    let mut newlines = 0;
    for c in text.chars() {
        if c == '\n' {
            newlines += 1;
            if newlines <= 2 {
                collapsed.push(c);
            }
        } else {
            newlines = 0;
            collapsed.push(c);
        }
    }
    let trimmed = collapsed.trim_matches('\n');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

enum Failure {
    /// An `ArgumentError`: reported by the parser whose parse is running.
    Argument(String),
    /// Already rendered (help, or an error of a nested parser).
    Exit(Exit),
}

type OptionTuple = (Option<usize>, String, Option<String>, Option<String>);

struct State<'a> {
    parser: &'a Parser,
    width: usize,
    namespace: Namespace,
    extras: Vec<String>,
    unrecognized: Vec<String>,
}

fn action_name(action: &Action) -> String {
    if !action.option_strings.is_empty() {
        action.option_strings.join("/")
    } else {
        action.metavar.clone().unwrap_or_else(|| action.dest.clone())
    }
}

fn argument_error(action: &Action, message: &str) -> Failure {
    Failure::Argument(format!("argument {}: {message}", action_name(action)))
}

/// `_negative_number_matcher`: `^-\d+$|^-\d*\.\d+$`. Python's `\d` is Unicode `Nd`; Rust's
/// `is_numeric` (Nd, Nl, No) stands in beyond ASCII, which only decides between "a positional"
/// and "an unknown option" for such a string.
fn looks_negative(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('-') else { return false };
    let digit = |c: char| c.is_ascii_digit() || (!c.is_ascii() && c.is_numeric());
    if !rest.is_empty() && rest.chars().all(digit) {
        return true;
    }
    match rest.split_once('.') {
        Some((head, tail)) => head.chars().all(digit) && !tail.is_empty() && tail.chars().all(digit),
        None => false,
    }
}

impl State<'_> {
    fn parse_optional(&self, arg: &str) -> Result<Option<OptionTuple>, Failure> {
        if arg.is_empty() || !arg.starts_with('-') {
            return Ok(None);
        }
        if let Some(index) = self.parser.lookup(arg) {
            return Ok(Some((Some(index), arg.to_string(), None, None)));
        }
        if arg.chars().count() == 1 {
            return Ok(None);
        }
        if let Some((option, explicit)) = arg.split_once('=') {
            if let Some(index) = self.parser.lookup(option) {
                return Ok(Some((Some(index), option.to_string(), Some("=".into()), Some(explicit.to_string()))));
            }
        }
        let tuples = self.option_tuples(arg);
        if tuples.len() > 1 {
            let matches: Vec<&str> = tuples.iter().map(|t| t.1.as_str()).collect();
            let message = format!("ambiguous option: {arg} could match {}", matches.join(", "));
            return Err(Failure::Exit(self.parser.error(&message, self.width)));
        }
        if let Some(tuple) = tuples.into_iter().next() {
            return Ok(Some(tuple));
        }
        if looks_negative(arg) || arg.contains(' ') {
            return Ok(None);
        }
        Ok(Some((None, arg.to_string(), None, None)))
    }

    fn option_tuples(&self, arg: &str) -> Vec<OptionTuple> {
        let mut result = Vec::new();
        let second_is_prefix = arg.chars().nth(1) == Some('-');
        if second_is_prefix {
            let (prefix, sep, explicit) = match arg.split_once('=') {
                Some((prefix, explicit)) => (prefix, Some("=".to_string()), Some(explicit.to_string())),
                None => (arg, None, None),
            };
            for (option, index) in self.parser.option_string_actions() {
                if option.starts_with(prefix) {
                    result.push((Some(index), option.to_string(), sep.clone(), explicit.clone()));
                }
            }
        } else {
            let short: String = arg.chars().take(2).collect();
            let short_explicit: String = arg.chars().skip(2).collect();
            for (option, index) in self.parser.option_string_actions() {
                if option == short {
                    result.push((Some(index), option.to_string(), Some(String::new()), Some(short_explicit.clone())));
                } else if option.starts_with(arg) {
                    result.push((Some(index), option.to_string(), None, None));
                }
            }
        }
        result
    }

    fn run(&mut self, args: &[String]) -> Result<(), Failure> {
        let mut pattern = String::new();
        let mut option_indices: BTreeMap<usize, OptionTuple> = BTreeMap::new();
        let mut after_double_dash = false;
        for (index, arg) in args.iter().enumerate() {
            if after_double_dash {
                pattern.push('A');
            } else if arg == "--" {
                pattern.push('-');
                after_double_dash = true;
            } else if let Some(tuple) = self.parse_optional(arg)? {
                option_indices.insert(index, tuple);
                pattern.push('O');
            } else {
                pattern.push('A');
            }
        }
        let mut seen: Vec<usize> = Vec::new();
        let mut positionals: Vec<usize> =
            (0..self.parser.actions.len()).filter(|i| self.parser.actions[*i].option_strings.is_empty()).collect();
        let max_option = option_indices.keys().next_back().copied();
        let mut start = 0usize;
        while max_option.is_some_and(|max| start <= max) {
            let next_option = *option_indices.range(start..).next().expect("an option at or after start").0;
            if start != next_option {
                let end = self.consume_positionals(args, &pattern, start, &mut positionals, &mut seen)?;
                if end > start {
                    start = end;
                    continue;
                }
                start = end;
            }
            if !option_indices.contains_key(&start) {
                self.extras.extend(args[start..next_option].iter().cloned());
                start = next_option;
            }
            start = self.consume_optional(args, &pattern, start, &option_indices, &mut seen)?;
        }
        let stop = self.consume_positionals(args, &pattern, start, &mut positionals, &mut seen)?;
        self.extras.extend(args[stop..].iter().cloned());
        let required: Vec<String> = self
            .parser
            .actions
            .iter()
            .enumerate()
            .filter(|(index, action)| action.required && !seen.contains(index))
            .map(|(_, action)| action_name(action))
            .collect();
        if !required.is_empty() {
            return Err(Failure::Argument(format!("the following arguments are required: {}", required.join(", "))));
        }
        Ok(())
    }

    fn consume_optional(
        &mut self,
        args: &[String],
        pattern: &str,
        start: usize,
        option_indices: &BTreeMap<usize, OptionTuple>,
        seen: &mut Vec<usize>,
    ) -> Result<usize, Failure> {
        let (mut action, mut option_string, mut sep, mut explicit) = option_indices[&start].clone();
        let mut tuples: Vec<(usize, Vec<String>, String)> = Vec::new();
        let stop;
        loop {
            let Some(index) = action else {
                self.extras.push(args[start].clone());
                return Ok(start + 1);
            };
            let current = &self.parser.actions[index];
            if let Some(explicit_arg) = explicit.clone() {
                let count =
                    match_count(current, "A").ok_or_else(|| argument_error(current, "expected one argument"))?;
                let second = option_string.chars().nth(1);
                if count == 0 && second != Some('-') && !explicit_arg.is_empty() {
                    if sep.as_deref().is_some_and(|s| !s.is_empty()) || explicit_arg.starts_with('-') {
                        return Err(argument_error(
                            current,
                            &format!("ignored explicit argument {}", py_repr(&explicit_arg)),
                        ));
                    }
                    tuples.push((index, Vec::new(), option_string.clone()));
                    let first = explicit_arg.chars().next().expect("non-empty");
                    option_string = format!("-{first}");
                    match self.parser.lookup(&option_string) {
                        Some(next) => {
                            action = Some(next);
                            let rest: String = explicit_arg.chars().skip(1).collect();
                            if rest.is_empty() {
                                sep = None;
                                explicit = None;
                            } else if let Some(stripped) = rest.strip_prefix('=') {
                                sep = Some("=".into());
                                explicit = Some(stripped.to_string());
                            } else {
                                sep = Some(String::new());
                                explicit = Some(rest);
                            }
                        }
                        None => {
                            self.extras.push(format!("-{explicit_arg}"));
                            stop = start + 1;
                            break;
                        }
                    }
                } else if count == 1 {
                    stop = start + 1;
                    tuples.push((index, vec![explicit_arg], option_string.clone()));
                    break;
                } else {
                    return Err(argument_error(
                        current,
                        &format!("ignored explicit argument {}", py_repr(&explicit_arg)),
                    ));
                }
            } else {
                let selected = &pattern[start + 1..];
                let count =
                    match_count(current, selected).ok_or_else(|| argument_error(current, "expected one argument"))?;
                stop = start + 1 + count;
                tuples.push((index, args[start + 1..stop].to_vec(), option_string.clone()));
                break;
            }
        }
        for (index, values, _) in tuples {
            self.take_action(index, values, seen)?;
        }
        Ok(stop)
    }

    fn consume_positionals(
        &mut self,
        args: &[String],
        pattern: &str,
        mut start: usize,
        positionals: &mut Vec<usize>,
        seen: &mut Vec<usize>,
    ) -> Result<usize, Failure> {
        let selected = &pattern[start..];
        let counts = match_partial(&self.parser.actions, positionals, selected);
        let taken: Vec<usize> = positionals.iter().copied().take(counts.len()).collect();
        for (index, count) in taken.iter().zip(&counts) {
            let values = args[start..start + count].to_vec();
            start += count;
            self.take_action(*index, values, seen)?;
        }
        positionals.drain(..counts.len());
        Ok(start)
    }

    fn take_action(&mut self, index: usize, mut values: Vec<String>, seen: &mut Vec<usize>) -> Result<(), Failure> {
        seen.push(index);
        let action = &self.parser.actions[index];
        if action.option_strings.is_empty() && action.nargs != Nargs::Parser {
            if let Some(position) = values.iter().position(|v| v == "--") {
                values.remove(position);
            }
        }
        let convert = |value: &str| if action.path { py_path_str(value) } else { value.to_string() };
        let check = |value: &str| -> Result<(), Failure> {
            if let Some(choices) = &action.choices {
                if !choices.values.iter().any(|choice| choice == value) {
                    return Err(argument_error(
                        action,
                        &format!("invalid choice: {} (choose from {})", py_repr(value), choices.reprs.join(", ")),
                    ));
                }
            }
            Ok(())
        };
        match &action.kind {
            Kind::Help => {
                return Err(Failure::Exit(Exit {
                    status: 0,
                    stdout: self.parser.format_help(self.width),
                    stderr: String::new(),
                }));
            }
            Kind::StoreTrue => {
                self.namespace.insert(action.dest.clone(), Arg::Bool(true));
            }
            Kind::Store => {
                let value = convert(&values[0]);
                check(&value)?;
                self.namespace.insert(action.dest.clone(), Arg::Str(value));
            }
            Kind::Subparsers(commands) => {
                check(&values[0])?;
                let name = values[0].clone();
                self.namespace.insert(action.dest.clone(), Arg::Str(name.clone()));
                let command = commands.iter().find(|c| c.name == name).expect("checked by choices");
                let (sub_namespace, sub_extras) =
                    command.parser.parse_known_args(&values[1..], self.width).map_err(Failure::Exit)?;
                self.namespace.extend(sub_namespace);
                self.unrecognized.extend(sub_extras);
            }
        }
        Ok(())
    }
}

/// A token of an nargs pattern: a literal pattern character or a starred class.
#[derive(Clone, Copy)]
enum Tok {
    Lit(char),
    Star(&'static str),
}

fn nargs_pattern(action: &Action) -> Vec<Tok> {
    let optional = !action.option_strings.is_empty();
    match (action.nargs, optional) {
        (Nargs::Zero, _) => vec![],
        (Nargs::One, true) => vec![Tok::Lit('A')],
        (Nargs::One, false) => vec![Tok::Star("-"), Tok::Lit('A'), Tok::Star("-")],
        (Nargs::Parser, true) => vec![Tok::Lit('A'), Tok::Star("AO")],
        (Nargs::Parser, false) => vec![Tok::Star("-"), Tok::Lit('A'), Tok::Star("-AO")],
    }
}

/// Greedy backtracking match of consecutive groups at the start of `text`: each group's length.
fn match_groups(groups: &[Vec<Tok>], text: &[char]) -> Option<Vec<usize>> {
    fn go(
        groups: &[Vec<Tok>],
        group: usize,
        tok: usize,
        text: &[char],
        pos: usize,
        start: usize,
        out: &mut Vec<usize>,
    ) -> bool {
        if group == groups.len() {
            return true;
        }
        if tok == groups[group].len() {
            out.push(pos - start);
            if go(groups, group + 1, 0, text, pos, pos, out) {
                return true;
            }
            out.pop();
            return false;
        }
        match groups[group][tok] {
            Tok::Lit(c) => text.get(pos) == Some(&c) && go(groups, group, tok + 1, text, pos + 1, start, out),
            Tok::Star(class) => {
                let mut end = pos;
                while text.get(end).is_some_and(|c| class.contains(*c)) {
                    end += 1;
                }
                (pos..=end).rev().any(|stop| go(groups, group, tok + 1, text, stop, start, out))
            }
        }
    }
    let mut out = Vec::new();
    go(groups, 0, 0, text, 0, 0, &mut out).then_some(out)
}

fn match_count(action: &Action, pattern: &str) -> Option<usize> {
    let text: Vec<char> = pattern.chars().collect();
    match_groups(&[nargs_pattern(action)], &text).map(|counts| counts[0])
}

fn match_partial(actions: &[Action], positionals: &[usize], pattern: &str) -> Vec<usize> {
    let text: Vec<char> = pattern.chars().collect();
    for take in (1..=positionals.len()).rev() {
        let groups: Vec<Vec<Tok>> = positionals[..take].iter().map(|i| nargs_pattern(&actions[*i])).collect();
        if let Some(counts) = match_groups(&groups, &text) {
            return counts;
        }
    }
    Vec::new()
}

/// `shutil.get_terminal_size().columns - 2`: `$COLUMNS`, else the terminal on stdout, else 80.
pub fn terminal_width() -> usize {
    if let Some(columns) = std::env::var("COLUMNS").ok().and_then(|v| v.parse::<usize>().ok()).filter(|c| *c > 0) {
        return columns.saturating_sub(2);
    }
    // SAFETY: TIOCGWINSZ fills a winsize; a failure leaves it zeroed.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let status = unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut size) };
    let columns = if status == 0 && size.ws_col > 0 { usize::from(size.ws_col) } else { 80 };
    columns.saturating_sub(2)
}

fn metavar(action: &Action, default: &str) -> String {
    if let Some(metavar) = &action.metavar {
        return metavar.clone();
    }
    match &action.choices {
        Some(choices) => format!("{{{}}}", choices.strs.join(",")),
        None => default.to_string(),
    }
}

fn format_args_usage(action: &Action, default: &str) -> String {
    let name = metavar(action, default);
    match action.nargs {
        Nargs::Zero => String::new(),
        Nargs::One => name,
        Nargs::Parser => format!("{name} ..."),
    }
}

fn default_metavar(action: &Action) -> String {
    if action.option_strings.is_empty() {
        action.dest.clone()
    } else {
        action.dest.to_uppercase()
    }
}

fn invocation(action: &Action) -> String {
    if action.option_strings.is_empty() {
        return metavar(action, &action.dest);
    }
    if action.nargs == Nargs::Zero {
        return action.option_strings.join(", ");
    }
    let args = format_args_usage(action, &default_metavar(action));
    action.option_strings.iter().map(|option| format!("{option} {args}")).collect::<Vec<_>>().join(", ")
}

/// The usage text of a list of actions (`_format_actions_usage`, no groups).
fn actions_usage(actions: &[&Action]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for action in actions {
        if action.help == Help::Suppress {
            continue;
        }
        if action.option_strings.is_empty() {
            parts.push(format_args_usage(action, &action.dest));
        } else {
            let mut part = if action.nargs == Nargs::Zero {
                action.option_strings[0].clone()
            } else {
                format!("{} {}", action.option_strings[0], format_args_usage(action, &default_metavar(action)))
            };
            if !action.required {
                part = format!("[{part}]");
            }
            parts.push(part);
        }
    }
    parts.join(" ").trim().to_string()
}

/// `re.findall(r'\(.*?\)+(?=\s|$)|\[.*?\]+(?=\s|$)|\S+', text)`.
fn usage_parts(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut parts = Vec::new();
    let mut pos = 0;
    while pos < chars.len() {
        if chars[pos].is_whitespace() {
            pos += 1;
            continue;
        }
        let bracketed = match chars[pos] {
            '(' => Some(')'),
            '[' => Some(']'),
            _ => None,
        };
        let mut end = None;
        if let Some(close) = bracketed {
            let mut k = pos + 1;
            while k < chars.len() {
                if chars[k] == close {
                    let mut m = k;
                    while m < chars.len() && chars[m] == close {
                        m += 1;
                    }
                    if m == chars.len() || chars[m].is_whitespace() {
                        end = Some(m);
                        break;
                    }
                }
                k += 1;
            }
        }
        let end = end.unwrap_or_else(|| {
            let mut m = pos;
            while m < chars.len() && !chars[m].is_whitespace() {
                m += 1;
            }
            m
        });
        parts.push(chars[pos..end].iter().collect());
        pos = end;
    }
    parts
}

struct Formatter {
    prog: String,
    width: usize,
    max_help_position: usize,
    action_max_length: usize,
}

impl Formatter {
    fn new(prog: &str, width: usize) -> Formatter {
        Formatter {
            prog: prog.into(),
            width,
            max_help_position: 24.min(width.saturating_sub(20).max(4)),
            action_max_length: 0,
        }
    }

    /// `_format_usage(None, actions, groups, None)`: `usage: …\n\n`.
    fn format_usage_text(&mut self, actions: &[Action]) -> String {
        let prefix = "usage: ";
        let optionals: Vec<&Action> = actions.iter().filter(|a| !a.option_strings.is_empty()).collect();
        let positionals: Vec<&Action> = actions.iter().filter(|a| a.option_strings.is_empty()).collect();
        let all: Vec<&Action> = optionals.iter().chain(positionals.iter()).copied().collect();
        let action_usage = actions_usage(&all);
        let mut usage = [self.prog.as_str(), action_usage.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        let text_width = self.width;
        if prefix.chars().count() + usage.chars().count() > text_width {
            let opt_parts = usage_parts(&actions_usage(&optionals));
            let pos_parts = usage_parts(&actions_usage(&positionals));
            let get_lines = |parts: &[String], indent: &str, with_prefix: bool| -> Vec<String> {
                let mut lines = Vec::new();
                let mut line: Vec<&str> = Vec::new();
                let indent_length = indent.chars().count();
                let mut line_len = if with_prefix { prefix.len() as isize - 1 } else { indent_length as isize - 1 };
                for part in parts {
                    let length = part.chars().count() as isize;
                    if line_len + 1 + length > text_width as isize && !line.is_empty() {
                        lines.push(format!("{indent}{}", line.join(" ")));
                        line.clear();
                        line_len = indent_length as isize - 1;
                    }
                    line.push(part);
                    line_len += length + 1;
                }
                if !line.is_empty() {
                    lines.push(format!("{indent}{}", line.join(" ")));
                }
                if with_prefix {
                    if let Some(first) = lines.first_mut() {
                        *first = first.chars().skip(indent_length).collect();
                    }
                }
                lines
            };
            let prog_length = self.prog.chars().count();
            let lines: Vec<String> = if (prefix.len() + prog_length) as f64 <= 0.75 * text_width as f64 {
                let indent = " ".repeat(prefix.len() + prog_length + 1);
                if !opt_parts.is_empty() {
                    let mut first: Vec<String> = vec![self.prog.clone()];
                    first.extend(opt_parts.iter().cloned());
                    let mut lines = get_lines(&first, &indent, true);
                    lines.extend(get_lines(&pos_parts, &indent, false));
                    lines
                } else if !pos_parts.is_empty() {
                    let mut first: Vec<String> = vec![self.prog.clone()];
                    first.extend(pos_parts.iter().cloned());
                    get_lines(&first, &indent, true)
                } else {
                    vec![self.prog.clone()]
                }
            } else {
                let indent = " ".repeat(prefix.len());
                let parts: Vec<String> = opt_parts.iter().chain(pos_parts.iter()).cloned().collect();
                let mut lines = get_lines(&parts, &indent, false);
                if lines.len() > 1 {
                    lines = get_lines(&opt_parts, &indent, false);
                    lines.extend(get_lines(&pos_parts, &indent, false));
                }
                let mut all = vec![self.prog.clone()];
                all.extend(lines);
                all
            };
            usage = lines.join("\n");
        }
        format!("{prefix}{usage}\n\n")
    }

    /// `_format_text(text)` at the root (indent 0).
    fn format_text(&self, text: &str) -> String {
        let width = self.width.max(11);
        format!("{}\n\n", wrap(&normalize_whitespace(text), width).join("\n"))
    }

    /// `add_argument` for each action of a section (indent 2): the widest invocation.
    fn measure(&mut self, actions: &[&Action]) {
        for action in actions {
            if action.help == Help::Suppress {
                continue;
            }
            let mut longest = invocation(action).chars().count();
            if let Kind::Subparsers(commands) = &action.kind {
                for command in commands.iter().filter(|c| c.help.is_some()) {
                    longest = longest.max(command.name.chars().count());
                }
            }
            self.action_max_length = self.action_max_length.max(longest + 2);
        }
    }

    fn section(&self, heading: &str, actions: &[&Action]) -> String {
        let mut items = String::new();
        for action in actions {
            if action.help == Help::Suppress {
                continue;
            }
            items.push_str(&self.format_action(action, 2));
        }
        if items.is_empty() {
            return String::new();
        }
        format!("\n{heading}:\n{items}\n")
    }

    fn format_action(&self, action: &Action, indent: usize) -> String {
        let help = match &action.help {
            Help::Text(text) => Some(text.as_str()),
            _ => None,
        };
        self.format_entry(&invocation(action), help, indent, action)
    }

    fn format_entry(&self, header: &str, help: Option<&str>, indent: usize, action: &Action) -> String {
        let help_position = (self.action_max_length + 2).min(self.max_help_position);
        let help_width = self.width.saturating_sub(help_position).max(11);
        let action_width = help_position as isize - indent as isize - 2;
        let pad = " ".repeat(indent);
        let mut out;
        let mut indent_first = 0;
        match help.filter(|h| !h.is_empty()) {
            None => out = format!("{pad}{header}\n"),
            Some(_) if header.chars().count() as isize <= action_width => {
                let width = action_width.max(0) as usize;
                out = format!("{pad}{header:<width$}  ");
            }
            Some(_) => {
                out = format!("{pad}{header}\n");
                indent_first = help_position;
            }
        }
        if let Some(text) = help.filter(|h| !h.trim().is_empty()) {
            let lines = wrap(&normalize_whitespace(text), help_width);
            if let Some((first, rest)) = lines.split_first() {
                out.push_str(&format!("{}{first}\n", " ".repeat(indent_first)));
                for line in rest {
                    out.push_str(&format!("{}{line}\n", " ".repeat(help_position)));
                }
            }
        } else if !out.ends_with('\n') {
            out.push('\n');
        }
        if let Kind::Subparsers(commands) = &action.kind {
            for command in commands.iter().filter(|c| c.help.is_some()) {
                let pseudo = Action {
                    option_strings: Vec::new(),
                    dest: command.name.clone(),
                    nargs: Nargs::One,
                    required: false,
                    help: Help::Text(command.help.clone().unwrap_or_default()),
                    metavar: Some(command.name.clone()),
                    choices: None,
                    kind: Kind::Store,
                    path: false,
                    default: None,
                };
                out.push_str(&self.format_action(&pseudo, indent + 2));
            }
        }
        out
    }
}

/// `_whitespace_matcher.sub(' ', text).strip()` (ASCII whitespace).
fn normalize_whitespace(text: &str) -> String {
    text.split(|c: char| c.is_ascii_whitespace()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
}

fn is_letter(c: char) -> bool {
    (c.is_alphanumeric() || c == '_') && !c.is_numeric()
}

/// `TextWrapper._split`: whitespace runs and words, a word split after a hyphen that has two
/// letters (or letter-hyphen-letter) before it and a letter, optional hyphen, letter after it.
fn chunks(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < chars.len() {
        let start = pos;
        if chars[pos] == ' ' {
            while pos < chars.len() && chars[pos] == ' ' {
                pos += 1;
            }
            out.push(chars[start..pos].iter().collect());
            continue;
        }
        while pos < chars.len() && chars[pos] != ' ' {
            if chars[pos] == '-' && pos > start {
                let before_two = pos >= 2 && is_letter(chars[pos - 1]) && is_letter(chars[pos - 2]);
                let before_lhl =
                    pos >= 3 && is_letter(chars[pos - 1]) && chars[pos - 2] == '-' && is_letter(chars[pos - 3]);
                let after = chars.get(pos + 1).is_some_and(|c| is_letter(*c))
                    && (chars.get(pos + 2).is_some_and(|c| is_letter(*c))
                        || (chars.get(pos + 2) == Some(&'-') && chars.get(pos + 3).is_some_and(|c| is_letter(*c))));
                if (before_two || before_lhl) && after && (pos + 1 - start) > 1 {
                    pos += 1;
                    break;
                }
            }
            pos += 1;
        }
        out.push(chars[start..pos].iter().collect());
    }
    out
}

/// `textwrap.wrap(text, width)` (break_long_words, break_on_hyphens, drop_whitespace).
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut reversed: Vec<String> = chunks(text);
    reversed.reverse();
    let mut lines: Vec<String> = Vec::new();
    while !reversed.is_empty() {
        let mut current: Vec<String> = Vec::new();
        let mut length = 0;
        if reversed.last().is_some_and(|c| c.trim().is_empty()) && !lines.is_empty() {
            reversed.pop();
        }
        while let Some(chunk) = reversed.last() {
            let size = chunk.chars().count();
            if length + size <= width {
                length += size;
                current.push(reversed.pop().expect("checked"));
            } else {
                break;
            }
        }
        if reversed.last().is_some_and(|c| c.chars().count() > width) {
            let space_left = if width < 1 { 1 } else { width - length };
            let chunk: Vec<char> = reversed.last().expect("checked").chars().collect();
            let mut end = space_left;
            if chunk.len() > space_left {
                if let Some(hyphen) = chunk[..space_left].iter().rposition(|c| *c == '-') {
                    if hyphen > 0 && chunk[..hyphen].iter().any(|c| *c != '-') {
                        end = hyphen + 1;
                    }
                }
            }
            let end = end.min(chunk.len());
            current.push(chunk[..end].iter().collect());
            *reversed.last_mut().expect("checked") = chunk[end..].iter().collect();
        }
        if current.last().is_some_and(|c| c.trim().is_empty()) {
            current.pop();
        }
        if !current.is_empty() {
            lines.push(current.concat());
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_on_hyphens_and_spaces() {
        assert_eq!(wrap("reconcile Core and version-agent code", 22), vec!["reconcile Core and", "version-agent code"]);
        assert_eq!(
            wrap("reconcile Core and version-agent code", 27),
            vec!["reconcile Core and version-", "agent code"]
        );
        assert_eq!(wrap("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
    }

    #[test]
    fn usage_parts_keep_brackets_together() {
        assert_eq!(
            usage_parts("[-h] [--lang {en,ru}] --config CONFIG"),
            vec!["[-h]", "[--lang {en,ru}]", "--config", "CONFIG"]
        );
    }
}
