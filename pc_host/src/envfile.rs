//! Decode systemd `EnvironmentFile` values without executing shell syntax or expanding variables.

use std::collections::BTreeMap;
use std::io;
use std::iter::Peekable;
use std::path::Path;
use std::str::Chars;

fn horizontal(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r')
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unterminated environment value")
}

fn append(value: &mut String, retained: &mut usize, c: char, quoted: bool) {
    value.push(c);
    if quoted || !horizontal(c) {
        *retained = value.len();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Leading,
    Unquoted,
    Single,
    Double,
}

fn value(input: &mut Peekable<Chars<'_>>) -> io::Result<String> {
    let mut output = String::new();
    let mut retained = 0;
    let mut mode = Mode::Leading;
    while let Some(c) = input.next() {
        match mode {
            Mode::Leading | Mode::Unquoted => match c {
                '\n' => break,
                c if mode == Mode::Leading && horizontal(c) => {}
                '\'' if mode == Mode::Leading => mode = Mode::Single,
                '"' if mode == Mode::Leading => mode = Mode::Double,
                '\\' => match input.next().ok_or_else(invalid)? {
                    '\n' => {}
                    escaped => {
                        append(&mut output, &mut retained, escaped, true);
                        mode = Mode::Unquoted;
                    }
                },
                c => {
                    append(&mut output, &mut retained, c, false);
                    mode = Mode::Unquoted;
                }
            },
            Mode::Single => {
                if c == '\'' {
                    mode = Mode::Unquoted;
                } else {
                    append(&mut output, &mut retained, c, true);
                }
            }
            Mode::Double => match c {
                '"' => mode = Mode::Unquoted,
                '\\' => match input.next().ok_or_else(invalid)? {
                    '\n' => {}
                    escaped @ ('"' | '\\' | '$' | '`') => append(&mut output, &mut retained, escaped, true),
                    other => {
                        append(&mut output, &mut retained, '\\', true);
                        append(&mut output, &mut retained, other, true);
                    }
                },
                c => append(&mut output, &mut retained, c, true),
            },
        }
    }
    if matches!(mode, Mode::Single | Mode::Double) {
        return Err(invalid());
    }
    output.truncate(retained);
    Ok(output)
}

fn key_is_valid(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn parse(text: &str) -> io::Result<BTreeMap<String, String>> {
    let mut input = text.chars().peekable();
    let mut values = BTreeMap::new();
    while let Some(c) = input.peek().copied() {
        if horizontal(c) || c == '\n' {
            input.next();
            continue;
        }
        if matches!(c, '#' | ';') {
            while let Some(c) = input.next() {
                if c == '\\' && input.peek() == Some(&'\n') {
                    input.next();
                } else if c == '\n' {
                    break;
                }
            }
            continue;
        }
        let mut key = String::new();
        let mut assigned = false;
        for c in input.by_ref() {
            if c == '=' {
                assigned = true;
                break;
            }
            if c == '\n' {
                break;
            }
            key.push(c);
        }
        if !assigned {
            continue;
        }
        let key = key.trim_end_matches(horizontal);
        if key_is_valid(key) {
            values.insert(key.to_owned(), value(&mut input)?);
        } else {
            for c in input.by_ref() {
                if c == '\n' {
                    break;
                }
            }
        }
    }
    Ok(values)
}

/// Read optional systemd environment assignments. Missing files mean no overrides.
/// Comments and invalid variable names are ignored; malformed quoting fails without exposing values.
pub fn read(path: &Path) -> io::Result<BTreeMap<String, String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn decodes_quoted_paths_continuations_and_literal_shell_characters() {
        let values = parse(concat!(
            "# FOO=ignored\n; BAR=ignored\n",
            "PROXY_CONTROL_COMPOSE_DIR=\"/opt/operator stack\"\n",
            "PROXY_CONTROL_COMPOSE_FILES=\"compose.yaml:\\\ncompose.naive.yaml\"\n",
            "STATE='/var/lib/operator state.json'\n",
            "LITERAL=\"$HOME `not-a-command` \\q \\\"quoted\\\"\"\n",
            "SPACES=  before  after  \t\r\n",
            "QUOTED_SPACES='  preserved  '  \n",
            "DUPLICATE=first\nDUPLICATE=last\n",
        ))
        .unwrap();
        assert_eq!(values["PROXY_CONTROL_COMPOSE_DIR"], "/opt/operator stack");
        assert_eq!(values["PROXY_CONTROL_COMPOSE_FILES"], "compose.yaml:compose.naive.yaml");
        assert_eq!(values["STATE"], "/var/lib/operator state.json");
        assert_eq!(values["LITERAL"], "$HOME `not-a-command` \\q \"quoted\"");
        assert_eq!(values["SPACES"], "before  after");
        assert_eq!(values["QUOTED_SPACES"], "  preserved  ");
        assert_eq!(values["DUPLICATE"], "last");
        assert!(!values.contains_key("FOO") && !values.contains_key("BAR"));
    }

    #[test]
    fn malformed_values_fail_without_echoing_the_secret() {
        for text in ["TOKEN='private-value", "TOKEN=\"private-value", "TOKEN=private-value\\"] {
            let error = parse(text).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(!error.to_string().contains("private-value"));
        }
    }
}
