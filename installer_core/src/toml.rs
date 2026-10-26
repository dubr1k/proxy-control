//! TOML 1.0.0 exactly as Python 3.12's `tomllib` reads it: a line-for-line port of
//! `tomllib/_parser.py` and `_re.py`, so that the operator sees the same `invalid TOML: …`
//! message (with the same line and column) and the same documents are accepted.
//!
//! Why not the `toml` crate: its messages differ, newer versions accept TOML 1.1 syntax that the
//! Python tools of a mixed fleet refuse, and the configuration checks need the document's key
//! order (the first unknown key wins). Positions are counted in code points, as Python does.
//!
//! Integers keep Python's unbounded range ([`PyInt`] carries the decimal text), so an
//! out-of-range port is reported as `contains invalid port: 99999999999999999999` like Python.

use std::collections::{HashMap, HashSet};

use crate::pystr::{py_repr, tuple_repr};

/// A parsed TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(PyInt),
    Float(f64),
    Boolean(bool),
    /// Offset or local date-time (the source text).
    Datetime(String),
    /// Local date (the source text).
    Date(String),
    /// Local time (the source text).
    Time(String),
    Array(Vec<Value>),
    Table(Table),
}

/// A table in document (insertion) order, like a Python `dict`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Table {
    entries: Vec<(String, Value)>,
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Insert or replace (a replaced key keeps its position, like a `dict`).
    pub fn insert(&mut self, key: String, value: Value) {
        match self.get_mut(&key) {
            Some(slot) => *slot = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Keys in document order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A Python `int`: arbitrary size, kept as its decimal text (`str(int)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyInt(String);

impl PyInt {
    pub fn from_i64(value: i64) -> PyInt {
        PyInt(value.to_string())
    }

    /// The decimal text (`str(value)`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value when it fits `i64`.
    pub fn to_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    /// `int(text, 0)` for a literal `RE_NUMBER` matched as an integer.
    fn parse_literal(text: &str) -> PyInt {
        let cleaned: String = text.chars().filter(|c| *c != '_').collect();
        let (negative, body) = match cleaned.strip_prefix('-') {
            Some(rest) => (true, rest.to_string()),
            None => (false, cleaned.strip_prefix('+').unwrap_or(&cleaned).to_string()),
        };
        let (radix, digits) = if let Some(rest) = body.strip_prefix("0x") {
            (16, rest)
        } else if let Some(rest) = body.strip_prefix("0o") {
            (8, rest)
        } else if let Some(rest) = body.strip_prefix("0b") {
            (2, rest)
        } else {
            (10, body.as_str())
        };
        let mut decimal = if radix == 10 {
            let trimmed = digits.trim_start_matches('0');
            if trimmed.is_empty() {
                "0".to_string()
            } else {
                trimmed.to_string()
            }
        } else {
            to_decimal(digits, radix)
        };
        if negative && decimal != "0" {
            decimal.insert(0, '-');
        }
        PyInt(decimal)
    }
}

/// Converts digits in `radix` to decimal text (little-endian base-10^9 limbs).
fn to_decimal(digits: &str, radix: u32) -> String {
    let mut limbs: Vec<u64> = vec![0];
    for ch in digits.chars() {
        let mut carry = u64::from(ch.to_digit(radix).unwrap_or(0));
        for limb in limbs.iter_mut() {
            let value = *limb * u64::from(radix) + carry;
            *limb = value % 1_000_000_000;
            carry = value / 1_000_000_000;
        }
        while carry > 0 {
            limbs.push(carry % 1_000_000_000);
            carry /= 1_000_000_000;
        }
    }
    let mut out = limbs.last().copied().unwrap_or(0).to_string();
    for limb in limbs.iter().rev().skip(1) {
        out.push_str(&format!("{limb:09}"));
    }
    out
}

/// `tomllib.TOMLDecodeError`: the message with its ` (at line L, column C)` suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

type Key = Vec<String>;
type Result<T> = std::result::Result<T, DecodeError>;

const FROZEN: u8 = 0;
const EXPLICIT_NEST: u8 = 1;

fn is_ascii_ctrl(c: char) -> bool {
    (c as u32) < 32 || c == '\u{7f}'
}

fn illegal_basic(c: char) -> bool {
    is_ascii_ctrl(c) && c != '\t'
}

fn illegal_multiline(c: char) -> bool {
    is_ascii_ctrl(c) && c != '\t' && c != '\n'
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn is_ws_or_newline(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n'
}

fn is_bare_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// `tomllib.loads(text)`.
pub fn loads(text: &str) -> Result<Table> {
    let src: Vec<char> = text.replace("\r\n", "\n").chars().collect();
    Parser { src: &src }.document()
}

#[derive(Default)]
struct FlagNode {
    flags: HashSet<u8>,
    recursive_flags: HashSet<u8>,
    nested: HashMap<String, FlagNode>,
}

#[derive(Default)]
struct Flags {
    root: HashMap<String, FlagNode>,
    pending: Vec<(Key, u8)>,
}

impl Flags {
    fn add_pending(&mut self, key: Key, flag: u8) {
        if !self.pending.iter().any(|(k, f)| *k == key && *f == flag) {
            self.pending.push((key, flag));
        }
    }

    fn finalize_pending(&mut self) {
        for (key, flag) in std::mem::take(&mut self.pending) {
            self.set(&key, flag, false);
        }
    }

    fn unset_all(&mut self, key: &[String]) {
        let mut cont = &mut self.root;
        for k in &key[..key.len() - 1] {
            match cont.get_mut(k) {
                Some(node) => cont = &mut node.nested,
                None => return,
            }
        }
        cont.remove(&key[key.len() - 1]);
    }

    fn set(&mut self, key: &[String], flag: u8, recursive: bool) {
        let mut cont = &mut self.root;
        for k in &key[..key.len() - 1] {
            cont = &mut cont.entry(k.clone()).or_default().nested;
        }
        let node = cont.entry(key[key.len() - 1].clone()).or_default();
        if recursive {
            node.recursive_flags.insert(flag);
        } else {
            node.flags.insert(flag);
        }
    }

    fn is(&self, key: &[String], flag: u8) -> bool {
        if key.is_empty() {
            return false;
        }
        let mut cont = &self.root;
        for k in &key[..key.len() - 1] {
            let Some(inner) = cont.get(k) else { return false };
            if inner.recursive_flags.contains(&flag) {
                return true;
            }
            cont = &inner.nested;
        }
        match cont.get(&key[key.len() - 1]) {
            Some(node) => node.flags.contains(&flag) || node.recursive_flags.contains(&flag),
            None => false,
        }
    }
}

/// `NestedDict.get_or_create_nest`: `Err(())` is Python's `KeyError`.
fn get_or_create_nest<'a>(
    root: &'a mut Table,
    key: &[String],
    access_lists: bool,
) -> std::result::Result<&'a mut Table, ()> {
    let mut cont = root;
    for k in key {
        if !cont.contains_key(k) {
            cont.insert(k.clone(), Value::Table(Table::new()));
        }
        let mut value = cont.get_mut(k).expect("inserted above");
        if access_lists {
            if let Value::Array(items) = value {
                value = items.last_mut().ok_or(())?;
            }
        }
        match value {
            Value::Table(table) => cont = table,
            _ => return Err(()),
        }
    }
    Ok(cont)
}

fn append_nest_to_list(root: &mut Table, key: &[String]) -> std::result::Result<(), ()> {
    let cont = get_or_create_nest(root, &key[..key.len() - 1], true)?;
    let last = &key[key.len() - 1];
    match cont.get_mut(last) {
        Some(Value::Array(items)) => {
            items.push(Value::Table(Table::new()));
            Ok(())
        }
        Some(_) => Err(()),
        None => {
            cont.insert(last.clone(), Value::Array(vec![Value::Table(Table::new())]));
            Ok(())
        }
    }
}

struct Parser<'a> {
    src: &'a [char],
}

impl Parser<'_> {
    fn at(&self, pos: usize) -> Option<char> {
        self.src.get(pos).copied()
    }

    fn starts_with(&self, pos: usize, text: &str) -> bool {
        text.chars().enumerate().all(|(offset, c)| self.at(pos + offset) == Some(c))
    }

    fn slice(&self, start: usize, end: usize) -> String {
        let end = end.min(self.src.len());
        if start >= end {
            return String::new();
        }
        self.src[start..end].iter().collect()
    }

    fn err(&self, pos: usize, message: impl Into<String>) -> DecodeError {
        let message = message.into();
        let coord = if pos >= self.src.len() {
            "end of document".to_string()
        } else {
            let before = &self.src[..pos];
            let line = before.iter().filter(|c| **c == '\n').count() + 1;
            let column = if line == 1 {
                pos + 1
            } else {
                pos - before.iter().rposition(|c| *c == '\n').expect("line > 1 has a newline")
            };
            format!("line {line}, column {column}")
        };
        DecodeError(format!("{message} (at {coord})"))
    }

    fn skip(&self, mut pos: usize, chars: fn(char) -> bool) -> usize {
        while let Some(c) = self.at(pos) {
            if !chars(c) {
                break;
            }
            pos += 1;
        }
        pos
    }

    fn find(&self, pos: usize, expect: &str) -> Option<usize> {
        let needle: Vec<char> = expect.chars().collect();
        if pos > self.src.len() {
            return None;
        }
        (pos..=self.src.len().saturating_sub(needle.len())).find(|start| self.src[*start..].starts_with(&needle))
    }

    fn skip_until(&self, pos: usize, expect: &str, error_on: fn(char) -> bool, error_on_eof: bool) -> Result<usize> {
        let new_pos = match self.find(pos, expect) {
            Some(found) => found,
            None => {
                if error_on_eof {
                    return Err(self.err(self.src.len(), format!("Expected {}", py_repr(expect))));
                }
                self.src.len()
            }
        };
        if let Some(offset) = self.src[pos.min(new_pos)..new_pos].iter().position(|c| error_on(*c)) {
            let bad = pos + offset;
            return Err(self.err(bad, format!("Found invalid character {}", py_repr(&self.src[bad].to_string()))));
        }
        Ok(new_pos)
    }

    fn skip_comment(&self, pos: usize) -> Result<usize> {
        if self.at(pos) == Some('#') {
            return self.skip_until(pos + 1, "\n", illegal_basic, false);
        }
        Ok(pos)
    }

    fn skip_comments_and_array_ws(&self, mut pos: usize) -> Result<usize> {
        loop {
            let before = pos;
            pos = self.skip(pos, is_ws_or_newline);
            pos = self.skip_comment(pos)?;
            if pos == before {
                return Ok(pos);
            }
        }
    }

    fn document(&self) -> Result<Table> {
        let mut data = Table::new();
        let mut flags = Flags::default();
        let mut header: Key = Vec::new();
        let mut pos = 0;
        loop {
            pos = self.skip(pos, is_ws);
            let Some(c) = self.at(pos) else { break };
            if c == '\n' {
                pos += 1;
                continue;
            }
            if is_bare_key_char(c) || c == '"' || c == '\'' {
                pos = self.key_value_rule(pos, &mut data, &mut flags, &header)?;
                pos = self.skip(pos, is_ws);
            } else if c == '[' {
                flags.finalize_pending();
                if self.at(pos + 1) == Some('[') {
                    (pos, header) = self.create_list_rule(pos, &mut data, &mut flags)?;
                } else {
                    (pos, header) = self.create_dict_rule(pos, &mut data, &mut flags)?;
                }
                pos = self.skip(pos, is_ws);
            } else if c != '#' {
                return Err(self.err(pos, "Invalid statement"));
            }
            pos = self.skip_comment(pos)?;
            let Some(c) = self.at(pos) else { break };
            if c != '\n' {
                return Err(self.err(pos, "Expected newline or end of document after a statement"));
            }
            pos += 1;
        }
        Ok(data)
    }

    fn create_dict_rule(&self, pos: usize, data: &mut Table, flags: &mut Flags) -> Result<(usize, Key)> {
        let mut pos = self.skip(pos + 1, is_ws);
        let key;
        (pos, key) = self.parse_key(pos)?;
        if flags.is(&key, EXPLICIT_NEST) || flags.is(&key, FROZEN) {
            return Err(self.err(pos, format!("Cannot declare {} twice", tuple_repr(&key))));
        }
        flags.set(&key, EXPLICIT_NEST, false);
        if get_or_create_nest(data, &key, true).is_err() {
            return Err(self.err(pos, "Cannot overwrite a value"));
        }
        if !self.starts_with(pos, "]") {
            return Err(self.err(pos, "Expected ']' at the end of a table declaration"));
        }
        Ok((pos + 1, key))
    }

    fn create_list_rule(&self, pos: usize, data: &mut Table, flags: &mut Flags) -> Result<(usize, Key)> {
        let mut pos = self.skip(pos + 2, is_ws);
        let key;
        (pos, key) = self.parse_key(pos)?;
        if flags.is(&key, FROZEN) {
            return Err(self.err(pos, format!("Cannot mutate immutable namespace {}", tuple_repr(&key))));
        }
        flags.unset_all(&key);
        flags.set(&key, EXPLICIT_NEST, false);
        if append_nest_to_list(data, &key).is_err() {
            return Err(self.err(pos, "Cannot overwrite a value"));
        }
        if !self.starts_with(pos, "]]") {
            return Err(self.err(pos, "Expected ']]' at the end of an array declaration"));
        }
        Ok((pos + 2, key))
    }

    fn key_value_rule(&self, pos: usize, data: &mut Table, flags: &mut Flags, header: &[String]) -> Result<usize> {
        let (pos, key, value) = self.parse_key_value_pair(pos)?;
        let (key_parent, key_stem) = key.split_at(key.len() - 1);
        let mut abs_key_parent: Key = header.to_vec();
        abs_key_parent.extend_from_slice(key_parent);
        for i in 1..key.len() {
            let mut cont_key: Key = header.to_vec();
            cont_key.extend_from_slice(&key[..i]);
            if flags.is(&cont_key, EXPLICIT_NEST) {
                return Err(self.err(pos, format!("Cannot redefine namespace {}", tuple_repr(&cont_key))));
            }
            flags.add_pending(cont_key, EXPLICIT_NEST);
        }
        if flags.is(&abs_key_parent, FROZEN) {
            return Err(self.err(pos, format!("Cannot mutate immutable namespace {}", tuple_repr(&abs_key_parent))));
        }
        let Ok(nest) = get_or_create_nest(data, &abs_key_parent, true) else {
            return Err(self.err(pos, "Cannot overwrite a value"));
        };
        if nest.contains_key(&key_stem[0]) {
            return Err(self.err(pos, "Cannot overwrite a value"));
        }
        if matches!(value, Value::Table(_) | Value::Array(_)) {
            let mut full: Key = header.to_vec();
            full.extend_from_slice(&key);
            flags.set(&full, FROZEN, true);
        }
        nest.insert(key_stem[0].clone(), value);
        Ok(pos)
    }

    fn parse_key_value_pair(&self, pos: usize) -> Result<(usize, Key, Value)> {
        let (pos, key) = self.parse_key(pos)?;
        if self.at(pos) != Some('=') {
            return Err(self.err(pos, "Expected '=' after a key in a key/value pair"));
        }
        let pos = self.skip(pos + 1, is_ws);
        let (pos, value) = self.parse_value(pos)?;
        Ok((pos, key, value))
    }

    fn parse_key(&self, pos: usize) -> Result<(usize, Key)> {
        let (mut pos, part) = self.parse_key_part(pos)?;
        let mut key = vec![part];
        pos = self.skip(pos, is_ws);
        loop {
            if self.at(pos) != Some('.') {
                return Ok((pos, key));
            }
            pos = self.skip(pos + 1, is_ws);
            let part;
            (pos, part) = self.parse_key_part(pos)?;
            key.push(part);
            pos = self.skip(pos, is_ws);
        }
    }

    fn parse_key_part(&self, pos: usize) -> Result<(usize, String)> {
        match self.at(pos) {
            Some(c) if is_bare_key_char(c) => {
                let end = self.skip(pos, is_bare_key_char);
                Ok((end, self.slice(pos, end)))
            }
            Some('\'') => self.parse_literal_str(pos),
            Some('"') => self.parse_basic_str(pos + 1, false),
            _ => Err(self.err(pos, "Invalid initial character for a key part")),
        }
    }

    fn parse_array(&self, pos: usize) -> Result<(usize, Value)> {
        let mut pos = self.skip_comments_and_array_ws(pos + 1)?;
        let mut array = Vec::new();
        if self.starts_with(pos, "]") {
            return Ok((pos + 1, Value::Array(array)));
        }
        loop {
            let value;
            (pos, value) = self.parse_value(pos)?;
            array.push(value);
            pos = self.skip_comments_and_array_ws(pos)?;
            match self.at(pos) {
                Some(']') => return Ok((pos + 1, Value::Array(array))),
                Some(',') => {}
                _ => return Err(self.err(pos, "Unclosed array")),
            }
            pos = self.skip_comments_and_array_ws(pos + 1)?;
            if self.starts_with(pos, "]") {
                return Ok((pos + 1, Value::Array(array)));
            }
        }
    }

    fn parse_inline_table(&self, pos: usize) -> Result<(usize, Value)> {
        let mut nested = Table::new();
        let mut flags = Flags::default();
        let mut pos = self.skip(pos + 1, is_ws);
        if self.starts_with(pos, "}") {
            return Ok((pos + 1, Value::Table(nested)));
        }
        loop {
            let (next, key, value) = self.parse_key_value_pair(pos)?;
            pos = next;
            let (key_parent, key_stem) = key.split_at(key.len() - 1);
            if flags.is(&key, FROZEN) {
                return Err(self.err(pos, format!("Cannot mutate immutable namespace {}", tuple_repr(&key))));
            }
            let Ok(nest) = get_or_create_nest(&mut nested, key_parent, false) else {
                return Err(self.err(pos, "Cannot overwrite a value"));
            };
            if nest.contains_key(&key_stem[0]) {
                return Err(self.err(pos, format!("Duplicate inline table key {}", py_repr(&key_stem[0]))));
            }
            let container = matches!(value, Value::Table(_) | Value::Array(_));
            nest.insert(key_stem[0].clone(), value);
            pos = self.skip(pos, is_ws);
            match self.at(pos) {
                Some('}') => return Ok((pos + 1, Value::Table(nested))),
                Some(',') => {}
                _ => return Err(self.err(pos, "Unclosed inline table")),
            }
            if container {
                flags.set(&key, FROZEN, true);
            }
            pos = self.skip(pos + 1, is_ws);
        }
    }

    fn parse_basic_str_escape(&self, pos: usize, multiline: bool) -> Result<(usize, String)> {
        let escape_id = self.slice(pos, pos + 2);
        let mut pos = pos + 2;
        if multiline && matches!(escape_id.as_str(), "\\ " | "\\\t" | "\\\n") {
            if escape_id != "\\\n" {
                pos = self.skip(pos, is_ws);
                match self.at(pos) {
                    None => return Ok((pos, String::new())),
                    Some('\n') => {}
                    Some(_) => return Err(self.err(pos, "Unescaped '\\' in a string")),
                }
                pos += 1;
            }
            pos = self.skip(pos, is_ws_or_newline);
            return Ok((pos, String::new()));
        }
        let replacement = match escape_id.as_str() {
            "\\u" => return self.parse_hex_char(pos, 4),
            "\\U" => return self.parse_hex_char(pos, 8),
            "\\b" => "\u{8}",
            "\\t" => "\t",
            "\\n" => "\n",
            "\\f" => "\u{c}",
            "\\r" => "\r",
            "\\\"" => "\"",
            "\\\\" => "\\",
            _ => return Err(self.err(pos, "Unescaped '\\' in a string")),
        };
        Ok((pos, replacement.to_string()))
    }

    fn parse_hex_char(&self, pos: usize, length: usize) -> Result<(usize, String)> {
        let hex = self.slice(pos, pos + length);
        if hex.chars().count() != length || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.err(pos, "Invalid hex value"));
        }
        let pos = pos + length;
        let code = u32::from_str_radix(&hex, 16).expect("validated hex");
        match char::from_u32(code) {
            Some(c) => Ok((pos, c.to_string())),
            None => Err(self.err(pos, "Escaped character is not a Unicode scalar value")),
        }
    }

    fn parse_literal_str(&self, pos: usize) -> Result<(usize, String)> {
        let start = pos + 1;
        let end = self.skip_until(start, "'", illegal_basic, true)?;
        Ok((end + 1, self.slice(start, end)))
    }

    fn parse_multiline_str(&self, pos: usize, literal: bool) -> Result<(usize, Value)> {
        let mut pos = pos + 3;
        if self.starts_with(pos, "\n") {
            pos += 1;
        }
        let (delim, mut result);
        if literal {
            delim = '\'';
            let end = self.skip_until(pos, "'''", illegal_multiline, true)?;
            result = self.slice(pos, end);
            pos = end + 3;
        } else {
            delim = '"';
            (pos, result) = self.parse_basic_str(pos, true)?;
        }
        if self.at(pos) != Some(delim) {
            return Ok((pos, Value::String(result)));
        }
        pos += 1;
        result.push(delim);
        if self.at(pos) != Some(delim) {
            return Ok((pos, Value::String(result)));
        }
        pos += 1;
        result.push(delim);
        Ok((pos, Value::String(result)))
    }

    fn parse_basic_str(&self, mut pos: usize, multiline: bool) -> Result<(usize, String)> {
        let error_on: fn(char) -> bool = if multiline { illegal_multiline } else { illegal_basic };
        let mut result = String::new();
        let mut start = pos;
        loop {
            let Some(c) = self.at(pos) else {
                return Err(self.err(pos, "Unterminated string"));
            };
            if c == '"' {
                if !multiline {
                    result.push_str(&self.slice(start, pos));
                    return Ok((pos + 1, result));
                }
                if self.starts_with(pos, "\"\"\"") {
                    result.push_str(&self.slice(start, pos));
                    return Ok((pos + 3, result));
                }
                pos += 1;
                continue;
            }
            if c == '\\' {
                result.push_str(&self.slice(start, pos));
                let escaped;
                (pos, escaped) = self.parse_basic_str_escape(pos, multiline)?;
                result.push_str(&escaped);
                start = pos;
                continue;
            }
            if error_on(c) {
                return Err(self.err(pos, format!("Illegal character {}", py_repr(&c.to_string()))));
            }
            pos += 1;
        }
    }

    fn parse_value(&self, pos: usize) -> Result<(usize, Value)> {
        match self.at(pos) {
            Some('"') => {
                if self.starts_with(pos, "\"\"\"") {
                    return self.parse_multiline_str(pos, false);
                }
                let (pos, text) = self.parse_basic_str(pos + 1, false)?;
                return Ok((pos, Value::String(text)));
            }
            Some('\'') => {
                if self.starts_with(pos, "'''") {
                    return self.parse_multiline_str(pos, true);
                }
                let (pos, text) = self.parse_literal_str(pos)?;
                return Ok((pos, Value::String(text)));
            }
            Some('t') if self.starts_with(pos, "true") => return Ok((pos + 4, Value::Boolean(true))),
            Some('f') if self.starts_with(pos, "false") => return Ok((pos + 5, Value::Boolean(false))),
            Some('[') => return self.parse_array(pos),
            Some('{') => return self.parse_inline_table(pos),
            _ => {}
        }
        if let Some(found) = self.match_datetime(pos) {
            if !found.valid {
                return Err(self.err(pos, "Invalid date or datetime"));
            }
            let text = self.slice(pos, found.end);
            let value = if found.has_time { Value::Datetime(text) } else { Value::Date(text) };
            return Ok((found.end, value));
        }
        if let Some(end) = self.match_time(pos) {
            return Ok((end, Value::Time(self.slice(pos, end))));
        }
        if let Some((end, float)) = self.match_number(pos) {
            let text = self.slice(pos, end);
            if float {
                let cleaned: String = text.chars().filter(|c| *c != '_').collect();
                return Ok((end, Value::Float(cleaned.parse().unwrap_or(f64::NAN))));
            }
            return Ok((end, Value::Integer(PyInt::parse_literal(&text))));
        }
        let three = self.slice(pos, pos + 3);
        if three == "inf" || three == "nan" {
            return Ok((pos + 3, Value::Float(if three == "inf" { f64::INFINITY } else { f64::NAN })));
        }
        let four = self.slice(pos, pos + 4);
        match four.as_str() {
            "+inf" => return Ok((pos + 4, Value::Float(f64::INFINITY))),
            "-inf" => return Ok((pos + 4, Value::Float(f64::NEG_INFINITY))),
            "+nan" | "-nan" => return Ok((pos + 4, Value::Float(f64::NAN))),
            _ => {}
        }
        Err(self.err(pos, "Invalid value"))
    }

    fn digits(&self, pos: usize, count: usize) -> Option<u32> {
        let mut value = 0;
        for index in pos..pos + count {
            let c = self.at(index)?;
            if !c.is_ascii_digit() {
                return None;
            }
            value = value * 10 + (c as u32 - '0' as u32);
        }
        Some(value)
    }

    /// `RE_LOCALTIME` (`_TIME_RE_STR`) at `pos`: the end of the match.
    fn match_time(&self, pos: usize) -> Option<usize> {
        let hour = self.digits(pos, 2)?;
        if hour > 23 || self.at(pos + 2) != Some(':') {
            return None;
        }
        let minute = self.digits(pos + 3, 2)?;
        if minute > 59 || self.at(pos + 5) != Some(':') {
            return None;
        }
        let second = self.digits(pos + 6, 2)?;
        if second > 59 {
            return None;
        }
        let mut end = pos + 8;
        if self.at(end) == Some('.') && self.at(end + 1).is_some_and(|c| c.is_ascii_digit()) {
            end += 1;
            while self.at(end).is_some_and(|c| c.is_ascii_digit()) {
                end += 1;
            }
        }
        Some(end)
    }

    /// `RE_DATETIME` at `pos` plus `match_to_datetime`'s calendar check.
    fn match_datetime(&self, pos: usize) -> Option<DatetimeMatch> {
        let year = self.digits(pos, 4)?;
        if self.at(pos + 4) != Some('-') {
            return None;
        }
        let month = self.digits(pos + 5, 2)?;
        if !(1..=12).contains(&month) || self.at(pos + 7) != Some('-') {
            return None;
        }
        let day = self.digits(pos + 8, 2)?;
        if !(1..=31).contains(&day) {
            return None;
        }
        let valid = year >= 1 && day <= days_in_month(year, month);
        let date_end = pos + 10;
        if !matches!(self.at(date_end), Some('T' | 't' | ' ')) {
            return Some(DatetimeMatch { end: date_end, has_time: false, valid });
        }
        let Some(mut end) = self.match_time(date_end + 1) else {
            return Some(DatetimeMatch { end: date_end, has_time: false, valid });
        };
        match self.at(end) {
            Some('Z' | 'z') => end += 1,
            Some('+' | '-') => {
                let offset_ok = self.digits(end + 1, 2).is_some_and(|h| h <= 23)
                    && self.at(end + 3) == Some(':')
                    && self.digits(end + 4, 2).is_some_and(|m| m <= 59);
                if offset_ok {
                    end += 6;
                }
            }
            _ => {}
        }
        Some(DatetimeMatch { end, has_time: true, valid })
    }

    /// `RE_NUMBER` at `pos`: the end and whether `floatpart` matched.
    fn match_number(&self, pos: usize) -> Option<(usize, bool)> {
        if self.at(pos) == Some('0') {
            let radix_digit: Option<fn(char) -> bool> = match self.at(pos + 1) {
                Some('x') => Some(|c: char| c.is_ascii_hexdigit()),
                Some('b') => Some(|c: char| c == '0' || c == '1'),
                Some('o') => Some(|c: char| ('0'..='7').contains(&c)),
                _ => None,
            };
            if let Some(is_digit) = radix_digit {
                if self.at(pos + 2).is_some_and(is_digit) {
                    return Some((self.underscored(pos + 3, is_digit), false));
                }
            }
        }
        let mut end = pos;
        if matches!(self.at(end), Some('+' | '-')) {
            end += 1;
        }
        match self.at(end) {
            Some('0') => end += 1,
            Some(c) if ('1'..='9').contains(&c) => end = self.underscored(end + 1, |c| c.is_ascii_digit()),
            _ => return None,
        }
        let int_end = end;
        if self.at(end) == Some('.') && self.at(end + 1).is_some_and(|c| c.is_ascii_digit()) {
            end = self.underscored(end + 2, |c| c.is_ascii_digit());
        }
        if matches!(self.at(end), Some('e' | 'E')) {
            let mut exponent = end + 1;
            if matches!(self.at(exponent), Some('+' | '-')) {
                exponent += 1;
            }
            if self.at(exponent).is_some_and(|c| c.is_ascii_digit()) {
                end = self.underscored(exponent + 1, |c| c.is_ascii_digit());
            }
        }
        Some((end, end != int_end))
    }

    /// `(?:_?D)*` after a first digit.
    fn underscored(&self, mut pos: usize, is_digit: fn(char) -> bool) -> usize {
        loop {
            match self.at(pos) {
                Some(c) if is_digit(c) => pos += 1,
                Some('_') if self.at(pos + 1).is_some_and(is_digit) => pos += 2,
                _ => return pos,
            }
        }
    }
}

struct DatetimeMatch {
    end: usize,
    has_time: bool,
    valid: bool,
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(text: &str) -> String {
        loads(text).unwrap_err().0
    }

    #[test]
    fn messages_match_tomllib() {
        assert_eq!(error("schema = 1\nhost_mode = \"fresh\n"), "Illegal character '\\n' (at line 2, column 19)");
        assert_eq!(error("schema =\n"), "Invalid value (at line 1, column 9)");
        assert_eq!(error("schema = 1\nschema = 1\n"), "Cannot overwrite a value (at line 2, column 11)");
        assert_eq!(error("[a]\nx = 1\n[a]\n"), "Cannot declare ('a',) twice (at line 3, column 3)");
        assert_eq!(error("x = \"a\\e\"\n"), "Unescaped '\\' in a string (at line 1, column 9)");
        assert_eq!(
            error("x = { a = 1,\n b = 2 }\n"),
            "Invalid initial character for a key part (at line 1, column 13)"
        );
        assert_eq!(error("\u{feff}x = 1\n"), "Invalid statement (at line 1, column 1)");
        assert_eq!(error("schema = ["), "Invalid value (at end of document)");
        assert_eq!(error("x = 'abc"), "Expected \"'\" (at end of document)");
        assert_eq!(error("x = 1 # \u{1}\n"), "Found invalid character '\\x01' (at line 1, column 9)");
        assert_eq!(error("x = 2023-02-30\n"), "Invalid date or datetime (at line 1, column 5)");
        assert_eq!(error("x = {a = 1, a = 2}\n"), "Duplicate inline table key 'a' (at line 1, column 18)");
        assert_eq!(error("x = 0x\n"), "Expected newline or end of document after a statement (at line 1, column 6)");
        assert_eq!(
            error("x = \"\\uD800\"\n"),
            "Escaped character is not a Unicode scalar value (at line 1, column 12)"
        );
        assert_eq!(error("a.b = 1\n[a]\n"), "Cannot declare ('a',) twice (at line 2, column 3)");
    }

    #[test]
    fn values_and_order() {
        let table = loads("b = 1\na = \"x\"\n[t]\nz = [1, 2]\ny = { k = true }\n").unwrap();
        assert_eq!(table.keys().collect::<Vec<_>>(), vec!["b", "a", "t"]);
        let Some(Value::Table(t)) = table.get("t") else { panic!() };
        assert_eq!(t.keys().collect::<Vec<_>>(), vec!["z", "y"]);
        assert_eq!(
            loads("x = 99999999999999999999\n").unwrap().get("x"),
            Some(&Value::Integer(PyInt("99999999999999999999".into())))
        );
        assert_eq!(loads("x = 0xff\n").unwrap().get("x"), Some(&Value::Integer(PyInt("255".into()))));
        assert_eq!(loads("x = -0\n").unwrap().get("x"), Some(&Value::Integer(PyInt("0".into()))));
        assert_eq!(loads("x = +1_000\n").unwrap().get("x"), Some(&Value::Integer(PyInt("1000".into()))));
        assert_eq!(
            loads("x = 0x1_0000_0000_0000_0000_0000_0000_0000_0000\n").unwrap().get("x"),
            Some(&Value::Integer(PyInt("340282366920938463463374607431768211456".into())))
        );
        assert!(matches!(loads("x = 1.5\n").unwrap().get("x"), Some(Value::Float(_))));
        assert!(matches!(loads("x = 1e3\n").unwrap().get("x"), Some(Value::Float(_))));
        assert!(matches!(loads("x = 1979-05-27T07:32:00Z\n").unwrap().get("x"), Some(Value::Datetime(_))));
        assert!(matches!(loads("x = 1979-05-27\n").unwrap().get("x"), Some(Value::Date(_))));
        assert!(matches!(loads("x = 07:32:00\n").unwrap().get("x"), Some(Value::Time(_))));
        assert_eq!(loads("x = \"\"\"\nab\"\"\"\"\n").unwrap().get("x"), Some(&Value::String("ab\"".into())));
        assert_eq!(loads("x = '''a''b'''\n").unwrap().get("x"), Some(&Value::String("a''b".into())));
        assert_eq!(loads("x = \"\"\"a\\\n   b\"\"\"\n").unwrap().get("x"), Some(&Value::String("ab".into())));
        assert_eq!(loads("\"q k\".'l' = 1\n").unwrap().len(), 1);
    }

    #[test]
    fn arrays_of_tables() {
        let table = loads("[[a]]\nx = 1\n[[a]]\nx = 2\n[a.b]\ny = 3\n").unwrap();
        let Some(Value::Array(items)) = table.get("a") else { panic!() };
        assert_eq!(items.len(), 2);
        let Value::Table(second) = &items[1] else { panic!() };
        assert!(second.contains_key("b"));
        assert_eq!(error("a = [1]\n[[a]]\n"), "Cannot mutate immutable namespace ('a',) (at line 2, column 4)");
    }
}
