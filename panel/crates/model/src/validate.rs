//! Pydantic-shaped validation of JSON input (pydantic 2.13, lax mode unless a field is strict).
//!
//! Every model of this crate validates a [`serde_json::Value`] the way pydantic validates what
//! `json.loads` made of the same text, and reports the same issues — `type`, `loc`, `msg`, `input`
//! and `ctx`, in pydantic's order — so a 422 body or a `str(ValidationError)` is byte-for-byte what
//! the Python panel answered. The building blocks here (one per pydantic schema the panel uses) are
//! public so the request models of later packages compose them the same way.
//!
//! A model validates in three steps, like pydantic: the input must be an object; every declared
//! field is validated in declaration order and every problem is collected; unknown keys are
//! refused (`extra="forbid"`) or dropped (`extra="ignore"`); only if the fields were all valid do
//! the model's own checks (`model_validator(mode="after")`) run, and the first one that fails is
//! the one reported, at the model's location.

use std::fmt;

use panel_core::errors::{ApiError, LocItem, ValidationIssue};
use panel_core::pytext;
use serde_json::{json, Map, Value};

use crate::pyrepr;

/// Where pydantic's documentation links point (`str(ValidationError)`).
pub const DOCS_URL: &str = "https://errors.pydantic.dev/2.13/v/";

/// How the input reached the model: as a FastAPI request body (FastAPI validates with
/// `from_attributes`, so a non-object answers `model_attributes_type`, and a missing body
/// `missing`) or through `Model.model_validate(...)` (a non-object answers `model_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Body,
    Python,
}

/// A location: field names and list indexes from the model's root.
pub type Loc = Vec<LocItem>;

/// `loc + [item]`.
pub fn at(loc: &[LocItem], item: impl Into<LocItem>) -> Loc {
    let mut child = loc.to_vec();
    child.push(item.into());
    child
}

/// `loc + [index]`.
pub fn at_index(loc: &[LocItem], index: usize) -> Loc {
    at(loc, LocItem::Index(index as i64))
}

/// The issues collected while validating one input.
#[derive(Debug)]
pub struct Cx {
    entry: Entry,
    issues: Vec<ValidationIssue>,
}

impl Cx {
    pub fn new(entry: Entry) -> Self {
        Self { entry, issues: Vec::new() }
    }

    pub fn entry(&self) -> Entry {
        self.entry
    }

    /// Records one issue.
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// How many issues were recorded so far (compare before and after a step to know whether it
    /// failed).
    pub fn count(&self) -> usize {
        self.issues.len()
    }

    pub fn into_issues(self) -> Vec<ValidationIssue> {
        self.issues
    }

    /// Runs `step` on a scratch context and returns its result with its issues (for unions, whose
    /// members' issues are reported only when every member failed).
    pub fn attempt<T>(&self, step: impl FnOnce(&mut Cx) -> Option<T>) -> (Option<T>, Vec<ValidationIssue>) {
        let mut scratch = Cx::new(self.entry);
        let value = step(&mut scratch);
        (value, scratch.issues)
    }
}

/// A failed validation: the model's name (`title`) and every issue, with locations relative to the
/// model. [`fmt::Display`] is pydantic's `str(ValidationError)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    pub title: &'static str,
    pub issues: Vec<ValidationIssue>,
}

impl ValidationError {
    /// A single issue at the model's root.
    pub fn single(title: &'static str, issue: ValidationIssue) -> Self {
        Self { title, issues: vec![issue] }
    }

    /// The issues as FastAPI reports a request body's: every location starts with `"body"`.
    pub fn body_issues(&self) -> Vec<ValidationIssue> {
        self.issues
            .iter()
            .map(|issue| {
                let mut issue = issue.clone();
                issue.loc.insert(0, LocItem::Key("body".into()));
                issue
            })
            .collect()
    }

    /// FastAPI's 422 answer for a request body that failed this way.
    pub fn to_api_error(&self) -> ApiError {
        ApiError::Validation(self.body_issues())
    }
}

impl fmt::Display for ValidationError {
    /// `str(ValidationError)`: a count line, then per issue its dotted location (when it has one),
    /// the message with type and input, and the documentation link.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.issues.len();
        write!(f, "{count} validation error{} for {}", if count == 1 { "" } else { "s" }, self.title)?;
        for issue in &self.issues {
            if !issue.loc.is_empty() {
                let parts: Vec<String> = issue
                    .loc
                    .iter()
                    .map(|item| match item {
                        LocItem::Key(key) => key.clone(),
                        LocItem::Index(index) => index.to_string(),
                    })
                    .collect();
                write!(f, "\n{}", parts.join("."))?;
            }
            write!(
                f,
                "\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit {DOCS_URL}{}",
                issue.msg,
                issue.kind,
                pyrepr::truncated_repr(&issue.input),
                pyrepr::type_name(&issue.input),
                issue.kind
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

/// A pydantic model: validated from JSON, dumped back to `model_dump()`'s value.
pub trait Model: Sized {
    /// The class name pydantic reports (`... validation errors for <TITLE>`).
    const TITLE: &'static str;

    /// Validates `input` found at `loc`, recording issues in `cx`; `None` when anything failed.
    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self>;

    /// `model_dump()`: every field, in declaration order.
    fn dump(&self) -> Value;

    /// `Model.model_validate(input)`.
    fn validate(input: &Value) -> Result<Self, ValidationError> {
        run(Self::TITLE, Entry::Python, input, Self::validate_at)
    }

    /// The model as a FastAPI request body (a JSON `null` body is a missing one).
    fn validate_body(input: &Value) -> Result<Self, ValidationError> {
        if input.is_null() {
            return Err(ValidationError::single(Self::TITLE, ValidationIssue::missing(Vec::new(), Value::Null)));
        }
        run(Self::TITLE, Entry::Body, input, Self::validate_at)
    }

    /// `model_dump_json()`: compact, raw UTF-8, declaration order.
    fn dump_json(&self) -> String {
        panel_core::pyjson::pydantic(&self.dump())
    }
}

fn run<T>(
    title: &'static str,
    entry: Entry,
    input: &Value,
    validate: impl FnOnce(&Value, &[LocItem], &mut Cx) -> Option<T>,
) -> Result<T, ValidationError> {
    let mut cx = Cx::new(entry);
    match validate(input, &[], &mut cx) {
        Some(value) if cx.count() == 0 => Ok(value),
        _ => Err(ValidationError { title, issues: cx.into_issues() }),
    }
}

// -- issue builders --------------------------------------------------------------------------

/// `value_error`: a `ValueError` raised by a validator; FastAPI renders its `ctx.error` as `{}`.
pub fn value_error(loc: Loc, input: &Value, message: impl fmt::Display) -> ValidationIssue {
    let mut ctx = Map::new();
    ctx.insert("error".into(), json!({}));
    ValidationIssue::new("value_error", loc, format!("Value error, {message}"), input.clone()).with_ctx(ctx)
}

fn issue(kind: &str, loc: &[LocItem], msg: &str, input: &Value) -> ValidationIssue {
    ValidationIssue::new(kind, loc.to_vec(), msg, input.clone())
}

fn with_ctx(issue: ValidationIssue, pairs: &[(&str, Value)]) -> ValidationIssue {
    let mut ctx = Map::new();
    for (key, value) in pairs {
        ctx.insert((*key).to_string(), value.clone());
    }
    issue.with_ctx(ctx)
}

/// The issue for a nested model's input that is not an object.
pub fn model_type_issue(entry: Entry, title: &str, loc: &[LocItem], input: &Value) -> ValidationIssue {
    match entry {
        Entry::Body => ValidationIssue::model_attributes_type(loc.to_vec(), input.clone()),
        Entry::Python => with_ctx(
            issue("model_type", loc, &format!("Input should be a valid dictionary or instance of {title}"), input),
            &[("class_name", json!(title))],
        ),
    }
}

fn too_long(loc: &[LocItem], input: &Value, field_type: &str, max_length: usize, actual: usize) -> ValidationIssue {
    let plural = if max_length == 1 { "" } else { "s" };
    with_ctx(
        issue(
            "too_long",
            loc,
            &format!("{field_type} should have at most {max_length} item{plural} after validation, not {actual}"),
            input,
        ),
        &[("field_type", json!(field_type)), ("max_length", json!(max_length)), ("actual_length", json!(actual))],
    )
}

// -- objects -------------------------------------------------------------------------------

/// What a model does with keys it does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extra {
    /// `extra="forbid"`: each one is an `extra_forbidden` issue.
    Forbid,
    /// `extra="ignore"`: dropped.
    Ignore,
}

/// The input of one model, read field by field.
pub struct Fields<'a> {
    map: &'a Map<String, Value>,
    whole: &'a Value,
    loc: Loc,
    declared: Vec<&'static str>,
    start: usize,
}

impl<'a> Fields<'a> {
    /// Opens `input` as the object of model `title`; records the type issue and answers `None`
    /// when it is not one.
    pub fn open(input: &'a Value, loc: &[LocItem], cx: &mut Cx, title: &str) -> Option<Self> {
        match input {
            Value::Object(map) => {
                Some(Self { map, whole: input, loc: loc.to_vec(), declared: Vec::new(), start: cx.count() })
            }
            _ => {
                cx.push(model_type_issue(cx.entry(), title, loc, input));
                None
            }
        }
    }

    /// The model's location.
    pub fn loc(&self) -> &[LocItem] {
        &self.loc
    }

    /// The model's whole input (what a model-level issue quotes).
    pub fn input(&self) -> &'a Value {
        self.whole
    }

    /// The location of a field.
    pub fn loc_of(&self, name: &str) -> Loc {
        at(&self.loc, name)
    }

    /// The raw value of a declared field, if present.
    pub fn raw(&mut self, name: &'static str) -> Option<&'a Value> {
        self.declared.push(name);
        self.map.get(name)
    }

    /// A required field: `missing` when absent, else `validate(value, loc, cx)`.
    pub fn required<T>(
        &mut self,
        cx: &mut Cx,
        name: &'static str,
        validate: impl FnOnce(&Value, &[LocItem], &mut Cx) -> Option<T>,
    ) -> Option<T> {
        let loc = self.loc_of(name);
        match self.raw(name) {
            Some(value) => validate(value, &loc, cx),
            None => {
                cx.push(ValidationIssue::missing(loc, self.whole.clone()));
                None
            }
        }
    }

    /// A field with a default (not validated, like pydantic's defaults).
    pub fn optional<T>(
        &mut self,
        cx: &mut Cx,
        name: &'static str,
        default: impl FnOnce() -> T,
        validate: impl FnOnce(&Value, &[LocItem], &mut Cx) -> Option<T>,
    ) -> Option<T> {
        let loc = self.loc_of(name);
        match self.raw(name) {
            Some(value) => validate(value, &loc, cx),
            None => Some(default()),
        }
    }

    /// Ends the field pass: refuses (or drops) undeclared keys and answers whether every field
    /// was valid — the condition for running the model's own checks.
    pub fn finish(self, cx: &mut Cx, extra: Extra) -> bool {
        if extra == Extra::Forbid {
            for (key, value) in self.map {
                if !self.declared.contains(&key.as_str()) {
                    cx.push(ValidationIssue::extra_forbidden(at(&self.loc, key.as_str()), value.clone()));
                }
            }
        }
        cx.count() == self.start
    }
}

// -- scalar schemas -------------------------------------------------------------------------

/// `str` (lax and strict alike for JSON input: only a string).
pub fn string(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<String> {
    match input {
        Value::String(text) => Some(text.clone()),
        _ => {
            cx.push(issue("string_type", loc, "Input should be a valid string", input));
            None
        }
    }
}

/// A `pattern=`: its text (quoted in the issue) and a matcher with the regex crate's semantics.
pub type Pattern = (&'static str, fn(&str) -> bool);

/// `Field(min_length=, max_length=, pattern=)` on a `str`: lengths in code points, then the
/// pattern (one issue at most, in that order).
#[derive(Clone, Copy)]
pub struct Str {
    pub min: Option<usize>,
    pub max: Option<usize>,
    /// The pattern's text (quoted in the issue) and a matcher with the regex crate's semantics.
    pub pattern: Option<Pattern>,
}

impl Str {
    pub const ANY: Str = Str { min: None, max: None, pattern: None };

    pub const fn len(min: usize, max: usize) -> Str {
        Str { min: Some(min), max: Some(max), pattern: None }
    }

    pub const fn max(max: usize) -> Str {
        Str { min: None, max: Some(max), pattern: None }
    }

    pub const fn min(min: usize) -> Str {
        Str { min: Some(min), max: None, pattern: None }
    }

    pub const fn pattern(text: &'static str, matcher: fn(&str) -> bool) -> Str {
        Str { min: None, max: None, pattern: Some((text, matcher)) }
    }

    /// Checks an already-typed string.
    pub fn check(&self, text: &str, input: &Value, loc: &[LocItem], cx: &mut Cx) -> bool {
        let length = pytext::len(text);
        if let Some(min) = self.min {
            if length < min {
                cx.push(ValidationIssue::string_too_short(loc.to_vec(), input.clone(), min));
                return false;
            }
        }
        if let Some(max) = self.max {
            if length > max {
                cx.push(ValidationIssue::string_too_long(loc.to_vec(), input.clone(), max));
                return false;
            }
        }
        if let Some((pattern, matcher)) = self.pattern {
            if !matcher(text) {
                cx.push(with_ctx(
                    issue("string_pattern_mismatch", loc, &format!("String should match pattern '{pattern}'"), input),
                    &[("pattern", json!(pattern))],
                ));
                return false;
            }
        }
        true
    }

    /// Validates a constrained string.
    pub fn validate(&self, input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<String> {
        let text = string(input, loc, cx)?;
        self.check(&text, input, loc, cx).then_some(text)
    }
}

/// `int` with `strict=`, `ge=` and `le=`.
#[derive(Clone, Copy)]
pub struct Int {
    pub strict: bool,
    pub ge: Option<i128>,
    pub le: Option<i128>,
}

/// An integer as pydantic parsed it, before the bounds.
enum Parsed {
    Value(i128),
    /// Beyond what Rust holds here (`i64`); its sign decides which bound it breaks.
    Huge(bool),
}

impl Int {
    pub const LAX: Int = Int { strict: false, ge: None, le: None };
    pub const STRICT: Int = Int { strict: true, ge: None, le: None };

    pub const fn lax(ge: Option<i128>, le: Option<i128>) -> Int {
        Int { strict: false, ge, le }
    }

    pub const fn strict(ge: Option<i128>, le: Option<i128>) -> Int {
        Int { strict: true, ge, le }
    }

    fn parse(&self, input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Parsed> {
        let int_type = |cx: &mut Cx| cx.push(issue("int_type", loc, "Input should be a valid integer", input));
        match input {
            Value::Bool(flag) if !self.strict => Some(Parsed::Value(i128::from(*flag))),
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    Some(Parsed::Value(i128::from(value)))
                } else if let Some(value) = number.as_u64() {
                    Some(Parsed::Value(i128::from(value)))
                } else if self.strict {
                    int_type(cx);
                    None
                } else {
                    let float = number.as_f64().unwrap_or(f64::NAN);
                    if float.fract() != 0.0 || !float.is_finite() {
                        cx.push(issue(
                            "int_from_float",
                            loc,
                            "Input should be a valid integer, got a number with a fractional part",
                            input,
                        ));
                        None
                    } else if float.abs() < 9.2e18 {
                        Some(Parsed::Value(float as i128))
                    } else {
                        Some(Parsed::Huge(float < 0.0))
                    }
                }
            }
            Value::String(text) if !self.strict => {
                let trimmed = text.trim();
                if trimmed.len() > 4300 {
                    cx.push(issue(
                        "int_parsing_size",
                        loc,
                        "Unable to parse input string as an integer, exceeded maximum size",
                        input,
                    ));
                    return None;
                }
                let attempt = |candidate: &str| -> Option<Parsed> {
                    match pytext::int_from_str(candidate) {
                        Ok(value) => Some(Parsed::Value(i128::from(value))),
                        Err(error) if error.0.starts_with("int() value out of range") => {
                            Some(Parsed::Huge(candidate.trim_start().starts_with('-')))
                        }
                        Err(_) => None,
                    }
                };
                let parsed = attempt(trimmed).or_else(|| {
                    // pydantic-core also takes `12.0`/`12.` (a fraction of zeros only).
                    let (whole, fraction) = trimmed.split_once('.')?;
                    fraction.chars().all(|ch| ch == '0').then(|| attempt(whole)).flatten()
                });
                if parsed.is_none() {
                    cx.push(issue(
                        "int_parsing",
                        loc,
                        "Input should be a valid integer, unable to parse string as an integer",
                        input,
                    ));
                }
                parsed
            }
            _ => {
                int_type(cx);
                None
            }
        }
    }

    /// Validates an integer field.
    pub fn validate(&self, input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<i64> {
        let parsed = self.parse(input, loc, cx)?;
        let le_issue = |cx: &mut Cx, le: i128| {
            cx.push(with_ctx(
                issue("less_than_equal", loc, &format!("Input should be less than or equal to {le}"), input),
                &[("le", int_json(le))],
            ))
        };
        let ge_issue = |cx: &mut Cx, ge: i128| {
            cx.push(with_ctx(
                issue("greater_than_equal", loc, &format!("Input should be greater than or equal to {ge}"), input),
                &[("ge", int_json(ge))],
            ))
        };
        match parsed {
            Parsed::Value(value) => {
                if let Some(le) = self.le.filter(|le| value > *le) {
                    le_issue(cx, le);
                    return None;
                }
                if let Some(ge) = self.ge.filter(|ge| value < *ge) {
                    ge_issue(cx, ge);
                    return None;
                }
                match i64::try_from(value) {
                    Ok(value) => Some(value),
                    Err(_) => {
                        huge_issue(cx, loc, input);
                        None
                    }
                }
            }
            Parsed::Huge(negative) => {
                match (negative, self.le, self.ge) {
                    (false, Some(le), _) => le_issue(cx, le),
                    (true, _, Some(ge)) => ge_issue(cx, ge),
                    _ => huge_issue(cx, loc, input),
                }
                None
            }
        }
    }
}

fn int_json(value: i128) -> Value {
    if let Ok(value) = i64::try_from(value) {
        json!(value)
    } else {
        json!(value as u64)
    }
}

/// An integer Python would hold but `i64` cannot (see DIFFERENCES.md).
fn huge_issue(cx: &mut Cx, loc: &[LocItem], input: &Value) {
    cx.push(issue("int_parsing_size", loc, "Unable to parse input string as an integer, exceeded maximum size", input));
}

/// `bool` in lax mode: `true`/`false`, `0`/`1`, `0.0`/`1.0`, and the strings pydantic knows
/// (`yes`, `off`, `t`, … in any ASCII case, no surrounding space).
pub fn boolean(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<bool> {
    let parsing = |cx: &mut Cx| {
        cx.push(issue("bool_parsing", loc, "Input should be a valid boolean, unable to interpret input", input))
    };
    match input {
        Value::Bool(flag) => Some(*flag),
        Value::Number(number) if !number.is_f64() => match number.as_i64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => {
                parsing(cx);
                None
            }
        },
        Value::Number(number) if number.as_f64() == Some(0.0) => Some(false),
        Value::Number(number) if number.as_f64() == Some(1.0) => Some(true),
        Value::String(text) => {
            const FALSE: [&str; 6] = ["0", "f", "n", "no", "off", "false"];
            const TRUE: [&str; 6] = ["1", "t", "y", "on", "yes", "true"];
            if FALSE.iter().any(|word| text.eq_ignore_ascii_case(word)) {
                Some(false)
            } else if TRUE.iter().any(|word| text.eq_ignore_ascii_case(word)) {
                Some(true)
            } else {
                parsing(cx);
                None
            }
        }
        _ => {
            cx.push(issue("bool_type", loc, "Input should be a valid boolean", input));
            None
        }
    }
}

/// `Literal[...]` of strings: the input must be one of `expected` (Python equality, so only a
/// string can match). The issue lists them in declaration order.
pub fn literal<'e>(input: &Value, loc: &[LocItem], cx: &mut Cx, expected: &[&'e str]) -> Option<&'e str> {
    if let Value::String(text) = input {
        if let Some(found) = expected.iter().find(|item| **item == text) {
            return Some(found);
        }
    }
    let quoted: Vec<String> = expected.iter().map(|item| pytext::repr(item)).collect();
    literal_issue(cx, loc, input, &quoted);
    None
}

/// `Literal[<int>]`: Python equality, so `True` and `1.0` match `1` (the literal's value is kept).
pub fn literal_int(input: &Value, loc: &[LocItem], cx: &mut Cx, expected: i64) -> Option<i64> {
    if pyrepr::eq(input, &json!(expected)) {
        return Some(expected);
    }
    literal_issue(cx, loc, input, &[expected.to_string()]);
    None
}

fn literal_issue(cx: &mut Cx, loc: &[LocItem], input: &Value, quoted: &[String]) {
    let text = match quoted {
        [one] => one.clone(),
        [init @ .., last] => format!("{} or {last}", init.join(", ")),
        [] => String::new(),
    };
    cx.push(with_ctx(
        issue("literal_error", loc, &format!("Input should be {text}"), input),
        &[("expected", json!(text))],
    ));
}

/// `dict` (any values): the object itself.
pub fn dict(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Map<String, Value>> {
    match input {
        Value::Object(map) => Some(map.clone()),
        _ => {
            cx.push(issue("dict_type", loc, "Input should be a valid dictionary", input));
            None
        }
    }
}

/// `X | None`: `null` is `None`, anything else goes to `validate`.
pub fn nullable<T>(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    validate: impl FnOnce(&Value, &[LocItem], &mut Cx) -> Option<T>,
) -> Option<Option<T>> {
    if input.is_null() {
        Some(None)
    } else {
        validate(input, loc, cx).map(Some)
    }
}

/// `list[X]` with an optional `max_length`: a longer list is one `too_long` issue (its items are
/// not looked at); otherwise every item is validated and every failure reported.
pub fn list<T>(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    max_length: Option<usize>,
    mut item: impl FnMut(&Value, &[LocItem], &mut Cx) -> Option<T>,
) -> Option<Vec<T>> {
    let Value::Array(items) = input else {
        cx.push(issue("list_type", loc, "Input should be a valid list", input));
        return None;
    };
    if let Some(max) = max_length.filter(|max| items.len() > *max) {
        cx.push(too_long(loc, input, "List", max, items.len()));
        return None;
    }
    let start = cx.count();
    let mut out = Vec::with_capacity(items.len());
    for (index, value) in items.iter().enumerate() {
        if let Some(valid) = item(value, &at_index(loc, index), cx) {
            out.push(valid);
        }
    }
    (cx.count() == start).then_some(out)
}

/// The issue of a list whose length is checked after an earlier step (a `mode="before"`
/// validator that changed it).
pub fn list_too_long(loc: &[LocItem], input: &Value, max_length: usize, actual: usize) -> ValidationIssue {
    too_long(loc, input, "List", max_length, actual)
}

/// `dict[K, V]` with an optional `max_length`: keys are validated at `loc + [key, "[key]"]`,
/// values at `loc + [key]`; entries keep the input's order.
pub fn dict_of<K, V>(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    max_length: Option<usize>,
    mut key: impl FnMut(&str, &[LocItem], &mut Cx) -> Option<K>,
    mut value: impl FnMut(&Value, &[LocItem], &mut Cx) -> Option<V>,
) -> Option<Vec<(K, V)>> {
    let Value::Object(map) = input else {
        cx.push(issue("dict_type", loc, "Input should be a valid dictionary", input));
        return None;
    };
    if let Some(max) = max_length.filter(|max| map.len() > *max) {
        cx.push(too_long(loc, input, "Dictionary", max, map.len()));
        return None;
    }
    let start = cx.count();
    let mut out = Vec::with_capacity(map.len());
    for (name, item) in map {
        let entry_loc = at(loc, name.as_str());
        let valid_key = key(name, &at(&entry_loc, "[key]"), cx);
        let valid_value = value(item, &entry_loc, cx);
        if let (Some(k), Some(v)) = (valid_key, valid_value) {
            out.push((k, v));
        }
    }
    (cx.count() == start).then_some(out)
}

/// A `str` key (always valid for JSON input).
pub fn str_key(key: &str, _loc: &[LocItem], _cx: &mut Cx) -> Option<String> {
    Some(key.to_string())
}

/// A `Literal[...]` key.
pub fn literal_key<'e>(expected: &'static [&'e str]) -> impl FnMut(&str, &[LocItem], &mut Cx) -> Option<&'e str> {
    move |key, loc, cx| literal(&Value::String(key.to_string()), loc, cx, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issues(validate: impl FnOnce(&mut Cx)) -> Vec<ValidationIssue> {
        let mut cx = Cx::new(Entry::Body);
        validate(&mut cx);
        cx.into_issues()
    }

    #[test]
    fn lax_integers_take_what_pydantic_takes() {
        let mut cx = Cx::new(Entry::Python);
        for (input, value) in [
            (json!(12), 12),
            (json!("12"), 12),
            (json!(" 12 "), 12),
            (json!("1_000"), 1000),
            (json!("12.0"), 12),
            (json!(12.0), 12),
            (json!(true), 1),
            (json!(false), 0),
            (json!("٨٠"), 80),
        ] {
            assert_eq!(Int::LAX.validate(&input, &[], &mut cx), Some(value), "{input}");
        }
        assert_eq!(cx.count(), 0);
        let found = issues(|cx| {
            Int::LAX.validate(&json!("1e3"), &[], cx);
            Int::LAX.validate(&json!(1.5), &[], cx);
            Int::STRICT.validate(&json!(true), &[], cx);
            Int::lax(Some(1), Some(10)).validate(&json!(11), &[], cx);
            Int::lax(Some(1), None).validate(&json!("99999999999999999999999"), &[], cx);
        });
        let kinds: Vec<&str> = found.iter().map(|issue| issue.kind.as_str()).collect();
        assert_eq!(kinds, ["int_parsing", "int_from_float", "int_type", "less_than_equal", "int_parsing_size"]);
    }

    #[test]
    fn literal_messages_list_the_choices() {
        let found = issues(|cx| {
            literal(&json!("x"), &[], cx, &["a", "b", "c"]);
            literal(&json!(1), &[], cx, &["own"]);
            literal_int(&json!("1"), &[], cx, 1);
        });
        assert_eq!(found[0].msg, "Input should be 'a', 'b' or 'c'");
        assert_eq!(found[1].msg, "Input should be 'own'");
        assert_eq!(found[2].msg, "Input should be 1");
        let mut cx = Cx::new(Entry::Python);
        assert_eq!(literal_int(&json!(true), &[], &mut cx, 1), Some(1));
        assert_eq!(literal_int(&json!(1.0), &[], &mut cx, 1), Some(1));
    }
}
