//! The request models of the routes in this package (`panel/schemas.py`): pydantic `BaseModel`s
//! with the default `extra="ignore"`, validated in lax mode.

use panel_core::errors::LocItem;
use panel_model::validate::{boolean, literal, nullable, Cx, Extra, Fields, Int, Model, Str};
use serde_json::{json, Value};

const ROLES: &[&str] = &["owner", "admin", "viewer"];
const SCOPES: &[&str] = &["admin", "monitor", "node-sync"];

/// `^[A-Za-z0-9_.-]{1,64}$` with the regex crate's `$` (end of text only).
fn admin_username(text: &str) -> bool {
    let count = text.chars().count();
    (1..=64).contains(&count) && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

/// `Login`: `username` 1..64, `password` 1..1024.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub username: String,
    pub password: String,
}

impl Model for Login {
    const TITLE: &'static str = "Login";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = fields.required(cx, "username", |value, loc, cx| Str::len(1, 64).validate(value, loc, cx));
        let password = fields.required(cx, "password", |value, loc, cx| Str::len(1, 1024).validate(value, loc, cx));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { username: username?, password: password? })
    }

    fn dump(&self) -> Value {
        json!({"username": self.username, "password": self.password})
    }
}

/// `AdminCreate`: `username` by pattern, `password` 12..1024, `role` one of the three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCreate {
    pub username: String,
    pub password: String,
    pub role: String,
}

impl Model for AdminCreate {
    const TITLE: &'static str = "AdminCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = fields.required(cx, "username", |value, loc, cx| {
            Str::pattern("^[A-Za-z0-9_.-]{1,64}$", admin_username).validate(value, loc, cx)
        });
        let password = fields.required(cx, "password", |value, loc, cx| Str::len(12, 1024).validate(value, loc, cx));
        let role = fields.required(cx, "role", |value, loc, cx| literal(value, loc, cx, ROLES).map(str::to_string));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { username: username?, password: password?, role: role? })
    }

    fn dump(&self) -> Value {
        json!({"username": self.username, "password": self.password, "role": self.role})
    }
}

/// `AdminUpdate`: every field optional.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminUpdate {
    pub role: Option<String>,
    pub password: Option<String>,
    pub active: Option<bool>,
}

impl Model for AdminUpdate {
    const TITLE: &'static str = "AdminUpdate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let role = fields.optional(
            cx,
            "role",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| literal(value, loc, cx, ROLES).map(str::to_string))
            },
        );
        let password = fields.optional(
            cx,
            "password",
            || None,
            |value, loc, cx| nullable(value, loc, cx, |value, loc, cx| Str::len(12, 1024).validate(value, loc, cx)),
        );
        let active = fields.optional(cx, "active", || None, |value, loc, cx| nullable(value, loc, cx, boolean));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { role: role?, password: password?, active: active? })
    }

    fn dump(&self) -> Value {
        json!({"role": self.role, "password": self.password, "active": self.active})
    }
}

/// `ApiKeyCreate`: `name` 1..64, `scope` one of three, `expires_at` an int ≥ 0 or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyCreate {
    pub name: String,
    pub scope: String,
    pub expires_at: Option<i64>,
}

impl Model for ApiKeyCreate {
    const TITLE: &'static str = "ApiKeyCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let name = fields.required(cx, "name", |value, loc, cx| Str::len(1, 64).validate(value, loc, cx));
        let scope = fields.required(cx, "scope", |value, loc, cx| literal(value, loc, cx, SCOPES).map(str::to_string));
        let expires_at = fields.optional(
            cx,
            "expires_at",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| Int::lax(Some(0), None).validate(value, loc, cx))
            },
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { name: name?, scope: scope?, expires_at: expires_at? })
    }

    fn dump(&self) -> Value {
        json!({"name": self.name, "scope": self.scope, "expires_at": self.expires_at})
    }
}

/// `ApiKeyEnabled`: `enabled` (lax bool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiKeyEnabled {
    pub enabled: bool,
}

impl Model for ApiKeyEnabled {
    const TITLE: &'static str = "ApiKeyEnabled";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let enabled = fields.required(cx, "enabled", boolean);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { enabled: enabled? })
    }

    fn dump(&self) -> Value {
        json!({"enabled": self.enabled})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_usernames_follow_the_regex_crate() {
        assert!(admin_username("probe-viewer.1_x"));
        assert!(!admin_username("abc\n"));
        assert!(!admin_username(""));
        assert!(!admin_username(&"a".repeat(65)));
        assert!(!admin_username("bad user"));
    }

    #[test]
    fn issues_come_in_field_order() {
        let error =
            ApiKeyCreate::validate_body(&json!({"name": "", "scope": "x", "expires_at": -1, "extra": 1})).unwrap_err();
        let kinds: Vec<&str> = error.issues.iter().map(|issue| issue.kind.as_str()).collect();
        assert_eq!(kinds, ["string_too_short", "literal_error", "greater_than_equal"]);
        assert_eq!(AdminUpdate::validate_body(&json!({})).unwrap(), AdminUpdate::default());
    }
}
