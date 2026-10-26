//! The request models of the protocol pages and the version routes (`panel/schemas.py`):
//! pydantic `BaseModel`s with the default `extra="ignore"`, lax unless a field says `strict=True`.

use panel_core::errors::LocItem;
use panel_model::validate::{boolean, list, nullable, value_error, Cx, Extra, Fields, Int, Model, Str};
use serde_json::{json, Map, Value};

use crate::isoformat::{fromisoformat, Parsed};

/// `2**63 - 1`.
const INT64_MAX: i128 = i64::MAX as i128;

/// `re.fullmatch(r"[A-Za-z0-9_.-]+", value)`.
fn plain_name(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

/// `^[A-Za-z0-9_.-]{1,64}$` (the regex crate's `$`: end of text only).
fn naive_username(text: &str) -> bool {
    let count = text.chars().count();
    (1..=64).contains(&count) && plain_name(text)
}

/// `^[A-Za-z0-9_.:-]{1,128}$`.
fn revision(text: &str) -> bool {
    let count = text.chars().count();
    (1..=128).contains(&count)
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-'))
}

/// `^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`.
fn version(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else { return false };
    first.is_ascii_alphanumeric()
        && text.chars().count() <= 64
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | ':' | '-'))
}

const NAIVE_USERNAME: &str = "^[A-Za-z0-9_.-]{1,64}$";
const REVISION: &str = "^[A-Za-z0-9_.:-]{1,128}$";
const VERSION: &str = "^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$";

/// `int | None = Field(default=None, strict=True, ge=1, le=…)`.
fn optional_count(value: &Value, loc: &[LocItem], cx: &mut Cx, le: i128) -> Option<Option<i64>> {
    nullable(value, loc, cx, |value, loc, cx| Int::strict(Some(1), Some(le)).validate(value, loc, cx))
}

/// `UserCreate`: `username` 1..32 characters, then `[A-Za-z0-9_.-]+` ("invalid username").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCreate {
    pub username: String,
}

impl Model for UserCreate {
    const TITLE: &'static str = "UserCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = fields.required(cx, "username", |value, loc, cx| {
            let text = Str::len(1, 32).validate(value, loc, cx)?;
            if !plain_name(&text) {
                cx.push(value_error(loc.to_vec(), value, "invalid username"));
                return None;
            }
            Some(text)
        });
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { username: username? })
    }

    fn dump(&self) -> Value {
        json!({"username": self.username})
    }
}

/// `UserLimits`: every field optional; [`UserLimits::set`] is `model_dump(exclude_unset=True)`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UserLimits {
    pub data_quota_bytes: Option<i64>,
    pub rate_limit_up_bps: Option<i64>,
    pub rate_limit_down_bps: Option<i64>,
    pub max_tcp_conns: Option<i64>,
    pub max_unique_ips: Option<i64>,
    pub expiration_rfc3339: Option<String>,
    /// The fields the request named, in declaration order, with their validated values.
    pub set: Map<String, Value>,
}

/// The `valid_expiration` validator: `datetime.fromisoformat(value.replace("Z", "+00:00"))` must
/// parse and carry a timezone.
fn expiration(value: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<String> {
    let text = Str::max(64).validate(value, loc, cx)?;
    match fromisoformat(&text.replace('Z', "+00:00")) {
        Ok(Parsed::Aware) => Some(text),
        Ok(Parsed::Naive) => {
            cx.push(value_error(loc.to_vec(), value, "timezone is required"));
            None
        }
        Err(_) => {
            cx.push(value_error(loc.to_vec(), value, "invalid RFC3339 timestamp"));
            None
        }
    }
}

impl Model for UserLimits {
    const TITLE: &'static str = "UserLimits";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let present = |name: &str| input.get(name).is_some();
        let count = |fields: &mut Fields<'_>, cx: &mut Cx, name: &'static str, le: i128| {
            fields.optional(cx, name, || None, |value, loc, cx| optional_count(value, loc, cx, le))
        };
        let data_quota_bytes = count(&mut fields, cx, "data_quota_bytes", INT64_MAX);
        let rate_limit_up_bps = count(&mut fields, cx, "rate_limit_up_bps", 1_000_000_000_000);
        let rate_limit_down_bps = count(&mut fields, cx, "rate_limit_down_bps", 1_000_000_000_000);
        let max_tcp_conns = count(&mut fields, cx, "max_tcp_conns", 100_000);
        let max_unique_ips = count(&mut fields, cx, "max_unique_ips", 100_000);
        let expiration_rfc3339 =
            fields.optional(cx, "expiration_rfc3339", || None, |value, loc, cx| nullable(value, loc, cx, expiration));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        let mut limits = Self {
            data_quota_bytes: data_quota_bytes?,
            rate_limit_up_bps: rate_limit_up_bps?,
            rate_limit_down_bps: rate_limit_down_bps?,
            max_tcp_conns: max_tcp_conns?,
            max_unique_ips: max_unique_ips?,
            expiration_rfc3339: expiration_rfc3339?,
            set: Map::new(),
        };
        let dumped = limits.dump();
        for (name, value) in dumped.as_object().into_iter().flatten() {
            if present(name) {
                limits.set.insert(name.clone(), value.clone());
            }
        }
        Some(limits)
    }

    fn dump(&self) -> Value {
        json!({
            "data_quota_bytes": self.data_quota_bytes,
            "rate_limit_up_bps": self.rate_limit_up_bps,
            "rate_limit_down_bps": self.rate_limit_down_bps,
            "max_tcp_conns": self.max_tcp_conns,
            "max_unique_ips": self.max_unique_ips,
            "expiration_rfc3339": self.expiration_rfc3339,
        })
    }
}

/// `NaiveUserCreate`: `username` by pattern, `quota_bytes` a strict int 1..2⁶³−1 or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaiveUserCreate {
    pub username: String,
    pub quota_bytes: Option<i64>,
}

impl Model for NaiveUserCreate {
    const TITLE: &'static str = "NaiveUserCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = fields.required(cx, "username", |value, loc, cx| {
            Str::pattern(NAIVE_USERNAME, naive_username).validate(value, loc, cx)
        });
        let quota_bytes =
            fields.optional(cx, "quota_bytes", || None, |value, loc, cx| optional_count(value, loc, cx, INT64_MAX));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { username: username?, quota_bytes: quota_bytes? })
    }

    fn dump(&self) -> Value {
        json!({"username": self.username, "quota_bytes": self.quota_bytes})
    }
}

/// `NaiveQuotaUpdate`: `quota_bytes` a strict int 1..2⁶³−1 or null (default null).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NaiveQuotaUpdate {
    pub quota_bytes: Option<i64>,
}

impl Model for NaiveQuotaUpdate {
    const TITLE: &'static str = "NaiveQuotaUpdate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let quota_bytes =
            fields.optional(cx, "quota_bytes", || None, |value, loc, cx| optional_count(value, loc, cx, INT64_MAX));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { quota_bytes: quota_bytes? })
    }

    fn dump(&self) -> Value {
        json!({"quota_bytes": self.quota_bytes})
    }
}

/// `MieruQuota`: `days` 1..3650, `megabytes` 1..2³¹−1, both strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MieruQuota {
    pub days: i64,
    pub megabytes: i64,
}

impl Model for MieruQuota {
    const TITLE: &'static str = "MieruQuota";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let days =
            fields.required(cx, "days", |value, loc, cx| Int::strict(Some(1), Some(3650)).validate(value, loc, cx));
        let megabytes = fields.required(cx, "megabytes", |value, loc, cx| {
            Int::strict(Some(1), Some(i128::from(i32::MAX))).validate(value, loc, cx)
        });
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { days: days?, megabytes: megabytes? })
    }

    fn dump(&self) -> Value {
        json!({"days": self.days, "megabytes": self.megabytes})
    }
}

fn quotas(value: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Vec<MieruQuota>> {
    list(value, loc, cx, Some(16), MieruQuota::validate_at)
}

fn expected_revision(value: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<String> {
    Str::pattern(REVISION, revision).validate(value, loc, cx)
}

/// The quotas as `[item.model_dump() for item in quotas]`.
pub fn dump_quotas(quotas: &[MieruQuota]) -> Value {
    Value::Array(quotas.iter().map(MieruQuota::dump).collect())
}

/// `MieruUserCreate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruUserCreate {
    pub username: String,
    pub quotas: Vec<MieruQuota>,
    pub expected_revision: String,
    pub allow_private_ip: bool,
    pub allow_loopback_ip: bool,
}

impl Model for MieruUserCreate {
    const TITLE: &'static str = "MieruUserCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = fields.required(cx, "username", |value, loc, cx| {
            let text = Str::len(1, 64).validate(value, loc, cx)?;
            if text.len() > 64 || !plain_name(&text) {
                cx.push(value_error(loc.to_vec(), value, "invalid username"));
                return None;
            }
            Some(text)
        });
        let quotas = fields.optional(cx, "quotas", Vec::new, quotas);
        let expected_revision = fields.required(cx, "expected_revision", expected_revision);
        let allow_private_ip = fields.optional(cx, "allow_private_ip", || false, boolean);
        let allow_loopback_ip = fields.optional(cx, "allow_loopback_ip", || false, boolean);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            username: username?,
            quotas: quotas?,
            expected_revision: expected_revision?,
            allow_private_ip: allow_private_ip?,
            allow_loopback_ip: allow_loopback_ip?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "username": self.username,
            "quotas": dump_quotas(&self.quotas),
            "expected_revision": self.expected_revision,
            "allow_private_ip": self.allow_private_ip,
            "allow_loopback_ip": self.allow_loopback_ip,
        })
    }
}

/// `MieruRevision`: `expected_revision` by pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruRevision {
    pub expected_revision: String,
}

impl Model for MieruRevision {
    const TITLE: &'static str = "MieruRevision";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let expected_revision = fields.required(cx, "expected_revision", expected_revision);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { expected_revision: expected_revision? })
    }

    fn dump(&self) -> Value {
        json!({"expected_revision": self.expected_revision})
    }
}

/// `MieruQuotaUpdate(MieruRevision)`: the inherited `expected_revision`, then `quotas` (required,
/// at most 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruQuotaUpdate {
    pub expected_revision: String,
    pub quotas: Vec<MieruQuota>,
}

impl Model for MieruQuotaUpdate {
    const TITLE: &'static str = "MieruQuotaUpdate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let expected_revision = fields.required(cx, "expected_revision", expected_revision);
        let quotas = fields.required(cx, "quotas", quotas);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { expected_revision: expected_revision?, quotas: quotas? })
    }

    fn dump(&self) -> Value {
        json!({"expected_revision": self.expected_revision, "quotas": dump_quotas(&self.quotas)})
    }
}

/// `VersionUpdate`: `version` and `expected_current` (or null), strict strings by pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionUpdate {
    pub version: String,
    pub expected_current: Option<String>,
}

impl Model for VersionUpdate {
    const TITLE: &'static str = "VersionUpdate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let version_text =
            fields.required(cx, "version", |value, loc, cx| Str::pattern(VERSION, version).validate(value, loc, cx));
        let expected_current = fields.optional(
            cx,
            "expected_current",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| Str::pattern(VERSION, version).validate(value, loc, cx))
            },
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { version: version_text?, expected_current: expected_current? })
    }

    fn dump(&self) -> Value {
        json!({"version": self.version, "expected_current": self.expected_current})
    }
}

/// The `component` path parameter of `POST /api/versions/{component}/update`.
pub const VERSION_COMPONENTS: &[&str] = &["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"];

/// The `operation` path parameter of the enable/disable/rotate routes.
pub const OPERATIONS: &[&str] = &["enable", "disable", "rotate"];

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds<M: Model + std::fmt::Debug>(input: Value) -> Vec<String> {
        M::validate_body(&input).unwrap_err().issues.iter().map(|issue| issue.kind.clone()).collect()
    }

    #[test]
    fn usernames_are_checked_after_their_length() {
        assert_eq!(UserCreate::validate_body(&json!({"username": "alice"})).unwrap().username, "alice");
        assert_eq!(kinds::<UserCreate>(json!({"username": "bad user"})), ["value_error"]);
        assert_eq!(kinds::<UserCreate>(json!({"username": "a".repeat(33)})), ["string_too_long"]);
        let error = UserCreate::validate_body(&json!({"username": "bad user"})).unwrap_err();
        assert_eq!(error.issues[0].msg, "Value error, invalid username");
        assert_eq!(kinds::<NaiveUserCreate>(json!({"username": "bad user"})), ["string_pattern_mismatch"]);
        assert_eq!(
            kinds::<MieruUserCreate>(json!({"username": "caf\u{e9}", "expected_revision": "r"})),
            ["value_error"]
        );
    }

    #[test]
    fn limits_remember_what_was_set() {
        let limits = UserLimits::validate_body(&json!({"max_tcp_conns": 3, "unknown": 1})).unwrap();
        assert_eq!(Value::Object(limits.set.clone()), json!({"max_tcp_conns": 3}));
        let cleared = UserLimits::validate_body(&json!({"expiration_rfc3339": null})).unwrap();
        assert_eq!(Value::Object(cleared.set), json!({"expiration_rfc3339": null}));
        assert!(UserLimits::validate_body(&json!({})).unwrap().set.is_empty());
        assert_eq!(kinds::<UserLimits>(json!({"data_quota_bytes": "5"})), ["int_type"]);
        assert_eq!(kinds::<UserLimits>(json!({"max_tcp_conns": 0})), ["greater_than_equal"]);
        let naive = UserLimits::validate_body(&json!({"expiration_rfc3339": "2027-01-01T00:00:00"})).unwrap_err();
        assert_eq!(naive.issues[0].msg, "Value error, timezone is required");
        let bad = UserLimits::validate_body(&json!({"expiration_rfc3339": "soon"})).unwrap_err();
        assert_eq!(bad.issues[0].msg, "Value error, invalid RFC3339 timestamp");
        assert!(UserLimits::validate_body(&json!({"expiration_rfc3339": "2027-01-01T00:00:00Z"})).is_ok());
    }

    #[test]
    fn mieru_and_version_models_follow_their_patterns() {
        let many = vec![json!({"days": 1, "megabytes": 1}); 17];
        assert_eq!(kinds::<MieruQuotaUpdate>(json!({"expected_revision": "r", "quotas": many})), ["too_long"]);
        assert_eq!(kinds::<MieruRevision>(json!({"expected_revision": "bad revision"})), ["string_pattern_mismatch"]);
        assert_eq!(kinds::<MieruQuotaUpdate>(json!({"expected_revision": "r"})), ["missing"]);
        let created =
            MieruUserCreate::validate_body(&json!({"username": "phone", "expected_revision": "rev-1"})).unwrap();
        assert!(created.quotas.is_empty() && !created.allow_private_ip);
        assert_eq!(kinds::<VersionUpdate>(json!({"version": "-1"})), ["string_pattern_mismatch"]);
        let update = VersionUpdate::validate_body(&json!({"version": "3.4.25", "expected_current": null})).unwrap();
        assert_eq!(update.expected_current, None);
        assert!(version("a") && version(&"a".repeat(64)) && !version(&"a".repeat(65)) && !version("1.0\n"));
    }
}
