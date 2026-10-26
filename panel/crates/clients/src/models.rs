//! The request models of the client API (`panel/schemas.py`): pydantic `BaseModel`s with the
//! default `extra="ignore"`, lax mode.

use panel_core::errors::{LocItem, ValidationIssue};
use panel_model::clients::is_username;
use panel_model::validate::{
    at, at_index, boolean, dict, list, literal, nullable, string, value_error, Cx, Extra, Fields, Int, Model, Str,
};
use panel_model::Protocol;
use serde_json::{json, Map, Value};

/// The protocols a request may name, in the `Literal`'s order.
pub const PROTOCOL_CHOICES: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];
/// `USERNAME_RE` as a field pattern.
pub const USERNAME_PATTERN: &str = "^[A-Za-z0-9_.-]{1,64}$";
/// `NODE_RE`.
pub const NODE_PATTERN: &str = "^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$";

/// `NODE_RE` with the regex crate's `$` (end of text only).
pub fn is_node_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes.len() {
        0 => false,
        1 => edge(bytes[0]),
        len => {
            len <= 64
                && edge(bytes[0])
                && edge(bytes[len - 1])
                && bytes[1..len - 1].iter().all(|&b| edge(b) || b == b'.' || b == b'-')
        }
    }
}

fn protocol(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Protocol> {
    literal(input, loc, cx, PROTOCOL_CHOICES).map(|text| Protocol::from_wire(text).expect("a protocol"))
}

/// `too_short` of a list with `min_length`.
fn list_too_short(loc: &[LocItem], input: &Value, min_length: usize, actual: usize) -> ValidationIssue {
    let plural = if min_length == 1 { "" } else { "s" };
    let mut ctx = Map::new();
    ctx.insert("field_type".into(), json!("List"));
    ctx.insert("min_length".into(), json!(min_length));
    ctx.insert("actual_length".into(), json!(actual));
    ValidationIssue::new(
        "too_short",
        loc.to_vec(),
        format!("List should have at least {min_length} item{plural} after validation, not {actual}"),
        input.clone(),
    )
    .with_ctx(ctx)
}

/// `list[...]` with `min_length` (and an optional `max_length`).
fn bounded_list<T>(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    min_length: usize,
    max_length: Option<usize>,
    item: impl FnMut(&Value, &[LocItem], &mut Cx) -> Option<T>,
) -> Option<Vec<T>> {
    let items = list(input, loc, cx, max_length, item)?;
    if items.len() < min_length {
        cx.push(list_too_short(loc, input, min_length, items.len()));
        return None;
    }
    Some(items)
}

/// `ClientCreate`: `display_name` 1..128, `subscription: bool = True`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCreate {
    pub display_name: String,
    pub subscription: bool,
}

impl Model for ClientCreate {
    const TITLE: &'static str = "ClientCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let display_name = f.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        let subscription = f.optional(cx, "subscription", || true, boolean);
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { display_name: display_name?, subscription: subscription? })
    }

    fn dump(&self) -> Value {
        json!({"display_name": self.display_name, "subscription": self.subscription})
    }
}

/// `ClientRename`: `display_name` 1..128.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRename {
    pub display_name: String,
}

impl Model for ClientRename {
    const TITLE: &'static str = "ClientRename";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let display_name = f.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { display_name: display_name? })
    }

    fn dump(&self) -> Value {
        json!({"display_name": self.display_name})
    }
}

/// `GrantLabel`: `label: str = ""` at most 64 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLabel {
    pub label: String,
}

impl Model for GrantLabel {
    const TITLE: &'static str = "GrantLabel";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let label = f.optional(cx, "label", String::new, |v, l, cx| Str::max(64).validate(v, l, cx));
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { label: label? })
    }

    fn dump(&self) -> Value {
        json!({"label": self.label})
    }
}

/// `ClientState`: `state: Literal["active", "suspended", "archived"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStateBody {
    pub state: String,
}

impl Model for ClientStateBody {
    const TITLE: &'static str = "ClientState";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let state = f.required(cx, "state", |v, l, cx| {
            literal(v, l, cx, &["active", "suspended", "archived"]).map(str::to_string)
        });
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { state: state? })
    }

    fn dump(&self) -> Value {
        json!({"state": self.state})
    }
}

/// `tuple[Literal[protocols], str]`.
fn protocol_pair(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<(Protocol, String)> {
    let Value::Array(items) = input else {
        cx.push(ValidationIssue::new("tuple_type", loc.to_vec(), "Input should be a valid tuple", input.clone()));
        return None;
    };
    let start = cx.count();
    let first = match items.first() {
        Some(value) => protocol(value, &at_index(loc, 0), cx),
        None => {
            cx.push(ValidationIssue::missing(at_index(loc, 0), input.clone()));
            None
        }
    };
    let second = match items.get(1) {
        Some(value) => string(value, &at_index(loc, 1), cx),
        None => {
            cx.push(ValidationIssue::missing(at_index(loc, 1), input.clone()));
            None
        }
    };
    if items.len() > 2 {
        let mut ctx = Map::new();
        ctx.insert("field_type".into(), json!("Tuple"));
        ctx.insert("max_length".into(), json!(2));
        ctx.insert("actual_length".into(), json!(items.len()));
        cx.push(
            ValidationIssue::new(
                "too_long",
                loc.to_vec(),
                format!("Tuple should have at most 2 items after validation, not {}", items.len()),
                input.clone(),
            )
            .with_ctx(ctx),
        );
    }
    if cx.count() != start {
        return None;
    }
    Some((first?, second?))
}

/// `ImportDecision` (request model): `display_name` 1..128, `client_id` ≤ 64 or null, `items`
/// 1..64 pairs whose usernames match `USERNAME_RE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDecisionBody {
    pub display_name: String,
    pub client_id: Option<String>,
    pub items: Vec<(Protocol, String)>,
}

impl Model for ImportDecisionBody {
    const TITLE: &'static str = "ImportDecision";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let display_name = f.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        let client_id = f.optional(
            cx,
            "client_id",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Str::max(64).validate(v, l, cx)),
        );
        let items = f.required(cx, "items", |v, l, cx| {
            let items = bounded_list(v, l, cx, 1, Some(64), protocol_pair)?;
            if items.iter().any(|(_, username)| !is_username(username)) {
                cx.push(value_error(l.to_vec(), v, "invalid runtime username"));
                return None;
            }
            Some(items)
        });
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { display_name: display_name?, client_id: client_id?, items: items? })
    }

    fn dump(&self) -> Value {
        json!({
            "display_name": self.display_name,
            "client_id": self.client_id,
            "items": self.items.iter().map(|(protocol, username)| json!([protocol.as_str(), username])).collect::<Vec<_>>(),
        })
    }
}

/// `ClientImport`: `decisions` 1..200.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientImport {
    pub decisions: Vec<ImportDecisionBody>,
}

impl Model for ClientImport {
    const TITLE: &'static str = "ClientImport";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let decisions = f.required(cx, "decisions", |v, l, cx| {
            bounded_list(v, l, cx, 1, Some(200), ImportDecisionBody::validate_at)
        });
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { decisions: decisions? })
    }

    fn dump(&self) -> Value {
        json!({"decisions": self.decisions.iter().map(Model::dump).collect::<Vec<_>>()})
    }
}

/// `GrantAdopt`: `allow_rotation: bool = False`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAdopt {
    pub allow_rotation: bool,
}

impl Model for GrantAdopt {
    const TITLE: &'static str = "GrantAdopt";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let allow_rotation = f.optional(cx, "allow_rotation", || false, boolean);
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { allow_rotation: allow_rotation? })
    }

    fn dump(&self) -> Value {
        json!({"allow_rotation": self.allow_rotation})
    }
}

/// `GrantAdoptBatch(GrantAdopt)`: `allow_rotation`, then `protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAdoptBatch {
    pub allow_rotation: bool,
    pub protocol: Protocol,
}

impl Model for GrantAdoptBatch {
    const TITLE: &'static str = "GrantAdoptBatch";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let allow_rotation = f.optional(cx, "allow_rotation", || false, boolean);
        let protocol = f.required(cx, "protocol", protocol);
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { allow_rotation: allow_rotation?, protocol: protocol? })
    }

    fn dump(&self) -> Value {
        json!({"allow_rotation": self.allow_rotation, "protocol": self.protocol.as_str()})
    }
}

/// `GrantRequest`: one grant of `GrantsCreate` (options are checked by the domain model later).
#[derive(Debug, Clone, PartialEq)]
pub struct GrantRequest {
    pub protocol: Protocol,
    pub node_id: String,
    pub runtime_username: String,
    pub options: Map<String, Value>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

fn optional_int(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<i64>> {
    nullable(input, loc, cx, |v, l, cx| Int::LAX.validate(v, l, cx))
}

impl Model for GrantRequest {
    const TITLE: &'static str = "GrantRequest";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let protocol = f.required(cx, "protocol", protocol);
        let node_id = f.optional(
            cx,
            "node_id",
            || "local".to_string(),
            |v, l, cx| Str::pattern(NODE_PATTERN, is_node_id).validate(v, l, cx),
        );
        let runtime_username = f.required(cx, "runtime_username", |v, l, cx| {
            Str::pattern(USERNAME_PATTERN, is_username).validate(v, l, cx)
        });
        let options = f.optional(cx, "options", Map::new, dict);
        let valid_from = f.optional(cx, "valid_from", || None, optional_int);
        let valid_until = f.optional(cx, "valid_until", || None, optional_int);
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            protocol: protocol?,
            node_id: node_id?,
            runtime_username: runtime_username?,
            options: options?,
            valid_from: valid_from?,
            valid_until: valid_until?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "protocol": self.protocol.as_str(),
            "node_id": self.node_id,
            "runtime_username": self.runtime_username,
            "options": self.options,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        })
    }
}

/// `GrantsCreate`: `grants` with at least one item.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantsCreate {
    pub grants: Vec<GrantRequest>,
}

impl Model for GrantsCreate {
    const TITLE: &'static str = "GrantsCreate";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let grants = f.required(cx, "grants", |v, l, cx| bounded_list(v, l, cx, 1, None, GrantRequest::validate_at));
        f.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { grants: grants? })
    }

    fn dump(&self) -> Value {
        json!({"grants": self.grants.iter().map(Model::dump).collect::<Vec<_>>()})
    }
}

/// The location helper re-exported for the routes' query checks.
pub fn query_loc(name: &str) -> Vec<LocItem> {
    at(&[LocItem::Key("query".into())], name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_follow_node_re() {
        for good in ["local", "a", "fra-1", "a.b", "0"] {
            assert!(is_node_id(good), "{good}");
        }
        for bad in ["", "-a", "a-", "A", "a_b", "local\n", &"a".repeat(65)] {
            assert!(!is_node_id(bad), "{bad}");
        }
    }

    #[test]
    fn grants_create_reports_like_fastapi() {
        let error = GrantsCreate::validate_body(&json!({"grants": [{"protocol": "nope", "runtime_username": "a b"}]}))
            .unwrap_err()
            .to_api_error();
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"literal_error","loc":["body","grants",0,"protocol"],"msg":"Input should be 'mtproxy', 'naive', 'mieru', 'amneziawg' or 'trusttunnel'","input":"nope","ctx":{"expected":"'mtproxy', 'naive', 'mieru', 'amneziawg' or 'trusttunnel'"}},{"type":"string_pattern_mismatch","loc":["body","grants",0,"runtime_username"],"msg":"String should match pattern '^[A-Za-z0-9_.-]{1,64}$'","input":"a b","ctx":{"pattern":"^[A-Za-z0-9_.-]{1,64}$"}}]}"#
        );
        let empty = GrantsCreate::validate_body(&json!({"grants": []})).unwrap_err();
        assert_eq!(empty.issues[0].kind, "too_short");
        let missing = ClientCreate::validate_body(&json!({})).unwrap_err().to_api_error();
        assert_eq!(
            missing.body_bytes(),
            br#"{"detail":[{"type":"missing","loc":["body","display_name"],"msg":"Field required","input":{}}]}"#
        );
    }
}
