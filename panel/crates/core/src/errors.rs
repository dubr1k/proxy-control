//! Machine error codes and the error bodies the panel's API answers with (inventory §2.6).
//!
//! Four body shapes exist, and [`ApiError`] has one variant per shape:
//! 1. `{"detail": "<text>"}` — `HTTPException`, the framework's 404/405, the manager handlers;
//! 2. `{"detail": "<text>", "code": "<code>"}` — fleet refusals, lane errors, `quota_exhausted`;
//! 3. `{"detail", "code", "compiled"?}` — routing errors (`detail` falls back to the code);
//! 4. `{"detail": [{"type", "loc", "msg", "input", "ctx"?}, …]}` — request validation (422).
//!
//! A body goes out as Starlette's `JSONResponse` renders it: compact, raw UTF-8
//! ([`crate::pyjson::compact_utf8`]). Codes travel as strings because a linked node's own code is
//! passed through unchanged; [`ErrorCode`] names every code the panel itself produces.

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::pyjson;

macro_rules! error_codes {
    ($($variant:ident => $text:literal,)*) => {
        /// Every machine code the Python panel produces, as an HTTP error `code` or as data
        /// (compiler limitations, adapter outcomes, node reports, fleet v2 conflicts).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum ErrorCode {
            $($variant,)*
        }

        impl ErrorCode {
            /// All codes, in declaration order.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)*];

            /// The code as it appears on the wire.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $text,)*
                }
            }

            /// The code for its wire text.
            pub fn from_wire(text: &str) -> Option<Self> {
                match text {
                    $($text => Some(ErrorCode::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

error_codes! {
    BackendCapabilityMissing => "backend_capability_missing",
    BackendMismatch => "backend_mismatch",
    ChainLoop => "chain_loop",
    DigestConflict => "digest_conflict",
    DigestInvalid => "digest_invalid",
    DocumentTooLarge => "document_too_large",
    Domain => "domain",
    EgressConflict => "egress_conflict",
    EgressInvalid => "egress_invalid",
    EgressNoPrevious => "egress_no_previous",
    EgressReadbackMismatch => "egress_readback_mismatch",
    EgressReloadFailed => "egress_reload_failed",
    EgressUnsupported => "egress_unsupported",
    ExitDisabled => "exit_disabled",
    ExitInUse => "exit_in_use",
    ExitInvalid => "exit_invalid",
    ExitLinkInvalid => "exit_link_invalid",
    ExitNotFound => "exit_not_found",
    ExitOtherNode => "exit_other_node",
    ExitSecretPending => "exit_secret_pending",
    ExitUnknown => "exit_unknown",
    ExitUnreachable => "exit_unreachable",
    ForeignMaster => "foreign_master",
    GrantNotFound => "grant_not_found",
    GuidMismatch => "guid_mismatch",
    IngressUnreachable => "ingress_unreachable",
    LaneInvalid => "lane_invalid",
    LaneNotAttached => "lane_not_attached",
    LaneNotFound => "lane_not_found",
    LanePolicy => "lane_policy",
    LaneRequiresRouter => "lane_requires_router",
    LanesUnsupported => "lanes_unsupported",
    ManagedByCentral => "managed_by_central",
    ManagerUnavailable => "manager_unavailable",
    ManualInterventionRequired => "manual_intervention_required",
    MetricsDisabled => "metrics_disabled",
    MetricsWarmingUp => "metrics_warming_up",
    NodeAuthFailed => "node_auth_failed",
    NodeLacksAmneziawgEgress => "node_lacks_amneziawg_egress",
    NodeLacksEgressV1 => "node_lacks_egress_v1",
    NodeLacksExits => "node_lacks_exits",
    NodeLacksGeodata => "node_lacks_geodata",
    NodeLacksLanes => "node_lacks_lanes",
    NodeLacksMtproxyEgress => "node_lacks_mtproxy_egress",
    NodeLacksRelay => "node_lacks_relay",
    NodeLacksRouter => "node_lacks_router",
    NodeLacksTrusttunnelEgress => "node_lacks_trusttunnel_egress",
    NodeNotFound => "node_not_found",
    NodeNotLocal => "node_not_local",
    NodeRejected => "node_rejected",
    NodeUnknown => "node_unknown",
    NodeUnreachable => "node_unreachable",
    NotAttached => "not_attached",
    PolicyApplied => "policy_applied",
    PolicyConflict => "policy_conflict",
    PolicyNotFound => "policy_not_found",
    PrivateDestination => "private_destination",
    ProtocolDisabledOnNode => "protocol_disabled_on_node",
    ProtocolOutOfScope => "protocol_out_of_scope",
    ProviderUnavailable => "provider_unavailable",
    ProviderUnreachable => "provider_unreachable",
    QuotaExhausted => "quota_exhausted",
    RelayCredentialPending => "relay_credential_pending",
    RelayDisabled => "relay_disabled",
    RelayNoWarp => "relay_no_warp",
    RelayUnavailable => "relay_unavailable",
    RouterLacksMtproxy => "router_lacks_mtproxy",
    RouterUnavailable => "router_unavailable",
    RouterUnreachable => "router_unreachable",
    RuleKindUnsupported => "rule_kind_unsupported",
    SecretStoreDisabled => "secret_store_disabled",
    StaleGeneration => "stale_generation",
    TelemtApiUnsupported => "telemt_api_unsupported",
    Unsupported => "unsupported",
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl From<ErrorCode> for String {
    fn from(code: ErrorCode) -> Self {
        code.as_str().to_string()
    }
}

/// One element of a `loc` path: a field name or a list index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum LocItem {
    Key(String),
    Index(i64),
}

impl From<&str> for LocItem {
    fn from(key: &str) -> Self {
        LocItem::Key(key.to_string())
    }
}

impl From<String> for LocItem {
    fn from(key: String) -> Self {
        LocItem::Key(key)
    }
}

impl From<i64> for LocItem {
    fn from(index: i64) -> Self {
        LocItem::Index(index)
    }
}

/// One pydantic v2 validation error as FastAPI reports it: `type`, `loc`, `msg`, `input` and an
/// optional `ctx`, in that key order. The message catalogue lives with the request models (WP4);
/// the constructors here are the cases checked against FastAPI 0.1xx/pydantic 2 in the panel image.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationIssue {
    #[serde(rename = "type")]
    pub kind: String,
    pub loc: Vec<LocItem>,
    pub msg: String,
    pub input: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<Map<String, Value>>,
}

impl ValidationIssue {
    /// Any issue, built field by field.
    pub fn new(kind: &str, loc: Vec<LocItem>, msg: impl Into<String>, input: Value) -> Self {
        Self { kind: kind.into(), loc, msg: msg.into(), input, ctx: None }
    }

    /// Adds `ctx` (insertion order kept).
    pub fn with_ctx(mut self, ctx: Map<String, Value>) -> Self {
        self.ctx = Some(ctx);
        self
    }

    /// `missing` — "Field required"; `input` is the whole enclosing object.
    pub fn missing(loc: Vec<LocItem>, enclosing: Value) -> Self {
        Self::new("missing", loc, "Field required", enclosing)
    }

    /// `extra_forbidden` — "Extra inputs are not permitted"; `input` is the extra value.
    pub fn extra_forbidden(loc: Vec<LocItem>, value: Value) -> Self {
        Self::new("extra_forbidden", loc, "Extra inputs are not permitted", value)
    }

    /// `string_too_short` with `ctx.min_length`.
    pub fn string_too_short(loc: Vec<LocItem>, value: Value, min_length: usize) -> Self {
        let plural = if min_length == 1 { "" } else { "s" };
        let mut ctx = Map::new();
        ctx.insert("min_length".into(), json!(min_length));
        Self::new("string_too_short", loc, format!("String should have at least {min_length} character{plural}"), value)
            .with_ctx(ctx)
    }

    /// `string_too_long` with `ctx.max_length`.
    pub fn string_too_long(loc: Vec<LocItem>, value: Value, max_length: usize) -> Self {
        let plural = if max_length == 1 { "" } else { "s" };
        let mut ctx = Map::new();
        ctx.insert("max_length".into(), json!(max_length));
        Self::new("string_too_long", loc, format!("String should have at most {max_length} character{plural}"), value)
            .with_ctx(ctx)
    }

    /// `int_parsing` — a string that is not an integer.
    pub fn int_parsing(loc: Vec<LocItem>, value: Value) -> Self {
        Self::new("int_parsing", loc, "Input should be a valid integer, unable to parse string as an integer", value)
    }

    /// `model_attributes_type` — the body is not an object.
    pub fn model_attributes_type(loc: Vec<LocItem>, value: Value) -> Self {
        Self::new(
            "model_attributes_type",
            loc,
            "Input should be a valid dictionary or object to extract fields from",
            value,
        )
    }

    /// `json_invalid` — the body is not JSON. FastAPI reports `loc: ["body", <byte offset>]`,
    /// `input: {}` and Python's `json` message in `ctx.error`, which a Rust parser cannot reproduce
    /// word for word; clients rely on `type` and `loc` only.
    pub fn json_invalid(position: i64, error: impl Into<String>) -> Self {
        let mut ctx = Map::new();
        ctx.insert("error".into(), Value::String(error.into()));
        Self::new("json_invalid", vec!["body".into(), position.into()], "JSON decode error", json!({})).with_ctx(ctx)
    }
}

/// An error answer of the panel's API.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    /// Shape 1: `{"detail": detail}`.
    Detail { status: u16, detail: String },
    /// Shape 2: `{"detail": detail, "code": code}`.
    Coded { status: u16, detail: String, code: String },
    /// Shape 3 (`RoutingError`): `{"detail": detail or code, "code": code}` plus `"compiled"` when
    /// present (already redacted by the caller).
    Routing { status: u16, code: String, detail: String, compiled: Option<Value> },
    /// Shape 4: 422 `{"detail": [issues…]}`.
    Validation(Vec<ValidationIssue>),
}

impl ApiError {
    /// `HTTPException(status, detail)`.
    pub fn detail(status: u16, detail: impl Into<String>) -> Self {
        ApiError::Detail { status, detail: detail.into() }
    }

    /// `{"detail", "code"}` with a status.
    pub fn coded(status: u16, code: impl Into<String>, detail: impl Into<String>) -> Self {
        ApiError::Coded { status, detail: detail.into(), code: code.into() }
    }

    /// `RoutingError(status, code, detail, compiled)`.
    pub fn routing(status: u16, code: impl Into<String>, detail: impl Into<String>, compiled: Option<Value>) -> Self {
        ApiError::Routing { status, code: code.into(), detail: detail.into(), compiled }
    }

    /// Starlette's 404 for an unknown path.
    pub fn not_found() -> Self {
        Self::detail(404, "Not Found")
    }

    /// Starlette's 405 (the route layer adds `Allow`).
    pub fn method_not_allowed() -> Self {
        Self::detail(405, "Method Not Allowed")
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            ApiError::Detail { status, .. } | ApiError::Coded { status, .. } | ApiError::Routing { status, .. } => {
                *status
            }
            ApiError::Validation(_) => 422,
        }
    }

    /// The body as a JSON value (keys in the order Python writes them).
    pub fn body(&self) -> Value {
        match self {
            ApiError::Detail { detail, .. } => json!({"detail": detail}),
            ApiError::Coded { detail, code, .. } => json!({"detail": detail, "code": code}),
            ApiError::Routing { code, detail, compiled, .. } => {
                let mut body = Map::new();
                body.insert(
                    "detail".into(),
                    Value::String(if detail.is_empty() { code.clone() } else { detail.clone() }),
                );
                body.insert("code".into(), Value::String(code.clone()));
                if let Some(compiled) = compiled {
                    body.insert("compiled".into(), compiled.clone());
                }
                Value::Object(body)
            }
            ApiError::Validation(issues) => {
                json!({"detail": serde_json::to_value(issues).expect("validation issues serialise")})
            }
        }
    }

    /// The body bytes as Starlette's `JSONResponse` renders them.
    pub fn body_bytes(&self) -> Vec<u8> {
        pyjson::compact_utf8(&self.body()).into_bytes()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status(), pyjson::compact_utf8(&self.body()))
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            assert!(seen.insert(code.as_str()), "duplicate {code}");
            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(*code));
        }
        assert_eq!(serde_json::to_string(&ErrorCode::NodeUnreachable).unwrap(), "\"node_unreachable\"");
    }

    #[test]
    fn bodies_have_the_four_shapes() {
        assert_eq!(ApiError::not_found().body_bytes(), br#"{"detail":"Not Found"}"#);
        assert_eq!(
            ApiError::coded(409, ErrorCode::QuotaExhausted, "Quota exhausted: reset traffic or raise the quota first")
                .body_bytes(),
            br#"{"detail":"Quota exhausted: reset traffic or raise the quota first","code":"quota_exhausted"}"#
        );
        assert_eq!(
            ApiError::routing(409, "policy_conflict", "", None).body_bytes(),
            br#"{"detail":"policy_conflict","code":"policy_conflict"}"#
        );
        let with_compiled = ApiError::routing(422, "unsupported", "Узел", Some(json!({"b": 1, "a": 2})));
        assert_eq!(
            with_compiled.body_bytes(),
            "{\"detail\":\"Узел\",\"code\":\"unsupported\",\"compiled\":{\"b\":1,\"a\":2}}".as_bytes()
        );
        assert_eq!(with_compiled.status(), 422);
    }

    /// The bodies FastAPI/pydantic produced in the panel image (python 3.13.5) for the same cases.
    #[test]
    fn validation_issues_match_fastapi() {
        let body = json!({"extra": 1});
        let error = ApiError::Validation(vec![
            ValidationIssue::missing(vec!["body".into(), "name".into()], body.clone()),
            ValidationIssue::missing(vec!["body".into(), "n".into()], body),
            ValidationIssue::extra_forbidden(vec!["body".into(), "extra".into()], json!(1)),
        ]);
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"missing","loc":["body","name"],"msg":"Field required","input":{"extra":1}},{"type":"missing","loc":["body","n"],"msg":"Field required","input":{"extra":1}},{"type":"extra_forbidden","loc":["body","extra"],"msg":"Extra inputs are not permitted","input":1}]}"#
        );
        let error = ApiError::Validation(vec![
            ValidationIssue::string_too_short(vec!["body".into(), "name".into()], json!(""), 1),
            ValidationIssue::int_parsing(vec!["body".into(), "n".into()], json!("x")),
        ]);
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"string_too_short","loc":["body","name"],"msg":"String should have at least 1 character","input":"","ctx":{"min_length":1}},{"type":"int_parsing","loc":["body","n"],"msg":"Input should be a valid integer, unable to parse string as an integer","input":"x"}]}"#
        );
        let error = ApiError::Validation(vec![ValidationIssue::string_too_long(
            vec!["body".into(), "name".into()],
            json!("abcd"),
            3,
        )]);
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"string_too_long","loc":["body","name"],"msg":"String should have at most 3 characters","input":"abcd","ctx":{"max_length":3}}]}"#
        );
        let error = ApiError::Validation(vec![ValidationIssue::json_invalid(
            1,
            "Expecting property name enclosed in double quotes",
        )]);
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"json_invalid","loc":["body",1],"msg":"JSON decode error","input":{},"ctx":{"error":"Expecting property name enclosed in double quotes"}}]}"#
        );
        let error = ApiError::Validation(vec![ValidationIssue::model_attributes_type(vec!["body".into()], json!([1]))]);
        assert_eq!(
            String::from_utf8(error.body_bytes()).unwrap(),
            r#"{"detail":[{"type":"model_attributes_type","loc":["body"],"msg":"Input should be a valid dictionary or object to extract fields from","input":[1]}]}"#
        );
    }
}
