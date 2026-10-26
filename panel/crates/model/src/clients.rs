//! What a client is and what access it holds — typed, and never carrying a credential
//! (`clients/models.py`).
//!
//! An [`AccessGrant`] names an account on one endpoint of one node and points at a secret version
//! by reference. The value itself lives encrypted in `secret_versions`, so a grant can be logged,
//! diffed and rendered without a credential ever passing through it.

use indexmap::IndexMap;
use panel_core::errors::{LocItem, ValidationIssue};
use panel_core::pytext;
use serde_json::{json, Map, Value};

use crate::common::{literal_enum, wire_enum, Protocol, SecretRef, WireEnum};
use crate::routing::net;
use crate::validate::{
    at, dict, dict_of, list, nullable, str_key, string, value_error, Cx, Extra, Fields, Int, Model, Str,
    ValidationError,
};

/// `PROTOCOLS`.
pub const PROTOCOLS: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];

wire_enum! {
    /// The AmneziaWG protocol versions a node can serve, oldest first; a grant names exactly one.
    pub enum AwgVersion {
        V1_5 => "1.5",
        V2_0 => "2.0",
        V3_1 => "3.1",
    }
}

/// Client-config keys a node's manager may publish as obfuscation parameters (sorted).
pub const AWG_OBFUSCATION_KEYS: &[&str] = &[
    "ContentPaddingAddition",
    "H1",
    "H2",
    "H3",
    "H4",
    "HeaderProtectionKey",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "Jc",
    "Jmax",
    "Jmin",
    "S1",
    "S2",
    "S3",
    "S4",
];

/// `fleet.LIMIT_FIELDS`: the bounds of Telemt's per-user limits.
pub const LIMIT_FIELDS: &[(&str, i128, i128)] = &[
    ("data_quota_bytes", 1, (1 << 63) - 1),
    ("rate_limit_up_bps", 1, 1_000_000_000_000),
    ("rate_limit_down_bps", 1, 1_000_000_000_000),
    ("max_tcp_conns", 1, 100_000),
    ("max_unique_ips", 1, 100_000),
];

/// `^[A-Za-z0-9_.-]{1,64}$` (`USERNAME_RE`, also the fleet resource's `runtime_username`).
pub fn is_username(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

pub const USERNAME_PATTERN: Str = Str::pattern("^[A-Za-z0-9_.-]{1,64}$", is_username);

const MAX_I63: i128 = (1 << 63) - 1;

fn strict_int(ge: i128, le: i128) -> impl Fn(&Value, &[LocItem], &mut Cx) -> Option<Option<i64>> {
    move |v, l, cx| nullable(v, l, cx, |v, l, cx| Int::strict(Some(ge), Some(le)).validate(v, l, cx))
}

fn optional_str(rule: Str) -> impl Fn(&Value, &[LocItem], &mut Cx) -> Option<Option<String>> {
    move |v, l, cx| nullable(v, l, cx, |v, l, cx| rule.validate(v, l, cx))
}

/// One Mieru quota: a window of days and a traffic allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruQuota {
    pub days: i64,
    pub megabytes: i64,
}

impl Model for MieruQuota {
    const TITLE: &'static str = "MieruQuota";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let days = f.required(cx, "days", |v, l, cx| Int::strict(Some(1), Some(3650)).validate(v, l, cx));
        let megabytes =
            f.required(cx, "megabytes", |v, l, cx| Int::strict(Some(1), Some((1 << 31) - 1)).validate(v, l, cx));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(MieruQuota { days: days?, megabytes: megabytes? })
    }

    fn dump(&self) -> Value {
        json!({"days": self.days, "megabytes": self.megabytes})
    }
}

/// Telemt's per-user limits (bounds from [`LIMIT_FIELDS`]) and where the runtime listens, learned
/// from the link Telemt returned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MtproxyOptions {
    pub data_quota_bytes: Option<i64>,
    pub rate_limit_up_bps: Option<i64>,
    pub rate_limit_down_bps: Option<i64>,
    pub max_tcp_conns: Option<i64>,
    pub max_unique_ips: Option<i64>,
    pub expiration: Option<i64>,
    pub host: Option<String>,
    pub port: Option<i64>,
}

impl Model for MtproxyOptions {
    const TITLE: &'static str = "MtproxyOptions";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let mut limits = Vec::with_capacity(LIMIT_FIELDS.len());
        for (name, low, high) in LIMIT_FIELDS {
            limits.push(f.optional(cx, name, || None, strict_int(*low, *high)));
        }
        let expiration = f.optional(cx, "expiration", || None, strict_int(0, MAX_I63));
        let host = f.optional(cx, "host", || None, optional_str(Str::len(1, 253)));
        let port = f.optional(cx, "port", || None, strict_int(1, 65535));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let mut limits = limits.into_iter();
        let mut next = || limits.next().flatten();
        Some(MtproxyOptions {
            data_quota_bytes: next()?,
            rate_limit_up_bps: next()?,
            rate_limit_down_bps: next()?,
            max_tcp_conns: next()?,
            max_unique_ips: next()?,
            expiration: expiration?,
            host: host?,
            port: port?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "data_quota_bytes": self.data_quota_bytes,
            "rate_limit_up_bps": self.rate_limit_up_bps,
            "rate_limit_down_bps": self.rate_limit_down_bps,
            "max_tcp_conns": self.max_tcp_conns,
            "max_unique_ips": self.max_unique_ips,
            "expiration": self.expiration,
            "host": self.host,
            "port": self.port,
        })
    }
}

/// NaiveProxy: an optional traffic quota.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NaiveOptions {
    pub quota_bytes: Option<i64>,
}

impl Model for NaiveOptions {
    const TITLE: &'static str = "NaiveOptions";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let quota_bytes = f.optional(cx, "quota_bytes", || None, strict_int(1, MAX_I63));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(NaiveOptions { quota_bytes: quota_bytes? })
    }

    fn dump(&self) -> Value {
        json!({"quota_bytes": self.quota_bytes})
    }
}

/// `^[a-z][a-z0-9+.-]*://(?P<credentials>[^@/]*)@` (`re.match`): the credentials part of a link,
/// if the template is shaped like one.
fn template_credentials(template: &str) -> Option<&str> {
    let first = template.chars().next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    let scheme_end = template
        .char_indices()
        .skip(1)
        .find(|(_, ch)| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || "+.-".contains(*ch)))
        .map_or(template.len(), |(index, _)| index);
    let rest = template[scheme_end..].strip_prefix("://")?;
    let end = rest.find(['@', '/']).unwrap_or(rest.len());
    rest[end..].starts_with('@').then(|| &rest[..end])
}

/// Mieru: quotas (none unless named) and the share template the node's mita publishes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MieruOptions {
    pub quotas: Vec<MieruQuota>,
    pub share_template: Option<String>,
}

impl MieruOptions {
    /// `template_holds_no_credential`: the placeholders, and no literal credential.
    pub fn check_template(template: &str) -> Result<(), &'static str> {
        if !template.contains("{username}") || !template.contains("{password}") {
            return Err("share_template must contain {username} and {password}");
        }
        if template_credentials(template).is_some_and(|credentials| credentials != "{username}:{password}") {
            return Err("share_template must carry placeholders, not a credential");
        }
        Ok(())
    }
}

impl Model for MieruOptions {
    const TITLE: &'static str = "MieruOptions";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let quotas = f.optional(cx, "quotas", Vec::new, |v, l, cx| list(v, l, cx, Some(16), MieruQuota::validate_at));
        let share_template = f.optional(
            cx,
            "share_template",
            || None,
            |v, l, cx| {
                let template = nullable(v, l, cx, |v, l, cx| Str::max(512).validate(v, l, cx))?;
                if let Some(Err(message)) = template.as_deref().map(Self::check_template) {
                    cx.push(value_error(l.to_vec(), v, message));
                    return None;
                }
                Some(template)
            },
        );
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(MieruOptions { quotas: quotas?, share_template: share_template? })
    }

    fn dump(&self) -> Value {
        json!({"quotas": self.quotas.iter().map(Model::dump).collect::<Vec<_>>(), "share_template": self.share_template})
    }
}

/// One AmneziaWG access: the operator's `version`, and what the node's manager taught at issue
/// time (address, port, server key, MTU, DNS, obfuscation), so a config rebuilt from escrow needs
/// no call to the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziawgOptions {
    pub version: AwgVersion,
    pub address: Option<String>,
    pub port: Option<i64>,
    pub server_public_key: Option<String>,
    pub mtu: Option<i64>,
    pub dns: Vec<String>,
    pub obfuscation: IndexMap<String, String>,
}

impl Default for AmneziawgOptions {
    fn default() -> Self {
        Self {
            version: AwgVersion::V2_0,
            address: None,
            port: None,
            server_public_key: None,
            mtu: None,
            dns: Vec::new(),
            obfuscation: IndexMap::new(),
        }
    }
}

impl Model for AmneziawgOptions {
    const TITLE: &'static str = "AmneziawgOptions";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let version =
            f.optional(cx, "version", || AwgVersion::V2_0, |v, l, cx| literal_enum(v, l, cx, &["1.5", "2.0", "3.1"]));
        let address = f.optional(
            cx,
            "address",
            || None,
            |v, l, cx| {
                let address = nullable(v, l, cx, |v, l, cx| Str::max(15).validate(v, l, cx))?;
                if let Some(Err(error)) = address.as_deref().map(net::ipv4_address) {
                    cx.push(value_error(l.to_vec(), v, error));
                    return None;
                }
                Some(address)
            },
        );
        let port = f.optional(cx, "port", || None, strict_int(1, 65535));
        let server_public_key = f.optional(cx, "server_public_key", || None, optional_str(Str::len(44, 44)));
        let mtu = f.optional(cx, "mtu", || None, strict_int(576, 1500));
        let dns = f.optional(cx, "dns", Vec::new, |v, l, cx| {
            let items = list(v, l, cx, Some(4), string)?;
            if let Some(error) = items.iter().find_map(|item| pytext::ip_address(item).err()) {
                cx.push(value_error(l.to_vec(), v, error));
                return None;
            }
            Some(items)
        });
        let obfuscation = f.optional(cx, "obfuscation", IndexMap::new, |v, l, cx| {
            let entries = dict_of(v, l, cx, None, str_key, string)?;
            if let Err(message) = check_obfuscation(&entries) {
                cx.push(value_error(l.to_vec(), v, message));
                return None;
            }
            Some(entries.into_iter().collect())
        });
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(AmneziawgOptions {
            version: version?,
            address: address?,
            port: port?,
            server_public_key: server_public_key?,
            mtu: mtu?,
            dns: dns?,
            obfuscation: obfuscation?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "version": self.version.as_str(),
            "address": self.address,
            "port": self.port,
            "server_public_key": self.server_public_key,
            "mtu": self.mtu,
            "dns": self.dns,
            "obfuscation": self.obfuscation.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>(),
        })
    }
}

/// `obfuscation_is_bounded`.
fn check_obfuscation(entries: &[(String, String)]) -> Result<(), String> {
    if entries.len() > AWG_OBFUSCATION_KEYS.len() {
        return Err("too many obfuscation parameters".into());
    }
    for (key, value) in entries {
        if !AWG_OBFUSCATION_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown obfuscation parameter {key}"));
        }
        if pytext::len(value) > 2048 || value.contains('\n') || value.contains('\r') {
            return Err(format!("invalid obfuscation parameter {key}"));
        }
    }
    Ok(())
}

/// `^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$` — without the trailing newline Python's `$`
/// also accepted (see DIFFERENCES.md).
pub fn is_hostname(text: &str) -> bool {
    let bytes = text.as_bytes();
    let edge = |b: u8| b.is_ascii_alphanumeric();
    match bytes.len() {
        0 => false,
        1 => edge(bytes[0]),
        len => {
            len <= 253
                && edge(bytes[0])
                && edge(bytes[len - 1])
                && bytes[1..len - 1].iter().all(|&b| edge(b) || b == b'.' || b == b'-')
        }
    }
}

/// `base64.b64decode(text, validate=True)` succeeds (CPython 3.13: strict mode — only the
/// alphabet, padding only at the end and only where a quad needs it).
pub fn is_strict_base64(text: &str) -> bool {
    let mut quad = 0u8;
    let mut pads = 0u8;
    let mut padding = false;
    let bytes = text.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'=' {
            padding = true;
            if quad == 0 {
                return false;
            }
            pads += 1;
            if quad >= 2 && quad + pads >= 4 {
                return index + 1 == bytes.len();
            }
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/') || padding {
            return false;
        }
        pads = 0;
        quad = (quad + 1) % 4;
    }
    quad == 0
}

/// One TrustTunnel access, learned from the node's manager at issue time (the TLS endpoint's
/// domain, the public port, a self-signed certificate in DER) plus the profile's label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrusttunnelOptions {
    pub hostname: Option<String>,
    pub port: Option<i64>,
    pub certificate_der_b64: Option<String>,
    pub name: Option<String>,
}

impl Model for TrusttunnelOptions {
    const TITLE: &'static str = "TrusttunnelOptions";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let hostname = f.optional(
            cx,
            "hostname",
            || None,
            |v, l, cx| {
                let host = nullable(v, l, cx, |v, l, cx| Str::max(253).validate(v, l, cx))?;
                if host.as_deref().is_some_and(|host| !is_hostname(host)) {
                    cx.push(value_error(l.to_vec(), v, "hostname must be a DNS name"));
                    return None;
                }
                Some(host)
            },
        );
        let port = f.optional(cx, "port", || None, strict_int(1, 65535));
        let certificate = f.optional(
            cx,
            "certificate_der_b64",
            || None,
            |v, l, cx| {
                let text = nullable(v, l, cx, |v, l, cx| Str::max(32768).validate(v, l, cx))?;
                if text.as_deref().is_some_and(|text| !is_strict_base64(text)) {
                    cx.push(value_error(l.to_vec(), v, "certificate_der_b64 must be base64"));
                    return None;
                }
                Some(text)
            },
        );
        let name = f.optional(cx, "name", || None, optional_str(Str::len(1, 64)));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(TrusttunnelOptions { hostname: hostname?, port: port?, certificate_der_b64: certificate?, name: name? })
    }

    fn dump(&self) -> Value {
        json!({
            "hostname": self.hostname,
            "port": self.port,
            "certificate_der_b64": self.certificate_der_b64,
            "name": self.name,
        })
    }
}

/// The options of one grant: exactly the model its protocol understands (`PROTOCOL_OPTIONS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOptions {
    Mtproxy(MtproxyOptions),
    Naive(NaiveOptions),
    Mieru(MieruOptions),
    Amneziawg(AmneziawgOptions),
    Trusttunnel(TrusttunnelOptions),
}

impl ProtocolOptions {
    /// The protocol whose model this is.
    pub fn protocol(&self) -> Protocol {
        match self {
            ProtocolOptions::Mtproxy(_) => Protocol::Mtproxy,
            ProtocolOptions::Naive(_) => Protocol::Naive,
            ProtocolOptions::Mieru(_) => Protocol::Mieru,
            ProtocolOptions::Amneziawg(_) => Protocol::Amneziawg,
            ProtocolOptions::Trusttunnel(_) => Protocol::Trusttunnel,
        }
    }

    /// The class name (`NaiveOptions`, …).
    pub fn model_name(protocol: Protocol) -> &'static str {
        match protocol {
            Protocol::Mtproxy => MtproxyOptions::TITLE,
            Protocol::Naive => NaiveOptions::TITLE,
            Protocol::Mieru => MieruOptions::TITLE,
            Protocol::Amneziawg => AmneziawgOptions::TITLE,
            Protocol::Trusttunnel => TrusttunnelOptions::TITLE,
        }
    }

    /// `PROTOCOL_OPTIONS[protocol]()`: the model with every default.
    pub fn default_for(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Mtproxy => ProtocolOptions::Mtproxy(MtproxyOptions::default()),
            Protocol::Naive => ProtocolOptions::Naive(NaiveOptions::default()),
            Protocol::Mieru => ProtocolOptions::Mieru(MieruOptions::default()),
            Protocol::Amneziawg => ProtocolOptions::Amneziawg(AmneziawgOptions::default()),
            Protocol::Trusttunnel => ProtocolOptions::Trusttunnel(TrusttunnelOptions::default()),
        }
    }

    /// `PROTOCOL_OPTIONS[protocol].model_validate(input)`.
    pub fn validate(protocol: Protocol, input: &Value) -> Result<Self, ValidationError> {
        Ok(match protocol {
            Protocol::Mtproxy => ProtocolOptions::Mtproxy(MtproxyOptions::validate(input)?),
            Protocol::Naive => ProtocolOptions::Naive(NaiveOptions::validate(input)?),
            Protocol::Mieru => ProtocolOptions::Mieru(MieruOptions::validate(input)?),
            Protocol::Amneziawg => ProtocolOptions::Amneziawg(AmneziawgOptions::validate(input)?),
            Protocol::Trusttunnel => ProtocolOptions::Trusttunnel(TrusttunnelOptions::validate(input)?),
        })
    }

    /// Validation at a location inside a larger model.
    pub fn validate_at(protocol: Protocol, input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        Some(match protocol {
            Protocol::Mtproxy => ProtocolOptions::Mtproxy(MtproxyOptions::validate_at(input, loc, cx)?),
            Protocol::Naive => ProtocolOptions::Naive(NaiveOptions::validate_at(input, loc, cx)?),
            Protocol::Mieru => ProtocolOptions::Mieru(MieruOptions::validate_at(input, loc, cx)?),
            Protocol::Amneziawg => ProtocolOptions::Amneziawg(AmneziawgOptions::validate_at(input, loc, cx)?),
            Protocol::Trusttunnel => ProtocolOptions::Trusttunnel(TrusttunnelOptions::validate_at(input, loc, cx)?),
        })
    }

    /// `options.model_dump()`.
    pub fn dump(&self) -> Value {
        match self {
            ProtocolOptions::Mtproxy(options) => options.dump(),
            ProtocolOptions::Naive(options) => options.dump(),
            ProtocolOptions::Mieru(options) => options.dump(),
            ProtocolOptions::Amneziawg(options) => options.dump(),
            ProtocolOptions::Trusttunnel(options) => options.dump(),
        }
    }

    /// `options.model_dump_json()` — what `access_grants.protocol_options_json` holds.
    pub fn dump_json(&self) -> String {
        panel_core::pyjson::pydantic(&self.dump())
    }

    /// The field names of this protocol's model (`type(options).model_fields`).
    pub fn field_names(protocol: Protocol) -> &'static [&'static str] {
        match protocol {
            Protocol::Mtproxy => &[
                "data_quota_bytes",
                "rate_limit_up_bps",
                "rate_limit_down_bps",
                "max_tcp_conns",
                "max_unique_ips",
                "expiration",
                "host",
                "port",
            ],
            Protocol::Naive => &["quota_bytes"],
            Protocol::Mieru => &["quotas", "share_template"],
            Protocol::Amneziawg => &["version", "address", "port", "server_public_key", "mtu", "dns", "obfuscation"],
            Protocol::Trusttunnel => &["hostname", "port", "certificate_der_b64", "name"],
        }
    }
}

wire_enum! {
    /// A client's lifecycle state.
    pub enum ClientState {
        Active => "active",
        Suspended => "suspended",
        Archived => "archived",
    }
}

wire_enum! {
    /// What the panel wants a grant to be.
    pub enum GrantDesiredState {
        Enabled => "enabled",
        Disabled => "disabled",
        Deleted => "deleted",
    }
}

wire_enum! {
    /// What the runtime last showed for a grant.
    pub enum GrantObservedState {
        Unknown => "unknown",
        Pending => "pending",
        Enabled => "enabled",
        Disabled => "disabled",
        Missing => "missing",
    }
}

wire_enum! {
    /// Whether the panel created the account or adopted one already running.
    pub enum GrantOrigin {
        Imported => "imported",
        Provisioned => "provisioned",
    }
}

/// A pattern of alternatives (`^(a|b|c)$`) as a literal-like check.
fn one_of(text: &str, choices: &[&str]) -> bool {
    choices.contains(&text)
}

fn pattern_enum<E: WireEnum>(
    pattern: &'static str,
    matcher: fn(&str) -> bool,
) -> impl Fn(&Value, &[LocItem], &mut Cx) -> Option<E> {
    move |v, l, cx| Str::pattern(pattern, matcher).validate(v, l, cx).map(|text| E::from_wire(&text).expect("pattern"))
}

/// A client: a person or device holding grants.
#[derive(Debug, Clone, PartialEq)]
pub struct Client {
    pub id: String,
    pub display_name: String,
    pub state: ClientState,
    pub metadata: Map<String, Value>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Model for Client {
    const TITLE: &'static str = "Client";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let id = f.required(cx, "id", string);
        let display_name = f.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        let state = f.required(
            cx,
            "state",
            pattern_enum("^(active|suspended|archived)$", |t| one_of(t, &["active", "suspended", "archived"])),
        );
        let metadata = f.optional(cx, "metadata", Map::new, dict);
        let created_at = f.required(cx, "created_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        let updated_at = f.required(cx, "updated_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(Client {
            id: id?,
            display_name: display_name?,
            state: state?,
            metadata: metadata?,
            created_at: created_at?,
            updated_at: updated_at?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "id": self.id,
            "display_name": self.display_name,
            "state": self.state.as_str(),
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

/// The issue `_ProtocolOptions.options_match_protocol` raises.
fn options_mismatch(protocol: Protocol, input: &Value, loc: &[LocItem]) -> ValidationIssue {
    value_error(loc.to_vec(), input, format!("{} requires {}", protocol, ProtocolOptions::model_name(protocol)))
}

/// Validates `protocol` (`^(mtproxy|naive|…)$`) and then `options` with that protocol's model.
fn protocol_and_options(f: &mut Fields<'_>, cx: &mut Cx) -> (Option<Protocol>, Option<ProtocolOptions>) {
    let protocol = f.required(
        cx,
        "protocol",
        pattern_enum("^(mtproxy|naive|mieru|amneziawg|trusttunnel)$", |t| one_of(t, PROTOCOLS)),
    );
    let options = f.required(cx, "options", |v, l, cx| match protocol {
        Some(protocol) => ProtocolOptions::validate_at(protocol, v, l, cx),
        // Without a valid protocol the options cannot be typed; pydantic would have tried every
        // model in turn (see DIFFERENCES.md) — the protocol's issue is the one reported.
        None => None,
    });
    (protocol, options)
}

/// What an operator asks for; the grant is what the panel then owns.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantIntent {
    pub protocol: Protocol,
    pub options: ProtocolOptions,
    pub node_id: String,
    pub endpoint_id: String,
    pub runtime_username: String,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

impl GrantIntent {
    /// `GrantIntent(protocol=, runtime_username=, options=)` with the defaults (`local`, `default`,
    /// no validity window), checked like the model.
    pub fn new(protocol: Protocol, runtime_username: &str, options: ProtocolOptions) -> Result<Self, ValidationError> {
        let intent = Self {
            protocol,
            options,
            node_id: "local".into(),
            endpoint_id: "default".into(),
            runtime_username: runtime_username.into(),
            valid_from: None,
            valid_until: None,
        };
        intent.check()?;
        Ok(intent)
    }

    /// The model's rules for an already-typed intent: the username pattern and options of the
    /// protocol's own model.
    pub fn check(&self) -> Result<(), ValidationError> {
        let mut cx = Cx::new(crate::validate::Entry::Python);
        let input = self.dump();
        let name = json!(self.runtime_username);
        USERNAME_PATTERN.check(&self.runtime_username, &name, &at(&[], "runtime_username"), &mut cx);
        if cx.count() == 0 && self.options.protocol() != self.protocol {
            cx.push(options_mismatch(self.protocol, &input, &[]));
        }
        finish_check(Self::TITLE, cx)
    }
}

fn finish_check(title: &'static str, cx: Cx) -> Result<(), ValidationError> {
    let issues = cx.into_issues();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(ValidationError { title, issues })
    }
}

fn optional_int(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<i64>> {
    nullable(input, loc, cx, |v, l, cx| Int::LAX.validate(v, l, cx))
}

impl Model for GrantIntent {
    const TITLE: &'static str = "GrantIntent";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let (protocol, options) = protocol_and_options(&mut f, cx);
        let node_id = f.optional(cx, "node_id", || "local".into(), string);
        let endpoint_id = f.optional(cx, "endpoint_id", || "default".into(), string);
        let runtime_username = f.required(cx, "runtime_username", |v, l, cx| USERNAME_PATTERN.validate(v, l, cx));
        let valid_from = f.optional(cx, "valid_from", || None, optional_int);
        let valid_until = f.optional(cx, "valid_until", || None, optional_int);
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(GrantIntent {
            protocol: protocol?,
            options: options?,
            node_id: node_id?,
            endpoint_id: endpoint_id?,
            runtime_username: runtime_username?,
            valid_from: valid_from?,
            valid_until: valid_until?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "protocol": self.protocol.as_str(),
            "options": self.options.dump(),
            "node_id": self.node_id,
            "endpoint_id": self.endpoint_id,
            "runtime_username": self.runtime_username,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        })
    }
}

/// One access a client holds: an account on one endpoint of one node, its credential by
/// reference.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessGrant {
    pub protocol: Protocol,
    pub options: ProtocolOptions,
    pub id: String,
    pub client_id: String,
    pub node_id: String,
    pub endpoint_id: String,
    pub runtime_username: String,
    pub secret_ref: Option<SecretRef>,
    pub desired_state: GrantDesiredState,
    pub observed_state: GrantObservedState,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub origin: GrantOrigin,
    /// `true` when the grant has its own routing lane on its node (`routing_lane = "own"`).
    pub own_lane: bool,
    /// The name this access carries in subscriptions; `None` = «node · protocol».
    pub label: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl AccessGrant {
    /// The model's rules for an already-typed grant (what constructing `AccessGrant(...)` checks
    /// beyond the types): the username pattern, the label's length and options of the protocol's
    /// own model.
    pub fn check(&self) -> Result<(), ValidationError> {
        let mut cx = Cx::new(crate::validate::Entry::Python);
        let name = json!(self.runtime_username);
        USERNAME_PATTERN.check(&self.runtime_username, &name, &at(&[], "runtime_username"), &mut cx);
        if let Some(label) = &self.label {
            Str::len(1, 64).check(label, &json!(label), &at(&[], "label"), &mut cx);
        }
        if cx.count() == 0 && self.options.protocol() != self.protocol {
            cx.push(options_mismatch(self.protocol, &self.dump(), &[]));
        }
        finish_check(Self::TITLE, cx)
    }

    /// `routing_lane` as stored: `"own"` or `None`.
    pub fn routing_lane(&self) -> Option<&'static str> {
        self.own_lane.then_some("own")
    }
}

fn secret_ref(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<SecretRef> {
    let mut f = Fields::open(input, loc, cx, "SecretRef")?;
    let secret_id = f.required(cx, "secret_id", string);
    let version = f.required(cx, "version", |v, l, cx| Int::LAX.validate(v, l, cx));
    if !f.finish(cx, Extra::Ignore) {
        return None;
    }
    Some(SecretRef { secret_id: secret_id?, version: version? })
}

impl Model for AccessGrant {
    const TITLE: &'static str = "AccessGrant";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let (protocol, options) = protocol_and_options(&mut f, cx);
        let id = f.required(cx, "id", string);
        let client_id = f.required(cx, "client_id", string);
        let node_id = f.required(cx, "node_id", string);
        let endpoint_id = f.optional(cx, "endpoint_id", || "default".into(), string);
        let runtime_username = f.required(cx, "runtime_username", |v, l, cx| USERNAME_PATTERN.validate(v, l, cx));
        let secret = f.optional(cx, "secret_ref", || None, |v, l, cx| nullable(v, l, cx, secret_ref));
        let desired_state = f.required(
            cx,
            "desired_state",
            pattern_enum("^(enabled|disabled|deleted)$", |t| one_of(t, &["enabled", "disabled", "deleted"])),
        );
        let observed_state = f.optional(
            cx,
            "observed_state",
            || GrantObservedState::Unknown,
            |v, l, cx| {
                pattern_enum("^(unknown|pending|enabled|disabled|missing)$", |t| {
                    one_of(t, &["unknown", "pending", "enabled", "disabled", "missing"])
                })(v, l, cx)
            },
        );
        let valid_from = f.optional(cx, "valid_from", || None, optional_int);
        let valid_until = f.optional(cx, "valid_until", || None, optional_int);
        let origin = f.required(
            cx,
            "origin",
            pattern_enum("^(imported|provisioned)$", |t| one_of(t, &["imported", "provisioned"])),
        );
        let routing_lane = f.optional(
            cx,
            "routing_lane",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Str::pattern("^own$", |t| t == "own").validate(v, l, cx)),
        );
        let label = f.optional(
            cx,
            "label",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Str::len(1, 64).validate(v, l, cx)),
        );
        let created_at = f.required(cx, "created_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        let updated_at = f.required(cx, "updated_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(AccessGrant {
            protocol: protocol?,
            options: options?,
            id: id?,
            client_id: client_id?,
            node_id: node_id?,
            endpoint_id: endpoint_id?,
            runtime_username: runtime_username?,
            secret_ref: secret?,
            desired_state: desired_state?,
            observed_state: observed_state?,
            valid_from: valid_from?,
            valid_until: valid_until?,
            origin: origin?,
            own_lane: routing_lane?.is_some(),
            label: label?,
            created_at: created_at?,
            updated_at: updated_at?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "protocol": self.protocol.as_str(),
            "options": self.options.dump(),
            "id": self.id,
            "client_id": self.client_id,
            "node_id": self.node_id,
            "endpoint_id": self.endpoint_id,
            "runtime_username": self.runtime_username,
            "secret_ref": self.secret_ref.as_ref().map(SecretRef::dump),
            "desired_state": self.desired_state.as_str(),
            "observed_state": self.observed_state.as_str(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "origin": self.origin.as_str(),
            "routing_lane": self.routing_lane(),
            "label": self.label,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

/// One place decides whether a grant is live right now — validity is not a state column.
pub fn effective_enabled(grant: &AccessGrant, client: &Client, now: i64) -> bool {
    client.state == ClientState::Active
        && grant.desired_state == GrantDesiredState::Enabled
        && within_validity(grant.valid_from, grant.valid_until, now)
}

/// The half-open window `[valid_from, valid_until)`, enforced by a node even without its central.
pub fn within_validity(valid_from: Option<i64>, valid_until: Option<i64>, now: i64) -> bool {
    valid_from.is_none_or(|from| from <= now) && valid_until.is_none_or(|until| now < until)
}

#[cfg(test)]
mod tests;
