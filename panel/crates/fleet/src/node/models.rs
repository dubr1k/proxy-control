//! The request models of the node routes (`fleet_v2/node_routes.py`), all `extra="forbid"`: a field
//! a strict node does not know is a 422, which is why a central omits what a node did not declare.

use panel_core::errors::LocItem;
use panel_model::clients::USERNAME_PATTERN;
use panel_model::fleet::CAPTURE_MAX_RESOURCES;
use panel_model::validate::{boolean, dict, list, literal, nullable, Cx, Extra, Fields, Int, Model, Str};
use serde_json::{json, Map, Value};

/// The protocols a node serves, in `Literal` order.
pub const PROTOCOLS: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];

/// One user to read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureItem {
    pub protocol: String,
    pub runtime_username: String,
}

impl Model for CaptureItem {
    const TITLE: &'static str = "CaptureItem";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let protocol = f.required(cx, "protocol", |v, l, cx| literal(v, l, cx, PROTOCOLS).map(str::to_string));
        let runtime_username = f.required(cx, "runtime_username", |v, l, cx| USERNAME_PATTERN.validate(v, l, cx));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(CaptureItem { protocol: protocol?, runtime_username: runtime_username? })
    }

    fn dump(&self) -> Value {
        json!({"protocol": self.protocol, "runtime_username": self.runtime_username})
    }
}

/// `POST /api/fleet/v2/credentials/capture`. `escrow` (the default) reveals only users this central
/// already owns here; `import` is the operator's explicit adoption of the node's own users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub resources: Vec<CaptureItem>,
    pub purpose: String,
}

impl Model for CaptureRequest {
    const TITLE: &'static str = "CaptureRequest";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let resources = f.required(cx, "resources", |v, l, cx| {
            list(v, l, cx, Some(CAPTURE_MAX_RESOURCES), CaptureItem::validate_at)
        });
        let purpose = f.optional(
            cx,
            "purpose",
            || "escrow".to_string(),
            |v, l, cx| literal(v, l, cx, &["escrow", "import"]).map(str::to_string),
        );
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(CaptureRequest { resources: resources?, purpose: purpose? })
    }

    fn dump(&self) -> Value {
        json!({"resources": self.resources.iter().map(Model::dump).collect::<Vec<_>>(), "purpose": self.purpose})
    }
}

/// Where the router's geodata comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeodataSource {
    pub kind: String,
    pub geosite_url: Option<String>,
    pub geoip_url: Option<String>,
}

fn optional_url(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<String>> {
    nullable(input, loc, cx, |v, l, cx| Str::max(1024).validate(v, l, cx))
}

impl Model for GeodataSource {
    const TITLE: &'static str = "GeodataSource";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let kind = f.required(cx, "kind", |v, l, cx| {
            literal(v, l, cx, &["xray", "loyalsoldier", "runetfreedom", "iran", "v2fly", "custom"]).map(str::to_string)
        });
        let geosite_url = f.optional(cx, "geosite_url", || None, optional_url);
        let geoip_url = f.optional(cx, "geoip_url", || None, optional_url);
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(GeodataSource { kind: kind?, geosite_url: geosite_url?, geoip_url: geoip_url? })
    }

    fn dump(&self) -> Value {
        json!({"kind": self.kind, "geosite_url": self.geosite_url, "geoip_url": self.geoip_url})
    }
}

/// `PUT /api/fleet/v2/geodata/settings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeodataSettings {
    pub source: Option<GeodataSource>,
    pub auto_update: Option<bool>,
    pub interval_hours: Option<i64>,
    pub update_hour: Option<i64>,
    /// `"update_hour" in model_fields_set`: an explicit `null` is forwarded.
    pub update_hour_set: bool,
}

impl GeodataSettings {
    /// `forwarded()`: `model_dump(exclude_none=True)`, plus `update_hour` when it was given.
    pub fn forwarded(&self) -> Map<String, Value> {
        let mut body = Map::new();
        if let Some(source) = &self.source {
            let mut dumped = Map::new();
            dumped.insert("kind".into(), json!(source.kind));
            if let Some(url) = &source.geosite_url {
                dumped.insert("geosite_url".into(), json!(url));
            }
            if let Some(url) = &source.geoip_url {
                dumped.insert("geoip_url".into(), json!(url));
            }
            body.insert("source".into(), Value::Object(dumped));
        }
        if let Some(flag) = self.auto_update {
            body.insert("auto_update".into(), json!(flag));
        }
        if let Some(hours) = self.interval_hours {
            body.insert("interval_hours".into(), json!(hours));
        }
        if self.update_hour.is_some() || self.update_hour_set {
            body.insert("update_hour".into(), json!(self.update_hour));
        }
        body
    }
}

impl Model for GeodataSettings {
    const TITLE: &'static str = "GeodataSettings";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let source = f.optional(cx, "source", || None, |v, l, cx| nullable(v, l, cx, GeodataSource::validate_at));
        let auto_update = f.optional(cx, "auto_update", || None, |v, l, cx| nullable(v, l, cx, boolean));
        let interval_hours = f.optional(
            cx,
            "interval_hours",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Int::lax(Some(1), Some(336)).validate(v, l, cx)),
        );
        let update_hour_set = input.as_object().is_some_and(|map| map.contains_key("update_hour"));
        let update_hour = f.optional(
            cx,
            "update_hour",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Int::lax(Some(0), Some(23)).validate(v, l, cx)),
        );
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(GeodataSettings {
            source: source?,
            auto_update: auto_update?,
            interval_hours: interval_hours?,
            update_hour: update_hour?,
            update_hour_set,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "source": self.source.as_ref().map(Model::dump),
            "auto_update": self.auto_update,
            "interval_hours": self.interval_hours,
            "update_hour": self.update_hour,
        })
    }
}

/// `POST /api/fleet/v2/exits/test {"exit": spec}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExitTestRequest {
    pub exit: Map<String, Value>,
}

impl Model for ExitTestRequest {
    const TITLE: &'static str = "ExitTestRequest";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let exit = f.required(cx, "exit", dict);
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(ExitTestRequest { exit: exit? })
    }

    fn dump(&self) -> Value {
        json!({"exit": self.exit})
    }
}

/// `^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$` (`schemas.VersionUpdate`).
pub fn is_version(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && text.chars().count() <= 64
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | ':' | '-'))
}

const VERSION_PATTERN: Str = Str::pattern("^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$", is_version);

/// `POST /api/fleet/v2/versions/update`: `VersionUpdate` (`version`, `expected_current`) plus the
/// component, in that field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionUpdateRequest {
    pub version: String,
    pub expected_current: Option<String>,
    pub component: String,
}

impl Model for VersionUpdateRequest {
    const TITLE: &'static str = "VersionUpdateRequest";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let version = f.required(cx, "version", |v, l, cx| VERSION_PATTERN.validate(v, l, cx));
        let expected_current = f.optional(
            cx,
            "expected_current",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| VERSION_PATTERN.validate(v, l, cx)),
        );
        let component = f.required(cx, "component", |v, l, cx| {
            literal(v, l, cx, &["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"])
                .map(str::to_string)
        });
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(VersionUpdateRequest { version: version?, expected_current: expected_current?, component: component? })
    }

    fn dump(&self) -> Value {
        json!({"version": self.version, "expected_current": self.expected_current, "component": self.component})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_requests_default_to_escrow_and_refuse_unknown_fields() {
        let body = json!({"resources": [{"protocol": "naive", "runtime_username": "bob"}]});
        let request = CaptureRequest::validate_body(&body).unwrap();
        assert_eq!(request.purpose, "escrow");
        assert!(CaptureRequest::validate_body(&json!({"resources": [], "purpose": "steal"})).is_err());
        assert!(CaptureRequest::validate_body(&json!({"resources": [], "extra": 1})).is_err());
        let many: Vec<Value> =
            (0..201).map(|i| json!({"protocol": "naive", "runtime_username": format!("u{i}")})).collect();
        assert!(CaptureRequest::validate_body(&json!({"resources": many})).is_err());
    }

    #[test]
    fn geodata_settings_forward_an_explicit_null_hour_only() {
        let settings =
            GeodataSettings::validate_body(&json!({"source": {"kind": "xray"}, "update_hour": null})).unwrap();
        assert_eq!(Value::Object(settings.forwarded()), json!({"source": {"kind": "xray"}, "update_hour": null}));
        let settings = GeodataSettings::validate_body(&json!({"interval_hours": 24})).unwrap();
        assert_eq!(Value::Object(settings.forwarded()), json!({"interval_hours": 24}));
        assert!(GeodataSettings::validate_body(&json!({"interval_hours": 337})).is_err());
        assert!(GeodataSettings::validate_body(&json!({"update_hour": 24})).is_err());
    }

    #[test]
    fn version_updates_follow_the_pattern_and_the_components() {
        let ok = json!({"component": "telemt", "version": "3.4.25", "expected_current": null});
        assert_eq!(VersionUpdateRequest::validate_body(&ok).unwrap().component, "telemt");
        for bad in [
            json!({"component": "nginx", "version": "1"}),
            json!({"component": "telemt", "version": "-1"}),
            json!({"component": "telemt", "version": "1", "surprise": true}),
        ] {
            assert!(VersionUpdateRequest::validate_body(&bad).is_err(), "{bad}");
        }
        assert!(is_version("a") && is_version(&"a".repeat(64)) && !is_version(&"a".repeat(65)));
    }
}
