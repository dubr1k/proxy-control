//! `panel/routing/routes.py` (row 17): engine-neutral policies, router targets, lanes,
//! relays, custom exits, presets and geodata. Reads are signed-in, previews allow every role,
//! and every mutation is owner-only.

use axum::extract::State;
use panel_clients::AuditContext;
use panel_core::errors::LocItem;
use panel_model::routing::document::redact_document;
use panel_model::routing::models::{PolicyInput, RoutingPolicy, LANE_SERVICE};
use panel_model::validate::{boolean, literal, nullable, Cx, Entry, Extra, Fields, Int, Model, Str};
use panel_routing::error::{blocking, RoutingFailure};
use panel_routing::exits::ExitInput;
use panel_routing::lanes::{LaneService, DEFAULT_RELAY_PORT};
use panel_routing::presets;
use panel_routing::service::{RoutingOutcome, RoutingService};
use serde_json::{json, Map, Value};

use crate::auth::Principal;
use crate::http::request::{BodyInput, Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

const ANYONE: &[&str] = &["owner", "admin", "viewer"];
const OWNER: &[&str] = &["owner"];
const LANE_PATTERN: &str = "^(svc|grant:[A-Za-z0-9_-]{1,64})$";

/// The routes in `register_routing_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/routing/targets", targets)
        .get("/api/routing/policies/{node_id}/{protocol}", get_policy)
        .put("/api/routing/policies/{node_id}/{protocol}", put_policy)
        .delete("/api/routing/policies/{node_id}/{protocol}", delete_policy)
        .post("/api/routing/policies/{node_id}/{protocol}/preview", preview)
        .post("/api/routing/policies/{node_id}/{protocol}/apply", apply)
        .post("/api/routing/policies/{node_id}/{protocol}/rollback", rollback)
        .get("/api/routing/policies/{node_id}/{protocol}/history", history)
        .post("/api/routing/policies/{node_id}/{protocol}/explain", explain)
        .post("/api/routing/relay/{node_id}/enable", relay_enable)
        .post("/api/routing/relay/{node_id}/rotate", relay_rotate)
        .post("/api/routing/lanes/{grant_id}", grant_lane)
        .get("/api/routing/exits", exits_list)
        .post("/api/routing/exits", exits_create)
        .post("/api/routing/exits/import", exits_import)
        .put("/api/routing/exits/{exit_id}", exits_update)
        .post("/api/routing/exits/{exit_id}/test", exits_test)
        .post("/api/routing/exits/{exit_id}/{action}", exits_action)
        .get("/api/routing/presets", routing_presets)
        .get("/api/routing/geodata", geodata_view)
        .get("/api/routing/geodata/codes", geodata_codes)
        .put("/api/routing/geodata/settings", geodata_settings)
        .post("/api/routing/geodata/{action}", geodata_action)
        .post("/api/routing/targets/{node_id}/{protocol}/attach", attach)
        .post("/api/routing/targets/{node_id}/{protocol}/detach", detach)
}

// -- request models ---------------------------------------------------------------------------

fn without(input: &Value, field: &str) -> Value {
    let mut value = input.clone();
    if let Value::Object(map) = &mut value {
        map.shift_remove(field);
    }
    value
}

pub struct PolicyPut {
    draft: PolicyInput,
    expected_revision: Option<i64>,
}

impl Model for PolicyPut {
    const TITLE: &'static str = "PolicyPut";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let draft = PolicyInput::validate_at(&without(input, "expected_revision"), loc, cx);
        let expected_revision = fields.optional(
            cx,
            "expected_revision",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| Int::lax(Some(0), None).validate(value, loc, cx))
            },
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { draft: draft?, expected_revision: expected_revision? })
    }

    fn dump(&self) -> Value {
        let mut value = self.draft.dump();
        value["expected_revision"] = json!(self.expected_revision);
        value
    }
}

pub struct RevisionBody {
    expected_revision: i64,
}

impl Model for RevisionBody {
    const TITLE: &'static str = "RevisionBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let expected_revision =
            fields.required(cx, "expected_revision", |value, loc, cx| Int::lax(Some(1), None).validate(value, loc, cx));
        fields.finish(cx, Extra::Forbid).then_some(())?;
        Some(Self { expected_revision: expected_revision? })
    }

    fn dump(&self) -> Value {
        json!({"expected_revision": self.expected_revision})
    }
}

pub struct ExplainBody {
    host: String,
    port: i64,
}

impl Model for ExplainBody {
    const TITLE: &'static str = "ExplainBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let host = fields.required(cx, "host", |value, loc, cx| Str::len(1, 253).validate(value, loc, cx));
        let port = fields.optional(
            cx,
            "port",
            || 443,
            |value, loc, cx| Int::lax(Some(1), Some(65535)).validate(value, loc, cx),
        );
        fields.finish(cx, Extra::Forbid).then_some(())?;
        Some(Self { host: host?, port: port? })
    }

    fn dump(&self) -> Value {
        json!({"host": self.host, "port": self.port})
    }
}

pub struct RelayEnableBody {
    port: i64,
}

impl Model for RelayEnableBody {
    const TITLE: &'static str = "RelayEnableBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let port = fields.optional(
            cx,
            "port",
            || DEFAULT_RELAY_PORT,
            |value, loc, cx| Int::lax(Some(1024), Some(65535)).validate(value, loc, cx),
        );
        fields.finish(cx, Extra::Forbid).then_some(())?;
        Some(Self { port: port? })
    }

    fn dump(&self) -> Value {
        json!({"port": self.port})
    }
}

#[derive(Clone)]
pub struct GeodataSourceBody {
    kind: String,
    geosite_url: Option<String>,
    geoip_url: Option<String>,
}

impl GeodataSourceBody {
    fn forwarded(&self) -> Value {
        let mut body = Map::new();
        body.insert("kind".into(), json!(self.kind));
        if let Some(value) = &self.geosite_url {
            body.insert("geosite_url".into(), json!(value));
        }
        if let Some(value) = &self.geoip_url {
            body.insert("geoip_url".into(), json!(value));
        }
        Value::Object(body)
    }
}

impl Model for GeodataSourceBody {
    const TITLE: &'static str = "GeodataSourceBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let kind = fields.required(cx, "kind", |value, loc, cx| {
            literal(value, loc, cx, &["xray", "loyalsoldier", "runetfreedom", "iran", "v2fly", "custom"])
                .map(str::to_string)
        });
        let geosite_url = fields.optional(
            cx,
            "geosite_url",
            || None,
            |value, loc, cx| nullable(value, loc, cx, |value, loc, cx| Str::max(1024).validate(value, loc, cx)),
        );
        let geoip_url = fields.optional(
            cx,
            "geoip_url",
            || None,
            |value, loc, cx| nullable(value, loc, cx, |value, loc, cx| Str::max(1024).validate(value, loc, cx)),
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { kind: kind?, geosite_url: geosite_url?, geoip_url: geoip_url? })
    }

    fn dump(&self) -> Value {
        json!({"kind": self.kind, "geosite_url": self.geosite_url, "geoip_url": self.geoip_url})
    }
}

pub struct GeodataSettingsBody {
    source: Option<GeodataSourceBody>,
    auto_update: Option<bool>,
    interval_hours: Option<i64>,
    update_hour: Option<i64>,
    update_hour_set: bool,
}

impl GeodataSettingsBody {
    fn forwarded(&self) -> Map<String, Value> {
        let mut body = Map::new();
        if let Some(source) = &self.source {
            body.insert("source".into(), source.forwarded());
        }
        if let Some(value) = self.auto_update {
            body.insert("auto_update".into(), json!(value));
        }
        if let Some(value) = self.interval_hours {
            body.insert("interval_hours".into(), json!(value));
        }
        if self.update_hour_set {
            body.insert("update_hour".into(), json!(self.update_hour));
        }
        body
    }
}

impl Model for GeodataSettingsBody {
    const TITLE: &'static str = "GeodataSettingsBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let source = fields.optional(
            cx,
            "source",
            || None,
            |value, loc, cx| nullable(value, loc, cx, GeodataSourceBody::validate_at),
        );
        let auto_update =
            fields.optional(cx, "auto_update", || None, |value, loc, cx| nullable(value, loc, cx, boolean));
        let interval_hours = fields.optional(
            cx,
            "interval_hours",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| Int::lax(Some(1), Some(336)).validate(value, loc, cx))
            },
        );
        let update_hour_set = input.as_object().is_some_and(|body| body.contains_key("update_hour"));
        let update_hour = fields.optional(
            cx,
            "update_hour",
            || None,
            |value, loc, cx| {
                nullable(value, loc, cx, |value, loc, cx| Int::lax(Some(0), Some(23)).validate(value, loc, cx))
            },
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            source: source?,
            auto_update: auto_update?,
            interval_hours: interval_hours?,
            update_hour: update_hour?,
            update_hour_set,
        })
    }

    fn dump(&self) -> Value {
        json!({"source": self.source.as_ref().map(Model::dump), "auto_update": self.auto_update,
               "interval_hours": self.interval_hours, "update_hour": self.update_hour})
    }
}

pub struct ExitImportBody {
    node_id: String,
    link: String,
    name: Option<String>,
}

impl Model for ExitImportBody {
    const TITLE: &'static str = "ExitImportBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let node_id = fields.required(cx, "node_id", |value, loc, cx| Str::len(1, 64).validate(value, loc, cx));
        let link = fields.required(cx, "link", |value, loc, cx| Str::len(1, 4096).validate(value, loc, cx));
        let name = fields.optional(
            cx,
            "name",
            || None,
            |value, loc, cx| nullable(value, loc, cx, |value, loc, cx| Str::max(48).validate(value, loc, cx)),
        );
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { node_id: node_id?, link: link?, name: name? })
    }

    fn dump(&self) -> Value {
        json!({"node_id": self.node_id, "link": self.link, "name": self.name})
    }
}

pub struct ExitCreateBody {
    node_id: String,
    data: ExitInput,
}

impl Model for ExitCreateBody {
    const TITLE: &'static str = "ExitCreateBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let data = ExitInput::validate_at(&without(input, "node_id"), loc, cx);
        let node_id = fields.required(cx, "node_id", |value, loc, cx| Str::len(1, 64).validate(value, loc, cx));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { node_id: node_id?, data: data? })
    }

    fn dump(&self) -> Value {
        let mut value = self.data.dump();
        value["node_id"] = json!(self.node_id);
        value
    }
}

fn lane_mode(text: &str) -> bool {
    matches!(text, "service" | "own")
}

pub struct LaneModeBody {
    mode: String,
}

impl Model for LaneModeBody {
    const TITLE: &'static str = "LaneModeBody";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let mode = fields
            .required(cx, "mode", |value, loc, cx| Str::pattern("^(service|own)$", lane_mode).validate(value, loc, cx));
        fields.finish(cx, Extra::Forbid).then_some(())?;
        Some(Self { mode: mode? })
    }

    fn dump(&self) -> Value {
        json!({"mode": self.mode})
    }
}

// -- request helpers --------------------------------------------------------------------------

fn service(app: &AppState) -> RoutingService {
    app.service::<RoutingService>().clone()
}

fn lanes(app: &AppState) -> LaneService {
    app.service::<LaneService>().clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

fn failed(error: RoutingFailure) -> Failure {
    match error.app_error() {
        Some(answer) => Failure::from(answer),
        None => Failure::internal(error),
    }
}

fn policy_view(policy: &RoutingPolicy) -> Value {
    let mut view = policy.dump();
    view["applied_current"] = json!(policy.applied_current());
    view
}

fn lane_is_valid(text: &str) -> bool {
    if text == LANE_SERVICE {
        return true;
    }
    let Some(id) = text.strip_prefix("grant:") else { return false };
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn lane(call: &Call, issues: &mut Issues) -> Option<String> {
    match call.query("lane") {
        None => Some(LANE_SERVICE.to_string()),
        Some(text) => {
            let mut cx = Cx::new(Entry::Body);
            let lane = Str { min: None, max: Some(72), pattern: Some((LANE_PATTERN, lane_is_valid)) }.validate(
                &Value::String(text),
                &["query".into(), "lane".into()],
                &mut cx,
            );
            for issue in cx.into_issues() {
                issues.push(issue);
            }
            lane
        }
    }
}

fn optional_body<M: Model>(input: &BodyInput, issues: &mut Issues) -> Option<Option<M>> {
    match input {
        BodyInput::Missing | BodyInput::Json(Value::Null) => Some(None),
        _ => issues.body::<M>(input).map(Some),
    }
}

fn outcome(result: RoutingOutcome) -> Value {
    let applied = result.applied.map(|applied| {
        json!({"revision": applied.revision, "digest": applied.digest,
               "readback_sha256": applied.readback_sha256, "replayed": applied.replayed})
    });
    json!({"policy": policy_view(&result.policy), "applied": applied, "compiled": result.compiled.redacted()})
}

// -- policy handlers --------------------------------------------------------------------------

async fn targets(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let items = service(&app).targets().await.map_err(failed)?;
    Ok(response::json(200, &json!({"items": items})))
}

async fn get_policy(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    issues.finish()?;
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    let policy = blocking(move || service.get(&node_id, &protocol, &lane.expect("validated"))).await.map_err(failed)?;
    Ok(response::json(200, &policy_view(&policy)))
}

async fn put_policy(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    let body = issues.body::<PolicyPut>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let context = audit_context(&user, &call);
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    let policy = blocking(move || {
        service.save(&node_id, &protocol, &body.draft, body.expected_revision, &lane.expect("validated"), &context)
    })
    .await
    .map_err(failed)?;
    Ok(response::json(200, &policy_view(&policy)))
}

async fn delete_policy(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    blocking(move || service.delete(&node_id, &protocol, &lane.expect("validated"), &context)).await.map_err(failed)?;
    Ok(response::empty(204))
}

async fn preview(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    app.roles(&call, ANYONE).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    let draft = optional_body::<PolicyInput>(&input, &mut issues);
    issues.finish()?;
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    let compiled = service
        .preview(&node_id, &protocol, draft.expect("validated"), &lane.expect("validated"))
        .await
        .map_err(failed)?;
    Ok(response::json(200, &compiled.redacted()))
}

async fn apply(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    let body = issues.body::<RevisionBody>(&input);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let result = service(&app)
        .apply(
            call.param("node_id"),
            call.param("protocol"),
            body.expect("validated").expected_revision,
            &lane.expect("validated"),
            &context,
        )
        .await
        .map_err(failed)?;
    Ok(response::json(200, &outcome(result)))
}

async fn rollback(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    let body = issues.body::<RevisionBody>(&input);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let result = service(&app)
        .rollback(
            call.param("node_id"),
            call.param("protocol"),
            body.expect("validated").expected_revision,
            &lane.expect("validated"),
            &context,
        )
        .await
        .map_err(failed)?;
    Ok(response::json(200, &outcome(result)))
}

async fn history(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    issues.finish()?;
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    let mut items =
        blocking(move || service.history(&node_id, &protocol, &lane.expect("validated"))).await.map_err(failed)?;
    for row in &mut items {
        let document = row.get("document").cloned().unwrap_or(Value::Null);
        row.insert("document".into(), redact_document(&document));
    }
    Ok(response::json(200, &json!({"items": items})))
}

async fn explain(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    app.roles(&call, ANYONE).await?;
    let mut issues = Issues::new();
    let lane = lane(&call, &mut issues);
    let body = issues.body::<ExplainBody>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let (service, node_id, protocol) =
        (service(&app), call.param("node_id").to_string(), call.param("protocol").to_string());
    let answer = blocking(move || {
        service.explain_destination(&node_id, &protocol, &body.host, body.port, &lane.expect("validated"))
    })
    .await
    .map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

// -- relays, lanes and targets ----------------------------------------------------------------

async fn relay_enable(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = optional_body::<RelayEnableBody>(&input, &mut issues);
    issues.finish()?;
    let port = body.expect("validated").map_or(DEFAULT_RELAY_PORT, |body| body.port);
    let context = audit_context(&user, &call);
    let answer = service(&app).relay_enable(call.param("node_id"), port, &context).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn relay_rotate(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let context = audit_context(&user, &call);
    let answer = service(&app).relay_rotate(call.param("node_id"), &context).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn grant_lane(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<LaneModeBody>(&input);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let lanes = lanes(&app);
    let answer = if body.expect("validated").mode == "own" {
        lanes.enable(call.param("grant_id"), &context).await
    } else {
        lanes.disable(call.param("grant_id"), &context).await
    }
    .map_err(failed)?;
    Ok(response::json(200, &answer))
}

async fn attach(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let context = audit_context(&user, &call);
    let target = service(&app).attach(call.param("node_id"), call.param("protocol"), &context).await.map_err(failed)?;
    Ok(response::json(200, &json!({"target": target})))
}

async fn detach(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let context = audit_context(&user, &call);
    let target = service(&app).detach(call.param("node_id"), call.param("protocol"), &context).await.map_err(failed)?;
    Ok(response::json(200, &json!({"target": target})))
}

// -- custom exits -----------------------------------------------------------------------------

async fn exits_list(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let node = call.query("node").unwrap_or_else(|| "local".into());
    let service = service(&app);
    let items = blocking(move || service.list_exits(&node)).await.map_err(failed)?;
    Ok(response::json(200, &json!({"items": items})))
}

async fn exits_create(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ExitCreateBody>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let context = audit_context(&user, &call);
    let service = service(&app);
    let answer =
        blocking(move || service.create_exit(&body.node_id, &body.data, &context, false)).await.map_err(failed)?;
    Ok(response::json(201, &Value::Object(answer)))
}

async fn exits_import(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ExitImportBody>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let context = audit_context(&user, &call);
    let service = service(&app);
    let answer = blocking(move || service.import_exit(&body.node_id, &body.link, body.name.as_deref(), &context))
        .await
        .map_err(failed)?;
    Ok(response::json(201, &Value::Object(answer)))
}

async fn exits_update(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ExitInput>(&input);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let service = service(&app);
    let exit_id = call.param("exit_id").to_string();
    let answer =
        blocking(move || service.update_exit(&exit_id, &body.expect("validated"), &context)).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn exits_test(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let context = audit_context(&user, &call);
    let answer = service(&app).test_exit(call.param("exit_id"), &context).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn exits_action(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let action = literal(
        &Value::String(call.param("action").to_string()),
        &["path".into(), "action".into()],
        &mut cx,
        &["enable", "disable", "delete"],
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let context = audit_context(&user, &call);
    let service = service(&app);
    let exit_id = call.param("exit_id").to_string();
    let action = action.expect("validated").to_string();
    let answer = match blocking({
        let service = service.clone();
        let exit_id = exit_id.clone();
        let context = context.clone();
        let action = action.clone();
        move || service.exit_action(&exit_id, &action, &context)
    })
    .await
    {
        Ok(answer) => answer,
        Err(RoutingFailure::Refused(reason)) if reason.code == "exit_in_use" => {
            let used_by = blocking(move || service.exit_usage(&exit_id)).await.map_err(failed)?;
            return Ok(response::json(409, &json!({"detail": reason.detail, "code": reason.code, "used_by": used_by})));
        }
        Err(error) => return Err(failed(error)),
    };
    Ok(response::json(200, &Value::Object(answer)))
}

// -- presets and geodata ----------------------------------------------------------------------

async fn routing_presets(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    Ok(response::json(200, &json!({"items": presets::presets()})))
}

async fn geodata_view(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let node = call.query("node").unwrap_or_else(|| "local".into());
    let answer = service(&app).geodata(&node, "view", None, None).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn geodata_codes(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let node = call.query("node").unwrap_or_else(|| "local".into());
    let answer = service(&app).geodata(&node, "codes", None, None).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn geodata_settings(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GeodataSettingsBody>(&input);
    issues.finish()?;
    let context = audit_context(&user, &call);
    let node = call.query("node").unwrap_or_else(|| "local".into());
    let forwarded = body.expect("validated").forwarded();
    let answer = service(&app).geodata(&node, "settings", Some(&forwarded), Some(&context)).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

async fn geodata_action(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let action = literal(
        &Value::String(call.param("action").to_string()),
        &["path".into(), "action".into()],
        &mut cx,
        &["update", "restore"],
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let context = audit_context(&user, &call);
    let node = call.query("node").unwrap_or_else(|| "local".into());
    let answer =
        service(&app).geodata(&node, action.expect("validated"), None, Some(&context)).await.map_err(failed)?;
    Ok(response::json(200, &Value::Object(answer)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse as _;
    use panel_managers::{Manager, ManagerError, TelemtError};
    use panel_model::Protocol;
    use panel_protocols::error::{crash, raw_manager, raw_telemt};

    #[tokio::test]
    async fn escaped_manager_errors_keep_protocol_http_answers() {
        for (protocol, manager, detail) in [
            (Protocol::Naive, Manager::Naive, "NaiveProxy manager unavailable"),
            (Protocol::Mieru, Manager::Mieru, "Mieru manager unavailable"),
            (Protocol::Amneziawg, Manager::Amneziawg, "AmneziaWG manager unavailable"),
            (Protocol::Trusttunnel, Manager::Trusttunnel, "TrustTunnel manager unavailable"),
        ] {
            let error = raw_manager(ManagerError::new(manager, "private upstream message", 422, None));
            let answer = failed(RoutingFailure::manager(protocol, error)).into_response();
            assert_eq!(answer.status(), 422);
            let body = axum::body::to_bytes(answer.into_body(), usize::MAX).await.unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"detail": detail}));
        }
        let error = raw_manager(ManagerError::new(Manager::Naive, "quota", 409, Some("quota_exhausted")));
        let answer = failed(RoutingFailure::manager(Protocol::Naive, error)).into_response();
        assert_eq!(answer.status(), 409);
        let body = axum::body::to_bytes(answer.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({
                "detail": "Quota exhausted: reset traffic or raise the quota first", "code": "quota_exhausted"
            })
        );
        let error = raw_telemt(TelemtError::indeterminate("lost reply"));
        let answer = failed(RoutingFailure::manager(Protocol::Mtproxy, error)).into_response();
        assert_eq!(answer.status(), 502);
        let body = axum::body::to_bytes(answer.into_body(), usize::MAX).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"detail":"Telemt service unavailable"}));
    }

    #[tokio::test]
    async fn actual_crashes_and_unhandled_router_errors_stay_bare_500() {
        for error in [
            RoutingFailure::manager(Protocol::Naive, crash("malformed manager answer")),
            RoutingFailure::Adapter(raw_manager(ManagerError::plain(Manager::XrayRouter, "unhandled"))),
            RoutingFailure::internal("database crashed"),
        ] {
            let answer = failed(error).into_response();
            assert_eq!(answer.status(), 500);
            assert_eq!(answer.headers()["content-type"], "text/plain; charset=utf-8");
            let body = axum::body::to_bytes(answer.into_body(), usize::MAX).await.unwrap();
            assert_eq!(body, "Internal Server Error");
        }
    }
}
