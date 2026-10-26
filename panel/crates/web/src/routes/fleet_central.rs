//! `fleet_v2/central_routes.py` (row 4): the owner/admin API for linked panels.
//!
//! The domain lives in `panel-fleet-central`; this module performs FastAPI-compatible validation,
//! gates and error rendering, and wires the central services and delivery loop.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use panel_clients::hooks::PublishForClient;
use panel_clients::AuditContext;
use panel_core::errors::{ApiError, ValidationIssue};
use panel_fleet::central::FINGERPRINT_TIMEOUT;
use panel_fleet_central::client::{fingerprint, validate_panel_url, NodeHttpFactory};
use panel_fleet_central::generations::{DesiredStore, PublishService};
use panel_fleet_central::importing::{FleetImporter, ImportItem};
use panel_fleet_central::links::{LinkUpdate, NodeLinkService};
use panel_fleet_central::metrics_source::FleetMetricsSource;
use panel_fleet_central::pusher::{FleetPusher, PusherOptions};
use panel_fleet_central::CentralError;
use panel_model::clients::USERNAME_PATTERN;
use panel_model::validate::{boolean, list, literal, nullable, Cx, Extra, Fields, Model, Str};
use panel_model::seams::NodeError;
use panel_model::Protocol;
use panel_nodes::read_model::view_to_value;
use panel_nodes::NodeLifecycleService;
use serde_json::{json, Map, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::lifespan::{BackgroundLoop, BoxFuture, StopSignal};
use crate::state::{AppState, Core, Services};

const PROTOCOLS: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];
const VERSION: Str = Str::pattern("^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$", is_version);
const SHA256: Str = Str::pattern("^[0-9a-fA-F]{64}$", is_sha256);

fn is_version(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+:-".contains(byte))
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn optional_string(rule: Str) -> impl Fn(&Value, &[panel_core::errors::LocItem], &mut Cx) -> Option<Option<String>> {
    move |value, loc, cx| nullable(value, loc, cx, |value, loc, cx| rule.validate(value, loc, cx))
}

fn too_short(loc: &[panel_core::errors::LocItem], input: &Value) -> ValidationIssue {
    let mut context = serde_json::Map::new();
    context.insert("field_type".into(), json!("List"));
    context.insert("min_length".into(), json!(1));
    context.insert("actual_length".into(), json!(0));
    ValidationIssue::new(
        "too_short",
        loc.to_vec(),
        "List should have at least 1 item after validation, not 0",
        input.clone(),
    )
    .with_ctx(context)
}

#[derive(Debug, Clone)]
pub struct NodeFingerprint {
    pub url: String,
    pub allow_private_address: bool,
}

impl Model for NodeFingerprint {
    const TITLE: &'static str = "NodeFingerprint";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let url = fields.required(cx, "url", |v, l, cx| Str::len(1, 512).validate(v, l, cx));
        let allow = fields.optional(cx, "allow_private_address", || false, boolean);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { url: url?, allow_private_address: allow? })
    }

    fn dump(&self) -> Value {
        json!({"url": self.url, "allow_private_address": self.allow_private_address})
    }
}

#[derive(Debug, Clone)]
pub struct NodeLinkTest {
    pub url: String,
    pub api_key: String,
    pub tls_verify: String,
    pub pinned_sha256: Option<String>,
    pub allow_private_address: bool,
}

impl Model for NodeLinkTest {
    const TITLE: &'static str = "NodeLinkTest";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let url = fields.required(cx, "url", |v, l, cx| Str::len(1, 512).validate(v, l, cx));
        let key = fields.required(cx, "api_key", |v, l, cx| Str::len(1, 256).validate(v, l, cx));
        let mode = fields.optional(cx, "tls_verify", || "verify".to_string(), |v, l, cx| {
            literal(v, l, cx, &["verify", "pin"]).map(str::to_string)
        });
        let pin = fields.optional(cx, "pinned_sha256", || None, optional_string(SHA256));
        let allow = fields.optional(cx, "allow_private_address", || false, boolean);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            url: url?,
            api_key: key?,
            tls_verify: mode?,
            pinned_sha256: pin?,
            allow_private_address: allow?,
        })
    }

    fn dump(&self) -> Value {
        json!({"url": self.url, "api_key": self.api_key, "tls_verify": self.tls_verify,
               "pinned_sha256": self.pinned_sha256, "allow_private_address": self.allow_private_address})
    }
}

#[derive(Debug, Clone)]
pub struct NodeLinkCreate {
    pub link: NodeLinkTest,
    pub display_name: String,
    pub auto_import: bool,
}

impl Model for NodeLinkCreate {
    const TITLE: &'static str = "NodeLinkCreate";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let url = fields.required(cx, "url", |v, l, cx| Str::len(1, 512).validate(v, l, cx));
        let key = fields.required(cx, "api_key", |v, l, cx| Str::len(1, 256).validate(v, l, cx));
        let mode = fields.optional(cx, "tls_verify", || "verify".to_string(), |v, l, cx| {
            literal(v, l, cx, &["verify", "pin"]).map(str::to_string)
        });
        let pin = fields.optional(cx, "pinned_sha256", || None, optional_string(SHA256));
        let allow = fields.optional(cx, "allow_private_address", || false, boolean);
        let name = fields.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        let auto = fields.optional(cx, "auto_import", || true, boolean);
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            link: NodeLinkTest {
                url: url?,
                api_key: key?,
                tls_verify: mode?,
                pinned_sha256: pin?,
                allow_private_address: allow?,
            },
            display_name: name?,
            auto_import: auto?,
        })
    }

    fn dump(&self) -> Value {
        let mut value = self.link.dump();
        let map = value.as_object_mut().expect("a link object");
        map.insert("display_name".into(), json!(self.display_name));
        map.insert("auto_import".into(), json!(self.auto_import));
        value
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeLinkUpdateBody {
    pub display_name: Option<String>,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub tls_verify: Option<String>,
    pub pinned_sha256: Option<String>,
    pub auto_import: Option<bool>,
}

impl Model for NodeLinkUpdateBody {
    const TITLE: &'static str = "NodeLinkUpdate";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let name = fields.optional(cx, "display_name", || None, optional_string(Str::len(1, 128)));
        let url = fields.optional(cx, "url", || None, optional_string(Str::len(1, 512)));
        let key = fields.optional(cx, "api_key", || None, optional_string(Str::len(1, 256)));
        let mode = fields.optional(cx, "tls_verify", || None, |v, l, cx| {
            nullable(v, l, cx, |v, l, cx| literal(v, l, cx, &["verify", "pin"]).map(str::to_string))
        });
        let pin = fields.optional(cx, "pinned_sha256", || None, optional_string(SHA256));
        let auto = fields.optional(cx, "auto_import", || None, |v, l, cx| nullable(v, l, cx, boolean));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self {
            display_name: name?,
            url: url?,
            api_key: key?,
            tls_verify: mode?,
            pinned_sha256: pin?,
            auto_import: auto?,
        })
    }

    fn dump(&self) -> Value {
        json!({"display_name": self.display_name, "url": self.url, "api_key": self.api_key,
               "tls_verify": self.tls_verify, "pinned_sha256": self.pinned_sha256,
               "auto_import": self.auto_import})
    }
}

#[derive(Debug, Clone)]
pub struct NodeImportItem {
    pub protocol: Protocol,
    pub runtime_username: String,
    pub client: String,
}

impl Model for NodeImportItem {
    const TITLE: &'static str = "NodeImportItem";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let protocol = fields.required(cx, "protocol", |v, l, cx| {
            literal(v, l, cx, PROTOCOLS).map(|text| Protocol::from_wire(text).expect("a protocol"))
        });
        let username = fields.required(cx, "runtime_username", |v, l, cx| USERNAME_PATTERN.validate(v, l, cx));
        let client = fields.required(cx, "client", |v, l, cx| Str::len(1, 64).validate(v, l, cx));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { protocol: protocol?, runtime_username: username?, client: client? })
    }

    fn dump(&self) -> Value {
        json!({"protocol": self.protocol.as_str(), "runtime_username": self.runtime_username,
               "client": self.client})
    }
}

#[derive(Debug, Clone)]
pub struct NodeImport {
    pub resources: Vec<NodeImportItem>,
}

impl Model for NodeImport {
    const TITLE: &'static str = "NodeImport";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let resources = fields.required(cx, "resources", |v, l, cx| {
            let items = list(v, l, cx, Some(200), NodeImportItem::validate_at)?;
            if items.is_empty() {
                cx.push(too_short(l, v));
                return None;
            }
            Some(items)
        });
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { resources: resources? })
    }

    fn dump(&self) -> Value {
        json!({"resources": self.resources.iter().map(Model::dump).collect::<Vec<_>>()})
    }
}

#[derive(Debug, Clone)]
pub struct NodeVersionUpdate {
    pub version: String,
    pub expected_current: Option<String>,
}

impl Model for NodeVersionUpdate {
    const TITLE: &'static str = "NodeVersionUpdate";

    fn validate_at(input: &Value, loc: &[panel_core::errors::LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let version = fields.required(cx, "version", |v, l, cx| VERSION.validate(v, l, cx));
        let current = fields.optional(cx, "expected_current", || None, optional_string(VERSION));
        fields.finish(cx, Extra::Ignore).then_some(())?;
        Some(Self { version: version?, expected_current: current? })
    }

    fn dump(&self) -> Value {
        json!({"version": self.version, "expected_current": self.expected_current})
    }
}

// -- routes -----------------------------------------------------------------------------------

pub const NOT_A_LINKED_PANEL: &str = "the local node has its own routes for this";
const OWNER: &[&str] = &["owner"];
const READER: &[&str] = &["owner", "admin"];

#[derive(Clone)]
pub struct CentralDomain {
    pub links: Arc<NodeLinkService>,
    pub desired: DesiredStore,
    pub importer: FleetImporter,
    pub pusher: Arc<FleetPusher>,
    pub nodes: NodeLifecycleService,
}

/// Build the central side immediately after the clients domain, as `create_app` does. The
/// publish hook runs in every client's mutation transaction; the pusher starts before the
/// enforcer loop through [`register_lifespan`].
pub fn wire(core: &Arc<Core>, services: &mut Services) -> Result<(), String> {
    let clients = services
        .get::<super::clients::ClientsDomain>()
        .cloned()
        .ok_or_else(|| "clients domain must be wired before fleet central".to_string())?;
    let nodes = NodeLifecycleService::new(core.database.clone(), core.clock.clone());
    let links = Arc::new(
        NodeLinkService::new(
            core.database.clone(),
            core.secrets.clone(),
            core.panel_guid.clone(),
            Arc::new(NodeHttpFactory),
            core.clock.clone(),
        )
        .with_provisioning(clients.provisioning.clone()),
    );
    let desired = DesiredStore::new(core.database.clone());
    let publisher = Arc::new(PublishService::new(
        core.panel_guid.clone(),
        desired.clone(),
        core.clock.clone(),
        None,
    ));
    clients.clients.add_hook(Arc::new(PublishForClient::new(publisher.clone())));
    let importer = FleetImporter::new(
        core.database.clone(),
        core.secrets.clone(),
        clients.clients.clone(),
        links.clone(),
        core.clock.clone(),
    );
    let options = PusherOptions {
        interval: Duration::from_secs(core.settings.fleet_heartbeat_seconds.max(1) as u64),
        ..PusherOptions::default()
    };
    let pusher = Arc::new(
        FleetPusher::with_options(
            core.database.clone(),
            links.clone(),
            desired.clone(),
            core.secrets.clone(),
            importer.clone(),
            clients.clients.clone(),
            clients.provisioning.clone(),
            core.events.clone(),
            core.clock.clone(),
            options,
        )
        .map_err(|error| error.to_string())?,
    );
    let metrics = Arc::new(FleetMetricsSource::new(core.database.clone(), links.clone(), core.clock.clone()));
    services.insert(nodes.clone());
    services.insert(desired.clone());
    services.insert(publisher);
    services.insert(links.clone());
    services.insert(importer.clone());
    services.insert(pusher.clone());
    services.insert(metrics);
    services.insert(CentralDomain { links, desired, importer, pusher, nodes });
    Ok(())
}

struct PusherLoop(Arc<FleetPusher>);

impl BackgroundLoop for PusherLoop {
    fn name(&self) -> &'static str {
        "pusher"
    }

    fn run(self: Arc<Self>, mut stop: StopSignal) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            self.0.clone().run_until(async move { stop.stopped().await }).await;
        })
    }

    fn tick(&self, _options: Value) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { self.0.tick().await.map_err(|error| error.to_string()) })
    }
}

pub fn register_lifespan(state: &AppState) {
    if let Some(domain) = state.try_service::<CentralDomain>() {
        state.lifespan.register_loop(Arc::new(PusherLoop(domain.pusher.clone())));
    }
}

pub fn routes() -> Routes {
    Routes::new()
        .post("/api/nodes/fingerprint", node_fingerprint)
        .post("/api/nodes/test", node_test)
        .post("/api/nodes/link", node_link)
        .post("/api/nodes/{node_id}/link", node_link_update)
        .post("/api/nodes/{node_id}/pause", node_pause)
        .post("/api/nodes/{node_id}/resume", node_resume)
        .post("/api/nodes/{node_id}/probe", node_probe)
        .delete("/api/nodes/{node_id}", node_unlink)
        .get("/api/nodes/{node_id}/inventory", node_inventory)
        .post("/api/nodes/{node_id}/import", node_import)
        .post("/api/nodes/{node_id}/versions/check", node_version_check)
        .post("/api/nodes/{node_id}/versions/{component}", node_version_update)
        .get("/api/nodes/{node_id}/generations", node_generations)
}

fn domain(app: &AppState) -> CentralDomain {
    app.service::<CentralDomain>().clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

fn refusal(status: u16, code: &str, detail: String) -> Failure {
    Failure::from(ApiError::coded(status, code, detail))
}

fn node_failure(error: NodeError) -> Failure {
    match error {
        NodeError::Unreachable(kind) => refusal(502, "node_unreachable", format!("the node is unreachable: {kind}")),
        NodeError::AuthFailed => refusal(409, "node_auth_failed", "the node refused the API key".into()),
        NodeError::Rejected { status, code, detail } => refusal(
            502,
            code.as_deref().filter(|code| !code.is_empty()).unwrap_or("node_rejected"),
            format!("the node answered {status}: {}", NodeError::Rejected { status, code, detail }),
        ),
        NodeError::InvalidAnswer(error) => Failure::internal(error),
    }
}

fn translate(error: CentralError) -> Failure {
    match error {
        CentralError::Node(error) => node_failure(error),
        CentralError::NotFound(_) => Failure::detail(404, "node not found"),
        CentralError::UnknownClient(_) => Failure::detail(404, "client not found"),
        CentralError::LinkConflict(message) => Failure::detail(409, message),
        CentralError::Invalid(message) => Failure::detail(422, message),
        CentralError::Secret(error) => Failure::detail(409, error.to_string()),
        CentralError::Clients(panel_clients::ClientsError::NotFound(_)) => Failure::detail(404, "client not found"),
        CentralError::Clients(panel_clients::ClientsError::Conflict(message)) => Failure::detail(409, message),
        CentralError::Clients(panel_clients::ClientsError::Invalid(message)) => Failure::detail(422, message),
        CentralError::Clients(error) => Failure::internal(error),
        other => Failure::internal(other),
    }
}

fn view(domain: &CentralDomain, node_id: &str) -> Result<Value, Failure> {
    domain
        .nodes
        .get(node_id)
        .map(|view| view_to_value(&view))
        .map_err(|error| match error {
            panel_nodes::NodesError::NotFound(_) => Failure::detail(404, "node not found"),
            other => Failure::internal(other),
        })
}

fn linked(domain: &CentralDomain, node_id: &str) -> Result<(), Failure> {
    if node_id == "local" {
        return Err(Failure::detail(422, NOT_A_LINKED_PANEL));
    }
    domain
        .links
        .database()
        .with_connection(|db| domain.links.link(db, node_id))
        .map(|_| ())
        .map_err(translate)
}

async fn node_fingerprint(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeFingerprint>(&input);
    issues.finish()?;
    let body = body.expect("validated body");
    let url = validate_panel_url(&body.url, body.allow_private_address).map_err(translate)?;
    let probe_url = url.clone();
    let work = tokio::task::spawn_blocking(move || fingerprint(&probe_url, FINGERPRINT_TIMEOUT, body.allow_private_address));
    let digest = match tokio::time::timeout(FINGERPRINT_TIMEOUT, work).await {
        Ok(result) => result.map_err(Failure::internal)?.map_err(translate)?,
        Err(_) => {
            return Err(node_failure(NodeError::Unreachable("TimeoutError".into())));
        }
    };
    Ok(response::json(200, &json!({"sha256": digest})))
}

async fn node_test(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeLinkTest>(&input);
    issues.finish()?;
    let body = body.expect("validated body");
    let result = domain(&app)
        .links
        .test(&body.url, &body.api_key, &body.tls_verify, body.pinned_sha256.as_deref(), body.allow_private_address)
        .await
        .map_err(translate)?;
    Ok(response::json(200, &Value::Object(result)))
}

async fn node_link(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeLinkCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated body");
    let link = body.link;
    let node_id = domain(&app)
        .links
        .add(
            &body.display_name,
            &link.url,
            &link.api_key,
            &link.tls_verify,
            link.pinned_sha256.as_deref(),
            link.allow_private_address,
            &audit_context(&user, &call),
            body.auto_import,
        )
        .await
        .map_err(translate)?;
    Ok(response::json(201, &json!({"node_id": node_id})))
}

async fn node_link_update(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeLinkUpdateBody>(&input);
    issues.finish()?;
    let body = body.expect("validated body");
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    let update = LinkUpdate {
        display_name: body.display_name,
        url: body.url,
        api_key: body.api_key,
        tls_verify: body.tls_verify,
        pinned_sha256: body.pinned_sha256,
        auto_import: body.auto_import,
    };
    domain.links.update(&node_id, update, &audit_context(&user, &call)).map_err(|error| match error {
        CentralError::Secret(secret) => refusal(409, "secret_store_disabled", secret.to_string()),
        other => translate(other),
    })?;
    Ok(response::json(200, &view(&domain, &node_id)?))
}

async fn set_enabled(app: &AppState, call: &Call, enabled: bool) -> Result<Value, Failure> {
    let user = app.roles(call, OWNER).await?;
    let domain = domain(app);
    let node_id = call.param("node_id").to_string();
    domain
        .links
        .set_enabled(&node_id, enabled, &audit_context(&user, call))
        .map_err(translate)?;
    view(&domain, &node_id)
}

async fn node_pause(State(app): State<AppState>, call: Call) -> Handled {
    Ok(response::json(200, &set_enabled(&app, &call, false).await?))
}

async fn node_resume(State(app): State<AppState>, call: Call) -> Handled {
    Ok(response::json(200, &set_enabled(&app, &call, true).await?))
}

async fn node_probe(State(app): State<AppState>, call: Call) -> Handled {
    app.roles(&call, OWNER).await?;
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    domain.pusher.sync_node(&node_id).await.map_err(translate)?;
    Ok(response::json(200, &view(&domain, &node_id)?))
}

fn force_query(call: &Call) -> Result<bool, Failure> {
    let Some(value) = call.query("force") else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Ok(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Ok(false),
        _ => {
            let issue = ValidationIssue::new(
                "bool_parsing",
                vec!["query".into(), "force".into()],
                "Input should be a valid boolean, unable to interpret input",
                Value::String(value),
            );
            Err(Failure::validation(vec![issue]))
        }
    }
}

async fn node_unlink(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let force = force_query(&call)?;
    let node_id = call.param("node_id").to_string();
    if node_id == "local" {
        return Err(Failure::detail(422, NOT_A_LINKED_PANEL));
    }
    domain(&app)
        .links
        .delete(&node_id, &audit_context(&user, &call), force)
        .await
        .map_err(translate)?;
    Ok(response::json(200, &json!({"ok": true})))
}

async fn node_inventory(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, READER).await?;
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    let client = domain.links.client_for(&node_id).map_err(translate)?;
    let inventory = client.inventory().await.map_err(node_failure)?;
    let mut table = inventory.get("protocols").and_then(Value::as_object).cloned().unwrap_or_default();
    domain.importer.annotate_inventory(&node_id, &mut table).map_err(translate)?;
    Ok(response::json(200, &json!({"protocols": table})))
}

async fn node_import(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeImport>(&input);
    issues.finish()?;
    let body = body.expect("validated body");
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    let decisions = body
        .resources
        .into_iter()
        .map(|item| ImportItem { protocol: item.protocol, runtime_username: item.runtime_username, client: item.client })
        .collect::<Vec<_>>();
    let result = domain
        .importer
        .import_resources(&node_id, &decisions, &audit_context(&user, &call), None, false)
        .await
        .map_err(translate)?;
    Ok(response::json(200, &result))
}

async fn node_version_check(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER).await?;
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    let client = domain.links.client_for(&node_id).map_err(translate)?;
    let result = client.check_versions().await.map_err(node_failure)?;
    app.audit(
        &user,
        "node.version.check",
        &node_id,
        &call,
        Some(json!({"checked_at": result.get("checked_at")}).as_object().unwrap().clone()),
    )
    .await?;
    Ok(response::json(200, &Value::Object(result)))
}

fn version_component(call: &Call, issues: &mut Issues) -> Option<String> {
    let component = call.param("component").to_string();
    let mut cx = Cx::new(panel_model::validate::Entry::Body);
    let valid = literal(
        &Value::String(component),
        &["path".into(), "component".into()],
        &mut cx,
        &["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"],
    )
    .map(str::to_string);
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    valid
}

async fn node_version_update(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER).await?;
    let mut issues = Issues::new();
    let component = version_component(&call, &mut issues);
    let body = issues.body::<NodeVersionUpdate>(&input);
    issues.finish()?;
    let component = component.expect("validated component");
    let body = body.expect("validated body");
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    let client = domain.links.client_for(&node_id).map_err(translate)?;
    let result = client
        .update_version(&component, &body.version, body.expected_current.as_deref())
        .await
        .map_err(node_failure)?;
    app.audit(
        &user,
        "node.version.update",
        &node_id,
        &call,
        Some(json!({"component": component, "version": body.version}).as_object().unwrap().clone()),
    )
    .await?;
    Ok(response::json(200, &Value::Object(result)))
}

async fn node_generations(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, READER).await?;
    let domain = domain(&app);
    let node_id = call.param("node_id").to_string();
    linked(&domain, &node_id)?;
    let (desired, observed) = domain
        .links
        .database()
        .with_connection(|db| {
            domain.links.link(db, &node_id)?;
            Ok((DesiredStore::latest(db, &node_id)?, DesiredStore::observed(db, &node_id)?))
        })
        .map_err(translate)?;
    let desired = desired.map(|latest| {
        json!({"generation": latest.generation, "digest": latest.digest,
               "content_digest": latest.content_digest, "pushed_at": latest.pushed_at,
               "acknowledged_at": latest.acknowledged_at,
               "resources": latest.document.resources.iter().map(Model::dump).collect::<Vec<_>>(),
               "created_at": latest.document.created_at})
    });
    Ok(response::json(200, &json!({"desired": desired, "observed": observed.map(|report| report.dump())})))
}
