//! `panel/client_routes.py` (row 14): the client API — reads for everyone signed in, changes for
//! owner/admin, import strictly read-only upstream — over the clients domain of `panel-clients`,
//! plus its wiring (the protocol adapters, the domain services, the access enforcer loop).
//!
//! Errors are answered the way the Python handlers translate them (`KeyError` → 404 with the
//! route's own text, `ClientConflict` → 409 or 422, `AdapterError` → 502, …); a manager failure
//! the adapter let escape gets the app's exception-handler body ([`runtime_answer`]); the ADR 003
//! gate is 409 "managed by central" with `X-Reason: managed_by_central`.

use std::sync::Arc;

use axum::extract::State;
use http::HeaderName;
use panel_clients::enforcement::PendingReconciler;
use panel_clients::error::runtime_answer;
use panel_clients::hosts::{PublicHosts, SettingsHosts};
use panel_clients::importer::{self, ImportDecision};
use panel_clients::models::{
    ClientCreate, ClientImport, ClientRename, ClientStateBody, GrantAdopt, GrantAdoptBatch, GrantLabel, GrantsCreate,
};
use panel_clients::store::{self, GrantFilter, PageFilters};
use panel_clients::subscriptions::SubscriptionIssuer;
use panel_clients::{
    AccessEnforcer, Adapters, AuditContext, ClientService, ClientsError, DomainFacade, GrantLifecycle,
    ProvisioningService,
};
use panel_core::errors::ApiError;
use panel_fleet::node::{FleetNode, ManagerRuntime, NodeRuntime as _};
use panel_model::clients::{GrantIntent, ProtocolOptions};
use panel_model::seams::SeamError;
use panel_model::validate::{literal, Cx, Entry, Int, Model as _, Str};
use panel_model::Protocol;
use panel_protocols::reveals::artifact_qr;
use serde_json::{json, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::lifespan::{BackgroundLoop, BoxFuture, StopSignal};
use crate::state::{AppState, Core, Services};

/// The routes, in `register_client_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/clients", list)
        .post("/api/clients", create)
        .get("/api/clients/import/inventory", import_inventory)
        .post("/api/clients/import", import_confirm)
        .post("/api/clients/grants/{grant_id}/adopt", adopt)
        .post("/api/clients/grants/adopt-batch", adopt_batch)
        .post("/api/clients/grants/{grant_id}/label", grant_label)
        .post("/api/clients/grants/{grant_id}/{action}", grant_action)
        .post("/api/clients/{client_id}/grants", create_grants)
        .get("/api/operations/{operation_id}", operation)
        .post("/api/operations/{operation_id}/resume", resume)
        .post("/api/operations/{operation_id}/bundle", bundle)
        .post("/api/clients/{client_id}/links", links)
        .get("/api/clients/{client_id}", client)
        .post("/api/clients/{client_id}/state", state)
        .delete("/api/clients/{client_id}", delete_client)
        .post("/api/clients/{client_id}/rename", rename)
}

// -- wiring ----------------------------------------------------------------------------------

/// The clients domain as `create_app` builds it (`app.state.clients`, `.provisioning`,
/// `.domain_facade`, `.lifecycle`, `.access_enforcer`, the adapters and `public_hosts_for`).
#[derive(Clone)]
pub struct ClientsDomain {
    pub adapters: Adapters,
    pub clients: ClientService,
    pub provisioning: ProvisioningService,
    pub facade: DomainFacade,
    pub lifecycle: GrantLifecycle,
    pub enforcer: AccessEnforcer,
    pub hosts: Arc<SettingsHosts>,
}

/// The subscriptions package's side of `POST /api/clients` (WP9 inserts it into the services).
#[derive(Clone)]
pub struct Subscriptions(pub Arc<dyn SubscriptionIssuer>);

/// The panel's one adapter set (`app.state.adapters`), taken from the node runtime WP12a builds.
pub fn adapters(runtime: &ManagerRuntime) -> Adapters {
    let adapters = Adapters::new();
    for protocol in [Protocol::Mtproxy, Protocol::Naive, Protocol::Mieru, Protocol::Amneziawg, Protocol::Trusttunnel] {
        if let Some(adapter) = runtime.adapter(protocol) {
            adapters.insert(protocol, adapter);
        }
    }
    adapters
}

/// `Reconciler.run_pending` as the enforcer's second failure boundary.
struct NodeReconciler(Arc<panel_fleet::node::Reconciler>);

impl PendingReconciler for NodeReconciler {
    fn run_pending(&self) -> panel_model::protocols::BoxFuture<'_, Result<(), SeamError>> {
        Box::pin(async move { self.0.run_pending().await.map_err(|error| -> SeamError { error.to_string().into() }) })
    }
}

/// Builds the clients domain over the panel's adapter set and adds it (and the adapters) to the
/// services; the enforcer ticks the node's reconciler too (`AccessEnforcer(clients, reconciler)`).
pub fn wire(core: &Arc<Core>, services: &mut Services, runtime: &Arc<ManagerRuntime>, node: &FleetNode) {
    let adapters = adapters(runtime);
    let clock = core.clock.clone();
    let clients = ClientService::new(core.database.clone(), core.secrets.clone(), clock.clone(), adapters.clone());
    let provisioning = ProvisioningService::new(
        core.database.clone(),
        core.secrets.clone(),
        adapters.clone(),
        clients.clone(),
        clock.clone(),
    );
    let facade = DomainFacade::new(clients.clone(), provisioning.clone(), adapters.clone(), clock.clone());
    let lifecycle = GrantLifecycle::new(facade.clone(), clock);
    let reconciler: Arc<dyn PendingReconciler> = Arc::new(NodeReconciler(node.reconciler().clone()));
    let enforcer = AccessEnforcer::new(clients.clone(), Some(reconciler));
    services.insert(adapters.clone());
    services.insert(ClientsDomain {
        adapters,
        clients,
        provisioning,
        facade,
        lifecycle,
        enforcer,
        hosts: Arc::new(SettingsHosts::new(&core.settings)),
    });
}

/// The access enforcer as a background loop (`enforcer`).
pub struct EnforcerLoop(pub AccessEnforcer);

impl BackgroundLoop for EnforcerLoop {
    fn name(&self) -> &'static str {
        "enforcer"
    }

    fn run(self: Arc<Self>, mut stop: StopSignal) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let interval = self.0.interval();
            while !stop.is_stopped() {
                if stop.wait(interval).await {
                    return;
                }
                self.0.tick(false).await;
            }
        })
    }

    fn tick(&self, options: Value) -> BoxFuture<'_, Result<(), String>> {
        let force = options.get("force").is_some_and(|value| value.as_bool() == Some(true));
        Box::pin(async move {
            self.0.tick(force).await;
            Ok(())
        })
    }
}

/// The enforcer's `tick(force=True)` before serving, then its loop.
pub fn register_lifespan(state: &AppState) {
    let Some(domain) = state.try_service::<ClientsDomain>() else {
        return;
    };
    let enforcer = domain.enforcer.clone();
    let startup = enforcer.clone();
    state.lifespan.register_startup(Box::new(move || {
        Box::pin(async move {
            startup.tick(true).await;
            Ok(())
        })
    }));
    state.lifespan.register_loop(Arc::new(EnforcerLoop(enforcer)));
}

// -- error answers ---------------------------------------------------------------------------

/// How one route translates the domain's exceptions (the `except` clauses of its handler).
#[derive(Clone, Copy, Default)]
struct Rules {
    /// `KeyError` → 404 with this text.
    not_found: Option<&'static str>,
    /// `ClientConflict` → this status with `str(exc)`.
    conflict: Option<u16>,
    /// `ManualInterventionRequired` → 409.
    manual: bool,
    /// `AdapterError` → 502.
    adapter: bool,
    /// `SecretError` → 409.
    secret: bool,
    /// `ValueError` (and pydantic's `ValidationError`) → 422.
    invalid: bool,
}

/// The answer of an exception none of the route's clauses caught: the ADR 003 gate's
/// `HTTPException`, a routing refusal raised by the lanes service, the app's handler for an
/// escaped manager failure, else Starlette's bare 500.
fn uncaught(error: ClientsError) -> Failure {
    if let ClientsError::ManagedByCentral = error {
        return Failure::detail(409, "managed by central")
            .with_header(HeaderName::from_static("x-reason"), "managed_by_central");
    }
    if let Some((protocol, failure)) = error.runtime() {
        return match runtime_answer(protocol, &failure) {
            Some(answer) => Failure::from(answer),
            None => Failure::internal(error),
        };
    }
    if let ClientsError::Seam(seam) = &error {
        if let Some(api) = seam.downcast_ref::<ApiError>() {
            return Failure::from(api.clone());
        }
    }
    Failure::internal(error)
}

fn translate(error: ClientsError, rules: Rules) -> Failure {
    match &error {
        ClientsError::NotFound(_) if rules.not_found.is_some() => Failure::detail(404, rules.not_found.unwrap_or("")),
        ClientsError::Conflict(message) if rules.conflict.is_some() => {
            Failure::detail(rules.conflict.unwrap_or(409), message.clone())
        }
        ClientsError::Adapter { .. } if rules.manual && error.is_manual_intervention() => {
            Failure::detail(409, error.to_string())
        }
        ClientsError::Adapter { .. } if rules.adapter && error.is_adapter_error() => {
            Failure::detail(502, error.to_string())
        }
        ClientsError::Secret(message) if rules.secret => Failure::detail(409, *message),
        ClientsError::Invalid(message) if rules.invalid => Failure::detail(422, message.clone()),
        ClientsError::Validation(validation) if rules.invalid => Failure::detail(422, validation.to_string()),
        _ => uncaught(error),
    }
}

/// Runs blocking domain work; its error translated by `rules`.
async fn blocking<T, F>(rules: Rules, work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, ClientsError> + Send + 'static,
    T: Send + 'static,
{
    panel_clients::blocking(work).await.map_err(|error| translate(error, rules))
}

fn domain(app: &AppState) -> ClientsDomain {
    app.service::<ClientsDomain>().clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

const OWNER_ADMIN: &[&str] = &["owner", "admin"];

// -- query parameters ------------------------------------------------------------------------

fn query_loc(name: &str) -> Vec<panel_core::errors::LocItem> {
    vec!["query".into(), name.into()]
}

/// A `Literal[...]` query parameter with a default.
fn query_literal(call: &Call, issues: &mut Issues, name: &str, choices: &[&str], default: &str) -> Option<String> {
    let Some(text) = call.query(name) else {
        return Some(default.to_string());
    };
    let mut cx = Cx::new(Entry::Body);
    let found = literal(&Value::String(text), &query_loc(name), &mut cx, choices).map(str::to_string);
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    found
}

/// A `str` query parameter with a default and a `max_length`.
fn query_text(call: &Call, issues: &mut Issues, name: &str, max: usize) -> Option<String> {
    issues.query_str(call, name, Str::max(max)).map(Option::unwrap_or_default)
}

// -- handlers --------------------------------------------------------------------------------

async fn list(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut issues = Issues::new();
    let limit = issues.query_int(&call, "limit", Int::lax(Some(1), Some(200)), None);
    let cursor = issues.query_str(&call, "cursor", Str::max(512));
    let query = query_text(&call, &mut issues, "query", 256);
    let state = query_literal(&call, &mut issues, "state", &["all", "active", "suspended", "archived"], "all");
    let protocol = query_literal(
        &call,
        &mut issues,
        "protocol",
        &["", "mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"],
        "",
    );
    let node = query_text(&call, &mut issues, "node", 128);
    let issue = query_literal(
        &call,
        &mut issues,
        "issue",
        &["", "problem", "pending", "failed", "orphan", "disabled", "lane", "empty"],
        "",
    );
    issues.finish()?;
    let filters = PageFilters {
        cursor: cursor.expect("validated"),
        query: query.expect("validated"),
        state: state.expect("validated"),
        protocol: protocol.expect("validated"),
        node: node.expect("validated"),
        issue: issue.expect("validated"),
    };
    let limit = limit.expect("validated");
    let database = domain(&app).clients.database().clone();
    let body = blocking(Rules { invalid: true, ..Rules::default() }, move || {
        database.with_connection(|db| match limit {
            Some(limit) => Ok(store::client_page(db, limit, &filters)?.to_json()),
            None => {
                let items: Vec<Value> = store::clients_with_grants(db)?
                    .iter()
                    .map(|(client, grants)| store::client_json(client, grants))
                    .collect();
                Ok(json!({"items": items}))
            }
        })
    })
    .await?;
    Ok(response::json(200, &body))
}

async fn create(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ClientCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let context = audit_context(&user, &call);
    let issuer = app.try_service::<Subscriptions>().map(|issuer| issuer.0.clone()).filter(|issuer| issuer.enabled());
    if let (true, Some(issuer)) = (body.subscription, issuer) {
        let (client, payload) =
            blocking(Rules::default(), move || issuer.create_with_client(&body.display_name, &context)).await?;
        let reveal = app.create_reveal(payload, &user);
        let mut answer = client.dump();
        answer["subscription_reveal_token"] = Value::String(reveal);
        return Ok(response::json(201, &answer));
    }
    let clients = domain(&app).clients;
    let client = blocking(Rules::default(), move || clients.create_client(&body.display_name, &context)).await?;
    let mut answer = client.dump();
    answer["subscription_reveal_token"] = Value::Null;
    Ok(response::json(201, &answer))
}

/// `_inventory()`: every manager is read (Telemt always, NaiveProxy and Mieru when switched on);
/// one that cannot be read contributes nothing.
async fn inventory(app: &AppState) -> Result<Vec<importer::InventoryItem>, Failure> {
    let managers = app.managers.clone();
    let (naive_on, mieru_on) = (app.settings.naive_enabled, app.settings.mieru_enabled);
    let rows = |answer: Option<Value>| match answer {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    let (telemt, naive, mieru) = tokio::join!(
        async { managers.telemt.list_users().await.ok() },
        async {
            if naive_on {
                managers.naive.list_users().await.ok()
            } else {
                None
            }
        },
        async {
            if mieru_on {
                managers.mieru.list_users().await.ok()
            } else {
                None
            }
        },
    );
    let collected =
        vec![(Protocol::Mtproxy, rows(telemt)), (Protocol::Naive, rows(naive)), (Protocol::Mieru, rows(mieru))];
    let database = domain(app).clients.database().clone();
    blocking(Rules::default(), move || importer::inventory(&database, &collected)).await
}

async fn import_inventory(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, OWNER_ADMIN).await?;
    let items = inventory(&app).await?;
    let proposals: Vec<Value> = importer::propose(&items)
        .iter()
        .map(|proposal| {
            json!({
                "display_name": proposal.display_name,
                "same_username_hint": proposal.same_username_hint,
                "items": proposal.items.iter().map(importer::InventoryItem::to_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    let already = items.iter().filter(|item| item.imported_grant_id.is_some()).count();
    Ok(response::json(200, &json!({"proposals": proposals, "already_imported": already})))
}

async fn import_confirm(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ClientImport>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let known = inventory(&app).await?;
    let decisions: Vec<ImportDecision> = body
        .decisions
        .into_iter()
        .map(|decision| ImportDecision {
            display_name: decision.display_name,
            client_id: decision.client_id,
            items: decision.items,
        })
        .collect();
    let (clients, context) = (domain(&app).clients, audit_context(&user, &call));
    let rules = Rules { invalid: true, not_found: Some("client not found"), conflict: Some(409), ..Rules::default() };
    let result = blocking(rules, move || importer::confirm(&clients, &decisions, &known, &context)).await?;
    Ok(response::json(200, &result.to_json()))
}

const ADOPT_RULES: Rules = Rules {
    not_found: Some("grant not found"),
    conflict: Some(409),
    manual: true,
    adapter: true,
    secret: true,
    invalid: false,
};

/// `_adopt(grant_id, allow_rotation, …)`, its errors untranslated.
async fn adopt_one(
    app: &AppState,
    grant_id: &str,
    allow_rotation: bool,
    context: &AuditContext,
) -> Result<Value, ClientsError> {
    let grant = domain(app).clients.adopt_credential(grant_id, allow_rotation, context).await?;
    Ok(json!({
        "grant_id": grant.id,
        "protocol": grant.protocol.as_str(),
        "runtime_username": grant.runtime_username,
        "adopted": grant.secret_ref.is_some(),
    }))
}

/// Whether `_adopt` answers the error with an `HTTPException` (what the batch collects as a
/// refusal); anything else escapes the batch as it escapes the single route.
fn adopt_refusal(error: &ClientsError) -> bool {
    matches!(
        error,
        ClientsError::NotFound(_)
            | ClientsError::Conflict(_)
            | ClientsError::Secret(_)
            | ClientsError::ManagedByCentral
    ) || error.is_adapter_error()
}

async fn adopt(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GrantAdopt>(&input);
    issues.finish()?;
    let answer =
        adopt_one(&app, call.param("grant_id"), body.expect("validated").allow_rotation, &audit_context(&user, &call))
            .await
            .map_err(|error| translate(error, ADOPT_RULES))?;
    Ok(response::json(200, &answer))
}

async fn adopt_batch(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GrantAdoptBatch>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let database = domain(&app).clients.database().clone();
    let protocol = body.protocol;
    let pending: Vec<String> = blocking(Rules::default(), move || {
        database.with_connection(|db| {
            Ok(store::grants(db, &GrantFilter { protocol: Some(protocol.as_str()), ..GrantFilter::default() })?
                .into_iter()
                .filter(|grant| grant.secret_ref.is_none())
                .map(|grant| grant.id)
                .collect())
        })
    })
    .await?;
    let context = audit_context(&user, &call);
    let (mut adopted, mut refused) = (Vec::new(), Vec::new());
    for grant_id in pending {
        match adopt_one(&app, &grant_id, body.allow_rotation, &context).await {
            Ok(result) => adopted.push(result),
            // One refusal must not hide the grants adopted before it.
            Err(error) if adopt_refusal(&error) => {
                let detail = match translate(error, ADOPT_RULES) {
                    Failure::Api(failure) => failure.error.body()["detail"].clone(),
                    Failure::Internal(message) => Value::String(message),
                };
                refused.push(json!({"grant_id": grant_id, "detail": detail}));
            }
            Err(error) => return Err(translate(error, ADOPT_RULES)),
        }
    }
    Ok(response::json(200, &json!({"adopted": adopted, "refused": refused})))
}

async fn grant_label(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GrantLabel>(&input);
    issues.finish()?;
    let label = body.expect("validated").label;
    let (clients, context, grant_id) =
        (domain(&app).clients, audit_context(&user, &call), call.param("grant_id").to_string());
    let rules = Rules { not_found: Some("grant not found"), conflict: Some(422), ..Rules::default() };
    let grant = blocking(rules, move || clients.set_grant_label(&grant_id, Some(&label), &context)).await?;
    Ok(response::json(200, &grant.dump()))
}

async fn grant_action(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let action = literal(
        &Value::String(call.param("action").to_string()),
        &["path".into(), "action".into()],
        &mut cx,
        &["enable", "disable", "rotate", "delete"],
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let lifecycle = domain(&app).lifecycle;
    let (grant_id, context) = (call.param("grant_id"), audit_context(&user, &call));
    let rules = Rules { secret: true, ..ADOPT_RULES };
    let grant = match action.expect("validated") {
        "enable" => lifecycle.set_enabled(grant_id, true, &context).await,
        "disable" => lifecycle.set_enabled(grant_id, false, &context).await,
        "rotate" => lifecycle.rotate(grant_id, &context).await,
        _ => {
            lifecycle.delete(grant_id, &context).await.map_err(|error| translate(error, rules))?;
            return Ok(response::json(200, &json!({"ok": true})));
        }
    }
    .map_err(|error| translate(error, rules))?;
    Ok(response::json(200, &grant.dump()))
}

async fn create_grants(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GrantsCreate>(&input);
    issues.finish()?;
    let mut intents = Vec::new();
    for item in body.expect("validated").grants {
        let options = ProtocolOptions::validate(item.protocol, &Value::Object(item.options))
            .map_err(|error| Failure::detail(422, error.to_string()))?;
        let intent = GrantIntent {
            protocol: item.protocol,
            options,
            node_id: item.node_id,
            endpoint_id: "default".into(),
            runtime_username: item.runtime_username,
            valid_from: item.valid_from,
            valid_until: item.valid_until,
        };
        intent.check().map_err(|error| Failure::detail(422, error.to_string()))?;
        intents.push(intent);
    }
    let provisioning = domain(&app).provisioning;
    let context = audit_context(&user, &call);
    let rules = Rules { not_found: Some("client not found"), conflict: Some(409), adapter: true, ..Rules::default() };
    let operation_id = provisioning
        .start(call.param("client_id"), intents, &context)
        .await
        .map_err(|error| translate(error, rules))?;
    let result = provisioning.run(&operation_id).await.map_err(uncaught)?;
    Ok(response::json(200, &json!({"operation_id": operation_id, "status": result.status})))
}

async fn operation(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, OWNER_ADMIN).await?;
    let (provisioning, id) = (domain(&app).provisioning, call.param("operation_id").to_string());
    let rules = Rules { not_found: Some("operation not found"), ..Rules::default() };
    let status = blocking(rules, move || provisioning.status(&id)).await?;
    Ok(response::json(200, &status))
}

async fn resume(State(app): State<AppState>, call: Call) -> Handled {
    app.roles(&call, OWNER_ADMIN).await?;
    let id = call.param("operation_id");
    let rules = Rules { not_found: Some("operation not found"), ..Rules::default() };
    let result = domain(&app).provisioning.run(id).await.map_err(|error| translate(error, rules))?;
    Ok(response::json(200, &json!({"operation_id": id, "status": result.status})))
}

async fn bundle(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let domain = domain(&app);
    let (provisioning, hosts, id) = (domain.provisioning, domain.hosts, call.param("operation_id").to_string());
    let rules = Rules { not_found: Some("operation not found"), conflict: Some(409), ..Rules::default() };
    let mut payload = blocking(rules, move || provisioning.bundle(&id, hosts.as_ref() as &dyn PublicHosts)).await?;
    for grant in payload["grants"].as_array_mut().into_iter().flatten() {
        // An AmneziaWG config is scanned, not typed: the other artifacts are one-line links.
        for artifact in grant["artifacts"].as_array_mut().into_iter().flatten() {
            let media_type = artifact["media_type"].as_str().unwrap_or("").to_string();
            if media_type == "text/x-amneziawg-conf" {
                let qr = artifact_qr(&media_type, artifact["value"].as_str().unwrap_or(""));
                artifact["qr"] = qr.map_or(Value::Null, Value::String);
            }
        }
    }
    Ok(response::json(200, &json!({"reveal_token": app.create_reveal(payload, &user)})))
}

async fn links(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let domain = domain(&app);
    let (protocol, grant_id) = (call.query("protocol"), call.query("grant_id"));
    let not_found = if grant_id.is_some() { "grant not found" } else { "client not found" };
    let rules = Rules { not_found: Some(not_found), secret: true, ..Rules::default() };
    let (provisioning, hosts, client_id, context) =
        (domain.provisioning, domain.hosts, call.param("client_id").to_string(), audit_context(&user, &call));
    let mut payload = blocking(rules, move || {
        provisioning.client_links(
            &client_id,
            hosts.as_ref() as &dyn PublicHosts,
            protocol.as_deref(),
            grant_id.as_deref(),
            &context,
        )
    })
    .await?;
    for grant in payload["grants"].as_array_mut().into_iter().flatten() {
        for artifact in grant["artifacts"].as_array_mut().into_iter().flatten() {
            let qr =
                artifact_qr(artifact["media_type"].as_str().unwrap_or(""), artifact["value"].as_str().unwrap_or(""));
            artifact["qr"] = qr.map_or(Value::Null, Value::String);
        }
    }
    Ok(response::json(200, &json!({"reveal_token": app.create_reveal(payload, &user)})))
}

async fn client(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let (clients, id) = (domain(&app).clients, call.param("client_id").to_string());
    let rules = Rules { not_found: Some("client not found"), ..Rules::default() };
    let (found, grants) = blocking(rules, move || clients.client_with_grants(&id)).await?;
    Ok(response::json(200, &store::client_json(&found, &grants)))
}

async fn state(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ClientStateBody>(&input);
    issues.finish()?;
    let wanted = body.expect("validated").state;
    let clients = domain(&app).clients;
    let (worker, context, id) = (clients.clone(), audit_context(&user, &call), call.param("client_id").to_string());
    let rules = Rules { not_found: Some("client not found"), conflict: Some(409), ..Rules::default() };
    let changed = blocking(rules, move || worker.set_state(&id, &wanted, &context)).await?;
    clients.reconcile_access(Some(call.param("client_id")), false).await.map_err(|error| translate(error, rules))?;
    Ok(response::json(200, &changed.dump()))
}

async fn delete_client(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let (clients, context, id) =
        (domain(&app).clients, audit_context(&user, &call), call.param("client_id").to_string());
    let rules = Rules { not_found: Some("client not found"), conflict: Some(409), ..Rules::default() };
    let deleted = id.clone();
    blocking(rules, move || clients.delete_client(&id, &context)).await?;
    Ok(response::json(200, &json!({"deleted": deleted})))
}

async fn rename(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ClientRename>(&input);
    issues.finish()?;
    let name = body.expect("validated").display_name;
    let (clients, context, id) =
        (domain(&app).clients, audit_context(&user, &call), call.param("client_id").to_string());
    let rules = Rules { not_found: Some("client not found"), conflict: Some(422), ..Rules::default() };
    let changed = blocking(rules, move || clients.rename_client(&id, &name, &context)).await?;
    Ok(response::json(200, &changed.dump()))
}
