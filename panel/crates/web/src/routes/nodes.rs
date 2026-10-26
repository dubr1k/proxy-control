//! `panel/node_routes.py` (WP11): the operator-facing node API, served by the handlers of
//! `panel_nodes::routes` behind this shell's gates and validation.
//!
//! Python order (`register_node_routes`): `GET /api/nodes`, `GET /api/nodes/{node_id}`, (`POST
//! /api/nodes`, retired with fleet v1: the path keeps `GET`, so it answers 405),
//! `POST …/rename|disable|enable` (`POST …/certificates/revoke-all`, retired: 404). Starlette's
//! first-match routing makes `GET /api/nodes/link|test|fingerprint` reach `GET
//! /api/nodes/{node_id}` (404 `node not found`) even once fleet v2 registers those paths for `POST`
//! earlier in the table.

use axum::extract::State;
use panel_model::protocols::BoxFuture;
use panel_model::seams::SeamError;
use panel_nodes::routes::{self as nodes, LocalManager, NodeRename, NodesState, RouteError};
use panel_nodes::{AuditContext, NodeLifecycleService};
use serde_json::Value;

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .get("/api/nodes", list)
        .get("/api/nodes/{node_id}", one)
        .post("/api/nodes/{node_id}/rename", rename)
        .post("/api/nodes/{node_id}/disable", disable)
        .post("/api/nodes/{node_id}/enable", enable)
}

impl NodesState for AppState {
    fn nodes(&self) -> &NodeLifecycleService {
        self.service::<NodeLifecycleService>()
    }

    fn panel_guid(&self) -> String {
        self.panel_guid.clone()
    }

    fn manager_enabled(&self, manager: LocalManager) -> bool {
        let settings = &self.settings;
        match manager {
            LocalManager::Telemt => true,
            LocalManager::Naive => settings.naive_enabled,
            LocalManager::Mieru => settings.mieru_enabled,
            LocalManager::Amneziawg => settings.amneziawg_enabled,
            LocalManager::Trusttunnel => settings.trusttunnel_enabled,
        }
    }

    fn manager_healthy(&self, manager: LocalManager) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let managers = &self.managers;
            match manager {
                LocalManager::Telemt => managers.telemt.health().await.is_ok(),
                LocalManager::Naive => managers.naive.health().await.is_ok(),
                LocalManager::Mieru => managers.mieru.health().await.is_ok(),
                LocalManager::Amneziawg => managers.amneziawg.health().await.is_ok(),
                LocalManager::Trusttunnel => managers.trusttunnel.health().await.is_ok(),
            }
        })
    }

    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, SeamError>> {
        Box::pin(async move {
            // `adapters["amneziawg"].versions()`: the adapter is a thin view of the client.
            let adapter = panel_protocols::amneziawg::AmneziawgAdapter::new(self.managers.amneziawg.clone(), "");
            adapter.versions().await.map_err(|error| Box::new(error) as SeamError)
        })
    }
}

fn failure(error: RouteError) -> Failure {
    match error {
        RouteError::Api(error) => Failure::from(error),
        RouteError::Internal(error) => Failure::internal(error),
    }
}

/// `_context(request, user)`: who acts, from where, in which request.
fn audit_context(call: &Call, user: &Principal) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

fn answer(result: Result<Value, RouteError>) -> Handled {
    Ok(response::json(200, &result.map_err(failure)?))
}

async fn list(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    answer(nodes::list_nodes(&app).await)
}

async fn one(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    answer(nodes::get_node(&app, call.param("node_id").to_string()).await)
}

async fn rename(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let body = issues.body::<NodeRename>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let context = audit_context(&call, &user);
    answer(nodes::rename_node(&app, call.param("node_id").to_string(), body, context).await)
}

async fn set_disabled(app: AppState, call: Call, disabled: bool) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    let context = audit_context(&call, &user);
    answer(nodes::set_node_disabled(&app, call.param("node_id").to_string(), disabled, context).await)
}

async fn disable(State(app): State<AppState>, call: Call) -> Handled {
    set_disabled(app, call, true).await
}

async fn enable(State(app): State<AppState>, call: Call) -> Handled {
    set_disabled(app, call, false).await
}
