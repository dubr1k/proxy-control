//! The API schema for the MCP server, owners and admins only. Public `/openapi.json`, `/docs`
//! and `/redoc` stay off.
//!
//! The checked-in `openapi/panel-openapi.json` fixes the MCP tool names, parameters and body
//! schemas. Retired Fleet v1 operations are absent. Route changes update that document;
//! `tests/openapi_routes.rs` keeps its operation set equal to the router's.

use axum::extract::State;

use crate::http::request::Call;
use crate::http::response::{self, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

/// The served document.
pub const DOCUMENT: &[u8] = include_bytes!("../../openapi/panel-openapi.json");

pub fn routes() -> Routes {
    Routes::new().get("/api/openapi.json", openapi_schema)
}

async fn openapi_schema(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, &["owner", "admin"]).await?;
    Ok(response::json_bytes(200, app.openapi.clone()))
}
