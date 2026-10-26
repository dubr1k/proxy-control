//! `panel/openapi_routes.py`: the API schema for the MCP server, owners and admins only. FastAPI's
//! public `/openapi.json`, `/docs` and `/redoc` stay off.
//!
//! The document is the exact bytes the Python panel served (`openapi/panel-openapi.json`,
//! recorded by `tests/fixtures/record_goldens.py`): the MCP server generates its tools from it,
//! so names, parameters and body schemas must not move. A route change edits that file by hand;
//! `tests/openapi_routes.rs` keeps the route set and the document's operations equal.

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
