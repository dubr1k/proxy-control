//! Test-only routes (cargo feature `test-hooks`, never in release images), the contract of
//! `panel/tests/harness/server.py` and `contract_stub.py`:
//!
//! - `POST /__test/clock {"time": t}` / `{"advance": s}` → `{"time", "monotonic"}`: one fake clock
//!   for wall and monotonic time (`monotonic = time - 1.7e9`);
//! - `POST /__test/tick/{loop}` (`pusher`, `enforcer`, `metrics`; optional JSON options) → one
//!   pass of that background loop;
//! - `POST /__test/settle` → once the work requests left running has finished;
//! - `POST /__test/probe-bridge {"answer": bool}` → what the MTProxy ingress probe answers.
//!
//! They sit behind the same stages as every route (host check, body limit), need no session and are
//! not in the OpenAPI document.

use axum::extract::State;
use panel_core::clock::Clock as _;
use serde_json::{json, Map, Value};

use crate::http::request::{BodyInput, Call};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .post("/__test/clock", clock)
        .hidden()
        .post("/__test/tick/{loop}", tick)
        .hidden()
        .post("/__test/settle", settle)
        .hidden()
        .post("/__test/probe-bridge", probe_bridge)
        .hidden()
}

/// A JSON object body (`body: dict = Body(...)`).
fn object(call: &Call, required: bool) -> Result<Map<String, Value>, Failure> {
    match call.body_input()? {
        BodyInput::Json(Value::Object(map)) => Ok(map),
        BodyInput::Missing | BodyInput::Json(Value::Null) if !required => Ok(Map::new()),
        _ => Err(Failure::detail(422, "a JSON object body is required")),
    }
}

async fn clock(State(app): State<AppState>, call: Call) -> Handled {
    let body = object(&call, true)?;
    if let Some(time) = body.get("time").and_then(Value::as_f64) {
        app.panel_clock.set(time);
    } else if let Some(seconds) = body.get("advance").and_then(Value::as_f64) {
        app.panel_clock.advance(seconds);
    } else {
        return Err(Failure::detail(422, "time or advance"));
    }
    Ok(response::json(200, &json!({"time": app.clock.time(), "monotonic": app.clock.monotonic()})))
}

async fn tick(State(app): State<AppState>, call: Call) -> Handled {
    let name = call.param("loop");
    if !matches!(name, "pusher" | "enforcer" | "metrics") {
        return Err(Failure::detail(404, "unknown loop"));
    }
    let options = object(&call, false)?;
    let Some(item) = app.lifespan.find(name) else {
        return Err(Failure::detail(404, format!("loop {name} is not registered in this build")));
    };
    item.tick(Value::Object(options)).await.map_err(Failure::internal)?;
    Ok(response::json(200, &json!({"ok": true})))
}

async fn settle(State(app): State<AppState>) -> Handled {
    app.background.settle().await;
    Ok(response::json(200, &json!({"ok": true})))
}

async fn probe_bridge(State(app): State<AppState>, call: Call) -> Handled {
    let body = object(&call, true)?;
    let answer = match body.get("answer") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    };
    app.test.set_bridge_answer(answer);
    Ok(response::json(200, &json!({"answer": answer})))
}
