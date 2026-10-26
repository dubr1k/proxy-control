//! `panel/auth_routes.py`: health, readiness, the login page and login/logout, who-am-I, the HTML
//! shell, reveals, administrators and the audit log — in that registration order.

use axum::extract::State;
use axum::response::Response;
use http::header::RETRY_AFTER;
use panel_model::validate::{Int, Str};
use panel_secrets::audit::{Actor, AuditQuery};
use panel_secrets::store::StoreError;
use serde_json::{json, Map, Value};

use crate::auth::blocking;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, add_cookie, Cookie, Failure, Handled};
use crate::http::router::Routes;
use crate::models::{AdminCreate, AdminUpdate, Login};
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .get("/healthz", healthz)
        .get("/api/readiness", readiness)
        .get("/login", login_page)
        .get("/favicon.ico", favicon)
        .hidden()
        .post("/api/auth/login", login)
        .post("/api/auth/logout", logout)
        .get("/api/auth/me", me)
        .get("/", index)
        .get("/api/reveal/{token}", reveal)
        .get("/api/admins", admins)
        .post("/api/admins", add_admin)
        .patch("/api/admins/{admin_id}", edit_admin)
        .delete("/api/admins/{admin_id}", remove_admin)
        .get("/api/audit", audit_log)
}

async fn healthz() -> Response {
    response::json(200, &json!({"status": "ok"}))
}

async fn readiness(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, &["owner", "admin"]).await?;
    let database = app.database.clone();
    let snapshot =
        tokio::task::spawn_blocking(move || super::readiness::snapshot(&database)).await.map_err(Failure::internal)?;
    let status = if snapshot["database"]["queryable"] == Value::Bool(true) { 200 } else { 503 };
    Ok(response::json(status, &snapshot))
}

/// A page of `panel/static`, read on every request in text mode (universal newlines).
async fn page(app: &AppState, name: &str) -> Result<String, Failure> {
    let bytes = tokio::fs::read(app.static_dir.join(name)).await.map_err(Failure::internal)?;
    let text = String::from_utf8(bytes).map_err(Failure::internal)?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

async fn login_page(State(app): State<AppState>, call: Call) -> Handled {
    let session = app.session_of(&call).await?;
    let existing = call.cookie("panel_csrf");
    let mut token = panel_core::ids::token_urlsafe(32);
    if let (Some(session), Some(existing)) = (&session, &existing) {
        if !existing.is_empty() && app.store.csrf_valid(session, Some(existing), Some(existing)) {
            token = existing.clone();
        }
    }
    let mut answer = response::html(page(&app, "login.html").await?);
    let cookie = Cookie {
        name: "panel_csrf",
        value: &token,
        path: Some("/"),
        secure: app.settings.session_cookie_secure,
        samesite: Some("strict"),
        ..Cookie::default()
    };
    add_cookie(&mut answer, &cookie.render());
    Ok(answer)
}

async fn favicon() -> Response {
    response::empty(204)
}

async fn login(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let mut issues = Issues::new();
    let body = issues.body::<Login>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let csrf = call.cookie("panel_csrf").filter(|value| !value.is_empty());
    let header = call.header("x-csrf-token").unwrap_or_default();
    if !csrf.is_some_and(|csrf| panel_secrets::compare_digest(&csrf, &header)) {
        return Err(Failure::detail(403, "CSRF validation failed"));
    }
    let ip = call.client_ip().to_string();
    let scopes = vec![
        format!("ip:{ip}"),
        format!("account:{}:{ip}", panel_secrets::casefold::casefold_for_ascii_match(&body.username)),
    ];
    let (store, attempts, window) = (app.store.clone(), app.settings.login_attempts, app.settings.login_window_seconds);
    let reserved = blocking(move || store.reserve_login_attempt(&scopes, attempts, window)).await?;
    let Some(reservation) = reserved else {
        return Err(Failure::detail(429, "too many attempts").with_header(RETRY_AFTER, window.to_string()));
    };
    let admin = {
        let _slot = app.login_slots.acquire().await.map_err(Failure::internal)?;
        let (store, username, password) = (app.store.clone(), body.username.clone(), body.password.clone());
        blocking(move || store.verify_admin(&username, &password)).await?
    };
    let Some(admin) = admin else {
        return Err(Failure::detail(401, "invalid credentials"));
    };
    let store = app.store.clone();
    blocking(move || store.release_login_attempt(&reservation)).await?;
    let (store, ttl) = (app.store.clone(), app.settings.session_ttl_seconds);
    let admin_id = admin.id;
    let (session, csrf) = blocking(move || store.create_session(admin_id, ttl)).await?;
    let mut answer = response::empty(204);
    let secure = app.settings.session_cookie_secure;
    let session_cookie = Cookie {
        name: "panel_session",
        value: &session,
        max_age: Some(ttl),
        path: Some("/"),
        secure,
        httponly: true,
        samesite: Some("strict"),
        ..Cookie::default()
    };
    let csrf_cookie = Cookie { name: "panel_csrf", value: &csrf, httponly: false, ..session_cookie.clone() };
    add_cookie(&mut answer, &session_cookie.render());
    add_cookie(&mut answer, &csrf_cookie.render());
    let (store, actor, username) =
        (app.store.clone(), Actor::new(Some(admin.id), admin.username.clone()), admin.username);
    let (ip, request_id) = (call.client_ip().to_string(), call.request_id().to_string());
    blocking(move || store.audit(&actor, "auth.login", &username, &ip, None, Some(&request_id))).await?;
    Ok(answer)
}

async fn logout(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.mutation(&call).await?;
    app.audit(&user, "auth.logout", &user.username, &call, None).await?;
    let (store, token) = (app.store.clone(), call.cookie("panel_session"));
    blocking(move || store.delete_session(token.as_deref())).await?;
    let mut answer = response::empty(204);
    add_cookie(&mut answer, &Cookie::deletion("panel_session"));
    add_cookie(&mut answer, &Cookie::deletion("panel_csrf"));
    Ok(answer)
}

async fn me(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.current(&call).await?;
    let settings = &app.settings;
    Ok(response::json(
        200,
        &json!({
            "username": user.username,
            "role": user.role,
            "via": user.via_text(),
            "panel_version": app.panel_version,
            "features": {
                "naive": settings.naive_enabled,
                "mieru": settings.mieru_enabled,
                "amneziawg": settings.amneziawg_enabled,
                "trusttunnel": settings.trusttunnel_enabled,
            },
        }),
    ))
}

async fn index(State(app): State<AppState>, call: Call) -> Handled {
    if app.session_of(&call).await?.is_none() {
        return Ok(response::redirect(303, "/login"));
    }
    Ok(response::html(page(&app, "index.html").await?))
}

async fn reveal(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.current(&call).await?;
    let data = app.reveals.consume(call.param("token"), &user.token_hash)?;
    Ok(response::json(200, &data))
}

async fn admins(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.current(&call).await?;
    if user.role != "owner" {
        return Err(Failure::detail(403, "insufficient role"));
    }
    let store = app.store.clone();
    let items = blocking(move || store.admins()).await?;
    Ok(response::json(200, &json!({"items": items})))
}

async fn add_admin(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let body = issues.body::<AdminCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let (store, username, password, role) =
        (app.store.clone(), body.username.clone(), body.password.clone(), body.role.clone());
    // Python turns any failure of `create_admin` into 409.
    let created = tokio::task::spawn_blocking(move || store.create_admin(&username, &password, &role))
        .await
        .map_err(Failure::internal)?;
    let Ok(admin_id) = created else {
        return Err(Failure::detail(409, "administrator exists"));
    };
    let mut detail = Map::new();
    detail.insert("role".into(), body.role.clone().into());
    app.audit(&user, "admin.create", &body.username, &call, Some(detail)).await?;
    Ok(response::json(201, &json!({"id": admin_id})))
}

async fn edit_admin(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let admin_id = issues.path_int(&call, "admin_id");
    let body = issues.body::<AdminUpdate>(&input);
    issues.finish()?;
    let (admin_id, body) = (admin_id.expect("validated"), body.expect("validated"));
    let (store, role, password, active) = (app.store.clone(), body.role.clone(), body.password.clone(), body.active);
    let updated =
        tokio::task::spawn_blocking(move || store.update_admin(admin_id, role.as_deref(), password.as_deref(), active))
            .await
            .map_err(Failure::internal)?;
    match updated {
        Ok(true) => {}
        Ok(false) => return Err(Failure::detail(404, "administrator not found")),
        Err(StoreError::LastOwner) => return Err(Failure::detail(409, "cannot demote last owner")),
        Err(error) => return Err(Failure::internal(error)),
    }
    let mut detail = Map::new();
    detail.insert("role".into(), body.role.into());
    detail.insert("active".into(), body.active.into());
    app.audit(&user, "admin.update", &admin_id.to_string(), &call, Some(detail)).await?;
    Ok(response::json(200, &json!({"ok": true})))
}

async fn remove_admin(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let admin_id = issues.path_int(&call, "admin_id");
    issues.finish()?;
    let admin_id = admin_id.expect("validated");
    let store = app.store.clone();
    let deleted = tokio::task::spawn_blocking(move || store.delete_admin(admin_id)).await.map_err(Failure::internal)?;
    match deleted {
        Ok(true) => {}
        Ok(false) => return Err(Failure::detail(404, "administrator not found")),
        Err(StoreError::LastOwner) => return Err(Failure::detail(409, "cannot delete last owner")),
        Err(error) => return Err(Failure::internal(error)),
    }
    app.audit(&user, "admin.delete", &admin_id.to_string(), &call, None).await?;
    Ok(response::empty(204))
}

async fn audit_log(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut issues = Issues::new();
    let limit = issues.query_int(&call, "limit", Int::lax(Some(1), Some(200)), Some(200));
    let before_id = issues.query_int(&call, "before_id", Int::lax(Some(1), None), None);
    let actor = issues.query_str(&call, "actor", Str::len(1, 64));
    let action = issues.query_str(&call, "action", Str::len(1, 128));
    let target = issues.query_str(&call, "target", Str::len(1, 256));
    let request_id = issues.query_str(&call, "request_id", Str::len(1, 64));
    issues.finish()?;
    let limit = limit.flatten().expect("validated with a default");
    let query = AuditQuery {
        limit: limit + 1,
        before_id: before_id.flatten(),
        actor: actor.flatten(),
        action: action.flatten(),
        target: target.flatten(),
        request_id: request_id.flatten(),
    };
    let store = app.store.clone();
    let mut rows = blocking(move || store.audits(&query)).await?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let mut answer = Map::new();
    let next = rows.last().and_then(|row| row.get("id").cloned());
    answer.insert("items".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    if more {
        answer.insert("next_cursor".into(), next.unwrap_or(Value::Null));
    }
    Ok(response::json(200, &Value::Object(answer)))
}
