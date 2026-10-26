//! The auth gates of `web_context.py:34-114` (inventory §2.2, §4.5–4.6).
//!
//! | Gate | Python | Use |
//! |---|---|---|
//! | [`AppState::current`] | `context.current` | any signed-in user or API key |
//! | [`AppState::mutation`] | `context.mutation` | `current` + CSRF for sessions |
//! | [`AppState::roles`] | `context.roles(*r)` | `mutation` + role (every state change) |
//! | [`AppState::read_roles`] | `context.read_roles(*r)` | `current` + role (reads) |
//! | [`AppState::fleet_key`] | `context.fleet_key` | a `node-sync`/`admin` API key |
//!
//! A gate answers the [`Principal`] or the exact `HTTPException` Python raises. Call it after
//! [`crate::http::request::Call::body_input`] and before validating parameters (FastAPI's order).

use panel_secrets::audit::Actor;
use panel_secrets::store::Session;
use serde_json::{Map, Value};

use crate::http::request::Call;
use crate::http::response::Failure;
use crate::state::AppState;

/// How the user authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Session,
    ApiKey,
}

/// The signed-in user (Python's user dict).
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub via: Via,
    /// The administrator id (sessions only).
    pub admin_id: Option<i64>,
    /// The key id (API keys only).
    pub key_id: Option<i64>,
    /// The administrator's name, or `key:<name>`.
    pub username: String,
    /// `owner`/`admin`/`viewer`, or a key's role (`admin→owner`, `monitor→viewer`, `node-sync`).
    pub role: String,
    /// The key's scope (API keys only).
    pub scope: Option<String>,
    /// The session's token hash, or `key:<id>` — who owns a reveal.
    pub token_hash: String,
    /// The session row (sessions only), for the CSRF check.
    pub session: Option<Session>,
}

impl Principal {
    fn from_session(session: Session) -> Self {
        Self {
            via: Via::Session,
            admin_id: Some(session.admin_id),
            key_id: None,
            username: session.username.clone(),
            role: session.role.clone(),
            scope: None,
            token_hash: session.token_hash.clone(),
            session: Some(session),
        }
    }

    /// `user.get("via", "session")`.
    pub fn via_text(&self) -> &'static str {
        match self.via {
            Via::Session => "session",
            Via::ApiKey => "api-key",
        }
    }

    /// The audit actor: `actor.get("admin_id") or actor.get("id")` and the username.
    pub fn actor(&self) -> Actor {
        Actor::new(self.admin_id, self.username.clone())
    }

    /// The user dict as Python passes it to services (`domain_context`'s `actor`).
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        match (&self.session, self.via) {
            (Some(session), Via::Session) => {
                out.insert("token_hash".into(), session.token_hash.clone().into());
                out.insert("admin_id".into(), session.admin_id.into());
                out.insert("csrf_hash".into(), session.csrf_hash.clone().into());
                out.insert("created_at".into(), session.created_at.into());
                out.insert("expires_at".into(), session.expires_at.into());
                out.insert("last_seen_at".into(), session.last_seen_at.into());
                out.insert("username".into(), session.username.clone().into());
                out.insert("role".into(), session.role.clone().into());
                out.insert("active".into(), session.active.into());
            }
            _ => {
                out.insert("id".into(), Value::Null);
                out.insert("key_id".into(), self.key_id.into());
                out.insert("username".into(), self.username.clone().into());
                out.insert("role".into(), self.role.clone().into());
                out.insert("scope".into(), self.scope.clone().into());
                out.insert("via".into(), "api-key".into());
                out.insert("token_hash".into(), self.token_hash.clone().into());
            }
        }
        out
    }
}

/// Runs blocking store work off the runtime; a join or store error is an unhandled 500.
pub async fn blocking<T, E, F>(work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(Failure::internal(error)),
        Err(error) => Err(Failure::internal(error)),
    }
}

impl AppState {
    /// `context.current`: a Bearer API key (checked first; case-insensitive scheme), else the
    /// `panel_session` cookie.
    pub async fn current(&self, call: &Call) -> Result<Principal, Failure> {
        let header = call.header("authorization").unwrap_or_default();
        // `header.lower().startswith("bearer ")`: no latin-1 character lowers into ASCII.
        let is_bearer = header.get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "));
        if is_bearer {
            let plaintext = panel_core::pytext::strip(&header.chars().skip(7).collect::<String>()).to_string();
            let keys = self.api_keys.clone();
            let principal = blocking(move || keys.authenticate(Some(&plaintext))).await?;
            let Some(principal) = principal else {
                return Err(Failure::detail(401, "invalid API key"));
            };
            if !self.key_rate.allow(principal.key_id) {
                return Err(Failure::detail(429, "API key rate limit exceeded"));
            }
            if principal.scope == "node-sync" && !call.path().starts_with("/api/fleet/v2/") {
                return Err(Failure::detail(403, "node-sync key is limited to the fleet API"));
            }
            return Ok(Principal {
                via: Via::ApiKey,
                admin_id: None,
                key_id: Some(principal.key_id),
                token_hash: format!("key:{}", principal.key_id),
                username: principal.username,
                role: principal.role.to_string(),
                scope: Some(principal.scope),
                session: None,
            });
        }
        match self.session_of(call).await? {
            Some(session) => Ok(Principal::from_session(session)),
            None => Err(Failure::detail(401, "authentication required")),
        }
    }

    /// The live session of the `panel_session` cookie, if any.
    pub async fn session_of(&self, call: &Call) -> Result<Option<Session>, Failure> {
        let cookie = call.cookie("panel_session");
        let store = self.store.clone();
        blocking(move || store.session(cookie.as_deref())).await
    }

    /// `context.mutation`: API keys pass; a session needs `X-CSRF-Token` == cookie `panel_csrf`
    /// == the session's CSRF. A header that equals the cookie but not the session ends the
    /// session (401 "session CSRF state invalid"); anything else is 403.
    pub async fn mutation(&self, call: &Call) -> Result<Principal, Failure> {
        let user = self.current(call).await?;
        let Some(session) = &user.session else {
            return Ok(user);
        };
        let supplied = call.header("x-csrf-token");
        let cookie = call.cookie("panel_csrf");
        if self.store.csrf_valid(session, supplied.as_deref(), cookie.as_deref()) {
            return Ok(user);
        }
        if let (Some(supplied), Some(cookie)) = (&supplied, &cookie) {
            if !supplied.is_empty() && !cookie.is_empty() && panel_secrets::compare_digest(supplied, cookie) {
                let token = call.cookie("panel_session");
                let store = self.store.clone();
                blocking(move || store.delete_session(token.as_deref())).await?;
                return Err(Failure::detail(401, "session CSRF state invalid"));
            }
        }
        Err(Failure::detail(403, "CSRF validation failed"))
    }

    /// `context.roles(*allowed)`.
    pub async fn roles(&self, call: &Call, allowed: &[&str]) -> Result<Principal, Failure> {
        let user = self.mutation(call).await?;
        if !allowed.contains(&user.role.as_str()) {
            return Err(Failure::detail(403, "insufficient role"));
        }
        Ok(user)
    }

    /// `context.read_roles(*allowed)`.
    pub async fn read_roles(&self, call: &Call, allowed: &[&str]) -> Result<Principal, Failure> {
        let user = self.current(call).await?;
        if !allowed.contains(&user.role.as_str()) {
            return Err(Failure::detail(403, "insufficient role"));
        }
        Ok(user)
    }

    /// `context.fleet_key`.
    pub async fn fleet_key(&self, call: &Call) -> Result<Principal, Failure> {
        let user = self.current(call).await?;
        if user.via != Via::ApiKey || !matches!(user.scope.as_deref(), Some("node-sync" | "admin")) {
            return Err(Failure::detail(403, "a node-sync or admin API key is required"));
        }
        Ok(user)
    }

    /// `context.audit(user, action, target, request, detail)` in its own connection.
    pub async fn audit(
        &self,
        user: &Principal,
        action: &str,
        target: &str,
        call: &Call,
        detail: Option<Map<String, Value>>,
    ) -> Result<(), Failure> {
        let (store, actor, action, target) = (self.store.clone(), user.actor(), action.to_string(), target.to_string());
        let (ip, request_id) = (call.client_ip().to_string(), call.request_id().to_string());
        blocking(move || store.audit(&actor, &action, &target, &ip, detail, Some(&request_id))).await.map(|_| ())
    }

    /// `context.create_reveal(data, owner)`.
    pub fn create_reveal(&self, data: Value, owner: &Principal) -> String {
        self.reveals.create(data, &owner.token_hash)
    }
}
