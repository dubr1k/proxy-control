//! Routing on the manager: the egress block (v0.4/v0.5) with its journal of applied
//! documents, and the lanes (v0.7) — each change the same transaction as a user change, an
//! egress change also read back from the running configuration.

use serde_json::{json, Map, Value};

use crate::egress::{self, ParsedEgress, Providers};
use crate::error::{Error, Result};
use crate::fsops::read_text;
use crate::pyutil::{compare_digest, join_lines, now_iso, sha256_hex, splitlines};
use crate::service::{handlers, object, object_mut, NaiveManager, Readback};
use crate::state;

impl NaiveManager {
    // ------------------------------------------------------------------ lanes

    /// Replaces the lanes: every named user moves into its lane's handler with the lane's
    /// router-ingress account as the upstream; users not named go back to the service's own
    /// handler. One transaction, one reload, the same recovery as users.
    pub fn set_lanes(&self, body: &Value) -> Result<Value> {
        self.synchronized(|| {
            let state = self.read_state()?;
            let lanes = crate::lanes::validate_request(body, &state::usernames(&state)).map_err(|err| match err {
                Error::LanesInvalid(message) => Error::conflict_code(message, "lanes_invalid"),
                other => other,
            })?;
            let router_url = self.settings.router_url.clone().filter(|url| !url.is_empty());
            if !lanes.is_empty() && router_url.is_none() {
                return Err(Error::egress_invalid("egress provider router is not configured on this node"));
            }
            let mut desired = state.clone();
            let by_user: std::collections::HashMap<&str, &str> = lanes
                .iter()
                .flat_map(|lane| lane.users.iter().map(move |user| (user.as_str(), lane.lane.as_str())))
                .collect();
            for row in desired["users"].as_array_mut().into_iter().flatten().filter_map(Value::as_object_mut) {
                let lane = row.get("username").and_then(Value::as_str).and_then(|name| by_user.get(name).copied());
                row.insert("lane".into(), lane.map(Value::from).unwrap_or(Value::Null));
            }
            let mut table = Map::new();
            for lane in &lanes {
                let url = egress::with_credential(
                    router_url.as_deref().unwrap_or(""),
                    &(lane.user.clone(), lane.password.clone()),
                );
                table.insert(lane.lane.clone(), json!({"upstream": url}));
            }
            object_mut(&mut desired)?.insert("lanes".into(), Value::Object(table));
            self.apply(desired.clone())?;
            Ok(lanes_view(&desired))
        })
    }

    pub fn lanes(&self) -> Result<Value> {
        self.synchronized(|| Ok(lanes_view(&self.read_state()?)))
    }

    // ------------------------------------------------------------------ egress: providers

    fn providers(&self, probe: bool) -> Result<Value> {
        let mut providers = Map::new();
        if let Some(url) = self.settings.provider_url.as_deref().filter(|u| !u.is_empty()) {
            let reachable = if probe { Value::Bool((self.hooks.reachability)(url, 3.0, false)?) } else { Value::Null };
            providers.insert("warp".into(), json!({"url": url, "reachable": reachable}));
        }
        if let Some(url) = self.settings.router_url.as_deref().filter(|u| !u.is_empty()) {
            let reachable = if probe { Value::Bool((self.hooks.reachability)(url, 3.0, true)?) } else { Value::Null };
            providers.insert("router".into(), json!({"url": egress::strip_userinfo(url), "reachable": reachable}));
        }
        Ok(Value::Object(providers))
    }

    fn router_credential(&self) -> Result<(String, String)> {
        match (self.settings.router_url.as_deref().filter(|u| !u.is_empty()), &self.settings.router_credential_file) {
            (Some(_), Some(file)) => egress::read_credential(file),
            _ => Err(Error::egress_invalid("egress provider router is not configured on this node")),
        }
    }

    /// The URLs the block may name: WARP as configured, the router with the credential the
    /// file holds right now (read only when the document asks for it).
    fn render_providers(&self, document: &Value) -> Result<Providers> {
        let mut providers = Providers::warp(self.settings.provider_url.as_deref());
        let wants_router =
            document.get("upstream").and_then(|u| u.get("provider")).and_then(Value::as_str) == Some("router");
        if wants_router {
            if let Some(url) = self.settings.router_url.as_deref().filter(|u| !u.is_empty()) {
                providers.router = Some(egress::with_credential(url, &self.router_credential()?));
            }
        }
        Ok(providers)
    }

    fn provider_of(&self, upstream: Option<&str>) -> Option<&'static str> {
        let upstream = upstream?;
        let bare = egress::strip_userinfo(upstream);
        if let Some(url) = self.settings.provider_url.as_deref().filter(|u| !u.is_empty()) {
            if bare == egress::strip_userinfo(url) && !upstream.contains('@') {
                return Some("warp");
            }
        }
        if let Some(url) = self.settings.router_url.as_deref().filter(|u| !u.is_empty()) {
            if bare == egress::strip_userinfo(url) {
                return Some("router");
            }
        }
        None
    }

    /// The router line carries a credential other than the file's (a rotation happened while
    /// this manager was down): the block is re-rendered at bootstrap.
    fn router_credential_stale(&self, parsed: &ParsedEgress) -> Result<bool> {
        if self.provider_of(parsed.upstream.as_deref()) != Some("router") {
            return Ok(false);
        }
        let credential = match self.router_credential() {
            Ok(credential) => credential,
            Err(Error::EgressInvalid(_)) => return Ok(false),
            Err(err) => return Err(err),
        };
        let expected = egress::with_credential(self.settings.router_url.as_deref().unwrap_or(""), &credential);
        Ok(parsed.upstream.as_deref() != Some(expected.as_str()))
    }

    /// The compiled document the block (or the adopted line) amounts to, or `None` for a
    /// `custom` upstream this host has no provider for.
    fn egress_document(&self, parsed: &ParsedEgress) -> Option<Value> {
        let upstream = match &parsed.upstream {
            None => Value::Null,
            Some(upstream) => json!({"provider": self.provider_of(Some(upstream))?}),
        };
        let acl = if parsed.acl_deny.is_empty() { json!([]) } else { json!([{"deny": parsed.acl_deny}]) };
        Some(json!({"schema": egress::SCHEMA, "upstream": upstream, "acl": acl}))
    }

    fn egress_view(&self, state: &Value, parsed: &ParsedEgress, probe: bool) -> Result<Value> {
        let document = self.egress_document(parsed);
        let mut mode = parsed.mode.clone();
        if mode == "custom" && document.is_some() {
            mode = "proxy".into(); // an unmanaged line that already names the provider
        }
        let journal = object(&state["egress"])?;
        let mut warnings = Vec::new();
        if parsed.upstream.is_some() && !parsed.managed {
            warnings.push("adopts_unmanaged_upstream");
        }
        if self.router_credential_stale(parsed)? {
            warnings.push("router_credential_stale");
        }
        let previous = match &journal["previous"] {
            Value::Null => Value::Null,
            previous => json!({"revision": field(previous, "revision")?}),
        };
        let current = match &journal["current"] {
            Value::Null => Value::Null,
            current => {
                let mut view = Map::new();
                for key in ["revision", "rendered_sha256", "operation_id", "applied_at"] {
                    view.insert(key.into(), field(current, key)?.clone());
                }
                Value::Object(view)
            }
        };
        Ok(json!({
            "revision": parsed.revision,
            "mode": mode,
            "upstream": parsed.upstream.as_deref().map(egress::redact_userinfo),
            "acl": parsed.acl_deny,
            "document": document,
            "managed": parsed.managed,
            "providers": self.providers(probe)?,
            "capabilities": egress::CAPABILITIES,
            "restart_required": false,
            "warnings": warnings,
            "previous": previous,
            "current": current,
        }))
    }

    pub fn egress(&self) -> Result<Value> {
        self.synchronized(|| {
            let state = self.read_state()?;
            let parsed = egress::parse(&read_text(&self.settings.caddyfile)?)?;
            self.egress_view(&state, &parsed, true)
        })
    }

    fn check_revision(parsed: &ParsedEgress, expected: &str) -> Result<()> {
        if !compare_digest(&parsed.revision, expected)? {
            return Err(Error::conflict_code("egress revision does not match", "egress_conflict"));
        }
        Ok(())
    }

    /// Validate, check the revision, render: what every plan and apply starts with.
    fn egress_target(&self, expected_revision: &str, document: &Value) -> Result<(Value, ParsedEgress, Value, String)> {
        let normalised = egress::validate_document(document)?;
        let state = self.read_state()?;
        self.assert_consistent(&state)?;
        let text = read_text(&self.settings.caddyfile)?;
        let parsed = egress::parse(&text)?;
        Self::check_revision(&parsed, expected_revision)?;
        let rendered = egress::render(&text, &normalised, &self.render_providers(&normalised)?)?;
        Ok((state, parsed, normalised, rendered))
    }

    /// The provider the document names answers its SOCKS5 greeting (direct: nothing to ask).
    fn provider_reachable(&self, document: &Value) -> Result<bool> {
        let provider = document.get("upstream").and_then(|u| u.get("provider")).and_then(Value::as_str);
        match provider {
            None => Ok(true),
            Some("router") => match self.settings.router_url.as_deref().filter(|u| !u.is_empty()) {
                Some(url) => (self.hooks.reachability)(url, 3.0, true),
                None => Ok(false),
            },
            Some(_) => match self.settings.provider_url.as_deref() {
                Some(url) => (self.hooks.reachability)(url, 3.0, false),
                None => Ok(false),
            },
        }
    }

    pub fn egress_plan(&self, expected_revision: &str, document: &Value) -> Result<Value> {
        self.synchronized(|| {
            let (_state, parsed, normalised, rendered) = self.egress_target(expected_revision, document)?;
            let before_text = join_lines(&parsed.raw_lines);
            let after_text = join_lines(&egress::parse(&rendered)?.raw_lines);
            let before = splitlines(&before_text);
            let after = splitlines(&after_text);
            let diff: Vec<String> = crate::difflib::changed_lines(&before, &after)
                .iter()
                .map(|line| egress::redact_userinfo(line))
                .collect();
            let mut reachability = Map::new();
            if let Some(provider) = normalised["upstream"].get("provider").and_then(Value::as_str) {
                reachability.insert(provider.into(), Value::Bool(self.provider_reachable(&normalised)?));
            }
            let warnings: Vec<&str> =
                if parsed.upstream.is_some() && !parsed.managed { vec!["adopts_unmanaged_upstream"] } else { vec![] };
            Ok(json!({
                "revision": parsed.revision,
                "target_revision": egress::revision_of(&rendered)?,
                "rendered_sha256": sha256_hex(rendered.as_bytes()),
                "diff": diff,
                "warnings": warnings,
                "reachability": reachability,
                "restart_required": false,
            }))
        })
    }

    /// Writes the block, reloads, reads the running config back; the previous entry stays in
    /// the journal for `egress_rollback`. Idempotent by `operation_id`: a retry after a lost
    /// reply gets the same answer without a second reload.
    pub fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> Result<Value> {
        self.lifecycle(|_| {
            if !state::is_operation_id(operation_id) {
                return Err(Error::value("invalid operation id"));
            }
            let normalised = egress::validate_document(document)?;
            let state = self.read_state()?;
            let current = &state["egress"]["current"];
            if !current.is_null() && object(current)?.get("operation_id").and_then(Value::as_str) == Some(operation_id)
            {
                if field(current, "document")? != &normalised {
                    return Err(Error::conflict_code(
                        "operation id already used for another request",
                        "operation_conflict",
                    ));
                }
                return Ok(json!({
                    "revision": field(current, "revision")?,
                    "applied": field(current, "document")?,
                    "readback_sha256": field(current, "rendered_sha256")?,
                    "replayed": true,
                }));
            }
            let (state, parsed, normalised, rendered) = self.egress_target(expected_revision, document)?;
            if !self.provider_reachable(&normalised)? {
                let provider = normalised["upstream"]["provider"].as_str().unwrap_or("");
                return Err(Error::EgressUnreachable(format!("egress provider {provider} is unreachable")));
            }
            let entry = json!({
                "document": normalised,
                "revision": egress::revision_of(&rendered)?,
                "rendered_sha256": sha256_hex(rendered.as_bytes()),
                "operation_id": operation_id,
                "applied_at": now_iso(),
            });
            self.egress_transaction(&state, &rendered, entry.clone(), &parsed, false)?;
            Ok(json!({
                "revision": entry["revision"],
                "applied": normalised,
                "readback_sha256": entry["rendered_sha256"],
                "replayed": false,
            }))
        })
    }

    /// Back to the previous journal entry: a managed document, or the unmanaged lines the
    /// first apply adopted (restored verbatim).
    pub fn egress_rollback(&self, expected_revision: &str) -> Result<Value> {
        self.lifecycle(|_| {
            let state = self.read_state()?;
            self.assert_consistent(&state)?;
            let text = read_text(&self.settings.caddyfile)?;
            let parsed = egress::parse(&text)?;
            Self::check_revision(&parsed, expected_revision)?;
            let previous = state["egress"]["previous"].clone();
            if previous.is_null() {
                return Err(Error::conflict_code("no previous egress to roll back to", "egress_no_previous"));
            }
            let previous_document = object(&previous)?.get("document").cloned().unwrap_or(Value::Null);
            let rendered = if !previous_document.is_null() {
                let rendered = egress::render(&text, &previous_document, &self.render_providers(&previous_document)?)?;
                if !self.provider_reachable(&previous_document)? {
                    let provider = previous_document["upstream"]["provider"].as_str().unwrap_or("");
                    return Err(Error::EgressUnreachable(format!("egress provider {provider} is unreachable")));
                }
                rendered
            } else {
                egress::render_raw(&text, &raw_lines(field(&previous, "raw_lines")?)?)?
            };
            let entry = json!({
                "document": previous_document,
                "revision": egress::revision_of(&rendered)?,
                "rendered_sha256": sha256_hex(rendered.as_bytes()),
                "operation_id": null,
                "applied_at": now_iso(),
                "raw_lines": object(&previous)?.get("raw_lines").cloned().unwrap_or(Value::Null),
            });
            self.egress_transaction(&state, &rendered, entry.clone(), &parsed, true)?;
            Ok(json!({"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["rendered_sha256"]}))
        })
    }

    /// The journal is a stack of what was applied, oldest first; its floor is what the
    /// Caddyfile had before the first apply (the adopted lines, kept verbatim). An apply
    /// pushes, a rollback pops — so repeated rollbacks walk back to the floor.
    fn egress_transaction(
        &self,
        state: &Value,
        rendered: &str,
        entry: Value,
        parsed: &ParsedEgress,
        rollback: bool,
    ) -> Result<()> {
        let mut history: Vec<Value> = state["egress"]["history"].as_array().cloned().unwrap_or_default();
        if rollback {
            history.pop();
            match history.last_mut() {
                Some(last) => *last = entry.clone(), // the restored entry, re-stamped
                None => return Err(Error::Other("list assignment index out of range".into())),
            }
        } else {
            if state["egress"]["current"].is_null() {
                history = vec![json!({
                    "document": null,
                    "revision": parsed.revision,
                    "raw_lines": parsed.raw_lines,
                    "rendered_sha256": null,
                    "operation_id": null,
                    "applied_at": null,
                })];
            }
            history.push(entry.clone());
            if history.len() > 10 {
                history.drain(..history.len() - 10);
            }
        }
        let readback = self.egress_readback(&entry)?;
        let mut desired = state.clone();
        let previous = if history.len() > 1 { history[history.len() - 2].clone() } else { Value::Null };
        let journal = json!({"current": history[history.len() - 1], "previous": previous, "history": history});
        object_mut(&mut desired)?.insert("egress".into(), journal);
        self.commit(rendered, &desired, Some(readback))
    }

    /// After a credential rotation the router line still carries the old key: the block is a
    /// function of the document and the file, so it is rendered again. A managed block keeps
    /// its journal entry (re-stamped, nothing pushed); the installer's seed — an unmanaged line
    /// naming the router — is adopted the way a first apply would adopt it.
    pub(crate) fn refresh_router_credential(&self, state: Value) -> Result<()> {
        let text = read_text(&self.settings.caddyfile)?;
        let Ok(parsed) = egress::parse(&text) else { return Ok(()) };
        if !self.router_credential_stale(&parsed)? {
            return Ok(());
        }
        let Some(document) = self.egress_document(&parsed) else { return Ok(()) };
        let rendered = egress::render(&text, &document, &self.render_providers(&document)?)?;
        if !parsed.managed || state["egress"]["current"].is_null() {
            let entry = json!({
                "document": document,
                "revision": egress::revision_of(&rendered)?,
                "rendered_sha256": sha256_hex(rendered.as_bytes()),
                "operation_id": null,
                "applied_at": now_iso(),
            });
            return self.egress_transaction(&state, &rendered, entry, &parsed, false);
        }
        let mut desired = state.clone();
        let mut current = object(&desired["egress"]["current"])?.clone();
        current.insert("revision".into(), json!(egress::revision_of(&rendered)?));
        current.insert("rendered_sha256".into(), json!(sha256_hex(rendered.as_bytes())));
        let current = Value::Object(current);
        desired["egress"]["current"] = current.clone();
        if let Some(last) = desired["egress"]["history"].as_array_mut().and_then(|h| h.last_mut()) {
            *last = current.clone();
        }
        let readback = self.egress_readback(&current)?;
        self.commit(&rendered, &desired, Some(readback))
    }

    /// What the running configuration must show after `entry` is applied: its upstream and
    /// its ACL subjects on the service's own handler.
    fn egress_readback(&self, entry: &Value) -> Result<Readback> {
        let document = entry.get("document").cloned().unwrap_or(Value::Null);
        let (expected_upstream, expected_deny): (Option<String>, Vec<String>) = if !document.is_null() {
            let upstream = egress::resolve_provider(&document, &self.render_providers(&document)?)?;
            let deny = document["acl"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|rule| rule["deny"].as_array().cloned().unwrap_or_default())
                .filter_map(|item| item.as_str().map(String::from))
                .collect();
            (upstream, deny)
        } else if let Some(lines) = entry.get("raw_lines").filter(|v| v.as_array().is_some_and(|a| !a.is_empty())) {
            let synthetic = format!("forward_proxy {{\n{}\n}}\n", join_lines(&raw_lines(lines)?));
            let parsed = egress::parse(&synthetic)?;
            (parsed.upstream, parsed.acl_deny)
        } else {
            (None, Vec::new())
        };
        Ok(Box::new(move |config: &Value| {
            let handler = forward_proxy_handler(config)?;
            let upstream = handler.get("upstream").cloned().unwrap_or(Value::Null);
            if upstream != expected_upstream.clone().map(Value::from).unwrap_or(Value::Null) {
                return Err(Error::conflict_code(
                    "running upstream differs from the applied egress",
                    "egress_readback_mismatch",
                ));
            }
            let mut subjects: Vec<String> = Vec::new();
            for rule in handler.get("acl").and_then(Value::as_array).into_iter().flatten() {
                for item in rule.get("subjects").and_then(Value::as_array).into_iter().flatten() {
                    subjects.push(item.as_str().map(String::from).unwrap_or_else(|| item.to_string()));
                }
            }
            let mut expected = expected_deny.clone();
            subjects.sort();
            expected.sort();
            if subjects != expected {
                return Err(Error::conflict_code(
                    "running acl differs from the applied egress",
                    "egress_readback_mismatch",
                ));
            }
            Ok(())
        }))
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    object(value)?.get(key).ok_or_else(|| Error::Key(format!("'{key}'")))
}

fn raw_lines(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| Error::Other("raw_lines is not a list".into()))?
        .iter()
        .map(|line| line.as_str().map(String::from).ok_or_else(|| Error::Other("raw_lines holds a non-string".into())))
        .collect()
}

/// The service's own handler is the last `forward_proxy`: lane handlers precede it.
fn forward_proxy_handler(config: &Value) -> Result<Map<String, Value>> {
    handlers(config)
        .into_iter()
        .rfind(|h| h["handler"] == "forward_proxy")
        .cloned()
        .ok_or_else(|| Error::conflict_code("unexpected proxy handler", "egress_readback_mismatch"))
}

fn lanes_view(state: &Value) -> Value {
    let users = state["users"].as_array().cloned().unwrap_or_default();
    let mut view = Vec::new();
    for (lane, entry) in state.get("lanes").and_then(Value::as_object).into_iter().flatten() {
        let members: Vec<&Value> =
            users.iter().filter(|row| row.get("lane").and_then(Value::as_str) == Some(lane)).collect();
        view.push(json!({
            "lane": lane,
            "users": members.iter().map(|row| row["username"].clone()).collect::<Vec<_>>(),
            "upstream": egress::redact_userinfo(entry["upstream"].as_str().unwrap_or("")),
            "enabled_users": members.iter().filter(|row| row["enabled"] == Value::Bool(true)).count(),
        }));
    }
    json!({"lanes": view})
}
