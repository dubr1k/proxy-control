//! What each adapter needs from its client, as traits the `panel_managers` clients implement.
//!
//! The Python adapters take any object with the right coroutines (the real client or its
//! in-memory twin); here an adapter is generic over one of these traits, with the real client as
//! the default type, so tests can hand it a replaying client. Every method answers what the
//! Python client's coroutine returns (decoded JSON, `Value::Null` for `None`).
//!
//! Where a Python adapter passes a value the Rust client types more narrowly (a Mieru revision
//! that may be `None`, a quota of any JSON type, a Telemt reload id), the trait takes the value and
//! the implementation sends it as the Python client would.

use std::future::Future;

use panel_core::pytext;
use panel_managers::{
    AmneziawgClient, ManagerError, MieruClient, NaiveClient, TelemtAccess, TelemtClient, TelemtError,
    TrusttunnelClient, XrayRouterClient,
};
use serde_json::{json, Value};

/// A manager client's answer.
pub type ManagerResult<T = Value> = Result<T, ManagerError>;
/// Telemt's answer.
pub type TelemtResult<T = Value> = Result<T, TelemtError>;

/// `NaiveClient` as `NaiveAdapter` uses it.
pub trait NaiveApi: Send + Sync {
    fn list_users(&self) -> impl Future<Output = ManagerResult> + Send;
    /// `create(username, quota_bytes, password=…, operation_id=…)`.
    fn create(
        &self,
        username: &str,
        quota_bytes: Option<i64>,
        password: &str,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn reveal(&self, username: &str) -> impl Future<Output = ManagerResult> + Send;
    /// `rotate(username, password=…, operation_id=…)`.
    fn rotate(&self, username: &str, password: &str, operation_id: &str) -> impl Future<Output = ManagerResult> + Send;
    fn set_enabled(&self, username: &str, enabled: bool) -> impl Future<Output = ManagerResult> + Send;
    fn set_quota(&self, username: &str, quota_bytes: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn delete(&self, username: &str) -> impl Future<Output = ManagerResult> + Send;
    fn egress(&self) -> impl Future<Output = ManagerResult> + Send;
    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send;
    fn lanes(&self) -> impl Future<Output = ManagerResult> + Send;
    fn set_lanes(&self, lanes: &Value) -> impl Future<Output = ManagerResult> + Send;
}

/// `MieruClient` as `MieruAdapter` uses it.
pub trait MieruApi: Send + Sync {
    fn health(&self) -> impl Future<Output = ManagerResult> + Send;
    fn list_users(&self) -> impl Future<Output = ManagerResult> + Send;
    fn create(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn operation(
        &self,
        username: &str,
        operation: &str,
        revision: &Value,
    ) -> impl Future<Output = ManagerResult> + Send;
    /// `rotate(username, revision, password=…, operation_id=…)`.
    fn rotate(
        &self,
        username: &str,
        revision: &Value,
        password: &str,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn delete(&self, username: &str, revision: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn set_quotas(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress(&self) -> impl Future<Output = ManagerResult> + Send;
    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send;
    fn lanes(&self) -> impl Future<Output = ManagerResult> + Send;
    fn set_lanes(&self, lanes: &Value) -> impl Future<Output = ManagerResult> + Send;
}

/// `AmneziawgClient` as `AmneziawgAdapter` uses it.
pub trait AmneziawgApi: Send + Sync {
    /// The `instances` list.
    fn instances(&self) -> impl Future<Output = ManagerResult> + Send;
    /// The `peers` list.
    fn peers(&self) -> impl Future<Output = ManagerResult> + Send;
    fn create_peer(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn peer_state(&self, username: &str, action: &str) -> impl Future<Output = ManagerResult> + Send;
    fn rotate_peer(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn delete_peer(&self, username: &str) -> impl Future<Output = ManagerResult> + Send;
    fn egress(&self) -> impl Future<Output = ManagerResult> + Send;
    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send;
}

/// `TrusttunnelClient` as `TrusttunnelAdapter` uses it.
pub trait TrusttunnelApi: Send + Sync {
    fn endpoint(&self) -> impl Future<Output = ManagerResult> + Send;
    /// The `clients` list.
    fn clients(&self) -> impl Future<Output = ManagerResult> + Send;
    fn create_client(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn client_state(&self, username: &str, action: &str) -> impl Future<Output = ManagerResult> + Send;
    fn rotate_client(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn delete_client(&self, username: &str) -> impl Future<Output = ManagerResult> + Send;
    fn egress(&self) -> impl Future<Output = ManagerResult> + Send;
    fn egress_plan(&self, document: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress_apply(&self, document: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn egress_rollback(&self) -> impl Future<Output = ManagerResult> + Send;
}

/// `XrayRouterClient` as `RouterAdapter` uses it.
pub trait RouterApi: Send + Sync {
    fn status(&self) -> impl Future<Output = ManagerResult> + Send;
    fn egress(&self, service: &str) -> impl Future<Output = ManagerResult> + Send;
    fn egress_plan(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn egress_apply(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send;
    fn egress_rollback(&self, service: &str, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send;
    fn lanes(&self, service: &str) -> impl Future<Output = ManagerResult> + Send;
    fn lane_issue(&self, service: &str, lane: &str) -> impl Future<Output = ManagerResult> + Send;
    fn lane_forget(&self, service: &str, lane: &str) -> impl Future<Output = ManagerResult> + Send;
    fn relay(&self) -> impl Future<Output = ManagerResult> + Send;
    fn ingress(&self, service: &str) -> impl Future<Output = ManagerResult> + Send;
    fn relay_enable(&self, server_name: &str, port: i64) -> impl Future<Output = ManagerResult> + Send;
    fn relay_disable(&self) -> impl Future<Output = ManagerResult> + Send;
    fn relay_set_accounts(&self, accounts: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn exit_test(&self, spec: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn geodata(&self) -> impl Future<Output = ManagerResult> + Send;
    fn geodata_codes(&self) -> impl Future<Output = ManagerResult> + Send;
    fn geodata_settings(&self, body: &Value) -> impl Future<Output = ManagerResult> + Send;
    fn geodata_update(&self) -> impl Future<Output = ManagerResult> + Send;
    fn geodata_restore(&self) -> impl Future<Output = ManagerResult> + Send;
}

/// `TelemtClient` as `TelemtAdapter` uses it.
pub trait TelemtApi: Send + Sync {
    /// What `async with client.batch():` holds (one inventory read serves the batch).
    type Batch: Send;
    fn batch(&self) -> Self::Batch;
    fn list_users(&self) -> impl Future<Output = TelemtResult> + Send;
    fn create_user(&self, username: &str, secret: Option<&str>) -> impl Future<Output = TelemtResult> + Send;
    fn delete_user(&self, username: &str) -> impl Future<Output = TelemtResult> + Send;
    fn set_enabled(&self, username: &str, enabled: bool) -> impl Future<Output = TelemtResult> + Send;
    fn rotate(&self, username: &str, secret: Option<&str>) -> impl Future<Output = TelemtResult> + Send;
    fn update_user(&self, username: &str, fields: &Value) -> impl Future<Output = TelemtResult> + Send;
    fn current_access(&self, username: &str) -> impl Future<Output = TelemtResult<Option<TelemtAccess>>> + Send;
    /// `(data, revision)` of `GET /v1/config`.
    fn config(&self) -> impl Future<Output = TelemtResult<(Value, Value)>> + Send;
    fn patch_config(&self, body: &Value, revision: &str) -> impl Future<Output = TelemtResult<(Value, Value)>> + Send;
    fn reload(&self, revision: &Value) -> impl Future<Output = TelemtResult> + Send;
    fn reload_status(&self, reload_id: &Value) -> impl Future<Output = TelemtResult> + Send;
}

impl NaiveApi for NaiveClient {
    fn list_users(&self) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::list_users(self)
    }

    fn create(
        &self,
        username: &str,
        quota_bytes: Option<i64>,
        password: &str,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::create(self, username, quota_bytes, Some(password), Some(operation_id))
    }

    fn reveal(&self, username: &str) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::reveal(self, username)
    }

    fn rotate(&self, username: &str, password: &str, operation_id: &str) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::rotate(self, username, Some(password), Some(operation_id))
    }

    fn set_enabled(&self, username: &str, enabled: bool) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::set_enabled(self, username, enabled)
    }

    async fn set_quota(&self, username: &str, quota_bytes: &Value) -> ManagerResult {
        let path = format!("/v1/users/{}/quota", pytext::quote_path(username));
        self.raw().request("POST", &path, Some(&json!({"quota_bytes": quota_bytes})), None).await
    }

    fn delete(&self, username: &str) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::delete(self, username)
    }

    fn egress(&self) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::egress(self)
    }

    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::egress_plan(self, expected_revision, document)
    }

    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::egress_apply(self, expected_revision, document, operation_id)
    }

    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::egress_rollback(self, expected_revision)
    }

    fn lanes(&self) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::lanes(self)
    }

    fn set_lanes(&self, lanes: &Value) -> impl Future<Output = ManagerResult> + Send {
        NaiveClient::set_lanes(self, lanes)
    }
}

/// `/v1/users/{quote(username, safe='')}…` of the Mieru client.
fn mieru_user(username: &str, tail: &str) -> String {
    format!("/v1/users/{}{tail}", pytext::quote(username, ""))
}

impl MieruApi for MieruClient {
    fn health(&self) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::health(self)
    }

    fn list_users(&self) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::list_users(self)
    }

    fn create(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::create(self, payload)
    }

    async fn operation(&self, username: &str, operation: &str, revision: &Value) -> ManagerResult {
        let body = json!({"expected_revision": revision});
        self.raw().request("POST", &mieru_user(username, &format!("/{operation}")), Some(&body), None).await
    }

    async fn rotate(&self, username: &str, revision: &Value, password: &str, operation_id: &str) -> ManagerResult {
        let body = json!({"expected_revision": revision, "password": password, "operation_id": operation_id});
        self.raw().request("POST", &mieru_user(username, "/rotate"), Some(&body), None).await
    }

    async fn delete(&self, username: &str, revision: &Value) -> ManagerResult {
        let body = json!({"expected_revision": revision});
        self.raw().request("DELETE", &mieru_user(username, ""), Some(&body), None).await
    }

    fn set_quotas(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::set_quotas(self, username, payload)
    }

    fn egress(&self) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::egress(self)
    }

    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::egress_plan(self, expected_revision, document)
    }

    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::egress_apply(self, expected_revision, document, operation_id)
    }

    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::egress_rollback(self, expected_revision)
    }

    fn lanes(&self) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::lanes(self)
    }

    fn set_lanes(&self, lanes: &Value) -> impl Future<Output = ManagerResult> + Send {
        MieruClient::set_lanes(self, lanes)
    }
}

impl AmneziawgApi for AmneziawgClient {
    fn instances(&self) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::instances(self)
    }

    fn peers(&self) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::peers(self)
    }

    fn create_peer(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::create_peer(self, payload)
    }

    fn peer_state(&self, username: &str, action: &str) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::peer_state(self, username, action)
    }

    fn rotate_peer(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::rotate_peer(self, username, payload)
    }

    fn delete_peer(&self, username: &str) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::delete_peer(self, username)
    }

    fn egress(&self) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::egress(self)
    }

    fn egress_plan(&self, expected_revision: &str, document: &Value) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::egress_plan(self, expected_revision, document)
    }

    fn egress_apply(
        &self,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::egress_apply(self, expected_revision, document, operation_id)
    }

    fn egress_rollback(&self, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send {
        AmneziawgClient::egress_rollback(self, expected_revision)
    }
}

impl TrusttunnelApi for TrusttunnelClient {
    fn endpoint(&self) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::endpoint(self)
    }

    fn clients(&self) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::clients(self)
    }

    fn create_client(&self, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::create_client(self, payload)
    }

    fn client_state(&self, username: &str, action: &str) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::client_state(self, username, action)
    }

    fn rotate_client(&self, username: &str, payload: &Value) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::rotate_client(self, username, payload)
    }

    fn delete_client(&self, username: &str) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::delete_client(self, username)
    }

    fn egress(&self) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::egress(self)
    }

    fn egress_plan(&self, document: &Value) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::egress_plan(self, document)
    }

    fn egress_apply(&self, document: &Value) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::egress_apply(self, document)
    }

    fn egress_rollback(&self) -> impl Future<Output = ManagerResult> + Send {
        TrusttunnelClient::egress_rollback(self)
    }
}

impl RouterApi for XrayRouterClient {
    fn status(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::status(self)
    }

    fn egress(&self, service: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::egress(self, service)
    }

    fn egress_plan(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
    ) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::egress_plan(self, service, expected_revision, document)
    }

    fn egress_apply(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::egress_apply(self, service, expected_revision, document, operation_id)
    }

    fn egress_rollback(&self, service: &str, expected_revision: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::egress_rollback(self, service, expected_revision)
    }

    fn lanes(&self, service: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::lanes(self, service)
    }

    fn lane_issue(&self, service: &str, lane: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::lane_issue(self, service, lane)
    }

    fn lane_forget(&self, service: &str, lane: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::lane_forget(self, service, lane)
    }

    fn relay(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::relay(self)
    }

    fn ingress(&self, service: &str) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::ingress(self, service)
    }

    fn relay_enable(&self, server_name: &str, port: i64) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::relay_enable(self, server_name, port)
    }

    fn relay_disable(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::relay_disable(self)
    }

    fn relay_set_accounts(&self, accounts: &Value) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::relay_set_accounts(self, accounts)
    }

    fn exit_test(&self, spec: &Value) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::exit_test(self, spec)
    }

    fn geodata(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::geodata(self)
    }

    fn geodata_codes(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::geodata_codes(self)
    }

    fn geodata_settings(&self, body: &Value) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::geodata_settings(self, body)
    }

    fn geodata_update(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::geodata_update(self)
    }

    fn geodata_restore(&self) -> impl Future<Output = ManagerResult> + Send {
        XrayRouterClient::geodata_restore(self)
    }
}

impl TelemtApi for TelemtClient {
    type Batch = panel_managers::TelemtBatch;

    fn batch(&self) -> Self::Batch {
        TelemtClient::batch(self)
    }

    fn list_users(&self) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::list_users(self)
    }

    fn create_user(&self, username: &str, secret: Option<&str>) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::create_user(self, username, secret)
    }

    fn delete_user(&self, username: &str) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::delete_user(self, username)
    }

    fn set_enabled(&self, username: &str, enabled: bool) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::set_enabled(self, username, enabled)
    }

    fn rotate(&self, username: &str, secret: Option<&str>) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::rotate(self, username, secret)
    }

    fn update_user(&self, username: &str, fields: &Value) -> impl Future<Output = TelemtResult> + Send {
        TelemtClient::update_user(self, username, fields)
    }

    fn current_access(&self, username: &str) -> impl Future<Output = TelemtResult<Option<TelemtAccess>>> + Send {
        TelemtClient::current_access(self, username)
    }

    fn config(&self) -> impl Future<Output = TelemtResult<(Value, Value)>> + Send {
        TelemtClient::config(self)
    }

    fn patch_config(&self, body: &Value, revision: &str) -> impl Future<Output = TelemtResult<(Value, Value)>> + Send {
        TelemtClient::patch_config(self, body, revision)
    }

    /// The revision is an `If-Match` header: Python passed whatever Telemt's envelope carried; a
    /// value that is not a string is sent as its `str()`.
    async fn reload(&self, revision: &Value) -> TelemtResult {
        let revision = match revision {
            Value::String(text) => text.clone(),
            other => panel_model::pyrepr::str(other),
        };
        TelemtClient::reload(self, &revision).await
    }

    /// `GET /v1/system/reload/{reload_id}` with Python's `str()` of the id (`None` included).
    async fn reload_status(&self, reload_id: &Value) -> TelemtResult {
        match reload_id.as_i64() {
            Some(id) if !reload_id.is_f64() => TelemtClient::reload_status(self, id).await,
            _ => {
                let path = format!("/v1/system/reload/{}", panel_model::pyrepr::str(reload_id));
                Ok(self.request(panel_managers::telemt::Method::GET, &path, None, None).await?.0)
            }
        }
    }
}
