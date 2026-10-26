//! NaiveProxy: the caller chooses the password, so a lost reply is replayed, not guessed
//! (`protocols/naive.py`).

use panel_core::pytext;
use panel_managers::{ManagerError, NaiveClient};
use panel_model::clients::{AccessGrant, GrantIntent, ProtocolOptions};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    applied_egress_from_view, egress_error, egress_target_from_view, AccessArtifact, AdapterError, AppliedEgress,
    AppliedGrant, AutoRefresh, CredentialPlan, EgressTarget, GrantRef, ObservedGrant, ObservedInventory, Preflight,
};
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::api::NaiveApi;
use crate::error::{crash, raw_manager};
use crate::util::{as_object, decode_utf8, rows};

/// `urlsplit(proxy_url).password` (still percent-encoded, as Python leaves it).
fn password_of(proxy_url: &str) -> Result<Option<String>, AdapterError> {
    let parts = pytext::urlsplit(proxy_url).map_err(|error| crash(error.to_string()))?;
    Ok(parts.password().map(str::to_string))
}

/// `https://{quote(username, safe='')}:{quote(password, safe='')}@{host}`.
pub fn proxy_url(username: &str, password: &str, host: &str) -> String {
    format!("https://{}:{}@{host}", pytext::quote(username, ""), pytext::quote(password, ""))
}

/// The NaiveProxy adapter over the naive-manager's client.
pub struct NaiveAdapter<C = NaiveClient> {
    client: C,
    public_host: String,
}

impl<C: NaiveApi> NaiveAdapter<C> {
    pub fn new(client: C, public_host: impl Into<String>) -> Self {
        Self { client, public_host: public_host.into() }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn public_host(&self) -> &str {
        &self.public_host
    }

    async fn exists(&self, username: &str) -> Result<bool, AdapterError> {
        let listed = self.client.list_users().await.map_err(raw_manager)?;
        Ok(rows(&listed)?.into_iter().any(|row| row.get("username") == Some(&json!(username))))
    }

    pub async fn discover(&self) -> Result<ObservedInventory, AdapterError> {
        let listed = self.client.list_users().await.map_err(raw_manager)?;
        let items = rows(&listed)?
            .into_iter()
            .filter_map(|row| {
                let username = row.get("username")?.as_str()?;
                Some(ObservedGrant {
                    runtime_username: username.to_string(),
                    enabled: row.get("enabled") == Some(&Value::Bool(true)),
                    options: Map::from_iter([(
                        "quota_bytes".to_string(),
                        row.get("quota_bytes").cloned().unwrap_or(Value::Null),
                    )]),
                    revision: None,
                })
            })
            .collect();
        Ok(ObservedInventory { items })
    }

    pub async fn preflight(&self, intent: &GrantIntent) -> Result<Preflight, AdapterError> {
        if self.exists(&intent.runtime_username).await? {
            return Ok(Preflight { ok: false, reason: Some("runtime username already exists".into()) });
        }
        Ok(Preflight { ok: true, reason: None })
    }

    fn applied(&self, username: &str, password: &str, enabled: bool, recovered: bool) -> AppliedGrant {
        AppliedGrant {
            credential: Some(password.as_bytes().to_vec()),
            artifact_template: Map::from_iter([("host".to_string(), json!(self.public_host))]),
            recovered,
            ..AppliedGrant::new(username, enabled)
        }
    }

    fn password(credential: &CredentialPlan) -> Result<String, AdapterError> {
        if credential.origin() != CredentialOrigin::Caller {
            return Err(AdapterError::new("NaiveProxy needs a caller-supplied password"));
        }
        decode_utf8(credential.plaintext().unwrap_or_default())
    }

    fn unrecoverable(error: &ManagerError) -> AdapterError {
        if matches!(error.code.as_deref(), Some("result_unrecoverable" | "operation_conflict")) {
            return AdapterError::manual_intervention("the NaiveProxy credential must be rotated", None);
        }
        AdapterError::new("NaiveProxy refused the request")
    }

    pub async fn create(
        &self,
        operation_id: &str,
        intent: &GrantIntent,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let password = Self::password(credential)?;
        let quota = match &intent.options {
            ProtocolOptions::Naive(options) => options.quota_bytes,
            _ => None,
        };
        let username = &intent.runtime_username;
        // The manager may have committed before the reply was lost: the same operation id either
        // replays that result or creates the account once.
        let recovered = match self.client.create(username, quota, &password, operation_id).await {
            Ok(_) => false,
            Err(_) => {
                self.client
                    .create(username, quota, &password, operation_id)
                    .await
                    .map_err(|error| Self::unrecoverable(&error))?;
                true
            }
        };
        Ok(self.applied(username, &password, true, recovered))
    }

    async fn set_enabled(&self, grant: &GrantRef, enabled: bool) -> Result<AppliedGrant, AdapterError> {
        let refused = |_| AdapterError::new("NaiveProxy refused the request");
        self.client.set_enabled(&grant.runtime_username, enabled).await.map_err(refused)?;
        let revealed = self.client.reveal(&grant.runtime_username).await.map_err(refused)?;
        let url = match as_object(&revealed)?.get("proxy_url") {
            Some(Value::String(url)) => url.clone(),
            _ => return Err(crash("the NaiveProxy manager revealed no proxy_url")),
        };
        let password = password_of(&url)?.unwrap_or_default();
        Ok(self.applied(&grant.runtime_username, &password, enabled, false))
    }

    pub async fn enable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.set_enabled(grant, true).await
    }

    pub async fn disable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.set_enabled(grant, false).await
    }

    pub async fn rotate(
        &self,
        operation_id: &str,
        grant: &GrantRef,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let password = Self::password(credential)?;
        let username = &grant.runtime_username;
        let recovered = match self.client.rotate(username, &password, operation_id).await {
            Ok(_) => false,
            Err(_) => {
                self.client
                    .rotate(username, &password, operation_id)
                    .await
                    .map_err(|error| Self::unrecoverable(&error))?;
                true
            }
        };
        Ok(self.applied(username, &password, true, recovered))
    }

    pub async fn delete(&self, grant: &GrantRef) -> Result<(), AdapterError> {
        match self.client.delete(&grant.runtime_username).await {
            Ok(_) => Ok(()),
            Err(error) if error.status_code == 404 => Err(AdapterError::already_gone("NaiveProxy refused the request")),
            Err(_) => Err(AdapterError::new("NaiveProxy refused the request")),
        }
    }

    pub async fn update_options(
        &self,
        grant: &GrantRef,
        options: &Map<String, Value>,
    ) -> Result<Option<AppliedGrant>, AdapterError> {
        let Some(quota) = options.get("quota_bytes") else { return Ok(None) };
        self.client
            .set_quota(&grant.runtime_username, quota)
            .await
            .map_err(|_| AdapterError::new("NaiveProxy refused the request"))?;
        Ok(Some(AppliedGrant {
            credential: Some(Vec::new()),
            artifact_template: Map::from_iter([("host".to_string(), json!(self.public_host))]),
            ..AppliedGrant::new(&grant.runtime_username, true)
        }))
    }

    /// The manager reveals the stored password, so adoption needs no rotation.
    pub async fn capture(&self, grant: &GrantRef) -> Result<Option<Vec<u8>>, AdapterError> {
        let revealed = self
            .client
            .reveal(&grant.runtime_username)
            .await
            .map_err(|_| AdapterError::new("NaiveProxy refused the request"))?;
        let url = match as_object(&revealed)?.get("proxy_url") {
            None => String::new(),
            Some(Value::String(url)) => url.clone(),
            Some(_) => return Err(crash("the NaiveProxy manager revealed a proxy_url that is not text")),
        };
        Ok(password_of(&url)?.filter(|password| !password.is_empty()).map(String::into_bytes))
    }

    pub fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        let url = proxy_url(&grant.runtime_username, &decode_utf8(credential)?, public_host);
        Ok(vec![AccessArtifact {
            kind: "proxy_url".into(),
            label: "Адрес прокси".into(),
            media_type: "text/uri-list".into(),
            value: url,
            auto_refresh: AutoRefresh::Supported,
        }])
    }

    fn egress_failure(error: ManagerError) -> AdapterError {
        egress_error("NaiveProxy", error.status_code, error.code.as_deref())
    }

    pub async fn egress_target(&self) -> Result<Option<EgressTarget>, AdapterError> {
        let view = self.client.egress().await.map_err(Self::egress_failure)?;
        Ok(Some(egress_target_from_view("naive", Backend::NaiveNative, as_object(&view)?)))
    }

    pub async fn plan_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
    ) -> Result<Map<String, Value>, AdapterError> {
        let document = Value::Object(document.clone());
        let plan = self.client.egress_plan(expected_revision, &document).await.map_err(Self::egress_failure)?;
        Ok(as_object(&plan)?.clone())
    }

    pub async fn apply_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
        operation_id: &str,
    ) -> Result<AppliedEgress, AdapterError> {
        let document = Value::Object(document.clone());
        let view =
            self.client.egress_apply(expected_revision, &document, operation_id).await.map_err(Self::egress_failure)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    pub async fn rollback_egress(&self, expected_revision: &str) -> Result<AppliedEgress, AdapterError> {
        let view = self.client.egress_rollback(expected_revision).await.map_err(Self::egress_failure)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    /// The manager's per-client handlers and slots (v0.7).
    pub async fn lanes(&self) -> Result<Value, AdapterError> {
        self.client.lanes().await.map_err(Self::egress_failure)
    }

    pub async fn set_lanes(&self, lanes: &Value) -> Result<Value, AdapterError> {
        self.client.set_lanes(lanes).await.map_err(Self::egress_failure)
    }
}

crate::protocol_adapter! {
    impl<C: NaiveApi> for NaiveAdapter<C>;
    protocol: Protocol::Naive,
    origin: CredentialOrigin::Caller,
    capture: true,
    accepts_caller: true,
}
