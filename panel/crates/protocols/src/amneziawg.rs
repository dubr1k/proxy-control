//! AmneziaWG: the panel chooses the client's keys, the node's manager owns the server side
//! (`protocols/amneziawg.py`).
//!
//! The credential is a small JSON document (`private_key` and `preshared_key`, base64) the panel
//! generates and escrows. The manager receives only the public key and the preshared key, so a node
//! never holds a client's private key. What a client's config needs (address, the interface port
//! of its version, the server key, the obfuscation parameters) is learned at issue time into the
//! grant's options and rendered from there, with no call to the node.

use base64::Engine as _;
use panel_managers::{AmneziawgClient, ManagerError};
use panel_model::clients::{AccessGrant, AmneziawgOptions, GrantIntent, ProtocolOptions};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    applied_egress_from_view, egress_error, egress_target_from_view, AccessArtifact, AdapterError, AppliedEgress,
    AppliedGrant, AutoRefresh, CredentialPlan, EgressTarget, GrantRef, ObservedGrant, ObservedInventory, Preflight,
};
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::api::AmneziawgApi;
use crate::error::crash;
use crate::util::{as_object, b64decode_lenient, b64decode_strict, py_str, rows};

/// The media type of the client config.
pub const CONF_MEDIA_TYPE: &str = "text/x-amneziawg-conf";
/// Client-config key order: the interface keys the apps expect first, parameters as the docs list
/// them.
pub const OBFUSCATION_ORDER: &[&str] = &[
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
];
/// The versions a node can serve, oldest first (`AWG_VERSIONS`).
pub const AWG_VERSIONS: &[&str] = &["1.5", "2.0", "3.1"];

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the system random source works");
    bytes
}

/// A fresh client key pair's private half and a preshared key, as the escrowed secret:
/// `{"private_key":…,"preshared_key":…}` (compact JSON, standard base64). The private key is
/// clamped as OpenSSL stores a generated X25519 key.
pub fn new_credential() -> Vec<u8> {
    let mut private = random_bytes();
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let engine = base64::engine::general_purpose::STANDARD;
    let document = json!({"private_key": engine.encode(private), "preshared_key": engine.encode(random_bytes())});
    panel_core::pyjson::compact(&document).into_bytes()
}

/// `(private_key, preshared_key)` of an escrowed credential; anything else is "malformed".
pub fn parse_credential(plaintext: &[u8]) -> Result<(String, String), AdapterError> {
    let malformed = || AdapterError::new("the AmneziaWG credential is malformed");
    let document: Value = serde_json::from_slice(plaintext).map_err(|_| malformed())?;
    let key = |name: &str| -> Result<String, AdapterError> {
        let value = document.as_object().and_then(|map| map.get(name)).ok_or_else(malformed)?;
        let text = value.as_str().ok_or_else(malformed)?;
        match b64decode_strict(text) {
            Some(bytes) if bytes.len() == 32 => Ok(text.to_string()),
            _ => Err(malformed()),
        }
    };
    let private = key("private_key")?;
    let preshared = key("preshared_key")?;
    Ok((private, preshared))
}

/// The base64 X25519 public key of a base64 private key.
pub fn public_key_of(private_b64: &str) -> Result<String, AdapterError> {
    let bytes = b64decode_lenient(private_b64.as_bytes()).map_err(crash)?;
    let private: [u8; 32] = bytes.try_into().map_err(|_| crash("An X25519 private key is 32 bytes long"))?;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    Ok(base64::engine::general_purpose::STANDARD.encode(public))
}

/// Python's `list(value)` of a JSON value (a string gives its characters, a dict its keys).
fn py_list(value: &Value) -> Result<Vec<Value>, AdapterError> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::String(text) => Ok(text.chars().map(|ch| json!(ch.to_string())).collect()),
        Value::Object(map) => Ok(map.keys().map(|key| json!(key)).collect()),
        _ => Err(crash("the manager answered a list that is not a list")),
    }
}

/// The option fields the client's config is built from, as the manager reported them.
pub fn learned_options(
    peer: &Map<String, Value>,
    instance: &Map<String, Value>,
) -> Result<Map<String, Value>, AdapterError> {
    let required = |map: &Map<String, Value>, key: &str| {
        map.get(key).cloned().ok_or_else(|| crash(format!("the AmneziaWG manager answered no '{key}'")))
    };
    let or_empty = |key: &str| instance.get(key).filter(|value| crate::util::truthy(Some(value)));
    let dns = or_empty("dns").map(py_list).transpose()?.unwrap_or_default();
    let obfuscation = match or_empty("obfuscation") {
        None => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(crash("the AmneziaWG manager answered obfuscation that is not a dict")),
    };
    Ok(Map::from_iter([
        ("version".to_string(), required(instance, "version")?),
        ("address".to_string(), required(peer, "address")?),
        ("port".to_string(), required(instance, "port")?),
        ("server_public_key".to_string(), required(instance, "server_public_key")?),
        ("mtu".to_string(), instance.get("mtu").cloned().unwrap_or(Value::Null)),
        ("dns".to_string(), Value::Array(dns)),
        ("obfuscation".to_string(), Value::Object(obfuscation)),
    ]))
}

fn options_of(grant: &AccessGrant) -> Result<&AmneziawgOptions, AdapterError> {
    match &grant.options {
        ProtocolOptions::Amneziawg(options) => Ok(options),
        _ => Err(crash("this grant carries no AmneziaWG options")),
    }
}

/// The client's `.conf`: `[Interface]` (key, address, DNS, MTU, obfuscation in the documented
/// order), then `[Peer]` (server key, preshared key, the whole internet, the endpoint), with a
/// final newline.
pub fn render_conf(grant: &AccessGrant, credential: &[u8], public_host: &str) -> Result<String, AdapterError> {
    let options = options_of(grant)?;
    let (private, preshared) = parse_credential(credential)?;
    let (Some(address), Some(port), Some(server_key)) = (
        options.address.as_deref().filter(|text| !text.is_empty()),
        options.port.filter(|port| *port != 0),
        options.server_public_key.as_deref().filter(|text| !text.is_empty()),
    ) else {
        return Err(AdapterError::new("this AmneziaWG access has not learned its server details yet"));
    };
    if public_host.is_empty() {
        return Err(AdapterError::new("no public host is known for this node"));
    }
    let mut lines =
        vec!["[Interface]".to_string(), format!("PrivateKey = {private}"), format!("Address = {address}/32")];
    if !options.dns.is_empty() {
        lines.push(format!("DNS = {}", options.dns.join(", ")));
    }
    if let Some(mtu) = options.mtu.filter(|mtu| *mtu != 0) {
        lines.push(format!("MTU = {mtu}"));
    }
    for key in OBFUSCATION_ORDER {
        if let Some(value) = options.obfuscation.get(*key) {
            lines.push(format!("{key} = {value}"));
        }
    }
    lines.extend([
        String::new(),
        "[Peer]".to_string(),
        format!("PublicKey = {server_key}"),
        format!("PresharedKey = {preshared}"),
        "AllowedIPs = 0.0.0.0/0, ::/0".to_string(),
        format!("Endpoint = {public_host}:{port}"),
        "PersistentKeepalive = 25".to_string(),
        String::new(),
    ]);
    Ok(lines.join("\n"))
}

/// The AmneziaWG adapter over the awg-manager's client.
pub struct AmneziawgAdapter<C = AmneziawgClient> {
    client: C,
    public_host: String,
}

impl<C: AmneziawgApi> AmneziawgAdapter<C> {
    pub fn new(client: C, public_host: impl Into<String>) -> Self {
        Self { client, public_host: public_host.into() }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn public_host(&self) -> &str {
        &self.public_host
    }

    fn unavailable(_: ManagerError) -> AdapterError {
        AdapterError::new("AmneziaWG manager unavailable")
    }

    fn refused(_: ManagerError) -> AdapterError {
        AdapterError::new("AmneziaWG manager refused the request")
    }

    async fn peers(&self) -> Result<Value, AdapterError> {
        self.client.peers().await.map_err(Self::unavailable)
    }

    /// `{item["version"]: item for item in instances}` (later duplicates win).
    async fn instances(&self) -> Result<Map<String, Value>, AdapterError> {
        let listed = self.client.instances().await.map_err(Self::unavailable)?;
        let Value::Array(items) = listed else {
            return Err(crash("the AmneziaWG manager answered instances that are not a list"));
        };
        let mut instances = Map::new();
        for item in items {
            let version = item
                .as_object()
                .and_then(|map| map.get("version"))
                .ok_or_else(|| crash("an instance without a version"))?;
            instances.insert(py_str(Some(version)), item.clone());
        }
        Ok(instances)
    }

    /// The versions this node serves, oldest first.
    pub async fn versions(&self) -> Result<Vec<String>, AdapterError> {
        let mut versions: Vec<String> = self.instances().await?.keys().cloned().collect();
        if versions.iter().any(|version| !AWG_VERSIONS.contains(&version.as_str())) {
            return Err(crash("the AmneziaWG manager serves a version the panel does not know"));
        }
        versions.sort_by_key(|version| AWG_VERSIONS.iter().position(|known| *known == version.as_str()));
        Ok(versions)
    }

    pub async fn discover(&self) -> Result<ObservedInventory, AdapterError> {
        let peers = self.peers().await?;
        let items = rows(&peers)?
            .into_iter()
            .filter_map(|row| {
                let username = row.get("username")?.as_str()?;
                Some(ObservedGrant {
                    runtime_username: username.to_string(),
                    enabled: row.get("enabled") != Some(&Value::Bool(false)),
                    options: Map::from_iter([
                        ("version".to_string(), row.get("version").cloned().unwrap_or(Value::Null)),
                        ("address".to_string(), row.get("address").cloned().unwrap_or(Value::Null)),
                    ]),
                    revision: Some(py_str(row.get("revision"))),
                })
            })
            .collect();
        Ok(ObservedInventory { items })
    }

    pub async fn preflight(&self, intent: &GrantIntent) -> Result<Preflight, AdapterError> {
        let ProtocolOptions::Amneziawg(options) = &intent.options else {
            return Err(crash("this intent carries no AmneziaWG options"));
        };
        let version = options.version.as_str();
        if !self.instances().await?.contains_key(version) {
            return Ok(Preflight {
                ok: false,
                reason: Some(format!("AmneziaWG {version} is not enabled on this node")),
            });
        }
        let peers = self.peers().await?;
        let taken = match &peers {
            Value::Array(items) => items.iter().any(|row| row.get("username") == Some(&json!(intent.runtime_username))),
            Value::Object(_) | Value::String(_) => false,
            _ => return Err(crash("the AmneziaWG manager answered peers that are not a list")),
        };
        if taken {
            return Ok(Preflight { ok: false, reason: Some("runtime username already exists".into()) });
        }
        Ok(Preflight { ok: true, reason: None })
    }

    fn keys(credential: &CredentialPlan) -> Result<(String, String), AdapterError> {
        if credential.origin() != CredentialOrigin::Caller {
            return Err(AdapterError::new("AmneziaWG needs a caller-supplied key pair so the panel can escrow it"));
        }
        let (private, preshared) = parse_credential(credential.plaintext().unwrap_or_default())?;
        Ok((public_key_of(&private)?, preshared))
    }

    fn peer_of(result: &Value) -> Result<&Map<String, Value>, AdapterError> {
        as_object(result)?
            .get("peer")
            .and_then(Value::as_object)
            .ok_or_else(|| crash("the AmneziaWG manager answered no peer"))
    }

    fn applied(
        &self,
        result: &Value,
        credential: Option<&[u8]>,
        recovered: bool,
    ) -> Result<AppliedGrant, AdapterError> {
        let peer = Self::peer_of(result)?;
        let instance = as_object(result)?.get("instance").filter(|value| crate::util::truthy(Some(value)));
        let template = match instance {
            Some(Value::Object(instance)) => learned_options(peer, instance)?,
            Some(_) => return Err(crash("the AmneziaWG manager answered an instance that is not a dict")),
            None => Map::from_iter([(
                "address".to_string(),
                peer.get("address").cloned().ok_or_else(|| crash("the AmneziaWG manager answered no 'address'"))?,
            )]),
        };
        let username =
            peer.get("username").and_then(Value::as_str).ok_or_else(|| crash("a peer without a username"))?;
        Ok(AppliedGrant {
            credential: credential.map(<[u8]>::to_vec),
            revision: Some(py_str(peer.get("revision"))),
            artifact_template: template,
            recovered,
            ..AppliedGrant::new(username, peer.get("enabled") != Some(&Value::Bool(false)))
        })
    }

    pub async fn create(
        &self,
        operation_id: &str,
        intent: &GrantIntent,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let (public, preshared) = Self::keys(credential)?;
        let ProtocolOptions::Amneziawg(options) = &intent.options else {
            return Err(crash("this intent carries no AmneziaWG options"));
        };
        let payload = json!({"operation_id": operation_id, "username": intent.runtime_username,
                             "version": options.version.as_str(), "public_key": public, "preshared_key": preshared});
        let (result, recovered) = match self.client.create_peer(&payload).await {
            Ok(result) => (result, false),
            Err(error)
                if matches!(error.status_code, 404 | 409 | 422)
                    && error.code.as_deref() != Some("operation_conflict") =>
            {
                return Err(Self::refused(error));
            }
            // The reply may have been lost: the same operation id replays safely.
            Err(_) => (self.client.create_peer(&payload).await.map_err(Self::refused)?, true),
        };
        self.applied(&result, credential.plaintext(), recovered)
    }

    async fn state(&self, grant: &GrantRef, action: &str) -> Result<AppliedGrant, AdapterError> {
        let result = self.client.peer_state(&grant.runtime_username, action).await.map_err(Self::refused)?;
        let peer = Self::peer_of(&result)?;
        Ok(AppliedGrant {
            revision: Some(py_str(peer.get("revision"))),
            ..AppliedGrant::new(&grant.runtime_username, action == "enable")
        })
    }

    pub async fn enable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.state(grant, "enable").await
    }

    pub async fn disable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.state(grant, "disable").await
    }

    pub async fn rotate(
        &self,
        operation_id: &str,
        grant: &GrantRef,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let (public, preshared) = Self::keys(credential)?;
        let payload = json!({"operation_id": operation_id, "public_key": public, "preshared_key": preshared});
        let username = &grant.runtime_username;
        let (result, recovered) = match self.client.rotate_peer(username, &payload).await {
            Ok(result) => (result, false),
            Err(error) if matches!(error.status_code, 404 | 409 | 422) => return Err(Self::refused(error)),
            Err(_) => (self.client.rotate_peer(username, &payload).await.map_err(Self::refused)?, true),
        };
        let peer = Self::peer_of(&result)?;
        Ok(AppliedGrant {
            credential: credential.plaintext().map(<[u8]>::to_vec),
            revision: Some(py_str(peer.get("revision"))),
            recovered,
            ..AppliedGrant::new(username, peer.get("enabled") != Some(&Value::Bool(false)))
        })
    }

    pub async fn delete(&self, grant: &GrantRef) -> Result<(), AdapterError> {
        match self.client.delete_peer(&grant.runtime_username).await {
            Ok(_) => Ok(()),
            Err(error) if error.status_code == 404 => {
                Err(AdapterError::already_gone("AmneziaWG manager refused the request"))
            }
            Err(error) => Err(Self::refused(error)),
        }
    }

    /// Always `None`: the manager keeps public keys only.
    pub async fn capture(&self, _grant: &GrantRef) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(None)
    }

    /// Always `None`: the version cannot change in place (a peer lives on one interface), and
    /// what the panel learned is the manager's to say.
    pub async fn update_options(
        &self,
        _grant: &GrantRef,
        _options: &Map<String, Value>,
    ) -> Result<Option<AppliedGrant>, AdapterError> {
        Ok(None)
    }

    pub fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        let version = options_of(grant)?.version;
        Ok(vec![AccessArtifact {
            kind: "awg_conf".into(),
            label: format!("AmneziaWG {version}"),
            media_type: CONF_MEDIA_TYPE.into(),
            value: render_conf(grant, credential, public_host)?,
            auto_refresh: AutoRefresh::Supported,
        }])
    }

    fn egress_failure(error: ManagerError) -> AdapterError {
        egress_error("AmneziaWG", error.status_code, error.code.as_deref())
    }

    /// The whole tunnel directly or through the manager's WARP tunnel (`amneziawg_native`); `None`
    /// for a manager older than v3.0.0 (it answers 404).
    pub async fn egress_target(&self) -> Result<Option<EgressTarget>, AdapterError> {
        let view = match self.client.egress().await {
            Ok(view) => view,
            Err(error) if error.status_code == 404 => return Ok(None),
            Err(error) => return Err(Self::egress_failure(error)),
        };
        Ok(Some(egress_target_from_view("amneziawg", Backend::AmneziawgNative, as_object(&view)?)))
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
}

crate::protocol_adapter! {
    impl<C: AmneziawgApi> for AmneziawgAdapter<C>;
    protocol: Protocol::Amneziawg,
    origin: CredentialOrigin::Caller,
    capture: false,
    accepts_caller: true,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_credential_is_a_key_pair_and_a_preshared_key() {
        let first = new_credential();
        let (private, preshared) = parse_credential(&first).unwrap();
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(engine.decode(&private).unwrap().len(), 32);
        assert_eq!(engine.decode(&preshared).unwrap().len(), 32);
        assert_eq!(public_key_of(&private).unwrap().len(), 44);
        assert_ne!(new_credential(), first);
        let raw = engine.decode(&private).unwrap();
        assert_eq!((raw[0] & 7, raw[31] & 0xc0), (0, 0x40));
    }

    #[test]
    fn a_malformed_credential_is_refused() {
        for bad in [&b"not json"[..], br#"{"private_key":"x","preshared_key":"y"}"#, b"[]", br#"{"private_key":1}"#] {
            assert_eq!(parse_credential(bad).unwrap_err().message, "the AmneziaWG credential is malformed");
        }
    }
}
