//! What a subscription is, and what a client's manifest says right now
//! (`subscriptions/models.py`). Neither type carries the token: the panel keeps its hash and, with
//! a keyring, an encrypted copy referenced by `secret_ref`.

use serde_json::{Map, Value};

use crate::common::SecretRef;

/// One client's subscription URL, by generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub client_id: String,
    pub generation: i64,
    pub state: String,
    pub update_interval_hours: i64,
    pub last_fetched_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub revoked_at: Option<i64>,
    /// Where the escrowed token lives; `None` = the URL can only be rotated, not shown.
    pub secret_ref: Option<SecretRef>,
}

/// One access as the subscription renders it.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestGrant {
    pub grant_id: String,
    pub protocol: String,
    pub node_id: String,
    pub endpoint_id: String,
    pub runtime_username: String,
    pub secret_version: i64,
    pub options: Map<String, Value>,
    pub enabled: bool,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    /// `""` unless known.
    pub node_name: String,
    /// `""` unless the access has its own label.
    pub label: String,
}

/// What a client's subscription says right now.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub client_id: String,
    pub client_name: String,
    pub generation: i64,
    pub grants: Vec<ManifestGrant>,
    /// The manifest format, `1`.
    pub version: i64,
}

impl Manifest {
    /// A manifest of format version 1.
    pub fn new(
        client_id: impl Into<String>,
        client_name: impl Into<String>,
        generation: i64,
        grants: Vec<ManifestGrant>,
    ) -> Self {
        Self { client_id: client_id.into(), client_name: client_name.into(), generation, grants, version: 1 }
    }
}
