//! `manifest`: the canonical JSON — the panel's own contract (`subscriptions/renderers/manifest.py`).
//!
//! Each grant as the manifest describes it (without the internal `node_name`/`label`), the
//! artifacts rendered for it, the reason it has none, and the compatibility matrix.
//! `json.dumps(…, ensure_ascii=False, sort_keys=True, indent=2)` plus a final newline.

use panel_core::pyjson::{self, Options};
use panel_model::protocols::AccessArtifact;
use panel_model::subscriptions::{Manifest, ManifestGrant};
use serde_json::{json, Value};

use super::base::{check, credential_reason, finish, Artifacts, RenderError};
use crate::compatibility;

/// `dataclasses.asdict(artifact)`.
pub fn artifact_json(artifact: &AccessArtifact) -> Value {
    json!({
        "kind": artifact.kind,
        "label": artifact.label,
        "media_type": artifact.media_type,
        "value": artifact.value,
        "auto_refresh": artifact.auto_refresh.as_str(),
    })
}

/// `dataclasses.asdict(grant)` without `node_name` and `label`.
fn grant_json(grant: &ManifestGrant) -> serde_json::Map<String, Value> {
    let value = json!({
        "grant_id": grant.grant_id,
        "protocol": grant.protocol,
        "node_id": grant.node_id,
        "endpoint_id": grant.endpoint_id,
        "runtime_username": grant.runtime_username,
        "secret_version": grant.secret_version,
        "options": grant.options,
        "enabled": grant.enabled,
        "valid_from": grant.valid_from,
        "valid_until": grant.valid_until,
    });
    match value {
        Value::Object(map) => map,
        _ => unreachable!("a JSON object"),
    }
}

pub fn render(manifest: &Manifest, artifacts: &Artifacts, max_bytes: usize) -> Result<Vec<u8>, RenderError> {
    check(manifest)?;
    let grants: Vec<Value> = manifest
        .grants
        .iter()
        .map(|grant| {
            let reason = if grant.enabled { credential_reason(grant, artifacts) } else { None };
            let mut item = grant_json(grant);
            let rendered: Vec<Value> = if grant.enabled {
                artifacts.get(&grant.grant_id).into_iter().flatten().map(artifact_json).collect()
            } else {
                Vec::new()
            };
            item.insert("artifacts".into(), Value::Array(rendered));
            item.insert("unsupported".into(), reason.map_or(Value::Null, Value::from));
            Value::Object(item)
        })
        .collect();
    let payload = json!({
        "version": manifest.version,
        "client_id": manifest.client_id,
        "client_name": manifest.client_name,
        "generation": manifest.generation,
        "grants": grants,
        "compatibility": compatibility::matrix_json(),
    });
    let options = Options { indent: Some(2), separators: None, sort_keys: true, ensure_ascii: false };
    finish(format!("{}\n", pyjson::dumps(&payload, &options)).into_bytes(), max_bytes)
}
