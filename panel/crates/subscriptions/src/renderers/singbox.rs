//! `singbox`: the JSON Karing, sing-box ≥ 1.13 and the fork cores import
//! (`subscriptions/renderers/singbox.py`).
//!
//! The renderer takes a `client`: `karing` (the default) gets naive and mieru, `singbox` naive
//! only, the fork cores (`hiddify`, `nekobox`, `throne`, and `fork` — a client the owner named in
//! `PANEL_SINGBOX_FORK_CLIENTS`) also the `trusttunnel` outbound. What a client cannot load is named
//! under `proxy_control.unsupported`, never shipped. `json.dumps(…, ensure_ascii=False, indent=2)`
//! in insertion order, plus a final newline.

use panel_core::pyjson::{self, Options};
use panel_core::pytext;
use panel_model::subscriptions::{Manifest, ManifestGrant};
use panel_protocols::mieru::{parse_share_url, singbox_outbounds};
use serde_json::{json, Map, Value};

use super::base::{check, credential_reason, finish, link_of, trusttunnel_fields, Artifacts, RenderError};
use crate::compatibility;
use crate::names::grant_names;

/// `RANGE_REASON`.
pub const RANGE_REASON: &str = "the sing-box mieru outbound has no field for a port range";
/// `CLIENTS`.
pub const CLIENTS: [&str; 6] = ["karing", "singbox", "hiddify", "nekobox", "throne", "fork"];
/// `TRUSTTUNNEL_CLIENTS`: the fork cores with a TrustTunnel outbound.
pub const TRUSTTUNNEL_CLIENTS: [&str; 4] = ["hiddify", "nekobox", "throne", "fork"];

/// `_naive_outbound(grant, proxy_url, name)`.
fn naive_outbound(proxy_url: &str, name: &str) -> Result<Value, RenderError> {
    let refused = || RenderError::new("naive: link is not renderable");
    let parts = pytext::urlsplit(proxy_url).map_err(|_| refused())?;
    let port = parts.port().map_err(|_| refused())?.filter(|port| *port != 0).unwrap_or(443);
    let hostname = parts.hostname();
    Ok(json!({
        "type": "naive",
        "tag": name,
        "server": hostname,
        "server_port": port,
        "username": pytext::unquote(parts.username().unwrap_or_default()),
        "password": pytext::unquote(parts.password().unwrap_or_default()),
        "tls": {"enabled": true, "server_name": hostname},
    }))
}

/// `_trusttunnel_outbound(grant, link, name)`: HTTP/2 over TLS, QUIC off; `insecure` only where the
/// link carries a certificate (or asks to skip verification); no `health_check`.
fn trusttunnel_outbound(grant: &ManifestGrant, link: &str, name: &str) -> Result<Value, RenderError> {
    let fields = trusttunnel_fields(link)?;
    let refused = || RenderError(format!("trusttunnel {}: link is not renderable", grant.runtime_username));
    let address = fields.addresses.first().ok_or_else(refused)?;
    let port = address.rsplit_once(':').map_or(address.as_str(), |(_, port)| port);
    let (Some(hostname), Some(username), Some(password)) = (&fields.hostname, &fields.username, &fields.password)
    else {
        return Err(refused());
    };
    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    tls.insert("server_name".into(), Value::from(hostname.as_str()));
    if fields.certificate.as_ref().is_some_and(|der| !der.is_empty()) || fields.skip_verification {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    let port = pytext::int_from_str(port).map_err(|_| refused())?;
    Ok(json!({
        "type": "trusttunnel",
        "tag": name,
        "server": hostname,
        "server_port": port,
        "username": username,
        "password": password,
        "quic": false,
        "tls": tls,
    }))
}

/// `_place(grant, artifacts, client, name)`: either outbounds for the grant or the reason it has
/// none — never both, never neither.
fn place(
    grant: &ManifestGrant,
    artifacts: &Artifacts,
    client: &str,
    name: &str,
) -> Result<(Vec<Value>, Option<String>), RenderError> {
    if let Some(reason) = credential_reason(grant, artifacts) {
        return Ok((Vec::new(), Some(reason.to_string())));
    }
    if grant.protocol == "trusttunnel" {
        if !TRUSTTUNNEL_CLIENTS.contains(&client) {
            let reason = compatibility::note("trusttunnel", client)
                .map_or_else(|| format!("no sing-box outbound for {}", grant.protocol), str::to_string);
            return Ok((Vec::new(), Some(reason)));
        }
        return Ok((vec![trusttunnel_outbound(grant, link_of(grant, artifacts)?, name)?], None));
    }
    let matrix_client =
        if client == "fork" || (client == "nekobox" && matches!(grant.protocol.as_str(), "naive" | "mieru")) {
            "karing"
        } else {
            client
        };
    if compatibility::status(&grant.protocol, matrix_client) != Some("supported") {
        // The matrix is the source: what this client cannot load is named, not shipped.
        let reason = compatibility::note(&grant.protocol, matrix_client)
            .map_or_else(|| format!("{client} cannot consume {}", grant.protocol), str::to_string);
        return Ok((Vec::new(), Some(reason)));
    }
    match grant.protocol.as_str() {
        "naive" => Ok((vec![naive_outbound(link_of(grant, artifacts)?, name)?], None)),
        "mieru" => {
            let share = parse_share_url(link_of(grant, artifacts)?).map_err(|_| {
                // The message names the grant, never the link: the link carries the password.
                RenderError(format!("mieru {}: share link is not renderable", grant.runtime_username))
            })?;
            Ok(match singbox_outbounds(&share, |port, protocol| format!("{name} \u{b7} {protocol} {port}")) {
                Some(outbounds) => (outbounds, None),
                None => (Vec::new(), Some(RANGE_REASON.to_string())),
            })
        }
        _ => Ok((Vec::new(), Some(format!("no sing-box outbound for {}", grant.protocol)))),
    }
}

pub fn render(
    manifest: &Manifest,
    artifacts: &Artifacts,
    client: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, RenderError> {
    if !CLIENTS.contains(&client) {
        return Err(RenderError(format!("unknown sing-box client: {client}")));
    }
    check(manifest)?;
    let names = grant_names(manifest)?;
    let mut outbounds: Vec<Value> = Vec::new();
    let mut unsupported: Vec<Value> = Vec::new();
    for grant in &manifest.grants {
        if !grant.enabled {
            continue;
        }
        let (placed, reason) = place(grant, artifacts, client, &names[&grant.grant_id])?;
        outbounds.extend(placed);
        if let Some(reason) = reason {
            unsupported.push(json!({
                "protocol": grant.protocol,
                "runtime_username": grant.runtime_username,
                "reason": reason,
            }));
        }
    }
    let payload = json!({
        "outbounds": outbounds,
        "proxy_control": {"generation": manifest.generation, "client": client, "unsupported": unsupported},
    });
    let options = Options { indent: Some(2), separators: None, sort_keys: false, ensure_ascii: false };
    finish(format!("{}\n", pyjson::dumps(&payload, &options)).into_bytes(), max_bytes)
}
