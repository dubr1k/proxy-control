//! What every renderer shares: the bounds, the one reveal, the link helpers
//! (`subscriptions/renderers/base.py`).
//!
//! Credentials enter exactly once, in [`resolve_artifacts`], which reveals each effective grant's
//! secret in memory and hands the adapter's artifacts back; no error message carries a link or a
//! plaintext. A manifest with more than [`MAX_GRANTS`] grants or a body over [`MAX_BYTES`] is
//! refused outright, never truncated.

use std::collections::HashMap;

use panel_clients::hosts::PublicHosts;
use panel_clients::{Adapters, ClientsError, CREDENTIAL_PURPOSE};
use panel_core::db::Conn;
use panel_core::pytext;
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_model::protocols::AccessArtifact;
use panel_model::subscriptions::{Manifest, ManifestGrant};
use panel_model::Protocol;
use panel_protocols::trusttunnel_link::{self, DeepLink, DeepLinkSpec};
use panel_secrets::secrets_store::{SecretRef, SecretStore};

/// `MEDIA_TYPE_MANIFEST`.
pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.proxy-control.subscription+json;version=1";
/// `MAX_GRANTS`.
pub const MAX_GRANTS: usize = 64;
/// `MAX_BYTES`.
pub const MAX_BYTES: usize = 512 * 1024;
/// `NO_CREDENTIAL`.
pub const NO_CREDENTIAL: &str = "no stored credential";

/// The artifacts rendered for each effective grant, by grant id.
pub type Artifacts = HashMap<String, Vec<AccessArtifact>>;

/// A manifest a renderer refuses (`RenderError`). The message never carries a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError(pub String);

impl RenderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RenderError {}

/// `check(manifest)`.
pub fn check(manifest: &Manifest) -> Result<(), RenderError> {
    if manifest.grants.len() > MAX_GRANTS {
        return Err(RenderError(format!("too many grants: {} > {MAX_GRANTS}", manifest.grants.len())));
    }
    Ok(())
}

/// `finish(body)` against a byte limit ([`MAX_BYTES`] in service).
pub fn finish(body: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, RenderError> {
    if body.len() > max_bytes {
        return Err(RenderError(format!("rendered subscription is too large: {} > {max_bytes} bytes", body.len())));
    }
    Ok(body)
}

/// `credential_reason(grant, artifacts)`: why an effective grant still has no link, or `None`.
pub fn credential_reason(grant: &ManifestGrant, artifacts: &Artifacts) -> Option<&'static str> {
    if grant.secret_version < 1 || artifacts.get(&grant.grant_id).is_none_or(Vec::is_empty) {
        return Some(NO_CREDENTIAL);
    }
    None
}

/// `link_of(grant, artifacts)`: the first `text/uri-list` artifact.
pub fn link_of<'a>(grant: &ManifestGrant, artifacts: &'a Artifacts) -> Result<&'a str, RenderError> {
    artifacts
        .get(&grant.grant_id)
        .into_iter()
        .flatten()
        .find(|artifact| artifact.media_type == "text/uri-list")
        .map(|artifact| artifact.value.as_str())
        .ok_or_else(|| RenderError(format!("{} {}: no link artifact", grant.protocol, grant.runtime_username)))
}

/// `urllib.parse.uses_netloc`.
const USES_NETLOC: [&str; 27] = [
    "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp", "snews", "prospero",
    "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git", "git+ssh", "ws", "wss", "itms-services",
];

/// `urllib.parse.urlunsplit` (Python 3.13).
pub fn urlunsplit(scheme: &str, netloc: &str, path: &str, query: &str, fragment: &str) -> String {
    let mut url = path.to_string();
    if !netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url = format!("/{url}");
        }
        url = format!("//{netloc}{url}");
    } else if url.starts_with("//") {
        url = format!("//{url}");
    } else if !scheme.is_empty() && USES_NETLOC.contains(&scheme) && (url.is_empty() || url.starts_with('/')) {
        url = format!("//{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    if !fragment.is_empty() {
        url.push('#');
        url.push_str(fragment);
    }
    url
}

fn not_renderable(protocol: &str) -> RenderError {
    RenderError(format!("{protocol}: link is not renderable"))
}

/// `named_share_url(grant, link, name)`: only the display field changes; Mieru bindings and
/// credentials stay byte for byte; an MTProxy link has no name field and is left alone.
pub fn named_share_url(grant: &ManifestGrant, link: &str, name: &str) -> Result<String, RenderError> {
    match grant.protocol.as_str() {
        "naive" => naive_share_url(link, &grant.runtime_username, Some(name)),
        "mieru" => {
            let parts = pytext::urlsplit(link).map_err(|_| not_renderable("mieru"))?;
            let query = parts
                .query
                .split('&')
                .map(|item| {
                    let key = item.split_once('=').map_or(item, |(key, _)| key);
                    if pytext::unquote(&key.replace('+', " ")) == "profile" {
                        format!("profile={}", pytext::quote(name, ""))
                    } else {
                        item.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
            Ok(urlunsplit(&parts.scheme, &parts.netloc, &parts.path, &query, &parts.fragment))
        }
        "trusttunnel" => trusttunnel_share_url(link, name),
        _ => Ok(link.to_string()),
    }
}

/// `trusttunnel_fields(link)`: the decoded `tt://` link. The error names the protocol, never the
/// link (it carries the password).
pub fn trusttunnel_fields(link: &str) -> Result<DeepLink, RenderError> {
    trusttunnel_link::decode_deeplink(link).map_err(|_| not_renderable("trusttunnel"))
}

/// `trusttunnel_share_url(link, name)`: the same access with the profile name replaced by the
/// feed's display name.
pub fn trusttunnel_share_url(link: &str, name: &str) -> Result<String, RenderError> {
    let fields = trusttunnel_fields(link)?;
    let (Some(hostname), Some(username), Some(password)) = (&fields.hostname, &fields.username, &fields.password) else {
        return Err(not_renderable("trusttunnel"));
    };
    let spec = DeepLinkSpec {
        hostname: hostname.clone(),
        addresses: fields.addresses.clone(),
        username: username.clone(),
        password: password.clone(),
        certificate_der: fields.certificate.clone(),
        upstream_protocol: fields.upstream_protocol,
        name: Some(name.to_string()),
        skip_verification: fields.skip_verification,
    };
    trusttunnel_link::encode_deeplink(&spec).map_err(|_| not_renderable("trusttunnel"))
}

/// Python's f-string of an optional text (`None` reads `None`).
fn or_none(text: Option<&str>) -> String {
    text.map_or_else(|| "None".to_string(), str::to_string)
}

/// `naive_share_url(proxy_url, username, name=…)`: `naive+https://user:pass@host:port#name` — what
/// NekoBox-family clients and QR scanners import. The userinfo stays percent-encoded as in the
/// proxy URL; the host is lower-cased (`urlsplit().hostname`).
pub fn naive_share_url(proxy_url: &str, username: &str, name: Option<&str>) -> Result<String, RenderError> {
    let parts = pytext::urlsplit(proxy_url).map_err(|_| not_renderable("naive"))?;
    let port = parts.port().map_err(|_| not_renderable("naive"))?.filter(|port| *port != 0).unwrap_or(443);
    let fallback = format!("Naive \u{b7} {username}");
    Ok(format!(
        "naive+https://{}:{}@{}:{port}#{}",
        or_none(parts.username()),
        or_none(parts.password()),
        or_none(parts.hostname().as_deref()),
        pytext::quote(name.unwrap_or(&fallback), "")
    ))
}

/// `_in_force(db, grant)`: the version the node actually runs, or `None`. The version a grant
/// names is `pending` while a remote node has not applied it; then the highest `retiring` one is
/// what still works.
fn in_force(db: &Conn, grant: &ManifestGrant) -> Result<Option<i64>, ClientsError> {
    let secret_id = format!("grant:{}", grant.grant_id);
    let state: Option<String> = db
        .query_row(
            "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
            params![secret_id, grant.secret_version],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match state.as_deref() {
        Some("active") => Some(grant.secret_version),
        Some("pending") => db.query_row(
            "SELECT max(version) FROM secret_versions WHERE secret_id=? AND state='retiring'",
            params![secret_id],
            |row| row.get(0),
        )?,
        _ => None,
    })
}

/// `resolve_artifacts(manifest, secrets, adapters, db, public_hosts=…)`: reveal each effective
/// grant's credential in memory and render its artifacts. Only grants enabled right now that point
/// at a stored secret in force are revealed; the grant row comes from the database (adapters
/// render from its typed options); each node's public hosts are asked once.
pub fn resolve_artifacts(
    manifest: &Manifest,
    secrets: &SecretStore,
    adapters: &Adapters,
    db: &Conn,
    public_hosts: &dyn PublicHosts,
) -> Result<Artifacts, ClientsError> {
    let mut hosts: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut result = Artifacts::new();
    for grant in &manifest.grants {
        if !grant.enabled || grant.secret_version < 1 {
            continue;
        }
        let Some(protocol) = Protocol::from_wire(&grant.protocol) else { continue };
        let Some(adapter) = adapters.get(protocol) else { continue };
        let row = panel_clients::store::grant(db, &grant.grant_id)?;
        let Some(version) = in_force(db, grant)? else {
            continue; // nothing the node runs yet: not a link a subscriber can use
        };
        let plaintext = secrets.reveal(
            db,
            &SecretRef::new(format!("grant:{}", grant.grant_id), version),
            CREDENTIAL_PURPOSE,
            Some(&grant.grant_id),
            Some(&grant.node_id),
        )?;
        if !hosts.contains_key(&grant.node_id) {
            hosts.insert(grant.node_id.clone(), public_hosts.hosts(db, &grant.node_id)?);
        }
        let host = hosts[&grant.node_id].get(&grant.protocol).cloned().unwrap_or_default();
        let artifacts = adapter
            .render_artifacts(&row, &plaintext, &host)
            .map_err(|error| ClientsError::adapter(protocol, error))?;
        result.insert(grant.grant_id.clone(), artifacts);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlunsplit_rebuilds_like_python() {
        assert_eq!(urlunsplit("mierus", "u:p@h", "", "profile=x&port=1", ""), "mierus://u:p@h?profile=x&port=1");
        assert_eq!(urlunsplit("https", "", "", "", ""), "https://");
        assert_eq!(urlunsplit("tg", "", "", "a=1", ""), "tg:?a=1");
        assert_eq!(urlunsplit("x", "h", "p", "", "f"), "x://h/p#f");
    }

    #[test]
    fn naive_share_urls_keep_the_userinfo_and_lowercase_the_host() {
        assert_eq!(
            naive_share_url("https://bob:p%40ss@Node.Example", "bob", None).unwrap(),
            "naive+https://bob:p%40ss@node.example:443#Naive%20%C2%B7%20bob"
        );
        assert_eq!(naive_share_url("https://u:p@h:0", "u", Some("n")).unwrap(), "naive+https://u:p@h:443#n");
        assert_eq!(naive_share_url("https://h", "u", Some("n")).unwrap(), "naive+https://None:None@h:443#n");
        assert!(naive_share_url("https://u:p@h:x", "u", Some("n")).is_err());
    }
}
