//! `raw`: one link per line, plain text, no base64 (`subscriptions/renderers/raw.py`).
//!
//! A grant that cannot be rendered is a comment line that says why, never a link that does not
//! work.

use panel_model::subscriptions::Manifest;

use super::base::{check, credential_reason, finish, link_of, named_share_url, Artifacts, RenderError};
use crate::names::grant_names;

pub fn render(manifest: &Manifest, artifacts: &Artifacts, max_bytes: usize) -> Result<Vec<u8>, RenderError> {
    check(manifest)?;
    let names = grant_names(manifest)?;
    let mut lines = Vec::with_capacity(manifest.grants.len());
    for grant in &manifest.grants {
        if !grant.enabled {
            lines.push(format!("# disabled {} {}", grant.protocol, grant.runtime_username));
            continue;
        }
        if let Some(reason) = credential_reason(grant, artifacts) {
            lines.push(format!("# unsupported {} {}: {reason}", grant.protocol, grant.runtime_username));
            continue;
        }
        let link = link_of(grant, artifacts)?;
        lines.push(named_share_url(grant, link, &names[&grant.grant_id])?);
    }
    finish(format!("{}\n", lines.join("\n")).into_bytes(), max_bytes)
}
