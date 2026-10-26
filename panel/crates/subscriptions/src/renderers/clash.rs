//! `clash`: the YAML mihomo (Clash.Meta) and Karing's clash core import
//! (`subscriptions/renderers/clash.py`).
//!
//! Only `type: mieru` and `type: trusttunnel` proxies live here; naive and MTProxy grants go under
//! `proxy-control.unsupported` with the matrix's reasons. The YAML is written by hand: every string
//! a single-quoted scalar, every number and boolean a plain one, and a string that cannot be proven
//! safe inside single quotes (a quote, a non-printable character) is a [`RenderError`].

use panel_core::pytext;
use panel_model::subscriptions::{Manifest, ManifestGrant};
use panel_protocols::mieru::{parse_share_url, MieruShare};
use serde_json::Value;

use super::base::{check, credential_reason, finish, link_of, trusttunnel_fields, Artifacts, RenderError};
use crate::compatibility;
use crate::names::grant_names;

/// One YAML scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    Bool(bool),
    Int(i64),
    Str(String),
}

impl From<&str> for Scalar {
    fn from(text: &str) -> Self {
        Scalar::Str(text.to_string())
    }
}

impl From<String> for Scalar {
    fn from(text: String) -> Self {
        Scalar::Str(text)
    }
}

/// `scalar(value)`: quoted strings, plain ints and booleans, nothing else.
pub fn scalar(value: &Scalar) -> Result<String, RenderError> {
    match value {
        Scalar::Bool(flag) => Ok(if *flag { "true" } else { "false" }.to_string()),
        Scalar::Int(number) => Ok(number.to_string()),
        Scalar::Str(text) => {
            if !pytext::is_printable(text) || text.contains('\'') {
                return Err(RenderError::new("a value cannot be written as a safe YAML scalar"));
            }
            Ok(format!("'{text}'"))
        }
    }
}

type Pairs = Vec<(&'static str, Scalar)>;

/// `_proxies(grant, share, label)`: one mihomo proxy per port binding.
fn proxies(share: &MieruShare, label: &str) -> Vec<Pairs> {
    share
        .bindings
        .iter()
        .map(|binding| {
            let protocol = binding.get("protocol").and_then(Value::as_str).unwrap_or_default().to_string();
            let (port_key, port_value, shown) = match binding.get("port").and_then(Value::as_i64) {
                Some(port) => ("port", Scalar::Int(port), port.to_string()),
                None => {
                    let range = binding.get("portRange").and_then(Value::as_str).unwrap_or_default().to_string();
                    ("port-range", Scalar::Str(range.clone()), range)
                }
            };
            vec![
                ("name", Scalar::Str(format!("{label} \u{b7} {protocol} {shown}"))),
                ("type", "mieru".into()),
                ("server", share.host.clone().into()),
                (port_key, port_value),
                ("transport", protocol.into()),
                ("username", share.username.clone().into()),
                ("password", share.password.clone().into()),
                ("udp", Scalar::Bool(true)),
            ]
        })
        .collect()
}

/// `_trusttunnel_proxy(grant, link, label)`: TCP only (`udp`, `quic` off); `skip-cert-verify` when
/// the link carries a certificate the system store does not trust, or asks to skip verification.
fn trusttunnel_proxy(grant: &ManifestGrant, link: &str, label: &str) -> Result<Pairs, RenderError> {
    let fields = trusttunnel_fields(link)?;
    let refused = || RenderError(format!("trusttunnel {}: link is not renderable", grant.runtime_username));
    let address = fields.addresses.first().ok_or_else(refused)?;
    // `address.rpartition(":")[2]`: the whole text when there is no colon.
    let port = address.rsplit_once(':').map_or(address.as_str(), |(_, port)| port);
    let port = pytext::int_from_str(port).map_err(|_| refused())?;
    let (Some(hostname), Some(username), Some(password)) = (&fields.hostname, &fields.username, &fields.password)
    else {
        return Err(refused());
    };
    let mut pairs: Pairs = vec![
        ("name", label.into()),
        ("type", "trusttunnel".into()),
        ("server", hostname.clone().into()),
        ("port", Scalar::Int(port)),
        ("username", username.clone().into()),
        ("password", password.clone().into()),
        ("udp", Scalar::Bool(false)),
        ("quic", Scalar::Bool(false)),
    ];
    if fields.certificate.as_ref().is_some_and(|der| !der.is_empty()) || fields.skip_verification {
        pairs.push(("skip-cert-verify", Scalar::Bool(true)));
    }
    Ok(pairs)
}

/// `_mapping_item(pairs, indent)`.
fn mapping_item(pairs: &[(&str, Scalar)], indent: &str) -> Result<String, RenderError> {
    let mut lines = Vec::with_capacity(pairs.len());
    for (index, (key, value)) in pairs.iter().enumerate() {
        let lead = if index == 0 { "- " } else { "  " };
        lines.push(format!("{indent}{lead}{key}: {}", scalar(value)?));
    }
    Ok(lines.join("\n"))
}

pub fn render(manifest: &Manifest, artifacts: &Artifacts, max_bytes: usize) -> Result<Vec<u8>, RenderError> {
    check(manifest)?;
    let names = grant_names(manifest)?;
    let mut all: Vec<Pairs> = Vec::new();
    let mut unsupported: Vec<(String, String, String)> = Vec::new();
    for grant in &manifest.grants {
        if !grant.enabled {
            continue;
        }
        let reason = credential_reason(grant, artifacts);
        if reason.is_none() && grant.protocol == "mieru" {
            let share = parse_share_url(link_of(grant, artifacts)?)
                .map_err(|_| RenderError(format!("mieru {}: share link is not renderable", grant.runtime_username)))?;
            all.extend(proxies(&share, &names[&grant.grant_id]));
            continue;
        }
        if reason.is_none() && grant.protocol == "trusttunnel" {
            all.push(trusttunnel_proxy(grant, link_of(grant, artifacts)?, &names[&grant.grant_id])?);
            continue;
        }
        let reason = match reason {
            Some(reason) => reason.to_string(),
            None => compatibility::note(&grant.protocol, "mihomo")
                .map_or_else(|| format!("no mihomo proxy type for {}", grant.protocol), str::to_string),
        };
        unsupported.push((grant.protocol.clone(), grant.runtime_username.clone(), reason));
    }

    let mut lines: Vec<String> = vec![if all.is_empty() { "proxies: []" } else { "proxies:" }.to_string()];
    for pairs in &all {
        lines.push(mapping_item(pairs, "  ")?);
    }
    lines.push("proxy-groups:".into());
    lines.push(mapping_item(&[("name", "proxy-control".into()), ("type", "select".into())], "  ")?);
    if all.is_empty() {
        lines.push("    proxies: []".into());
    } else {
        lines.push("    proxies:".into());
        for pairs in &all {
            // `dict(pairs)['name']`: the last `name` (there is exactly one).
            let name = pairs.iter().rev().find(|(key, _)| *key == "name").map(|(_, value)| value.clone());
            lines.push(format!("      - {}", scalar(&name.unwrap_or(Scalar::Str(String::new())))?));
        }
    }
    lines.push("proxy-control:".into());
    lines.push(format!("  generation: {}", scalar(&Scalar::Int(manifest.generation))?));
    lines.push(if unsupported.is_empty() { "  unsupported: []" } else { "  unsupported:" }.into());
    for (protocol, user, reason) in unsupported {
        lines.push(mapping_item(
            &[("protocol", protocol.into()), ("runtime_username", user.into()), ("reason", reason.into())],
            "    ",
        )?);
    }
    finish(format!("{}\n", lines.join("\n")).into_bytes(), max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_yaml_writer_refuses_values_it_cannot_prove_safe() {
        for value in ["line\nbreak", "quote'inside", "tab\there", "\x1b[31m", "\u{2028}"] {
            assert!(scalar(&value.into()).is_err(), "{value:?}");
        }
    }

    #[test]
    fn the_yaml_writer_quotes_the_ordinary_and_doubles_nothing() {
        assert_eq!(scalar(&"mieru-carol-TCP-8443".into()).unwrap(), "'mieru-carol-TCP-8443'");
        assert_eq!(scalar(&"MetaCubeX/mihomo#273: open".into()).unwrap(), "'MetaCubeX/mihomo#273: open'");
        assert_eq!(scalar(&Scalar::Int(8443)).unwrap(), "8443");
        assert_eq!(scalar(&Scalar::Bool(true)).unwrap(), "true");
    }
}
