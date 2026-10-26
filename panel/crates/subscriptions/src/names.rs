//! One safe, node-first display name across subscription formats (`subscriptions/names.py`).
//!
//! Only presentation changes: usernames, endpoints and credentials remain untouched. The whole
//! manifest participates (including disabled grants), so toggling a sibling cannot rename the
//! selected profile. Stable suffixes resolve duplicate names, independent of row order.

use std::collections::{BTreeMap, HashMap, HashSet};

use panel_core::pytext;
use panel_model::subscriptions::Manifest;

/// `PROTOCOL_TITLES.get(protocol, protocol)`.
pub fn protocol_title(protocol: &str) -> &str {
    match protocol {
        "mtproxy" => "MTProxy",
        "naive" => "Naive",
        "mieru" => "Mieru",
        "amneziawg" => "AmneziaWG",
        "trusttunnel" => "TrustTunnel",
        other => other,
    }
}

/// `display_text(value)`: NFC, every non-printable character a space, whitespace collapsed, `'`
/// turned into `’` (U+2019), the first 64 code points, stripped.
pub fn display_text(value: &str) -> String {
    let normalized = pytext::nfc(value);
    let printable: String = normalized.chars().map(|ch| if pytext::is_printable_char(ch) { ch } else { ' ' }).collect();
    let folded = pytext::collapse_whitespace(&printable).replace('\'', "\u{2019}");
    pytext::strip(pytext::truncate(&folded, 64)).to_string()
}

/// The suffix a duplicate name could not be widened past (`ValueError` in Python).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCollision;

impl std::fmt::Display for NameCollision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("subscription display name collision")
    }
}

impl std::error::Error for NameCollision {}

/// `grant_names(manifest)`: grant id → display name, in grant id order.
pub fn grant_names(manifest: &Manifest) -> Result<BTreeMap<String, String>, NameCollision> {
    let mut bases: BTreeMap<String, String> = BTreeMap::new();
    for grant in &manifest.grants {
        // A name the operator gave this access wins over «node · protocol».
        let custom = display_text(&grant.label);
        let node = [display_text(&grant.node_name), display_text(&grant.node_id)]
            .into_iter()
            .find(|text| !text.is_empty())
            .unwrap_or_else(|| "Local".to_string());
        let base =
            if custom.is_empty() { format!("{node} \u{b7} {}", protocol_title(&grant.protocol)) } else { custom };
        bases.insert(grant.grant_id.clone(), base);
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for base in bases.values() {
        *counts.entry(base.as_str()).or_default() += 1;
    }
    // Reserve all literal names first, including names that look like a suffix.
    let mut used: HashSet<String> = bases.values().cloned().collect();
    let mut result = BTreeMap::new();
    for (grant_id, base) in &bases {
        if counts[base.as_str()] == 1 {
            result.insert(grant_id.clone(), base.clone());
            continue;
        }
        let digest = panel_core::ids::sha256_hex(grant_id.as_bytes());
        let mut width = 8;
        let mut candidate = format!("{base} [{}]", &digest[..width]);
        while used.contains(&candidate) {
            width += 1;
            if width > digest.len() {
                return Err(NameCollision);
            }
            candidate = format!("{base} [{}]", &digest[..width]);
        }
        used.insert(candidate.clone());
        result.insert(grant_id.clone(), candidate);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_folds_like_python() {
        assert_eq!(display_text("  AMS's\n\u{202e}<script> "), "AMS\u{2019}s <script>");
        assert_eq!(display_text("Cafe\u{301}"), "Caf\u{e9}");
        assert_eq!(display_text(&"я".repeat(70)), "я".repeat(64));
        assert_eq!(display_text(" "), "");
        assert_eq!(display_text("Дом   'кухня'\u{7} — Wi\u{2011}Fi"), "Дом \u{2019}кухня\u{2019} — Wi\u{2011}Fi");
    }
}
