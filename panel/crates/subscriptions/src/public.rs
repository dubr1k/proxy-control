//! The decisions of `GET|HEAD /s/{token}` that need no HTTP (`subscription_routes.py`): the token
//! shape, content negotiation, the fork-core User-Agent sniffing, which `client` a format takes.

use panel_core::pytext;

/// `FETCHES_PER_MINUTE`: per client address, across all tokens, misses included.
pub const FETCHES_PER_MINUTE: i64 = 60;

/// `TOKEN_RE.fullmatch(token)`: `^[A-Za-z0-9_-]{43,64}$`.
pub fn is_token(token: &str) -> bool {
    (43..=64).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `ACCEPT_FORMATS`: a plain substring test of the raw `Accept` header, table order wins.
const ACCEPT_FORMATS: [(&str, &str); 5] = [
    ("text/html", "html"),
    ("application/vnd.proxy-control.subscription+json", "manifest"),
    ("text/yaml", "clash"),
    ("application/yaml", "clash"),
    ("application/json", "singbox"),
];

/// `negotiate(accept)`.
pub fn negotiate(accept: &str) -> &'static str {
    ACCEPT_FORMATS.iter().find(|(media_type, _)| accept.contains(media_type)).map_or("raw", |(_, name)| name)
}

/// `FORMAT_CLIENTS.get(name, ())`: which `client` values a format understands.
pub fn format_clients(name: &str) -> &'static [&'static str] {
    match name {
        "singbox" => &["karing", "singbox", "hiddify", "nekobox", "nyamebox", "throne"],
        _ => &[],
    }
}

/// `FORK_AGENTS`: User-Agent tokens of the sing-box fork clients whose core has a TrustTunnel
/// outbound; the first match names the cut.
const FORK_AGENTS: [(&str, &str); 5] = [
    ("hiddify", "hiddify"),
    ("nyamebox", "nekobox"),
    ("nekobox", "nekobox"),
    ("nekoray", "nekobox"),
    ("throne", "throne"),
];

/// `fork_client(user_agent, extra)`: the renderer client a fork-core User-Agent asks for; the
/// owner's extra tokens (`PANEL_SINGBOX_FORK_CLIENTS`, comma-separated) give `fork`.
pub fn fork_client(user_agent: &str, extra: &str) -> Option<&'static str> {
    let agent = pytext::lower(user_agent);
    if let Some((_, client)) = FORK_AGENTS.iter().find(|(token, _)| agent.contains(token)) {
        return Some(client);
    }
    extra
        .split(',')
        .map(|item| pytext::lower(pytext::strip(item)))
        .any(|token| !token.is_empty() && agent.contains(&token))
        .then_some("fork")
}

/// `CLIENT_ALIASES.get(client, client)`.
pub fn client_alias(client: &str) -> &str {
    match client {
        "nyamebox" => "nekobox",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_tokens_can_be_extended_by_the_owner_setting() {
        assert_eq!(fork_client("Karing/1.2", ""), None);
        assert_eq!(fork_client("Streisand/3", "karing, streisand"), Some("fork"));
        assert_eq!(fork_client("Throne/1", "karing"), Some("throne"));
        assert_eq!(fork_client("", "karing,"), None);
        assert_eq!(fork_client("NyameBox/1", ""), Some("nekobox"));
        assert_eq!(fork_client("HiddifyNext/2.5", ""), Some("hiddify"));
        assert_eq!(fork_client("sing-box 1.13.0", ""), None);
    }

    #[test]
    fn negotiation_is_a_substring_test_in_table_order() {
        assert_eq!(negotiate("application/json, text/html;q=0.1"), "html");
        assert_eq!(negotiate("application/vnd.proxy-control.subscription+json"), "manifest");
        assert_eq!(negotiate("application/yaml"), "clash");
        assert_eq!(negotiate("*/*"), "raw");
    }

    #[test]
    fn tokens_are_43_to_64_url_safe_characters() {
        assert!(is_token(&"A".repeat(43)) && is_token(&"_-9".repeat(21)));
        assert!(!is_token("short") && !is_token(&"A".repeat(65)) && !is_token(&format!("{}!", "A".repeat(42))));
        assert!(!is_token(&format!("{}é", "A".repeat(42))));
    }
}
