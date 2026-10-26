//! Which client refreshes which protocol from the feed — by verified fact, not by app name
//! (`subscriptions/compatibility.py`).
//!
//! `MATRIX` and `NOTES` copy the `clients` section of `tests/fixtures/vnext-capabilities.json`; a
//! test fails the moment the two drift apart. The order of protocols and clients is Python's dict
//! order: the compatibility endpoint serialises them in that order.

use serde_json::{Map, Value};

/// The statuses a cell may hold.
pub const STATUSES: [&str; 3] = ["supported", "unsupported", "unproven"];

/// The matrix columns (`CLIENTS`), in order.
pub const CLIENTS: [&str; 10] =
    ["karing", "singbox", "mihomo", "mieru_cli", "telegram", "shadowrocket", "nekobox", "v2rayn", "hiddify", "throne"];

/// The matrix rows, in order.
pub const PROTOCOLS: [&str; 4] = ["mtproxy", "naive", "mieru", "trusttunnel"];

/// `MATRIX[protocol][client]`, rows in [`PROTOCOLS`] order, cells in [`CLIENTS`] order.
const MATRIX: [[&str; 10]; 4] = [
    [
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
    ],
    [
        "supported",
        "supported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unproven",
        "unproven",
        "unproven",
        "unproven",
        "supported",
    ],
    [
        "supported",
        "unsupported",
        "supported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unsupported",
        "unproven",
        "unsupported",
        "supported",
    ],
    [
        "unproven",
        "unsupported",
        "supported",
        "unsupported",
        "unsupported",
        "unproven",
        "unproven",
        "unproven",
        "unproven",
        "unproven",
    ],
];

/// `NOTES[protocol][client]`, in the same layout as the matrix.
const NOTES: [[&str; 10]; 4] = [
    [
        "no MTProto import path; the tg:// link is handed over manually",
        "sing-box has no MTProto outbound",
        "mihomo has no MTProto proxy type",
        "single-protocol client",
        "Telegram accepts a tg://proxy link and never polls a subscription URL",
        "MTProto is imported manually, not from a mixed feed",
        "no MTProto import path",
        "no MTProto import path",
        "no MTProto import path",
        "no MTProto import path",
    ],
    [
        "sing-box fork core; accepts a sing-box JSON subscription with a naive outbound",
        "outbound type naive exists since sing-box 1.13.0 on Apple, Android, Windows and part of the Linux builds",
        "naiveproxy support is an open feature request, MetaCubeX/mihomo#273",
        "single-protocol client",
        "not a Telegram protocol",
        "no verified naive import format for our renderers; not offered until proven on the lab host",
        "NekoBox forks parse naive+https:// links, but subscription auto-refresh with our feed is unverified",
        "depends on the bundled core version; not verified against our sing-box renderer",
        "sing-box based, but the shipped core version and naive build variant are unverified",
        "ThroneCore (a sing-box fork) takes the naive outbound from either sing-box JSON cut; verified with Throne 1.3.1 on the lab host",
    ],
    [
        "release notes list Mieru support for both the sing-box and clash cores",
        "official sing-box has no mieru outbound",
        "proxy type mieru with server, port/port-range, transport, username, password, multiplexing, udp",
        "the official client has no subscription mechanism at all: mieru apply config / mieru import config only (enfein/mieru docs/client-install.md)",
        "not a Telegram protocol",
        "no verified Mieru import format (docs/MIERU_SHARING.en.md)",
        "no verified Mieru import format (docs/MIERU_SHARING.en.md)",
        "depends on the bundled core version; not verified against our clash renderer",
        "sing-box based; the official core has no mieru outbound",
        "the mieru outbound comes from the Karing sing-box JSON cut, never from Clash YAML (Throne's clash parser has no mieru type); in Throne 1.3.1 a UDP binding connects only when the server is an IP address",
    ],
    [
        "ships a mihomo (Clash.Meta) core next to the sing-box one, but a trusttunnel proxy in a Clash feed is unverified in Karing; the sing-box cut has no TrustTunnel outbound",
        "upstream sing-box has no TrustTunnel outbound (planned: SagerNet/sing-box#3723, milestone 1.14); an official sing-box rejects an unknown outbound type and drops the whole config, so the feed never emits TrustTunnel for plain sing-box",
        "proxy type trusttunnel with server, port, username, password, udp, quic, skip-cert-verify (MetaCubeX wiki, config/proxies/trusttunnel); verified 2026-10-20 with mihomo v1.19.32 on the lab host: the proxy from our Clash feed carried a request (200) out through the node; Clash Verge Rev, FlClash, Mihomo Party, ClashMi and the other Mihomo-core clients take it while their bundled core is recent",
        "single-protocol client",
        "not a Telegram protocol",
        "the TrustTunnel README lists Shadowrocket as a supporting client, but its import format is unverified: enter the server by hand or check whether it takes the tt:// link; no Clash or sing-box import is claimed",
        "the feed carries the trusttunnel outbound for a NekoBox, NyameBox or NekoRay User-Agent and for ?format=singbox&client=nekobox; the NekoBox fork NyameBox (qr243vbi/nekobox) lists a trusttunnel outbound in its core fork, but we could not run that core: unverified",
        "depends on the bundled core version; not verified against our clash renderer",
        "delivered by default in the sing-box subscription (a Hiddify User-Agent or ?format=singbox&client=hiddify); verified 2026-10-19 only against hiddify-sing-box built from master ae5cb1488: no Hiddify app release carries the outbound yet (the app's latest release, 4.1.1, is from 2026-03), so the app itself is unverified: sing-box check passes, an official sing-box 1.14.3 refuses it as an unknown outbound type, and a request through it returned 200 with the traffic counted on the gate; health_check is not emitted because that build panicked with it on",
        "the sing-box subscription carries the trusttunnel outbound for a Throne User-Agent or ?format=singbox&client=throne, and ThroneCore 1.4.0-beta.3 (sing-box v1.14.1 fork) contains the outbound, but whether Throne's subscription import keeps it is unverified; Throne does not import tt:// links (throneproj/Throne#1416), so the fallback is a profile created by hand (Ctrl+N, Type TrustTunnel, address, port, username, password, SNI; leave QUIC off)",
    ],
];

fn cell(table: &'static [[&'static str; 10]; 4], protocol: &str, client: &str) -> Option<&'static str> {
    let row = PROTOCOLS.iter().position(|name| *name == protocol)?;
    let column = CLIENTS.iter().position(|name| *name == client)?;
    Some(table[row][column])
}

/// `MATRIX.get(protocol, {}).get(client)`.
pub fn status(protocol: &str, client: &str) -> Option<&'static str> {
    cell(&MATRIX, protocol, client)
}

/// `NOTES.get(protocol, {}).get(client)`.
pub fn note(protocol: &str, client: &str) -> Option<&'static str> {
    cell(&NOTES, protocol, client)
}

fn table_json(table: &'static [[&'static str; 10]; 4]) -> Value {
    let mut rows = Map::new();
    for (protocol, row) in PROTOCOLS.iter().zip(table) {
        let cells: Map<String, Value> =
            CLIENTS.iter().zip(row).map(|(client, text)| (client.to_string(), Value::from(*text))).collect();
        rows.insert(protocol.to_string(), Value::Object(cells));
    }
    Value::Object(rows)
}

/// `MATRIX` as JSON, in Python's order.
pub fn matrix_json() -> Value {
    table_json(&MATRIX)
}

/// `NOTES` as JSON, in Python's order.
pub fn notes_json() -> Value {
    table_json(&NOTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/fixtures/vnext-capabilities.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn compatibility_matrix_follows_the_fixture_and_never_claims_telegram_auto_refresh() {
        let matrix = matrix_json();
        assert_eq!(matrix.as_object().unwrap().keys().collect::<Vec<_>>(), PROTOCOLS.iter().collect::<Vec<_>>());
        assert!(PROTOCOLS
            .iter()
            .all(|protocol| CLIENTS.iter().all(|client| STATUSES.contains(&status(protocol, client).unwrap()))));
        assert_eq!(status("mtproxy", "telegram"), Some("unsupported"));
        assert_eq!((status("naive", "karing"), status("mieru", "karing")), (Some("supported"), Some("supported")));
        assert_eq!((status("naive", "singbox"), status("mieru", "singbox")), (Some("supported"), Some("unsupported")));
        assert_eq!((status("mieru", "mihomo"), status("naive", "mihomo")), (Some("supported"), Some("unsupported")));
        let clients = &fixture()["clients"];
        for protocol in PROTOCOLS {
            for (client, cells) in clients.as_object().unwrap() {
                assert_eq!(status(protocol, client), cells[protocol]["status"].as_str(), "{protocol} {client}");
                assert_eq!(note(protocol, client), cells[protocol]["note"].as_str(), "{protocol} {client}");
            }
        }
        assert_eq!(clients.as_object().unwrap().len(), CLIENTS.len());
    }

    #[test]
    fn trusttunnel_matrix_row_is_evidence_honest() {
        let row = |client| status("trusttunnel", client).unwrap();
        assert_eq!(row("mihomo"), "supported");
        assert!(["singbox", "mieru_cli", "telegram"].iter().all(|client| row(client) == "unsupported"));
        assert!(["hiddify", "nekobox", "throne"].iter().all(|client| row(client) == "unproven"));
        assert!(note("trusttunnel", "mihomo").unwrap().contains("verified 2026-10-20 with mihomo v1.19.32"));
        assert!(note("trusttunnel", "hiddify").unwrap().contains("verified 2026-10-19 only"));
        assert!(note("trusttunnel", "nekobox").unwrap().contains("unverified"));
        assert!(note("trusttunnel", "throne").unwrap().contains("unverified"));
        assert!(CLIENTS.iter().filter(|client| **client != "mihomo").all(|client| row(client) != "supported"));
    }
}
