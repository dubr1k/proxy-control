"""Which client refreshes which protocol from our feed — by verified fact, not by app name.

`MATRIX` and `NOTES` copy the `clients` section of `tests/fixtures/vnext-capabilities.json`
(owner decision 2 of the v0.2 plan). The fixture stays the single source: the panel image
does not ship `tests/`, so the copy lives here, and
`test_compatibility_matrix_follows_the_fixture…` fails the moment the two drift apart.

A cell is `supported` where auto-refresh was proven on the lab host or, for a client whose
core the vendor documents (the TrustTunnel cell of mihomo), where the note says "not verified
by us"; the sing-box feed delivers TrustTunnel to the fork cores by User-Agent or `client=` whatever
their cell says (Hiddify's was run against a real core; Throne's and NekoBox's were not); `unproven`
where the client could plausibly work but nobody has shown it, and `unsupported` where
the client has no way to consume that protocol at all. A missing cell is not allowed.
"""
from __future__ import annotations

STATUSES = ("supported", "unsupported", "unproven")

MATRIX: dict[str, dict[str, str]] = {
    "mtproxy": {
        "karing": "unsupported",
        "singbox": "unsupported",
        "mihomo": "unsupported",
        "mieru_cli": "unsupported",
        "telegram": "unsupported",
        "shadowrocket": "unsupported",
        "nekobox": "unsupported",
        "v2rayn": "unsupported",
        "hiddify": "unsupported",
        "throne": "unsupported",
    },
    "naive": {
        "karing": "supported",
        "singbox": "supported",
        "mihomo": "unsupported",
        "mieru_cli": "unsupported",
        "telegram": "unsupported",
        "shadowrocket": "unproven",
        "nekobox": "unproven",
        "v2rayn": "unproven",
        "hiddify": "unproven",
        "throne": "supported",
    },
    "mieru": {
        "karing": "supported",
        "singbox": "unsupported",
        "mihomo": "supported",
        "mieru_cli": "unsupported",
        "telegram": "unsupported",
        "shadowrocket": "unsupported",
        "nekobox": "unsupported",
        "v2rayn": "unproven",
        "hiddify": "unsupported",
        "throne": "supported",
    },
    "trusttunnel": {
        "karing": "unproven",
        "singbox": "unsupported",
        "mihomo": "supported",
        "mieru_cli": "unsupported",
        "telegram": "unsupported",
        "shadowrocket": "unproven",
        "nekobox": "unproven",
        "v2rayn": "unproven",
        "hiddify": "supported",
        "throne": "unproven",
    },
}

NOTES: dict[str, dict[str, str]] = {
    "mtproxy": {
        "karing": "no MTProto import path; the tg:// link is handed over manually",
        "singbox": "sing-box has no MTProto outbound",
        "mihomo": "mihomo has no MTProto proxy type",
        "mieru_cli": "single-protocol client",
        "telegram": "Telegram accepts a tg://proxy link and never polls a subscription URL",
        "shadowrocket": "MTProto is imported manually, not from a mixed feed",
        "nekobox": "no MTProto import path",
        "v2rayn": "no MTProto import path",
        "hiddify": "no MTProto import path",
        "throne": "no MTProto import path",
    },
    "naive": {
        "karing": "sing-box fork core; accepts a sing-box JSON subscription with a naive outbound",
        "singbox": "outbound type naive exists since sing-box 1.13.0 on Apple, Android, Windows and part of the Linux builds",
        "mihomo": "naiveproxy support is an open feature request, MetaCubeX/mihomo#273",
        "mieru_cli": "single-protocol client",
        "telegram": "not a Telegram protocol",
        "shadowrocket": "no verified naive import format for our renderers; not offered until proven on the lab host",
        "nekobox": "NekoBox forks parse naive+https:// links, but subscription auto-refresh with our feed is unverified",
        "v2rayn": "depends on the bundled core version; not verified against our sing-box renderer",
        "hiddify": "sing-box based, but the shipped core version and naive build variant are unverified",
        "throne": "ThroneCore (a sing-box fork) takes the naive outbound from either sing-box JSON cut; verified with Throne 1.3.1 on the lab host",
    },
    "mieru": {
        "karing": "release notes list Mieru support for both the sing-box and clash cores",
        "singbox": "official sing-box has no mieru outbound",
        "mihomo": "proxy type mieru with server, port/port-range, transport, username, password, multiplexing, udp",
        "mieru_cli": "the official client has no subscription mechanism at all: mieru apply config / mieru import config only (enfein/mieru docs/client-install.md)",
        "telegram": "not a Telegram protocol",
        "shadowrocket": "no verified Mieru import format (docs/MIERU_SHARING.en.md)",
        "nekobox": "no verified Mieru import format (docs/MIERU_SHARING.en.md)",
        "v2rayn": "depends on the bundled core version; not verified against our clash renderer",
        "hiddify": "sing-box based; the official core has no mieru outbound",
        "throne": "the mieru outbound comes from the Karing sing-box JSON cut, never from Clash YAML (Throne's clash parser has no mieru type); in Throne 1.3.1 a UDP binding connects only when the server is an IP address",
    },
    "trusttunnel": {
        "karing": "ships a mihomo (Clash.Meta) core next to the sing-box one, but a trusttunnel proxy in a Clash feed is unverified in Karing; the sing-box cut has no TrustTunnel outbound",
        "singbox": "upstream sing-box has no TrustTunnel outbound (planned: SagerNet/sing-box#3723, milestone 1.14); an official sing-box rejects an unknown outbound type and drops the whole config, so the feed never emits TrustTunnel for plain sing-box",
        "mihomo": "proxy type trusttunnel with server, port, username, password, udp, quic, skip-cert-verify (MetaCubeX wiki, config/proxies/trusttunnel); documented by the core vendor, not verified by us; Clash Verge Rev, FlClash, Mihomo Party, ClashMi and the other Mihomo-core clients take it while their bundled core is recent",
        "mieru_cli": "single-protocol client",
        "telegram": "not a Telegram protocol",
        "shadowrocket": "the TrustTunnel README lists Shadowrocket as a supporting client, but its import format is unverified: enter the server by hand or check whether it takes the tt:// link; no Clash or sing-box import is claimed",
        "nekobox": "the feed carries the trusttunnel outbound for a NekoBox, NyameBox or NekoRay User-Agent and for ?format=singbox&client=nekobox; the NekoBox fork NyameBox (qr243vbi/nekobox) lists a trusttunnel outbound in its core fork, but we could not run that core: unverified",
        "v2rayn": "depends on the bundled core version; not verified against our clash renderer",
        "hiddify": "delivered by default in the sing-box subscription (a Hiddify User-Agent or ?format=singbox&client=hiddify); verified 2026-10-19 against hiddify-sing-box built from master ae5cb1488 (no release has the outbound yet): sing-box check passes, an official sing-box 1.14.3 refuses it as an unknown outbound type, and a request through it returned 200 with the traffic counted on the gate; health_check is not emitted because that build panicked with it on",
        "throne": "the sing-box subscription carries the trusttunnel outbound for a Throne User-Agent or ?format=singbox&client=throne, and ThroneCore 1.4.0-beta.3 (sing-box v1.14.1 fork) contains the outbound, but whether Throne's subscription import keeps it is unverified; Throne does not import tt:// links (throneproj/Throne#1416), so the fallback is a profile created by hand (Ctrl+N, Type TrustTunnel, address, port, username, password, SNI; leave QUIC off)",
    },
}

CLIENTS = tuple(MATRIX["mtproxy"])
