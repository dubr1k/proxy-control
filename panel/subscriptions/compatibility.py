"""Which client refreshes which protocol from our feed — by verified fact, not by app name.

`MATRIX` and `NOTES` copy the `clients` section of `tests/fixtures/vnext-capabilities.json`
(owner decision 2 of the v0.2 plan). The fixture stays the single source: the panel image
does not ship `tests/`, so the copy lives here, and
`test_compatibility_matrix_follows_the_fixture…` fails the moment the two drift apart.

A cell is `supported` only where auto-refresh was proven on the lab host, `unproven`
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
    },
}

CLIENTS = tuple(MATRIX["mtproxy"])
