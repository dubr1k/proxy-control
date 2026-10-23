"""«На чём клиент?» — the one catalogue of apps that take our subscription link.

The client window and the access bundle (the chooser of `static/js/link-chooser.js`) read it through
`GET /api/subscriptions/compatibility`; the end-user subscription page can render from the same
module. No UI code here.

An app maps to exactly one link variant — a key of `SHARE_VARIANTS` in `subscription_routes.py` (the
format and the `client=` parameter) — and to one column of the compatibility matrix. What the app gets
is derived, not retyped: a protocol is `works` when the variant delivers it and the matrix cell is
`supported`, `unverified` when it is delivered but not proven, `no` otherwise (not delivered, or the
client cannot consume it at all).

`deeplink` is a template for the «Открыть в приложении» button, or None. A scheme is shipped only
where the vendor's own docs or source state it (the source sits next to each one); `{url}` is the
subscription link as is, `{url_enc}` and `{name_enc}` are percent-encoded. An app without a verified
scheme gets no button, only «Копировать» and the QR.
"""
from __future__ import annotations

from .compatibility import MATRIX

# The protocols a subscription carries (MTProxy and AmneziaWG are not subscription protocols).
SUBSCRIPTION_PROTOCOLS = ("naive", "mieru", "trusttunnel")

PLATFORMS = (
    ("ios", "iPhone / iPad"),
    ("android", "Android"),
    ("windows", "Windows"),
    ("macos", "macOS"),
    ("linux", "Linux"),
)

STATUSES = ("works", "unverified", "no")

# `delivers`: the protocols the feed puts into this variant for this app (see the variant texts in
# subscriptions.js and the renderers); `matrix`: the column whose cells say what was proven.
APPS = (
    {
        "id": "karing", "name": "Karing", "variant": "singbox", "matrix": "karing",
        "platforms": ("ios", "android", "windows", "macos", "linux"),
        "delivers": ("naive", "mieru"),
        "summary": "Бесплатное приложение, само подтягивает изменения по ссылке.",
        # https://karing.app/en/cooperation/scheme — karing://install-config?url=xxxx&name=xxx
        "deeplink": "karing://install-config?url={url_enc}&name={name_enc}",
        "downloads": (("Сайт приложения", "https://karing.app/"), ("Выпуски на GitHub", "https://github.com/KaringX/karing/releases")),
    },
    {
        "id": "hiddify", "name": "Hiddify", "variant": "singbox-hiddify", "matrix": "hiddify",
        "platforms": ("ios", "android", "windows", "macos", "linux"),
        "delivers": ("trusttunnel",),
        "summary": "Бесплатное приложение; нужен только для TrustTunnel.",
        # https://hiddify.com/app/URL-Scheme/ — hiddify://import/<sublink>#name
        "deeplink": "hiddify://import/{url}#{name_enc}",
        "downloads": (("Сайт приложения", "https://hiddify.com/app/"), ("Выпуски на GitHub", "https://github.com/hiddify/hiddify-app/releases")),
    },
    {
        "id": "singbox", "name": "sing-box", "variant": "singbox-official", "matrix": "singbox",
        "platforms": ("ios", "android", "macos"),
        "delivers": ("naive",),
        "summary": "Официальное приложение sing-box; подойдёт, если нужен только NaiveProxy.",
        # https://sing-box.sagernet.org/clients/general/ — sing-box://import-remote-profile?url=urlEncodedURL#urlEncodedName
        "deeplink": "sing-box://import-remote-profile?url={url_enc}#{name_enc}",
        "downloads": (("Где скачать", "https://sing-box.sagernet.org/clients/general/"),),
    },
    {
        "id": "throne", "name": "Throne", "variant": "singbox", "matrix": "throne",
        "platforms": ("windows", "macos", "linux", "android"),
        "delivers": ("naive", "mieru", "trusttunnel"),
        "summary": "Бесплатное приложение для компьютера.",
        # No deep link: Throne has none yet (throneproj/Throne#1179, closed as a duplicate of #855).
        "deeplink": None,
        "downloads": (("Сайт приложения", "https://throneproj.github.io/"), ("Выпуски на GitHub", "https://github.com/throneproj/Throne/releases")),
    },
    {
        "id": "flclash", "name": "FlClash", "variant": "clash", "matrix": "mihomo",
        "platforms": ("android", "windows", "macos", "linux"),
        "delivers": ("mieru", "trusttunnel"),
        "summary": "Бесплатное приложение на ядре mihomo (Clash Meta).",
        # https://github.com/chen08209/FlClash (README, Usage) — clash://install-config?url=<URL-encoded subscription link>
        "deeplink": "clash://install-config?url={url_enc}",
        "downloads": (("Выпуски на GitHub", "https://github.com/chen08209/FlClash/releases"),),
    },
    {
        "id": "clash-verge-rev", "name": "Clash Verge Rev", "variant": "clash", "matrix": "mihomo",
        "platforms": ("windows", "macos", "linux"),
        "delivers": ("mieru", "trusttunnel"),
        "summary": "Бесплатное приложение на ядре mihomo (Clash Meta).",
        # No deep link: its import scheme is not stated in any doc we could check.
        "deeplink": None,
        "downloads": (("Выпуски на GitHub", "https://github.com/clash-verge-rev/clash-verge-rev/releases"),),
    },
    {
        "id": "clashmi", "name": "Clash Mi", "variant": "clash", "matrix": "mihomo",
        "platforms": ("ios", "android", "windows", "macos", "linux"),
        "delivers": ("mieru", "trusttunnel"),
        "summary": "Бесплатное приложение на ядре mihomo (Clash Meta).",
        # No deep link: the scheme is not stated in the docs we could check (KaringX/clashmi-docu).
        "deeplink": None,
        "downloads": (("Выпуски на GitHub", "https://github.com/KaringX/clashmi/releases"),),
    },
)


def protocol_status(app: dict, protocol: str) -> str:
    """works / unverified / no for one subscription protocol in one app."""
    if protocol not in app["delivers"]:
        return "no"
    cell = MATRIX[protocol][app["matrix"]]
    return {"supported": "works", "unproven": "unverified"}.get(cell, "no")


def catalogue() -> dict:
    """The JSON the panel UI renders the chooser from."""
    return {
        "platforms": [{"id": key, "name": name} for key, name in PLATFORMS],
        "apps": [
            {
                "id": app["id"],
                "name": app["name"],
                "summary": app["summary"],
                "platforms": list(app["platforms"]),
                "variant": app["variant"],
                "protocols": {protocol: protocol_status(app, protocol) for protocol in SUBSCRIPTION_PROTOCOLS},
                "deeplink": app["deeplink"],
                "downloads": [{"label": label, "url": url} for label, url in app["downloads"]],
            }
            for app in APPS
        ],
    }
