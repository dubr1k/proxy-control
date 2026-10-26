"""Record WP9 renderer goldens with the production Python 3.13.5 panel.

Run from the repository root inside the Python 3.13.5 panel image:
    PYTHONPATH=. python panel/crates/subscriptions/tests/fixtures/record_goldens.py

The input is deterministic and contains no real credential. HTML goldens include the exact QR SVG
bytes: the shared Rust QR implementation is byte-compatible with python-qrcode 8.2.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

from panel.protocols.base import AccessArtifact
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import RENDERERS
from panel.subscriptions.service import SubscriptionService
from panel.trusttunnel_link import encode_deeplink

HERE = Path(__file__).resolve().parent
URL = "https://sub.example.com/s/TOKEN"
UPDATED_AT = 1_800_000_000


def grant(grant_id, protocol, username, *, node="ams", node_name="AMS", enabled=True, secret=1, label="", options=None):
    return ManifestGrant(
        grant_id=grant_id, protocol=protocol, node_id=node, endpoint_id="default",
        runtime_username=username, secret_version=secret, options=options or {}, enabled=enabled,
        valid_from=1_700_000_000, valid_until=1_900_000_000, node_name=node_name, label=label,
    )


def artifact(kind, label, media_type, value):
    return AccessArtifact(kind=kind, label=label, media_type=media_type, value=value)


def tt_link(username, *, certificate=None):
    return encode_deeplink(
        hostname="gate.example.com", addresses=["gate.example.com:443"], username=username,
        password="tt-pass-CANARY-01", certificate_der=certificate,
    )


def tt_artifacts(username, *, certificate=None):
    certificate_pem = "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----\n" if certificate else ""
    manual = json.dumps({
        "server": "gate.example.com", "port": 443, "username": username,
        "password": "tt-pass-CANARY-01", "sni": "gate.example.com", "protocol": "HTTP/2",
        "quic": False, "certificate_pem": certificate_pem,
        "surge": f"trust-tunnel, gate.example.com, 443, username={username}, password=tt-pass-CANARY-01",
    }, ensure_ascii=False, indent=2)
    toml = (
        'loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = true\n\n'
        '[endpoint]\nhostname = "gate.example.com"\naddresses = ["gate.example.com:443"]\n'
        f'username = "{username}"\npassword = "tt-pass-CANARY-01"\nskip_verification = false\n'
        'upstream_protocol = "http2"\n\n[listener.tun]\n'
        'included_routes = ["0.0.0.0/0", "2000::/3"]\nmtu_size = 1350\n'
    )
    return [
        artifact("trusttunnel_link", "Ссылка TrustTunnel", "text/uri-list", tt_link(username, certificate=certificate)),
        artifact("trusttunnel_toml", "Конфиг TrustTunnel (TOML)", "application/toml", toml),
        artifact("trusttunnel_manual", "Данные для ручной настройки", "application/json", manual),
    ]


def fixture():
    grants = [
        grant("g-mt", "mtproxy", "alice"),
        grant("g-naive", "naive", "bob"),
        grant("g-mieru", "mieru", "carol", node="fra", node_name="FRA"),
        grant("g-none", "mieru", "dave", node="fra", node_name="FRA", secret=0),
        grant("g-off", "naive", "erin", enabled=False),
        grant("g-range", "mieru", "frank", node="fra", node_name="FRA"),
        grant("g-tt", "trusttunnel", "trusted", node="tt", node_name="TT"),
        grant("g-tt-cert", "trusttunnel", "selfsigned", node="tt", node_name="TT", label="Phone"),
        grant("g-tt-off", "trusttunnel", "paused", node="tt", node_name="TT", enabled=False),
    ]
    manifest = Manifest(client_id="c1", client_name="Sergey <b>&</b>", generation=3, grants=grants)
    artifacts = {
        "g-mt": [artifact("link", "Ссылка Telegram", "text/uri-list", "tg://proxy?server=proxy.example.com&port=443&secret=ee00112233445566778899aabbccddeeff")],
        "g-naive": [artifact("proxy_url", "Адрес прокси", "text/uri-list", "https://bob:naive-pass-01@naive.example.com")],
        "g-mieru": [artifact("share_url", "Ссылка Mieru", "text/uri-list", "mierus://carol:mieru-pass-01@mieru.example.com?profile=carol&port=8443&protocol=TCP")],
        "g-range": [artifact("share_url", "Ссылка Mieru", "text/uri-list", "mierus://frank:mieru-pass-03@mieru.example.com?profile=frank&port=8000-8010&protocol=TCP")],
        "g-tt": tt_artifacts("trusted"),
        "g-tt-cert": tt_artifacts("selfsigned", certificate=b"\x30\x03\x02\x01\x05"),
    }
    return manifest, artifacts


def main():
    manifest, artifacts = fixture()
    case = {
        "manifest": dataclasses.asdict(manifest),
        "artifacts": {key: [dataclasses.asdict(item) for item in value] for key, value in artifacts.items()},
        "url": URL,
        "updated_at": UPDATED_AT,
    }
    (HERE / "case.json").write_text(json.dumps(case, ensure_ascii=False, sort_keys=True, indent=2) + "\n")

    for name in ("raw", "clash", "manifest"):
        (HERE / f"{name}.golden").write_bytes(RENDERERS[name].render(manifest, artifacts))
    for client in ("karing", "singbox", "hiddify", "nekobox", "throne", "fork"):
        body = RENDERERS["singbox"].render(manifest, artifacts, client=client)
        (HERE / f"singbox.{client}.golden").write_bytes(body)
    for lang in ("ru", "en"):
        body = RENDERERS["html"].render(manifest, artifacts, url=URL, lang=lang, updated_at=UPDATED_AT)
        (HERE / f"html.{lang}.golden").write_bytes(body)

    etags = {}
    for name, renderer in RENDERERS.items():
        variants = ("", "karing", "singbox", "hiddify", "nekobox", "throne", "fork") if name == "singbox" else ("",)
        if name == "html":
            variants = ("ru:1800000000", "en:1800000000")
        for variant in variants:
            etags[f"{name}:{variant}"] = SubscriptionService.etag(manifest, renderer.version, variant)
    (HERE / "etags.json").write_text(json.dumps(etags, sort_keys=True, indent=2) + "\n")
    print(f"recorded {len(list(HERE.glob('*.golden')))} renderer goldens and {len(etags)} ETags with Python {sys.version.split()[0]}")


if __name__ == "__main__":
    main()
