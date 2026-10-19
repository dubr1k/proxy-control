"""`html`: the page a person opens — links, QR codes and the compatibility matrix.

No JavaScript, no external resources: the page must render inside any in-app browser
and must not phone anywhere. Every value goes through `html.escape`, including the
`href`s, and the page asks not to be indexed — a subscription URL is a bearer token.
"""
from __future__ import annotations

import base64
import json
from html import escape

from ...reveals import qr_data
from ..compatibility import CLIENTS, MATRIX, NOTES
from ..models import Manifest, ManifestGrant
from ..names import grant_names
from .base import check, credential_reason, finish, named_share_url

PROTOCOL_TITLES = {"mtproxy": "MTProxy", "naive": "NaiveProxy", "mieru": "Mieru", "amneziawg": "AmneziaWG", "trusttunnel": "TrustTunnel"}
STATUS_TITLES = {"supported": "да", "unsupported": "нет", "unproven": "не проверено"}
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:44rem;padding:1rem;color:#1a1a1a;background:#fff}
h1,h2{font-weight:600}section{border:1px solid #ddd;border-radius:.5rem;padding:1rem;margin:1rem 0}
code{display:block;overflow-wrap:anywhere;background:#f4f4f4;padding:.5rem;border-radius:.25rem}
div.scroll{overflow-x:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}
img{width:12rem;height:12rem;display:block;margin:.5rem 0}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.25rem .5rem;text-align:left}
.muted{color:#666}.supported{background:#e6f4ea}.unsupported{background:#fdecea}.unproven{background:#fff4e5}
"""

MANUAL_LABELS = (
    ("server", "Сервер"), ("port", "Порт"), ("username", "Логин"), ("password", "Пароль"), ("sni", "SNI"),
)
# Which app takes TrustTunnel and how (compact form of the panel's «Как подключить» table). Everything
# below the first group is documented by the vendors, not verified by us: the page says so.
TRUSTTUNNEL_APPS = (
    ("AdGuard TrustTunnel", "iOS, Android", "ссылка tt:// или QR",
     (("App Store", "https://apps.apple.com/us/app/trusttunnel/id6755807890"),
      ("Google Play", "https://play.google.com/store/apps/details?id=com.adguard.trusttunnel"))),
    ("TrustTunnel CLI", "Linux, macOS, Windows", "файл TOML",
     (("GitHub", "https://github.com/TrustTunnel/TrustTunnelClient"),)),
    ("Throne", "Windows, Linux, macOS, Android", "вручную: Профиль → Тип TrustTunnel, QUIC выключен", ()),
    ("Surge", "macOS, iOS", "строка политики (ниже)",
     (("документация", "https://manual.nssurge.com/policies/trust-tunnel.html"),)),
    ("Clash Verge Rev, FlClash, Mihomo Party, ClashMi", "Windows, macOS, Linux, Android, iOS",
     "подписка Clash (?format=clash)", ()),
    ("Hiddify, NekoBox", "по клиенту", "подписка sing-box: ?format=singbox&client=hiddify или client=nekobox", ()),
    ("Shadowrocket, Trusty, FreeTunnel, FireTunnel, TrustTunnel-GUI-Client", "iOS, Windows, macOS, Linux",
     "не проверено: проверьте импорт ссылки tt:// или TOML, либо введите данные вручную",
     (("Trusty", "https://github.com/Meddelin/trusty"), ("FreeTunnel", "https://github.com/dimmmmmmmer/freetunnel"),
      ("FireTunnel", "https://github.com/pnsrc/firetunnel"),
      ("TrustTunnel-GUI-Client", "https://github.com/blazuryk/TrustTunnel-GUI-Client"))),
)


def _manual_block(artifact) -> str:
    """The fields of a client that imports neither the link nor the TOML, from the manual artifact."""
    try:
        fields = json.loads(artifact.value)
    except ValueError:
        return ""
    if not isinstance(fields, dict):
        return ""
    rows = "".join(
        f"<tr><th>{label}</th><td><code>{escape(str(fields.get(key, '')))}</code></td></tr>"
        for key, label in MANUAL_LABELS
    )
    rows += "<tr><th>Протокол</th><td>HTTP/2, QUIC выключен</td></tr>"
    if fields.get("certificate_pem"):
        rows += (f"<tr><th>Сертификат</th><td><pre><code>{escape(str(fields['certificate_pem']))}</code></pre></td></tr>")
    surge = f"<p>Surge, строка политики:</p><code>Proxy-TrustTunnel = {escape(str(fields.get('surge', '')))}</code>"
    return f"<h3>{escape(artifact.label)}</h3><div class=\"scroll\"><table>{rows}</table></div>{surge}"


def _apps_block() -> str:
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}{}</td></tr>".format(
            escape(name), escape(platforms), escape(how),
            "".join(
                f" · <a href=\"{escape(url)}\" target=\"_blank\" rel=\"noopener noreferrer\">{escape(label)}</a>"
                for label, url in links
            ),
        )
        for name, platforms, how, links in TRUSTTUNNEL_APPS
    )
    return (
        "<h3>Как подключить</h3><div class=\"scroll\"><table><tr><th>Приложение</th><th>Платформа</th>"
        f"<th>Как импортировать</th></tr>{rows}</table></div>"
    )


def _grant_section(grant: ManifestGrant, artifacts: dict, name: str) -> str:
    title = escape(f"{name} · {grant.runtime_username}")
    if not grant.enabled:
        return f"<section><h2>{title}</h2><p class=\"muted\">Доступ отключён.</p></section>"
    reason = credential_reason(grant, artifacts)
    if reason is not None:
        return f"<section><h2>{title}</h2><p class=\"muted\">Недоступно: {escape(reason)}</p></section>"
    parts = [f"<section><h2>{title}</h2>"]
    for artifact in artifacts[grant.grant_id]:
        value = artifact.value
        if artifact.media_type == "application/json":
            parts.append(_manual_block(artifact))
            continue
        if artifact.media_type == "text/uri-list":
            value = named_share_url(grant, value, name)
        shown = escape(value)
        if artifact.media_type == "application/toml":
            # A config file: shown in full to copy, and offered as a download. No script needed.
            href = "data:application/toml;base64," + base64.b64encode(value.encode()).decode()
            parts.append(
                f"<p>{escape(artifact.label)} · <a href=\"{href}\" download=\"trusttunnel_client.toml\">"
                f"скачать</a></p><pre><code>{shown}</code></pre>"
            )
            continue
        parts.append(f"<p><a href=\"{shown}\">{escape(artifact.label)}</a></p><code>{shown}</code>")
        if artifact.media_type == "text/uri-list":
            parts.append(f"<img src=\"{escape(qr_data(value))}\" alt=\"QR\">")
    if grant.protocol == "trusttunnel":
        parts.append(_apps_block())
    parts.append("</section>")
    return "".join(parts)


def _matrix() -> str:
    head = "".join(f"<th>{escape(client)}</th>" for client in CLIENTS)
    rows = []
    for protocol, cells in MATRIX.items():
        body = "".join(
            f"<td class=\"{cells[client]}\" title=\"{escape(NOTES[protocol][client])}\">"
            f"{STATUS_TITLES[cells[client]]}</td>"
            for client in CLIENTS
        )
        rows.append(f"<tr><th>{escape(PROTOCOL_TITLES.get(protocol, protocol))}</th>{body}</tr>")
    return (
        "<section><h2>Автообновление по клиентам</h2>"
        f"<table><tr><th></th>{head}</tr>{''.join(rows)}</table></section>"
    )


class HtmlRenderer:
    name = "html"
    media_type = "text/html; charset=utf-8"
    version = 3

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        name = escape(manifest.client_name)
        names = grant_names(manifest)
        sections = "".join(_grant_section(grant, artifacts, names[grant.grant_id]) for grant in manifest.grants)
        page = (
            "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta name=\"robots\" content=\"noindex\">"
            f"<title>Доступы · {name}</title><style>{STYLE}</style></head><body>"
            f"<h1>Доступы · {name}</h1>"
            f"<p class=\"muted\">Версия набора: {manifest.generation}. Ссылка на эту страницу — "
            "ваш личный ключ, не передавайте её другим.</p>"
            f"{sections}{_matrix()}</body></html>"
        )
        return finish(page.encode())
