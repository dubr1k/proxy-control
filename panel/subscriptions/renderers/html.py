"""`html`: the page a person opens — links, QR codes and the compatibility matrix.

No JavaScript, no external resources: the page must render inside any in-app browser
and must not phone anywhere. Every value goes through `html.escape`, including the
`href`s, and the page asks not to be indexed — a subscription URL is a bearer token.
"""
from __future__ import annotations

from html import escape

from ...reveals import qr_data
from ..compatibility import CLIENTS, MATRIX, NOTES
from ..models import Manifest, ManifestGrant
from .base import check, credential_reason, finish, naive_share_url

PROTOCOL_TITLES = {"mtproxy": "MTProxy", "naive": "NaiveProxy", "mieru": "Mieru"}
STATUS_TITLES = {"supported": "да", "unsupported": "нет", "unproven": "не проверено"}
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:44rem;padding:1rem;color:#1a1a1a;background:#fff}
h1,h2{font-weight:600}section{border:1px solid #ddd;border-radius:.5rem;padding:1rem;margin:1rem 0}
code{display:block;overflow-wrap:anywhere;background:#f4f4f4;padding:.5rem;border-radius:.25rem}
img{width:12rem;height:12rem;display:block;margin:.5rem 0}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.25rem .5rem;text-align:left}
.muted{color:#666}.supported{background:#e6f4ea}.unsupported{background:#fdecea}.unproven{background:#fff4e5}
"""


def _grant_section(grant: ManifestGrant, artifacts: dict) -> str:
    title = escape(f"{PROTOCOL_TITLES.get(grant.protocol, grant.protocol)} · {grant.runtime_username}")
    if not grant.enabled:
        return f"<section><h2>{title}</h2><p class=\"muted\">Доступ отключён.</p></section>"
    reason = credential_reason(grant, artifacts)
    if reason is not None:
        return f"<section><h2>{title}</h2><p class=\"muted\">Недоступно: {escape(reason)}</p></section>"
    parts = [f"<section><h2>{title}</h2>"]
    for artifact in artifacts[grant.grant_id]:
        value = artifact.value
        if grant.protocol == "naive" and artifact.media_type == "text/uri-list":
            value = naive_share_url(value, grant.runtime_username)
        shown = escape(value)
        parts.append(f"<p><a href=\"{shown}\">{escape(artifact.label)}</a></p><code>{shown}</code>")
        if artifact.media_type == "text/uri-list":
            parts.append(f"<img src=\"{escape(qr_data(value))}\" alt=\"QR\">")
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
    version = 1

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        name = escape(manifest.client_name)
        sections = "".join(_grant_section(grant, artifacts) for grant in manifest.grants)
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
