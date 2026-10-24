"""`html`: the page a person opens — the apps that take the link, the link itself and each access.

The reader is the client's end user, not the operator. The top of the page is what they do first:
«Добавить в <app>» buttons built from the one app catalogue (`subscriptions/apps.py`) and «Копировать
ссылку подписки»; the QR of that link is behind «Показать QR» because it is for a second device. Each
access is a collapsed section with copy buttons. No external resources: the stylesheet and the one
copy script are inline and admitted by hash (`page_assets.py`). Every value goes through
`html.escape`, including the `href`s, and the page asks not to be indexed — a subscription URL is a
bearer token. Russian by default, English with `?lang=en` (the route passes `lang`).
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlsplit

from ...reveals import qr_data
from ..apps import SHARE_VARIANTS, SUBSCRIPTION_PROTOCOLS, apps_for, deep_link
from ..models import Manifest, ManifestGrant
from ..names import display_text, grant_names
from ..page_assets import SCRIPT, STYLE
from .base import RenderError, check, credential_reason, finish, named_share_url, trusttunnel_fields

PROTOCOL_TITLES = {"mtproxy": "MTProxy", "naive": "NaiveProxy", "mieru": "Mieru", "amneziawg": "AmneziaWG", "trusttunnel": "TrustTunnel"}

MANUAL_LABELS = (
    ("server", "Сервер", "Server"), ("port", "Порт", "Port"), ("username", "Логин", "Username"),
    ("password", "Пароль", "Password"), ("sni", "SNI", "SNI"),
)
# Which app takes TrustTunnel and how — only what was run against this panel's own output:
# the official deep-link decoder and CLI client (TrustTunnelClient 1.1.11) with the tt:// link and
# the TOML, and the mihomo core (v1.19.32) with the Clash feed. Vendor-documented apps that were
# never run are not listed (the panel's grant window keeps them, marked «не проверено нами»).
TRUSTTUNNEL_APPS = (
    (("AdGuard TrustTunnel", "AdGuard TrustTunnel"), ("iOS, Android", "iOS, Android"),
     ("ссылка tt:// или QR", "tt:// link or QR"),
     (("App Store", "https://apps.apple.com/us/app/trusttunnel/id6755807890"),
      ("Google Play", "https://play.google.com/store/apps/details?id=com.adguard.trusttunnel"))),
    (("TrustTunnel CLI", "TrustTunnel CLI"), ("Linux, macOS, Windows", "Linux, macOS, Windows"),
     ("файл TOML", "TOML file"),
     (("GitHub", "https://github.com/TrustTunnel/TrustTunnelClient"),)),
    (("Приложения на ядре mihomo (Clash Meta)", "Apps built on the mihomo core (Clash Meta)"),
     ("Windows, macOS, Linux, Android, iOS", "Windows, macOS, Linux, Android, iOS"),
     ("подписка Clash: эта ссылка с ?format=clash", "Clash subscription: this link with ?format=clash"), ()),
)


class _Page:
    """Language, unique element ids and the copy-button markup for one render."""

    def __init__(self, lang: str):
        self.lang = lang if lang in ("ru", "en") else "ru"
        self.count = 0

    def t(self, ru: str, en: str) -> str:
        return ru if self.lang == "ru" else en

    def copy(self, value: str, label: str | None = None, *, extra: str = "") -> str:
        """A readable value and the button that copies it; the script reads the value from the page."""
        self.count += 1
        ident = f"v{self.count}"
        label = label or self.t("Копировать", "Copy")
        return (
            f"<code id=\"{ident}\">{escape(value)}</code>"
            f"<button type=\"button\" class=\"btn small\" data-copy=\"{ident}\" "
            f"data-done=\"{self.t('Скопировано', 'Copied')}\" data-fail=\"{self.t('Не получилось — выделите вручную', 'Failed — select it by hand')}\">"
            f"{escape(label)}</button>{extra}"
        )

    def qr(self, value: str) -> str:
        return (
            f"<details class=\"qr\"><summary>{self.t('Показать QR', 'Show QR')}</summary>"
            f"<p class=\"muted small\">{self.t('Для другого устройства: наведите на него камеру или сканер в приложении.', 'For another device: scan it with its camera or the scanner in the app.')}</p>"
            f"<img src=\"{escape(qr_data(value))}\" alt=\"QR\"></details>"
        )


def _endpoint_domain(grant: ManifestGrant, artifacts: dict) -> str:
    """The host an access connects to, from its own link; "" when there is no link to read it from."""
    for artifact in artifacts.get(grant.grant_id, []):
        if artifact.media_type != "text/uri-list":
            continue
        try:
            if grant.protocol == "trusttunnel":
                return str(trusttunnel_fields(artifact.value).get("hostname") or "")
            parts = urlsplit(artifact.value)
            if grant.protocol == "mtproxy":
                host = dict(item.partition("=")[::2] for item in parts.query.split("&")).get("server", "")
                return host
            return parts.hostname or ""
        except (ValueError, RenderError):
            return ""
    return ""


def _titles(manifest: Manifest, artifacts: dict) -> dict[str, str]:
    """What a person sees above each access: the name the operator gave it, else «protocol · domain»
    (never the local node's default name). Two accesses that read the same get their login added.
    The `#fragment` names inside the links are `grant_names` and stay as they are."""
    names = grant_names(manifest)
    titles = {}
    for grant in manifest.grants:
        if display_text(grant.label):
            titles[grant.grant_id] = names[grant.grant_id]
            continue
        domain = _endpoint_domain(grant, artifacts)
        protocol = PROTOCOL_TITLES.get(grant.protocol, grant.protocol)
        titles[grant.grant_id] = f"{protocol} · {domain}" if domain else protocol
    seen: dict[str, int] = {}
    for title in titles.values():
        seen[title] = seen.get(title, 0) + 1
    return {
        grant.grant_id: (f"{titles[grant.grant_id]} · {grant.runtime_username}" if seen[titles[grant.grant_id]] > 1 else titles[grant.grant_id])
        for grant in manifest.grants
    }


def _manual_block(page: _Page, artifact) -> str:
    """The fields of a client that imports neither the link nor the TOML, from the manual artifact."""
    try:
        fields = json.loads(artifact.value)
    except ValueError:
        return ""
    if not isinstance(fields, dict):
        return ""
    rows = "".join(
        f"<tr><th>{page.t(ru, en)}</th><td>{page.copy(str(fields.get(key, '')))}</td></tr>"
        for key, ru, en in MANUAL_LABELS
    )
    rows += f"<tr><th>{page.t('Протокол', 'Protocol')}</th><td>{page.t('HTTP/2, QUIC выключен', 'HTTP/2, QUIC off')}</td></tr>"
    if fields.get("certificate_pem"):
        rows += f"<tr><th>{page.t('Сертификат', 'Certificate')}</th><td>{page.copy(str(fields['certificate_pem']))}</td></tr>"
    return f"<h3>{escape(artifact.label)}</h3><table>{rows}</table>"


def _apps_block(page: _Page) -> str:
    items = "".join(
        "<li><b>{}</b> ({}): {}{}</li>".format(
            escape(page.t(*name)), escape(page.t(*platforms)), escape(page.t(*how)),
            "".join(
                f" · <a href=\"{escape(url)}\" target=\"_blank\" rel=\"noopener noreferrer\">{escape(label)}</a>"
                for label, url in links
            ),
        )
        for name, platforms, how, links in TRUSTTUNNEL_APPS
    )
    return f"<h3>{page.t('Как подключить', 'How to connect')}</h3><ul>{items}</ul>"


def _grant_section(page: _Page, grant: ManifestGrant, artifacts: dict, name: str, title: str) -> str:
    heading = escape(title)
    if not grant.enabled:
        return f"<details class=\"card\"><summary>{heading}</summary><p class=\"muted\">{page.t('Доступ отключён.', 'This access is turned off.')}</p></details>"
    reason = credential_reason(grant, artifacts)
    if reason is not None:
        return (f"<details class=\"card\"><summary>{heading}</summary><p class=\"muted\">"
                f"{page.t('Недоступно', 'Unavailable')}: {escape(reason)}</p></details>")
    parts = [f"<details class=\"card\"><summary>{heading}</summary>"]
    for artifact in artifacts[grant.grant_id]:
        value = artifact.value
        if artifact.media_type == "application/json":
            parts.append(_manual_block(page, artifact))
            continue
        if artifact.media_type == "text/uri-list":
            value = named_share_url(grant, value, name)
        if artifact.media_type == "application/toml":
            # A config file: shown in full to copy, and offered as a download.
            href = "data:application/toml;base64," + base64.b64encode(value.encode()).decode()
            parts.append(
                f"<h3>{escape(artifact.label)}</h3>{page.copy(value)}"
                f"<a class=\"btn small\" href=\"{href}\" download=\"trusttunnel_client.toml\">{page.t('Скачать файл', 'Download the file')}</a>"
            )
            continue
        parts.append(f"<h3>{escape(artifact.label)}</h3>")
        if artifact.media_type == "text/uri-list":
            parts.append(f"<a class=\"btn primary\" href=\"{escape(value)}\">{page.t('Открыть', 'Open')}</a>")
        parts.append(page.copy(value, page.t("Копировать ссылку", "Copy the link"),
                               extra=page.qr(value) if artifact.media_type == "text/uri-list" else ""))
    if grant.protocol == "trusttunnel":
        parts.append(_apps_block(page))
    parts.append("</details>")
    return "".join(parts)


def _gets(page: _Page, entry: dict) -> str:
    names = lambda items: ", ".join(PROTOCOL_TITLES.get(p, p) for p in items)  # noqa: E731
    lines = []
    if entry["works"]:
        lines.append(f"{page.t('Получите', 'You get')}: {names(entry['works'])}.")
    if entry["unverified"]:
        lines.append(f"{page.t('Должно работать, но мы это не проверяли', 'Should work, but we have not tested it')}: {names(entry['unverified'])}.")
    if entry["no"] or entry["pending"]:
        lines.append(f"{page.t('Не работает в этом приложении', 'Not available in this app')}: {names(entry['no'] + entry['pending'])}.")
    return "".join(f"<p class=\"muted small\">{escape(line)}</p>" for line in lines)


PLATFORM_NAMES = {
    "ios": ("iPhone / iPad", "iPhone / iPad"), "android": ("Android", "Android"), "windows": ("Windows", "Windows"),
    "macos": ("macOS", "macOS"), "linux": ("Linux", "Linux"),
}


def _auto_refresh(page: _Page, manifest: Manifest, artifacts: dict, url: str) -> str:
    """The first thing on the page: add the link to an app once, and later changes arrive by themselves."""
    protocols = [
        grant.protocol for grant in manifest.grants
        if grant.enabled and artifacts.get(grant.grant_id) and grant.protocol in SUBSCRIPTION_PROTOCOLS
    ]
    protocols = list(dict.fromkeys(protocols))
    if not url:
        return ""
    entries = []
    for entry in apps_for(protocols):
        app = entry["app"]
        href = deep_link(app, f"{url}{SHARE_VARIANTS[app['variant']]}", manifest.client_name)
        if not href:
            continue
        platforms = ", ".join(page.t(*PLATFORM_NAMES[key]) for key in app["platforms"])
        entries.append(
            f"<div class=\"app\"><p class=\"app-name\">{escape(app['name'])}</p>"
            f"<p class=\"muted small\">{escape(platforms)}</p>{_gets(page, entry)}"
            f"<a class=\"btn{' primary' if not entries else ''}\" href=\"{escape(href)}\">"
            f"{page.t('Добавить в', 'Add to')} {escape(app['name'])}</a></div>"
        )
    intro = page.t(
        "Добавьте ссылку в приложение один раз — новые доступы появятся в нём сами, без повторной настройки.",
        "Add the link to an app once — new accesses will show up in it by themselves, no need to set it up again.",
    )
    apps = ""
    if entries:
        apps = (f"<h3>{page.t('Приложения', 'Apps')}</h3><p class=\"muted small\">"
                f"{page.t('Кнопка работает на устройстве, где приложение уже установлено.', 'The button works on the device where the app is already installed.')}</p>"
                + "".join(entries))
    return (
        f"<section class=\"card\"><h2>{page.t('Подписка обновляется сама', 'The subscription updates itself')}</h2><p>{intro}</p>"
        f"{page.copy(url, page.t('Копировать ссылку подписки', 'Copy the subscription link'))}"
        f"{page.qr(url)}{apps}</section>"
    )


def _footer(page: _Page, manifest: Manifest, updated_at: int | None) -> str:
    when = ""
    if updated_at:
        stamp = datetime.fromtimestamp(updated_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        when = f"{page.t('Обновлено', 'Updated')} {stamp} · "
    return f"<footer>{when}{page.t('версия набора', 'set version')} {manifest.generation}</footer>"


class HtmlRenderer:
    name = "html"
    media_type = "text/html; charset=utf-8"
    version = 5

    def render(self, manifest: Manifest, artifacts: dict, *, url: str = "", lang: str = "ru",
               updated_at: int | None = None) -> bytes:
        check(manifest)
        page = _Page(lang)
        name = escape(manifest.client_name)
        names = grant_names(manifest)
        titles = _titles(manifest, artifacts)
        sections = "".join(
            _grant_section(page, grant, artifacts, names[grant.grant_id], titles[grant.grant_id])
            for grant in manifest.grants
        )
        title = f"{page.t('Доступы', 'Accesses')} · {name}"
        warning = page.t(
            "Ссылка на эту страницу — ваш личный ключ, не передавайте её другим.",
            "The link to this page is your personal key — do not share it.",
        )
        body = (
            f"<!doctype html><html lang=\"{page.lang}\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta name=\"robots\" content=\"noindex\">"
            f"<title>{title}</title><style>{STYLE}</style></head><body><main>"
            f"<h1>{title}</h1><p class=\"warn\">{warning}</p>"
            f"{_auto_refresh(page, manifest, artifacts, url)}"
            f"<h2>{page.t('Все доступы', 'All accesses')}</h2>{sections}"
            f"{_footer(page, manifest, updated_at)}<script>{SCRIPT}</script></main></body></html>"
        )
        return finish(body.encode())
