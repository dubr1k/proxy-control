from __future__ import annotations

from enum import StrEnum


class Locale(StrEnum):
    EN = "en"
    RU = "ru"


_CATALOG: dict[Locale, dict[str, str]] = {
    Locale.EN: {
        "language": "Language / Язык",
        "host_mode": "Host mode",
        "host_mode_help": (
            "  fresh   — a clean server: the installer sets up Nginx and takes TCP 80 and 443\n"
            "  coexist — your Nginx with a `stream` block already owns 443: the installer adds its SNI routes beside yours"
        ),
        "profile": "Proxy Control profile",
        "profile_help": (
            "  core       — the panel and MTProxy (Telegram)\n"
            "  core-naive — the same plus NaiveProxy\n"
            "  core-mieru — the same plus Mieru\n"
            "  full       — the panel, MTProxy, NaiveProxy and Mieru"
        ),
        "three_xui_mode": "3x-ui mode",
        "three_xui_mode_help": (
            "  none        — no 3x-ui\n"
            "  existing    — 3x-ui is already installed: only routes to its VLESS Reality inbounds are added on 443\n"
            "  managed-new — the installer sets up its own 3x-ui (VLESS Reality TCP/XHTTP, Hysteria2)"
        ),
        "panel_domain": "Panel domain",
        "mtproxy_domain": "MTProxy Fake-TLS domain",
        "subscription_domain": "Client subscription domain (blank to keep subscriptions off)",
        "mcp_domain": "MCP server domain — central panel only (blank to keep MCP off)",
        "naive_domain": "NaiveProxy domain",
        "mieru_domain": "Mieru hostname",
        "mieru_tcp_ports": "Mieru TCP ports (comma-separated)",
        "mieru_udp_ports": "Mieru UDP ports (comma-separated)",
        "xui_panel_domain": "3x-ui panel domain",
        "xui_vless_tcp_domain": "VLESS Reality TCP domain",
        "xui_vless_xhttp_domain": "VLESS Reality XHTTP domain",
        "xui_hysteria_domain": "Hysteria2 domain",
        "warp": "Enable WARP routing",
        "warp_domains": "Domains and geosite lists 3x-ui sends through WARP (comma-separated, at least one: example.com, geosite:openai)",
        "warp_naive": "Send all NaiveProxy traffic through WARP",
        "warp_mieru": "Send all Mieru traffic through WARP",
        "router": "Install the Xray-router (pinned Xray-core {version}; the archive is fetched unless staged in /var/lib/proxy-control)",
        "router_naive": "Send all NaiveProxy traffic through the Xray-router",
        "router_mieru": "Send all Mieru traffic through the Xray-router",
        "acme_email": "ACME email",
        "initial_user": "Name of the first MTProxy and Mieru user (the panel login is always owner)",
        "panel_password": "Password of the panel login owner (blank to generate one)",
        "panel_password_again": "Repeat the panel password",
        "xui_username": "3x-ui panel username",
        "xui_password": "3x-ui panel password (blank to generate one)",
        "xui_password_again": "Repeat the 3x-ui panel password",
        "password_mismatch": "The two entries differ; type the same password twice.",
        "invalid_password": "Use at least 12 characters, or leave it blank to generate one.",
        "credentials_saved": "Credentials saved privately: {path}",
        "manage_ufw": "Open the installer's ports in UFW (fresh host only)",
        "secrets_notice": "Keys and every password left blank are generated during installation; typed passwords never enter the configuration file.",
        "review_title": "Configuration review",
        "review_header": "field | value",
        "action": "Action",
        "edit_field": "Field to edit",
        "saved": "Configuration saved: {path}",
        "quit": "No changes were made.",
        "digest": "Type the first 12 plan digest characters ({prefix}), or quit",
        "digest_mismatch": "plan digest confirmation does not match",
        "invalid_choice": "Choose one of: {choices}.",
        "invalid_value": "Enter a valid value.",
        "invalid_integer": "Enter an integer.",
        "invalid_range": "Enter a number from {minimum} to {maximum}.",
        "invalid_ports": "Enter one or more comma-separated ports.",
        "duplicate_ports": "Enter unique ports.",
        "invalid_port_range": "Use ports from {minimum} to 65535.",
        "xui_existing_help": "The installed 3x-ui gets SNI routes to its VLESS Reality inbounds on 443; leave blank the one you do not use.",
        "xui_existing_required": "At least one VLESS domain is needed: the installer routes only those to the installed 3x-ui.",
        "invalid_route": "Enter a route as domain=port.",
        "duplicate_route": "Enter each route domain only once.",
        "invalid_yes_no": "Enter yes or no.",
        "invalid_domain": "Enter a fully-qualified domain name.",
        "invalid_email": "Enter a valid email address.",
        "invalid_name": "Use only letters, digits, underscore, or hyphen.",
        "invalid_domains": "Enter one or more comma-separated domains or geosite:name lists.",
        "duplicate_domains": "Enter unique domains.",
        "invalid_config": "The configuration is invalid: {reason}. Choose the field to fix.",
    },
    Locale.RU: {
        "language": "Language / Язык",
        "host_mode": "Режим сервера",
        "host_mode_help": (
            "  fresh   — чистый сервер: установщик сам поставит Nginx и займёт TCP 80 и 443\n"
            "  coexist — ваш Nginx с блоком `stream` уже держит 443: установщик добавит свои SNI-маршруты рядом с вашими"
        ),
        "profile": "Профиль Proxy Control",
        "profile_help": (
            "  core       — панель и MTProxy (Telegram)\n"
            "  core-naive — то же и NaiveProxy\n"
            "  core-mieru — то же и Mieru\n"
            "  full       — панель, MTProxy, NaiveProxy и Mieru"
        ),
        "three_xui_mode": "Режим 3x-ui",
        "three_xui_mode_help": (
            "  none        — без 3x-ui\n"
            "  existing    — 3x-ui уже установлен: на 443 добавятся только маршруты к его инбаундам VLESS Reality\n"
            "  managed-new — установщик поставит свой 3x-ui (VLESS Reality TCP/XHTTP, Hysteria2)"
        ),
        "panel_domain": "Домен панели",
        "mtproxy_domain": "Fake-TLS домен MTProxy",
        "subscription_domain": "Домен подписки клиентов (пусто — подписки выключены)",
        "mcp_domain": "Домен MCP-сервера — только на центральной панели (пусто — MCP выключен)",
        "naive_domain": "Домен NaiveProxy",
        "mieru_domain": "Имя хоста Mieru",
        "mieru_tcp_ports": "TCP-порты Mieru (через запятую)",
        "mieru_udp_ports": "UDP-порты Mieru (через запятую)",
        "xui_panel_domain": "Домен панели 3x-ui",
        "xui_vless_tcp_domain": "Домен VLESS Reality TCP",
        "xui_vless_xhttp_domain": "Домен VLESS Reality XHTTP",
        "xui_hysteria_domain": "Домен Hysteria2",
        "warp": "Включить маршрутизацию WARP",
        "warp_domains": "Домены и geosite-списки, которые 3x-ui пустит через WARP (через запятую, хотя бы один: example.com, geosite:openai)",
        "warp_naive": "Направлять весь трафик NaiveProxy через WARP",
        "warp_mieru": "Направлять весь трафик Mieru через WARP",
        "router": "Установить Xray-router (закреплённый Xray-core {version}; архив скачивается сам, если не положен в /var/lib/proxy-control)",
        "router_naive": "Направлять весь трафик NaiveProxy через Xray-router",
        "router_mieru": "Направлять весь трафик Mieru через Xray-router",
        "acme_email": "Email для ACME",
        "initial_user": "Имя первого пользователя MTProxy и Mieru (логин в панель всегда owner)",
        "panel_password": "Пароль для входа в панель под owner (пусто — создать автоматически)",
        "panel_password_again": "Повторите пароль панели",
        "xui_username": "Имя пользователя панели 3x-ui",
        "xui_password": "Пароль панели 3x-ui (пусто — создать автоматически)",
        "xui_password_again": "Повторите пароль панели 3x-ui",
        "password_mismatch": "Введённые пароли не совпадают; повторите один и тот же пароль дважды.",
        "invalid_password": "Не короче 12 символов, либо оставьте пусто, чтобы пароль создался автоматически.",
        "credentials_saved": "Учётные данные сохранены приватно: {path}",
        "manage_ufw": "Открыть порты установщика в UFW (только на свежем сервере)",
        "secrets_notice": "Ключи и пароли, оставленные пустыми, создаются при установке; введённые пароли в файл конфигурации не попадают.",
        "review_title": "Проверка конфигурации",
        "review_header": "поле | значение",
        "action": "Действие",
        "edit_field": "Поле для изменения",
        "saved": "Конфигурация сохранена: {path}",
        "quit": "Изменения не внесены.",
        "digest": "Введите первые 12 символов дайджеста плана ({prefix}) или quit",
        "digest_mismatch": "подтверждение дайджеста плана не совпадает",
        "invalid_choice": "Выберите одно из: {choices}.",
        "invalid_value": "Введите допустимое значение.",
        "invalid_integer": "Введите целое число.",
        "invalid_range": "Введите число от {minimum} до {maximum}.",
        "invalid_ports": "Введите один или несколько портов через запятую.",
        "duplicate_ports": "Введите неповторяющиеся порты.",
        "invalid_port_range": "Используйте порты от {minimum} до 65535.",
        "xui_existing_help": "Установленному 3x-ui добавятся SNI-маршруты к его инбаундам VLESS Reality на 443; тот, которым вы не пользуетесь, оставьте пустым.",
        "xui_existing_required": "Нужен хотя бы один домен VLESS: установщик маршрутизирует к установленному 3x-ui только их.",
        "invalid_route": "Введите маршрут в формате домен=порт.",
        "duplicate_route": "Укажите каждый домен маршрута только один раз.",
        "invalid_yes_no": "Введите да или нет.",
        "invalid_domain": "Введите полное доменное имя.",
        "invalid_email": "Введите корректный адрес электронной почты.",
        "invalid_name": "Используйте только буквы, цифры, подчёркивание или дефис.",
        "invalid_domains": "Введите один или несколько доменов или geosite-списков через запятую.",
        "duplicate_domains": "Введите неповторяющиеся домены.",
        "invalid_config": "Конфигурация недопустима: {reason}. Выберите поле, которое нужно исправить.",
    },
}


def locale_from_environment(value: str | None) -> Locale:
    if value and value.strip().lower().replace("-", "_").startswith("ru"):
        return Locale.RU
    return Locale.EN


def parse_locale(value: str | Locale | None, *, default: Locale = Locale.EN) -> Locale:
    if value is None or not str(value).strip():
        return default
    normalized = str(value).strip().lower().replace("-", "_")
    if normalized in {"ru", "rus", "russian", "русский"} or normalized.startswith("ru_"):
        return Locale.RU
    if normalized in {"en", "eng", "english", "английский"} or normalized.startswith("en_"):
        return Locale.EN
    raise ValueError("language must be en or ru")


def text(locale: Locale, key: str, **values: object) -> str:
    try:
        message = _CATALOG[locale][key]
    except KeyError as exc:
        raise KeyError(f"unknown message: {key}") from exc
    return message.format(**values)


__all__ = ["Locale", "locale_from_environment", "parse_locale", "text"]
