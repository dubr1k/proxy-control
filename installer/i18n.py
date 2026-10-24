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
            "  coexist — your Nginx with a `stream` block already owns 443: the installer adds its SNI routes beside yours\n"
            "  fresh preserves panel client IPs; coexist needs an operator-configured PROXY bridge (see INSTALLER_REFERENCE)"
        ),
        "profile": "Proxy Control profile",
        "profile_help": (
            "  core       — the panel and MTProxy (Telegram)\n"
            "  core-naive — the same plus NaiveProxy\n"
            "  core-mieru — the same plus Mieru\n"
            "  full       — the panel, MTProxy, NaiveProxy and Mieru\n"
            "  AmneziaWG and TrustTunnel are not part of a profile: they are separate questions further below"
        ),
        "three_xui_mode": "3x-ui mode",
        "three_xui_mode_help": (
            "  none        — no 3x-ui\n"
            "  existing    — 3x-ui is already installed: only routes to its VLESS Reality inbounds are added on 443\n"
            "  managed-new — the installer sets up its own 3x-ui 3.10.2 (VLESS Reality TCP/XHTTP, Hysteria2)"
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
        "router": "Install the Xray-router (pinned Xray-core {version}; the archive is fetched unless staged in /var/lib/proxy-control; MTProxy can be routed through it from the panel too)",
        "router_naive": "Send all NaiveProxy traffic through the Xray-router",
        "router_mieru": "Send all Mieru traffic through the Xray-router",
        "amneziawg_help": (
            "AmneziaWG is obfuscated WireGuard 1.5 / 2.0 / 3.1. Clients connect over UDP straight to this server,\n"
            "so it needs no new domain: the panel domain works if it points at this server and is not proxied."
        ),
        "amneziawg": "Install AmneziaWG",
        "amneziawg_versions": "AmneziaWG versions (comma-separated from 1.5, 2.0, 3.1)",
        "amneziawg_host": "Name or IPv4 address clients dial for AmneziaWG (not proxied)",
        "amneziawg_ports_help": (
            "One UDP port per version, in this order, from 1024 to 65535. The free random ports shown are not\n"
            "well-known, so Enter is the sensible choice."
        ),
        "amneziawg_ports": "AmneziaWG UDP ports for versions {versions} ({count}, comma-separated)",
        "trusttunnel_help": (
            "TrustTunnel is AdGuard's HTTP/2 over TLS VPN, TCP only. It shares TCP/443 with the other services\n"
            "through SNI, so no port and no UDP rule are added. It needs a domain of its own with an A record to this\n"
            "server, DNS only: do not put a CDN proxy in front of it."
        ),
        "trusttunnel": "Install TrustTunnel",
        "trusttunnel_domain": "TrustTunnel domain (an A record to this server, DNS only; its own name, not one used above)",
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
        "review_acme_email": "ACME email",
        "review_amneziawg_host": "AmneziaWG: host clients dial",
        "review_amneziawg_ports": "AmneziaWG: UDP ports",
        "review_amneziawg_versions": "AmneziaWG: versions",
        "review_domains_mcp": "MCP server domain",
        "review_domains_mieru": "Mieru hostname",
        "review_domains_mtproxy": "MTProxy Fake-TLS domain",
        "review_domains_naive": "NaiveProxy domain",
        "review_domains_panel": "Panel domain",
        "review_domains_subscription": "Client subscription domain",
        "review_domains_trusttunnel": "TrustTunnel domain",
        "review_egress_mieru": "Mieru egress",
        "review_egress_naive": "NaiveProxy egress",
        "review_egress_router": "Xray-router",
        "review_egress_relay_port": "Xray-router relay port",
        "review_egress_warp_port": "WARP port",
        "review_mieru_lane_slots": "Mieru lane slots",
        "review_three_xui_warp_port": "3x-ui WARP port",
        "review_egress_warp": "WARP for NaiveProxy and Mieru",
        "review_firewall_manage_ufw": "Open ports in UFW",
        "review_host_mode": "Host mode",
        "review_initial_user": "First MTProxy and Mieru user",
        "review_mieru_tcp_ports": "Mieru TCP ports",
        "review_mieru_udp_ports": "Mieru UDP ports",
        "review_profile": "Profile",
        "review_three_xui_hysteria_domain": "Hysteria2 domain",
        "review_three_xui_mode": "3x-ui mode",
        "review_three_xui_panel_domain": "3x-ui panel domain",
        "review_three_xui_subscription_domain": "3x-ui subscription domain",
        "review_three_xui_vless_tcp_domain": "VLESS Reality TCP domain",
        "review_three_xui_vless_xhttp_domain": "VLESS Reality XHTTP domain",
        "review_three_xui_warp": "3x-ui through WARP",
        "review_three_xui_warp_domains": "Domains 3x-ui sends through WARP",
        "review_header": "field | value",
        "already_installed": "Proxy Control {version} is already installed on this server. To update it: bash install-release.sh --update",
        "already_installed_unknown": "Proxy Control is already installed on this server. To update it: bash install-release.sh --update",
        "reinstall": "What now",
        "reinstall_help": "  quit     — leave without changes (the default)\n  continue — go on with a reinstall",
        "yes": "yes",
        "no": "no",
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
        "invalid_awg_versions": "Enter one or more of 1.5, 2.0, 3.1, comma-separated, without repeats.",
        "invalid_awg_host": "Enter a DNS name or an IPv4 address.",
        "invalid_awg_ports": "Enter distinct port numbers between 1024 and 65535, comma-separated, {count} in total.",
        "invalid_domains": "Enter one or more comma-separated domains or geosite:name lists.",
        "duplicate_domains": "Enter unique domains.",
        "invalid_config": "The configuration is invalid: {reason}. Choose the field to fix.",
    },
    Locale.RU: {
        "language": "Language / Язык",
        "host_mode": "Режим сервера",
        "host_mode_help": (
            "  fresh   — чистый сервер: установщик сам поставит Nginx и займёт TCP 80 и 443\n"
            "  coexist — ваш Nginx с блоком `stream` уже держит 443: установщик добавит свои SNI-маршруты рядом с вашими\n"
            "  fresh сохраняет IP клиентов панели; для coexist нужен операторский PROXY bridge (см. INSTALLER_REFERENCE)"
        ),
        "profile": "Профиль Proxy Control",
        "profile_help": (
            "  core       — панель и MTProxy (Telegram)\n"
            "  core-naive — то же и NaiveProxy\n"
            "  core-mieru — то же и Mieru\n"
            "  full       — панель, MTProxy, NaiveProxy и Mieru\n"
            "  AmneziaWG и TrustTunnel в профиль не входят: о них спросят отдельными вопросами ниже"
        ),
        "three_xui_mode": "Режим 3x-ui",
        "three_xui_mode_help": (
            "  none        — без 3x-ui\n"
            "  existing    — 3x-ui уже установлен: на 443 добавятся только маршруты к его инбаундам VLESS Reality\n"
            "  managed-new — установщик поставит свой 3x-ui 3.10.2 (VLESS Reality TCP/XHTTP, Hysteria2)"
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
        "router": "Установить Xray-router (закреплённый Xray-core {version}; архив скачивается сам, если не положен в /var/lib/proxy-control; через него из панели можно направить и MTProxy)",
        "router_naive": "Направлять весь трафик NaiveProxy через Xray-router",
        "router_mieru": "Направлять весь трафик Mieru через Xray-router",
        "amneziawg_help": (
            "AmneziaWG — обфусцированный WireGuard 1.5 / 2.0 / 3.1. Клиенты подключаются по UDP прямо к этому серверу,\n"
            "поэтому новый домен не нужен: подойдёт домен панели, если он указывает на этот сервер и не проксируется."
        ),
        "amneziawg": "Установить AmneziaWG",
        "amneziawg_versions": "Версии AmneziaWG (через запятую из 1.5, 2.0, 3.1)",
        "amneziawg_host": "Имя или IPv4-адрес, по которому клиенты подключаются к AmneziaWG (без прокси)",
        "amneziawg_ports_help": (
            "По одному UDP-порту на версию, в этом порядке, от 1024 до 65535. Показанные свободные случайные порты\n"
            "не из общеизвестных, так что Enter — разумный выбор."
        ),
        "amneziawg_ports": "UDP-порты AmneziaWG для версий {versions} ({count}, через запятую)",
        "trusttunnel_help": (
            "TrustTunnel — VPN AdGuard поверх HTTP/2 и TLS, только TCP. Делит TCP/443 с остальными сервисами\n"
            "по SNI, поэтому порт и правило UDP не добавляются. Нужен отдельный домен с A-записью на этот сервер,\n"
            "только DNS: не ставьте перед ним прокси CDN."
        ),
        "trusttunnel": "Установить TrustTunnel",
        "trusttunnel_domain": "Домен TrustTunnel (A-запись на этот сервер, только DNS; отдельное имя, не одно из названных выше)",
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
        "review_acme_email": "Email для ACME",
        "review_amneziawg_host": "AmneziaWG: адрес для клиентов",
        "review_amneziawg_ports": "AmneziaWG: UDP-порты",
        "review_amneziawg_versions": "AmneziaWG: версии",
        "review_domains_mcp": "Домен MCP-сервера",
        "review_domains_mieru": "Имя хоста Mieru",
        "review_domains_mtproxy": "Fake-TLS домен MTProxy",
        "review_domains_naive": "Домен NaiveProxy",
        "review_domains_panel": "Домен панели",
        "review_domains_subscription": "Домен подписки клиентов",
        "review_domains_trusttunnel": "Домен TrustTunnel",
        "review_egress_mieru": "Выход Mieru",
        "review_egress_naive": "Выход NaiveProxy",
        "review_egress_router": "Xray-router",
        "review_egress_relay_port": "Порт relay Xray-router",
        "review_egress_warp_port": "Порт WARP",
        "review_mieru_lane_slots": "Слоты линий Mieru",
        "review_three_xui_warp_port": "Порт WARP для 3x-ui",
        "review_egress_warp": "WARP для NaiveProxy и Mieru",
        "review_firewall_manage_ufw": "Открыть порты в UFW",
        "review_host_mode": "Режим сервера",
        "review_initial_user": "Первый пользователь MTProxy и Mieru",
        "review_mieru_tcp_ports": "TCP-порты Mieru",
        "review_mieru_udp_ports": "UDP-порты Mieru",
        "review_profile": "Профиль",
        "review_three_xui_hysteria_domain": "Домен Hysteria2",
        "review_three_xui_mode": "Режим 3x-ui",
        "review_three_xui_panel_domain": "Домен панели 3x-ui",
        "review_three_xui_subscription_domain": "Домен подписки 3x-ui",
        "review_three_xui_vless_tcp_domain": "Домен VLESS Reality TCP",
        "review_three_xui_vless_xhttp_domain": "Домен VLESS Reality XHTTP",
        "review_three_xui_warp": "3x-ui через WARP",
        "review_three_xui_warp_domains": "Домены 3x-ui через WARP",
        "review_header": "поле | значение",
        "already_installed": "На этом сервере уже установлен Proxy Control {version}. Для обновления: bash install-release.sh --update",
        "already_installed_unknown": "На этом сервере уже установлен Proxy Control. Для обновления: bash install-release.sh --update",
        "reinstall": "Что дальше",
        "reinstall_help": "  quit     — выйти без изменений (по умолчанию)\n  continue — продолжить переустановку",
        "yes": "да",
        "no": "нет",
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
        "invalid_awg_versions": "Введите одну или несколько версий из 1.5, 2.0, 3.1 через запятую, без повторов.",
        "invalid_awg_host": "Введите DNS-имя или IPv4-адрес.",
        "invalid_awg_ports": "Введите разные номера портов от 1024 до 65535 через запятую, всего: {count}.",
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
