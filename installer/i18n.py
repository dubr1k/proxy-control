from __future__ import annotations

from enum import StrEnum


class Locale(StrEnum):
    EN = "en"
    RU = "ru"


_CATALOG: dict[Locale, dict[str, str]] = {
    Locale.EN: {
        "language": "Language / Язык",
        "host_mode": "Host mode",
        "profile": "Proxy Control profile",
        "three_xui_mode": "3x-ui mode",
        "panel_domain": "Panel domain",
        "mtproxy_domain": "MTProxy Fake-TLS domain",
        "naive_domain": "NaiveProxy domain",
        "mieru_domain": "Mieru hostname",
        "mieru_tcp_ports": "Mieru TCP ports (comma-separated)",
        "mieru_udp_ports": "Mieru UDP ports (comma-separated)",
        "xui_panel_domain": "3x-ui panel domain",
        "xui_vless_tcp_domain": "VLESS Reality TCP domain",
        "xui_vless_xhttp_domain": "VLESS Reality XHTTP domain",
        "xui_hysteria_domain": "Hysteria2 domain",
        "warp": "Enable WARP routing",
        "warp_domains": "WARP domains (comma-separated, blank for none)",
        "acme_email": "ACME email",
        "initial_user": "Initial user",
        "manage_ufw": "Manage UFW",
        "secrets_notice": "Passwords and keys are generated only during installation.",
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
        "invalid_route": "Enter a route as domain=port.",
        "duplicate_route": "Enter each route domain only once.",
        "invalid_yes_no": "Enter yes or no.",
        "invalid_domain": "Enter a fully-qualified domain name.",
        "invalid_email": "Enter a valid email address.",
        "invalid_name": "Use only letters, digits, underscore, or hyphen.",
        "invalid_domains": "Enter one or more comma-separated domains.",
        "duplicate_domains": "Enter unique domains.",
        "invalid_config": "The configuration is invalid; edit the highlighted fields.",
    },
    Locale.RU: {
        "language": "Language / Язык",
        "host_mode": "Режим сервера",
        "profile": "Профиль Proxy Control",
        "three_xui_mode": "Режим 3x-ui",
        "panel_domain": "Домен панели",
        "mtproxy_domain": "Fake-TLS домен MTProxy",
        "naive_domain": "Домен NaiveProxy",
        "mieru_domain": "Имя хоста Mieru",
        "mieru_tcp_ports": "TCP-порты Mieru (через запятую)",
        "mieru_udp_ports": "UDP-порты Mieru (через запятую)",
        "xui_panel_domain": "Домен панели 3x-ui",
        "xui_vless_tcp_domain": "Домен VLESS Reality TCP",
        "xui_vless_xhttp_domain": "Домен VLESS Reality XHTTP",
        "xui_hysteria_domain": "Домен Hysteria2",
        "warp": "Включить маршрутизацию WARP",
        "warp_domains": "Домены WARP (через запятую; пусто — нет)",
        "acme_email": "Email для ACME",
        "initial_user": "Первый пользователь",
        "manage_ufw": "Управлять UFW",
        "secrets_notice": "Пароли и ключи будут созданы только при установке.",
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
        "invalid_route": "Введите маршрут в формате домен=порт.",
        "duplicate_route": "Укажите каждый домен маршрута только один раз.",
        "invalid_yes_no": "Введите да или нет.",
        "invalid_domain": "Введите полное доменное имя.",
        "invalid_email": "Введите корректный адрес электронной почты.",
        "invalid_name": "Используйте только буквы, цифры, подчёркивание или дефис.",
        "invalid_domains": "Введите один или несколько доменов через запятую.",
        "duplicate_domains": "Введите неповторяющиеся домены.",
        "invalid_config": "Конфигурация недопустима; исправьте отмеченные поля.",
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
