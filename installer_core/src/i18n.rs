//! The wizard's message catalogue in English and Russian (`installer/i18n.py`): 115 keys in each
//! language with the same `{placeholders}`, Python `str.format` substitution, the language
//! default from the environment and the `--lang`/prompt answer parser.
//!
//! `text` has no fallback language, like Python: an unknown key is a programming error
//! (`KeyError("unknown message: <key>")`), reported as a panic; [`try_text`] is the
//! non-panicking form the review labels use.

use crate::pystr::{lower, strip};

/// `Locale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    En,
    Ru,
}

impl Locale {
    pub const ALL: [Locale; 2] = [Locale::En, Locale::Ru];

    /// The enum value (`en`/`ru`).
    pub fn value(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
        }
    }
}

/// `locale_from_environment(LC_ALL or LANG)`: Russian when the value starts with `ru`
/// (after `strip().lower()` and `-` → `_`), else English.
pub fn locale_from_environment(value: Option<&str>) -> Locale {
    match value {
        Some(value) if lower(strip(value)).replace('-', "_").starts_with("ru") => Locale::Ru,
        _ => Locale::En,
    }
}

/// The default language the way the wizard reads it: `LC_ALL`, or `LANG` when `LC_ALL` is
/// unset or empty (`os.environ.get("LC_ALL") or os.environ.get("LANG")`).
pub fn environment_locale_value() -> Option<String> {
    let read = |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    read("LC_ALL").filter(|value| !value.is_empty()).or_else(|| read("LANG"))
}

/// `parse_locale(value, default=…)`: `ru rus russian русский ru_*` / `en eng english английский
/// en_*`; blank is the default; anything else is `ValueError("language must be en or ru")`.
pub fn parse_locale(value: Option<&str>, default: Locale) -> Result<Locale, String> {
    let Some(value) = value.filter(|value| !strip(value).is_empty()) else { return Ok(default) };
    let normalized = lower(strip(value)).replace('-', "_");
    if ["ru", "rus", "russian", "русский"].contains(&normalized.as_str()) || normalized.starts_with("ru_") {
        return Ok(Locale::Ru);
    }
    if ["en", "eng", "english", "английский"].contains(&normalized.as_str()) || normalized.starts_with("en_") {
        return Ok(Locale::En);
    }
    Err("language must be en or ru".into())
}

/// Every key and message of one language, sorted by key.
pub fn catalog(locale: Locale) -> &'static [(&'static str, &'static str)] {
    match locale {
        Locale::En => &EN,
        Locale::Ru => &RU,
    }
}

/// The raw message (with its placeholders) of `key`.
pub fn message(locale: Locale, key: &str) -> Option<&'static str> {
    let table = catalog(locale);
    table.binary_search_by(|(name, _)| (*name).cmp(key)).ok().map(|index| table[index].1)
}

/// `text(locale, key, **values)`, or `Err("unknown message: <key>")`.
pub fn try_text(locale: Locale, key: &str, values: &[(&str, &str)]) -> Result<String, String> {
    let template = message(locale, key).ok_or_else(|| format!("unknown message: {key}"))?;
    format(template, values)
}

/// `text(locale, key, **values)`. Panics on an unknown key or a missing placeholder value
/// (Python's `KeyError`); every call site names a key of the catalogue.
pub fn text(locale: Locale, key: &str, values: &[(&str, &str)]) -> String {
    try_text(locale, key, values).unwrap_or_else(|err| panic!("{err}"))
}

/// `str.format(**values)` for plain `{name}` fields and `{{`/`}}` escapes.
pub fn format(template: &str, values: &[(&str, &str)]) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err("expected '}' before end of string".into()),
                    }
                }
                let value = values.iter().find(|(key, _)| *key == name).ok_or_else(|| format!("'{name}'"))?;
                out.push_str(value.1);
            }
            '}' => return Err("Single '}' encountered in format string".into()),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// The `{placeholder}` names of a message, sorted and unique (`string.Formatter().parse`).
pub fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        if let Some(stripped) = after.strip_prefix('{') {
            rest = stripped;
            continue;
        }
        let Some(end) = after.find('}') else { break };
        names.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    names.sort();
    names.dedup();
    names
}

const EN: [(&str, &str); 115] = [
    ("acme_email", "ACME email"),
    ("action", "Action"),
    ("already_installed", "Proxy Control {version} is already installed on this server. To update it: bash install-release.sh --update"),
    ("already_installed_unknown", "Proxy Control is already installed on this server. To update it: bash install-release.sh --update"),
    ("amneziawg", "Install AmneziaWG"),
    ("amneziawg_help", "AmneziaWG is obfuscated WireGuard 1.5 / 2.0 / 3.1. Clients connect over UDP straight to this server,\nso it needs no new domain: the panel domain works if it points at this server and is not proxied."),
    ("amneziawg_host", "Name or IPv4 address clients dial for AmneziaWG (not proxied)"),
    ("amneziawg_ports", "AmneziaWG UDP ports for versions {versions} ({count}, comma-separated)"),
    ("amneziawg_ports_help", "One UDP port per version, in this order, from 1024 to 65535. The free random ports shown are not\nwell-known, so Enter is the sensible choice."),
    ("amneziawg_versions", "AmneziaWG versions (comma-separated from 1.5, 2.0, 3.1)"),
    ("credentials_saved", "Credentials saved privately: {path}"),
    ("digest", "Type the first 12 plan digest characters ({prefix}), or quit"),
    ("digest_mismatch", "plan digest confirmation does not match"),
    ("duplicate_domains", "Enter unique domains."),
    ("duplicate_ports", "Enter unique ports."),
    ("duplicate_route", "Enter each route domain only once."),
    ("edit_field", "Field to edit"),
    ("host_mode", "Host mode"),
    ("host_mode_help", "  fresh   — a clean server: the installer sets up Nginx and takes TCP 80 and 443\n  coexist — your Nginx with a `stream` block already owns 443: the installer adds its SNI routes beside yours\n  fresh preserves panel client IPs; coexist needs an operator-configured PROXY bridge (see INSTALLER_REFERENCE)"),
    ("initial_user", "Name of the first MTProxy and Mieru user (the panel login is always owner)"),
    ("invalid_awg_host", "Enter a DNS name or an IPv4 address."),
    ("invalid_awg_ports", "Enter distinct port numbers between 1024 and 65535, comma-separated, {count} in total."),
    ("invalid_awg_versions", "Enter one or more of 1.5, 2.0, 3.1, comma-separated, without repeats."),
    ("invalid_choice", "Choose one of: {choices}."),
    ("invalid_config", "The configuration is invalid: {reason}. Choose the field to fix."),
    ("invalid_domain", "Enter a fully-qualified domain name."),
    ("invalid_domains", "Enter one or more comma-separated domains or geosite:name lists."),
    ("invalid_email", "Enter a valid email address."),
    ("invalid_integer", "Enter an integer."),
    ("invalid_name", "Use only letters, digits, underscore, or hyphen."),
    ("invalid_password", "Use at least 12 characters, or leave it blank to generate one."),
    ("invalid_port_range", "Use ports from {minimum} to 65535."),
    ("invalid_ports", "Enter one or more comma-separated ports."),
    ("invalid_range", "Enter a number from {minimum} to {maximum}."),
    ("invalid_route", "Enter a route as domain=port."),
    ("invalid_value", "Enter a valid value."),
    ("invalid_yes_no", "Enter yes or no."),
    ("language", "Language / Язык"),
    ("manage_ufw", "Open the installer's ports in UFW (fresh host only)"),
    ("mcp_domain", "MCP server domain — central panel only (blank to keep MCP off)"),
    ("mieru_domain", "Mieru hostname"),
    ("mieru_tcp_ports", "Mieru TCP ports (comma-separated)"),
    ("mieru_udp_ports", "Mieru UDP ports (comma-separated)"),
    ("mtproxy_domain", "MTProxy Fake-TLS domain"),
    ("naive_domain", "NaiveProxy domain"),
    ("no", "no"),
    ("panel_domain", "Panel domain"),
    ("panel_password", "Password of the panel login owner (blank to generate one)"),
    ("panel_password_again", "Repeat the panel password"),
    ("password_mismatch", "The two entries differ; type the same password twice."),
    ("profile", "Proxy Control profile"),
    ("profile_help", "  core       — the panel and MTProxy (Telegram)\n  core-naive — the same plus NaiveProxy\n  core-mieru — the same plus Mieru\n  full       — the panel, MTProxy, NaiveProxy and Mieru\n  AmneziaWG and TrustTunnel are not part of a profile: they are separate questions further below"),
    ("quit", "No changes were made."),
    ("reinstall", "What now"),
    ("reinstall_help", "  quit     — leave without changes (the default)\n  continue — go on with a reinstall"),
    ("review_acme_email", "ACME email"),
    ("review_amneziawg_host", "AmneziaWG: host clients dial"),
    ("review_amneziawg_ports", "AmneziaWG: UDP ports"),
    ("review_amneziawg_versions", "AmneziaWG: versions"),
    ("review_domains_mcp", "MCP server domain"),
    ("review_domains_mieru", "Mieru hostname"),
    ("review_domains_mtproxy", "MTProxy Fake-TLS domain"),
    ("review_domains_naive", "NaiveProxy domain"),
    ("review_domains_panel", "Panel domain"),
    ("review_domains_subscription", "Client subscription domain"),
    ("review_domains_trusttunnel", "TrustTunnel domain"),
    ("review_egress_mieru", "Mieru egress"),
    ("review_egress_naive", "NaiveProxy egress"),
    ("review_egress_relay_port", "Xray-router relay port"),
    ("review_egress_router", "Xray-router"),
    ("review_egress_warp", "WARP for NaiveProxy and Mieru"),
    ("review_egress_warp_port", "WARP port"),
    ("review_firewall_manage_ufw", "Open ports in UFW"),
    ("review_header", "field | value"),
    ("review_host_mode", "Host mode"),
    ("review_initial_user", "First MTProxy and Mieru user"),
    ("review_mieru_lane_slots", "Mieru lane slots"),
    ("review_mieru_tcp_ports", "Mieru TCP ports"),
    ("review_mieru_udp_ports", "Mieru UDP ports"),
    ("review_profile", "Profile"),
    ("review_three_xui_hysteria_domain", "Hysteria2 domain"),
    ("review_three_xui_mode", "3x-ui mode"),
    ("review_three_xui_panel_domain", "3x-ui panel domain"),
    ("review_three_xui_subscription_domain", "3x-ui subscription domain"),
    ("review_three_xui_vless_tcp_domain", "VLESS Reality TCP domain"),
    ("review_three_xui_vless_xhttp_domain", "VLESS Reality XHTTP domain"),
    ("review_three_xui_warp", "3x-ui through WARP"),
    ("review_three_xui_warp_domains", "Domains 3x-ui sends through WARP"),
    ("review_three_xui_warp_port", "3x-ui WARP port"),
    ("review_title", "Configuration review"),
    ("router", "Install the Xray-router (pinned Xray-core {version}; the archive is fetched unless staged in /var/lib/proxy-control; MTProxy can be routed through it from the panel too)"),
    ("router_mieru", "Send all Mieru traffic through the Xray-router"),
    ("router_naive", "Send all NaiveProxy traffic through the Xray-router"),
    ("saved", "Configuration saved: {path}"),
    ("secrets_notice", "Keys and every password left blank are generated during installation; typed passwords never enter the configuration file."),
    ("subscription_domain", "Client subscription domain (blank to keep subscriptions off)"),
    ("three_xui_mode", "3x-ui mode"),
    ("three_xui_mode_help", "  none        — no 3x-ui\n  existing    — 3x-ui is already installed: only routes to its VLESS Reality inbounds are added on 443\n  managed-new — the installer sets up its own 3x-ui 3.10.2 (VLESS Reality TCP/XHTTP, Hysteria2)"),
    ("trusttunnel", "Install TrustTunnel"),
    ("trusttunnel_domain", "TrustTunnel domain (an A record to this server, DNS only; its own name, not one used above)"),
    ("trusttunnel_help", "TrustTunnel is AdGuard's HTTP/2 over TLS VPN, TCP only. It shares TCP/443 with the other services\nthrough SNI, so no port and no UDP rule are added. It needs a domain of its own with an A record to this\nserver, DNS only: do not put a CDN proxy in front of it."),
    ("warp", "Enable WARP routing"),
    ("warp_domains", "Domains and geosite lists 3x-ui sends through WARP (comma-separated, at least one: example.com, geosite:openai)"),
    ("warp_mieru", "Send all Mieru traffic through WARP"),
    ("warp_naive", "Send all NaiveProxy traffic through WARP"),
    ("xui_existing_help", "The installed 3x-ui gets SNI routes to its VLESS Reality inbounds on 443; leave blank the one you do not use."),
    ("xui_existing_required", "At least one VLESS domain is needed: the installer routes only those to the installed 3x-ui."),
    ("xui_hysteria_domain", "Hysteria2 domain"),
    ("xui_panel_domain", "3x-ui panel domain"),
    ("xui_password", "3x-ui panel password (blank to generate one)"),
    ("xui_password_again", "Repeat the 3x-ui panel password"),
    ("xui_username", "3x-ui panel username"),
    ("xui_vless_tcp_domain", "VLESS Reality TCP domain"),
    ("xui_vless_xhttp_domain", "VLESS Reality XHTTP domain"),
    ("yes", "yes"),
];

const RU: [(&str, &str); 115] = [
    ("acme_email", "Email для ACME"),
    ("action", "Действие"),
    ("already_installed", "На этом сервере уже установлен Proxy Control {version}. Для обновления: bash install-release.sh --update"),
    ("already_installed_unknown", "На этом сервере уже установлен Proxy Control. Для обновления: bash install-release.sh --update"),
    ("amneziawg", "Установить AmneziaWG"),
    ("amneziawg_help", "AmneziaWG — обфусцированный WireGuard 1.5 / 2.0 / 3.1. Клиенты подключаются по UDP прямо к этому серверу,\nпоэтому новый домен не нужен: подойдёт домен панели, если он указывает на этот сервер и не проксируется."),
    ("amneziawg_host", "Имя или IPv4-адрес, по которому клиенты подключаются к AmneziaWG (без прокси)"),
    ("amneziawg_ports", "UDP-порты AmneziaWG для версий {versions} ({count}, через запятую)"),
    ("amneziawg_ports_help", "По одному UDP-порту на версию, в этом порядке, от 1024 до 65535. Показанные свободные случайные порты\nне из общеизвестных, так что Enter — разумный выбор."),
    ("amneziawg_versions", "Версии AmneziaWG (через запятую из 1.5, 2.0, 3.1)"),
    ("credentials_saved", "Учётные данные сохранены приватно: {path}"),
    ("digest", "Введите первые 12 символов дайджеста плана ({prefix}) или quit"),
    ("digest_mismatch", "подтверждение дайджеста плана не совпадает"),
    ("duplicate_domains", "Введите неповторяющиеся домены."),
    ("duplicate_ports", "Введите неповторяющиеся порты."),
    ("duplicate_route", "Укажите каждый домен маршрута только один раз."),
    ("edit_field", "Поле для изменения"),
    ("host_mode", "Режим сервера"),
    ("host_mode_help", "  fresh   — чистый сервер: установщик сам поставит Nginx и займёт TCP 80 и 443\n  coexist — ваш Nginx с блоком `stream` уже держит 443: установщик добавит свои SNI-маршруты рядом с вашими\n  fresh сохраняет IP клиентов панели; для coexist нужен операторский PROXY bridge (см. INSTALLER_REFERENCE)"),
    ("initial_user", "Имя первого пользователя MTProxy и Mieru (логин в панель всегда owner)"),
    ("invalid_awg_host", "Введите DNS-имя или IPv4-адрес."),
    ("invalid_awg_ports", "Введите разные номера портов от 1024 до 65535 через запятую, всего: {count}."),
    ("invalid_awg_versions", "Введите одну или несколько версий из 1.5, 2.0, 3.1 через запятую, без повторов."),
    ("invalid_choice", "Выберите одно из: {choices}."),
    ("invalid_config", "Конфигурация недопустима: {reason}. Выберите поле, которое нужно исправить."),
    ("invalid_domain", "Введите полное доменное имя."),
    ("invalid_domains", "Введите один или несколько доменов или geosite-списков через запятую."),
    ("invalid_email", "Введите корректный адрес электронной почты."),
    ("invalid_integer", "Введите целое число."),
    ("invalid_name", "Используйте только буквы, цифры, подчёркивание или дефис."),
    ("invalid_password", "Не короче 12 символов, либо оставьте пусто, чтобы пароль создался автоматически."),
    ("invalid_port_range", "Используйте порты от {minimum} до 65535."),
    ("invalid_ports", "Введите один или несколько портов через запятую."),
    ("invalid_range", "Введите число от {minimum} до {maximum}."),
    ("invalid_route", "Введите маршрут в формате домен=порт."),
    ("invalid_value", "Введите допустимое значение."),
    ("invalid_yes_no", "Введите да или нет."),
    ("language", "Language / Язык"),
    ("manage_ufw", "Открыть порты установщика в UFW (только на свежем сервере)"),
    ("mcp_domain", "Домен MCP-сервера — только на центральной панели (пусто — MCP выключен)"),
    ("mieru_domain", "Имя хоста Mieru"),
    ("mieru_tcp_ports", "TCP-порты Mieru (через запятую)"),
    ("mieru_udp_ports", "UDP-порты Mieru (через запятую)"),
    ("mtproxy_domain", "Fake-TLS домен MTProxy"),
    ("naive_domain", "Домен NaiveProxy"),
    ("no", "нет"),
    ("panel_domain", "Домен панели"),
    ("panel_password", "Пароль для входа в панель под owner (пусто — создать автоматически)"),
    ("panel_password_again", "Повторите пароль панели"),
    ("password_mismatch", "Введённые пароли не совпадают; повторите один и тот же пароль дважды."),
    ("profile", "Профиль Proxy Control"),
    ("profile_help", "  core       — панель и MTProxy (Telegram)\n  core-naive — то же и NaiveProxy\n  core-mieru — то же и Mieru\n  full       — панель, MTProxy, NaiveProxy и Mieru\n  AmneziaWG и TrustTunnel в профиль не входят: о них спросят отдельными вопросами ниже"),
    ("quit", "Изменения не внесены."),
    ("reinstall", "Что дальше"),
    ("reinstall_help", "  quit     — выйти без изменений (по умолчанию)\n  continue — продолжить переустановку"),
    ("review_acme_email", "Email для ACME"),
    ("review_amneziawg_host", "AmneziaWG: адрес для клиентов"),
    ("review_amneziawg_ports", "AmneziaWG: UDP-порты"),
    ("review_amneziawg_versions", "AmneziaWG: версии"),
    ("review_domains_mcp", "Домен MCP-сервера"),
    ("review_domains_mieru", "Имя хоста Mieru"),
    ("review_domains_mtproxy", "Fake-TLS домен MTProxy"),
    ("review_domains_naive", "Домен NaiveProxy"),
    ("review_domains_panel", "Домен панели"),
    ("review_domains_subscription", "Домен подписки клиентов"),
    ("review_domains_trusttunnel", "Домен TrustTunnel"),
    ("review_egress_mieru", "Выход Mieru"),
    ("review_egress_naive", "Выход NaiveProxy"),
    ("review_egress_relay_port", "Порт relay Xray-router"),
    ("review_egress_router", "Xray-router"),
    ("review_egress_warp", "WARP для NaiveProxy и Mieru"),
    ("review_egress_warp_port", "Порт WARP"),
    ("review_firewall_manage_ufw", "Открыть порты в UFW"),
    ("review_header", "поле | значение"),
    ("review_host_mode", "Режим сервера"),
    ("review_initial_user", "Первый пользователь MTProxy и Mieru"),
    ("review_mieru_lane_slots", "Слоты линий Mieru"),
    ("review_mieru_tcp_ports", "TCP-порты Mieru"),
    ("review_mieru_udp_ports", "UDP-порты Mieru"),
    ("review_profile", "Профиль"),
    ("review_three_xui_hysteria_domain", "Домен Hysteria2"),
    ("review_three_xui_mode", "Режим 3x-ui"),
    ("review_three_xui_panel_domain", "Домен панели 3x-ui"),
    ("review_three_xui_subscription_domain", "Домен подписки 3x-ui"),
    ("review_three_xui_vless_tcp_domain", "Домен VLESS Reality TCP"),
    ("review_three_xui_vless_xhttp_domain", "Домен VLESS Reality XHTTP"),
    ("review_three_xui_warp", "3x-ui через WARP"),
    ("review_three_xui_warp_domains", "Домены 3x-ui через WARP"),
    ("review_three_xui_warp_port", "Порт WARP для 3x-ui"),
    ("review_title", "Проверка конфигурации"),
    ("router", "Установить Xray-router (закреплённый Xray-core {version}; архив скачивается сам, если не положен в /var/lib/proxy-control; через него из панели можно направить и MTProxy)"),
    ("router_mieru", "Направлять весь трафик Mieru через Xray-router"),
    ("router_naive", "Направлять весь трафик NaiveProxy через Xray-router"),
    ("saved", "Конфигурация сохранена: {path}"),
    ("secrets_notice", "Ключи и пароли, оставленные пустыми, создаются при установке; введённые пароли в файл конфигурации не попадают."),
    ("subscription_domain", "Домен подписки клиентов (пусто — подписки выключены)"),
    ("three_xui_mode", "Режим 3x-ui"),
    ("three_xui_mode_help", "  none        — без 3x-ui\n  existing    — 3x-ui уже установлен: на 443 добавятся только маршруты к его инбаундам VLESS Reality\n  managed-new — установщик поставит свой 3x-ui 3.10.2 (VLESS Reality TCP/XHTTP, Hysteria2)"),
    ("trusttunnel", "Установить TrustTunnel"),
    ("trusttunnel_domain", "Домен TrustTunnel (A-запись на этот сервер, только DNS; отдельное имя, не одно из названных выше)"),
    ("trusttunnel_help", "TrustTunnel — VPN AdGuard поверх HTTP/2 и TLS, только TCP. Делит TCP/443 с остальными сервисами\nпо SNI, поэтому порт и правило UDP не добавляются. Нужен отдельный домен с A-записью на этот сервер,\nтолько DNS: не ставьте перед ним прокси CDN."),
    ("warp", "Включить маршрутизацию WARP"),
    ("warp_domains", "Домены и geosite-списки, которые 3x-ui пустит через WARP (через запятую, хотя бы один: example.com, geosite:openai)"),
    ("warp_mieru", "Направлять весь трафик Mieru через WARP"),
    ("warp_naive", "Направлять весь трафик NaiveProxy через WARP"),
    ("xui_existing_help", "Установленному 3x-ui добавятся SNI-маршруты к его инбаундам VLESS Reality на 443; тот, которым вы не пользуетесь, оставьте пустым."),
    ("xui_existing_required", "Нужен хотя бы один домен VLESS: установщик маршрутизирует к установленному 3x-ui только их."),
    ("xui_hysteria_domain", "Домен Hysteria2"),
    ("xui_panel_domain", "Домен панели 3x-ui"),
    ("xui_password", "Пароль панели 3x-ui (пусто — создать автоматически)"),
    ("xui_password_again", "Повторите пароль панели 3x-ui"),
    ("xui_username", "Имя пользователя панели 3x-ui"),
    ("xui_vless_tcp_domain", "Домен VLESS Reality TCP"),
    ("xui_vless_xhttp_domain", "Домен VLESS Reality XHTTP"),
    ("yes", "да"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_sorted_and_complete() {
        for locale in Locale::ALL {
            let table = catalog(locale);
            assert_eq!(table.len(), 115);
            assert!(table.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
    }

    /// `test_installer_catalog_has_the_same_keys_and_placeholders_in_both_languages`.
    #[test]
    fn installer_catalog_has_the_same_keys_and_placeholders_in_both_languages() {
        let english: Vec<&str> = EN.iter().map(|(key, _)| *key).collect();
        let russian: Vec<&str> = RU.iter().map(|(key, _)| *key).collect();
        assert_eq!(english, russian);
        for ((key, en), (_, ru)) in EN.iter().zip(RU.iter()) {
            assert_eq!(placeholders(en), placeholders(ru), "{key}");
        }
        for key in [
            "amneziawg",
            "amneziawg_versions",
            "amneziawg_host",
            "invalid_awg_versions",
            "invalid_awg_host",
            "trusttunnel",
            "trusttunnel_domain",
        ] {
            assert!(message(Locale::En, key).is_some() && message(Locale::Ru, key).is_some(), "{key}");
        }
    }

    #[test]
    fn locales_parse_like_python() {
        assert_eq!(locale_from_environment(Some(" RU-ru.UTF-8")), Locale::Ru);
        assert_eq!(locale_from_environment(Some("C.UTF-8")), Locale::En);
        assert_eq!(locale_from_environment(None), Locale::En);
        assert_eq!(parse_locale(Some("Русский"), Locale::En), Ok(Locale::Ru));
        assert_eq!(parse_locale(Some("en-US"), Locale::Ru), Ok(Locale::En));
        assert_eq!(parse_locale(Some("  "), Locale::Ru), Ok(Locale::Ru));
        assert_eq!(parse_locale(None, Locale::Ru), Ok(Locale::Ru));
        assert_eq!(parse_locale(Some("de"), Locale::En), Err("language must be en or ru".into()));
    }

    #[test]
    fn format_substitutes_named_fields() {
        assert_eq!(
            text(Locale::En, "invalid_range", &[("minimum", "1"), ("maximum", "65535")]),
            "Enter a number from 1 to 65535."
        );
        assert_eq!(format("{{x}} {a}", &[("a", "1")]), Ok("{x} 1".into()));
        assert_eq!(try_text(Locale::En, "nope", &[]), Err("unknown message: nope".into()));
        assert!(try_text(Locale::En, "invalid_range", &[]).is_err());
    }
}
