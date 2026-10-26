//! `html`: the page a person opens — the apps that take the link, the link itself and each access
//! (`subscriptions/renderers/html.py`).
//!
//! Built by string concatenation exactly as Python does; every value goes through
//! [`escape`] (`html.escape`); the stylesheet and the copy script are the byte-exact constants of
//! [`crate::page_assets`] (admitted by hash). Russian by default, English with `lang = "en"`.

use std::collections::HashMap;

use base64::Engine as _;
use panel_core::pytext;
use panel_model::protocols::AccessArtifact;
use panel_model::subscriptions::{Manifest, ManifestGrant};
use serde_json::Value;

use super::base::{check, credential_reason, finish, named_share_url, trusttunnel_fields, Artifacts, RenderError};
use crate::apps::{apps_for, deep_link, share_variant, AppEntry, SUBSCRIPTION_PROTOCOLS};
use crate::names::{display_text, grant_names};
use crate::page_assets::{SCRIPT, STYLE};
use crate::text::{escape, is_deep_link, utc_minute};

/// `PROTOCOL_TITLES` of the page (NaiveProxy, not Naive).
fn protocol_title(protocol: &str) -> &str {
    match protocol {
        "mtproxy" => "MTProxy",
        "naive" => "NaiveProxy",
        "mieru" => "Mieru",
        "amneziawg" => "AmneziaWG",
        "trusttunnel" => "TrustTunnel",
        other => other,
    }
}

/// `MANUAL_LABELS`.
const MANUAL_LABELS: [(&str, &str, &str); 5] = [
    ("server", "Сервер", "Server"),
    ("port", "Порт", "Port"),
    ("username", "Логин", "Username"),
    ("password", "Пароль", "Password"),
    ("sni", "SNI", "SNI"),
];

type Pair = (&'static str, &'static str);

/// `TRUSTTUNNEL_APPS`: name, platforms, how, links — only what was run against this panel's output.
const TRUSTTUNNEL_APPS: [(Pair, Pair, Pair, &[Pair]); 3] = [
    (
        ("AdGuard TrustTunnel", "AdGuard TrustTunnel"),
        ("iOS, Android", "iOS, Android"),
        ("ссылка tt:// или QR", "tt:// link or QR"),
        &[
            ("App Store", "https://apps.apple.com/us/app/trusttunnel/id6755807890"),
            ("Google Play", "https://play.google.com/store/apps/details?id=com.adguard.trusttunnel"),
        ],
    ),
    (
        ("TrustTunnel CLI", "TrustTunnel CLI"),
        ("Linux, macOS, Windows", "Linux, macOS, Windows"),
        ("файл TOML", "TOML file"),
        &[("GitHub", "https://github.com/TrustTunnel/TrustTunnelClient")],
    ),
    (
        ("Приложения на ядре mihomo (Clash Meta)", "Apps built on the mihomo core (Clash Meta)"),
        ("Windows, macOS, Linux, Android, iOS", "Windows, macOS, Linux, Android, iOS"),
        ("подписка Clash: эта ссылка с ?format=clash", "Clash subscription: this link with ?format=clash"),
        &[],
    ),
];

/// `KIND_LABELS`: the adapters store Russian labels; the page shows them by artifact kind.
fn kind_label(kind: &str) -> Option<Pair> {
    Some(match kind {
        "share_url" => ("Ссылка Mieru", "Mieru link"),
        "proxy_url" => ("Адрес прокси", "Proxy address"),
        "link" => ("Ссылка Telegram", "Telegram link"),
        "trusttunnel_link" => ("Ссылка TrustTunnel", "TrustTunnel link"),
        "trusttunnel_toml" => ("Конфиг TrustTunnel (TOML)", "TrustTunnel config (TOML)"),
        "trusttunnel_manual" => ("Данные для ручной настройки", "Manual setup data"),
        _ => return None,
    })
}

/// `DOWNLOAD_LABELS.get(label, label)`.
fn download_label(label: &str) -> &str {
    match label {
        "Сайт приложения" => "App website",
        "Выпуски на GitHub" => "Releases on GitHub",
        "Где скачать" => "Where to download",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::download_label;
    use crate::apps::APPS;

    #[test]
    fn every_catalogue_download_label_has_an_english_translation() {
        for app in APPS {
            for (label, _) in app.downloads {
                let english = download_label(label);
                assert_ne!(english, *label, "{}: {label}", app.id);
                assert!(english.is_ascii(), "{}: {label}", app.id);
            }
        }
    }
}

/// `PLATFORM_NAMES`.
fn platform_name(key: &str) -> Pair {
    match key {
        "ios" => ("iPhone / iPad", "iPhone / iPad"),
        "android" => ("Android", "Android"),
        "windows" => ("Windows", "Windows"),
        "macos" => ("macOS", "macOS"),
        _ => ("Linux", "Linux"),
    }
}

/// `_Page`: language, unique element ids and the copy-button markup for one render.
struct Page {
    english: bool,
    count: usize,
}

impl Page {
    fn new(lang: &str) -> Self {
        Self { english: lang == "en", count: 0 }
    }

    fn lang(&self) -> &'static str {
        if self.english {
            "en"
        } else {
            "ru"
        }
    }

    fn t<'a>(&self, ru: &'a str, en: &'a str) -> &'a str {
        if self.english {
            en
        } else {
            ru
        }
    }

    fn label<'a>(&self, artifact: &'a AccessArtifact) -> &'a str {
        match kind_label(&artifact.kind) {
            Some((ru, en)) => self.t(ru, en),
            None => &artifact.label,
        }
    }

    /// A readable value and the button that copies it.
    fn copy(&mut self, value: &str, label: Option<&str>, extra: &str) -> String {
        self.count += 1;
        let ident = format!("v{}", self.count);
        let label = label.unwrap_or(self.t("Копировать", "Copy"));
        format!(
            "<code id=\"{ident}\">{}</code><button type=\"button\" class=\"btn small\" data-copy=\"{ident}\" \
             data-done=\"{}\" data-fail=\"{}\">{}</button>{extra}",
            escape(value),
            self.t("Скопировано", "Copied"),
            self.t("Не получилось — выделите вручную", "Failed — select it by hand"),
            escape(label),
        )
    }

    fn qr(&self, value: &str) -> Result<String, RenderError> {
        let image = panel_protocols::reveals::qr_data(value).map_err(|error| RenderError(error.to_string()))?;
        Ok(format!(
            "<details class=\"qr\"><summary>{}</summary><p class=\"muted small\">{}</p><img src=\"{}\" alt=\"QR\"></details>",
            self.t("Показать QR", "Show QR"),
            self.t(
                "Для другого устройства: наведите на него камеру или сканер в приложении.",
                "For another device: scan it with its camera or the scanner in the app."
            ),
            escape(&image),
        ))
    }
}

/// `_endpoint_domain(grant, artifacts)`: the host an access connects to, from its own link; `""`
/// when there is no link to read it from.
fn endpoint_domain(grant: &ManifestGrant, artifacts: &Artifacts) -> String {
    for artifact in artifacts.get(&grant.grant_id).into_iter().flatten() {
        if artifact.media_type != "text/uri-list" {
            continue;
        }
        if grant.protocol == "trusttunnel" {
            return trusttunnel_fields(&artifact.value).ok().and_then(|fields| fields.hostname).unwrap_or_default();
        }
        let Ok(parts) = pytext::urlsplit(&artifact.value) else { return String::new() };
        if grant.protocol == "mtproxy" {
            // `dict(item.partition("=")[::2] for item in query.split("&")).get("server", "")`.
            let mut found = String::new();
            for item in parts.query.split('&') {
                let (key, value) = item.split_once('=').unwrap_or((item, ""));
                if key == "server" {
                    found = value.to_string();
                }
            }
            return found;
        }
        return parts.hostname().unwrap_or_default();
    }
    String::new()
}

/// `_titles(manifest, artifacts)`: the name the operator gave an access, else «protocol · domain»
/// (never the local node's name); two that read the same get their login added.
fn titles(
    manifest: &Manifest,
    artifacts: &Artifacts,
    names: &std::collections::BTreeMap<String, String>,
) -> HashMap<String, String> {
    let mut titles: HashMap<String, String> = HashMap::new();
    for grant in &manifest.grants {
        if !display_text(&grant.label).is_empty() {
            titles.insert(grant.grant_id.clone(), names[&grant.grant_id].clone());
            continue;
        }
        let domain = endpoint_domain(grant, artifacts);
        let shown = if domain.is_empty() { grant.runtime_username.clone() } else { domain };
        titles.insert(grant.grant_id.clone(), format!("{} \u{b7} {shown}", protocol_title(&grant.protocol)));
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    for title in titles.values() {
        *seen.entry(title.clone()).or_default() += 1;
    }
    manifest
        .grants
        .iter()
        .map(|grant| {
            let title = &titles[&grant.grant_id];
            let shown =
                if seen[title] > 1 { format!("{title} \u{b7} {}", grant.runtime_username) } else { title.clone() };
            (grant.grant_id.clone(), shown)
        })
        .collect()
}

/// `_manual_block(page, artifact)`: the fields of a client that imports neither link nor TOML.
fn manual_block(page: &mut Page, artifact: &AccessArtifact) -> String {
    let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(&artifact.value) else { return String::new() };
    let mut rows = String::new();
    for (key, ru, en) in MANUAL_LABELS {
        let value = fields.get(key).map_or_else(String::new, panel_model::pyrepr::str);
        let cell = page.copy(&value, None, "");
        rows.push_str(&format!("<tr><th>{}</th><td>{cell}</td></tr>", page.t(ru, en)));
    }
    rows.push_str(&format!(
        "<tr><th>{}</th><td>{}</td></tr>",
        page.t("Протокол", "Protocol"),
        page.t("HTTP/2, QUIC выключен", "HTTP/2, QUIC off")
    ));
    if let Some(pem) = fields.get("certificate_pem").filter(|value| crate::truthy(value)) {
        let cell = page.copy(&panel_model::pyrepr::str(pem), None, "");
        rows.push_str(&format!("<tr><th>{}</th><td>{cell}</td></tr>", page.t("Сертификат", "Certificate")));
    }
    format!("<h3>{}</h3><table>{rows}</table>", escape(page.label(artifact)))
}

/// `_apps_block(page)`: how to connect a TrustTunnel access.
fn apps_block(page: &Page) -> String {
    let items: String = TRUSTTUNNEL_APPS
        .iter()
        .map(|(name, platforms, how, links)| {
            let anchors: String = links
                .iter()
                .map(|(label, url)| {
                    format!(
                        " \u{b7} <a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>",
                        escape(url),
                        escape(label)
                    )
                })
                .collect();
            format!(
                "<li><b>{}</b> ({}): {}{anchors}</li>",
                escape(page.t(name.0, name.1)),
                escape(page.t(platforms.0, platforms.1)),
                escape(page.t(how.0, how.1)),
            )
        })
        .collect();
    format!("<h3>{}</h3><ul>{items}</ul>", page.t("Как подключить", "How to connect"))
}

/// `_grant_section(page, grant, artifacts, name, title)`.
fn grant_section(
    page: &mut Page,
    grant: &ManifestGrant,
    artifacts: &Artifacts,
    name: &str,
    title: &str,
) -> Result<String, RenderError> {
    let heading = escape(title);
    if !grant.enabled {
        return Ok(format!(
            "<details class=\"card\"><summary>{heading}</summary><p class=\"muted\">{}</p></details>",
            page.t("Доступ отключён.", "This access is turned off.")
        ));
    }
    if let Some(reason) = credential_reason(grant, artifacts) {
        return Ok(format!(
            "<details class=\"card\"><summary>{heading}</summary><p class=\"muted\">{}: {}</p></details>",
            page.t("Недоступно", "Unavailable"),
            escape(reason)
        ));
    }
    let mut parts = vec![format!("<details class=\"card\"><summary>{heading}</summary>")];
    for artifact in &artifacts[&grant.grant_id] {
        let mut value = artifact.value.clone();
        if artifact.media_type == "application/json" {
            parts.push(manual_block(page, artifact));
            continue;
        }
        if artifact.media_type == "text/uri-list" {
            value = named_share_url(grant, &value, name)?;
        }
        if artifact.media_type == "application/toml" {
            // A config file: shown in full to copy, and offered as a download.
            let href = format!(
                "data:application/toml;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
            );
            let copied = page.copy(&value, None, "");
            parts.push(format!(
                "<h3>{}</h3>{copied}<a class=\"btn small\" href=\"{href}\" download=\"trusttunnel_client.toml\">{}</a>",
                escape(page.label(artifact)),
                page.t("Скачать файл", "Download the file")
            ));
            continue;
        }
        parts.push(format!("<h3>{}</h3>", escape(page.label(artifact))));
        if artifact.media_type == "text/uri-list" && is_deep_link(&value) {
            parts.push(format!(
                "<a class=\"btn primary\" href=\"{}\">{}</a>",
                escape(&value),
                page.t("Открыть", "Open")
            ));
        }
        let extra = if artifact.media_type == "text/uri-list" { page.qr(&value)? } else { String::new() };
        let label = page.t("Копировать ссылку", "Copy the link").to_string();
        parts.push(page.copy(&value, Some(&label), &extra));
    }
    if grant.protocol == "trusttunnel" {
        parts.push(apps_block(page));
    }
    parts.push("</details>".into());
    Ok(parts.concat())
}

/// `_gets(page, entry)`: what an app gets.
fn gets(page: &Page, entry: &AppEntry) -> String {
    let names = |items: &[String]| items.iter().map(|protocol| protocol_title(protocol)).collect::<Vec<_>>().join(", ");
    let mut lines = Vec::new();
    if !entry.works.is_empty() {
        lines.push(format!("{}: {}.", page.t("Получите", "You get"), names(&entry.works)));
    }
    if !entry.unverified.is_empty() {
        lines.push(format!(
            "{}: {}.",
            page.t("Должно работать, но мы это не проверяли", "Should work, but we have not tested it"),
            names(&entry.unverified)
        ));
    }
    if !entry.no.is_empty() || !entry.pending.is_empty() {
        let missing: Vec<String> = entry.no.iter().chain(&entry.pending).cloned().collect();
        lines.push(format!(
            "{}: {}.",
            page.t("Не работает в этом приложении", "Not available in this app"),
            names(&missing)
        ));
    }
    lines.iter().map(|line| format!("<p class=\"muted small\">{}</p>", escape(line))).collect()
}

/// `_app_entry(page, manifest, entry, url, first)`: what an app gets, and either its «Добавить в»
/// button or the link to paste and where to get the app.
fn app_entry(page: &mut Page, manifest: &Manifest, entry: &AppEntry, url: &str, first: bool) -> String {
    let app = entry.app;
    let link = format!("{url}{}", share_variant(app.variant).unwrap_or_default());
    let href = deep_link(app, &link, &manifest.client_name);
    let platforms = app
        .platforms
        .iter()
        .map(|key| {
            let (ru, en) = platform_name(key);
            page.t(ru, en)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let head = format!(
        "<div class=\"app\"><p class=\"app-name\">{}</p><p class=\"muted small\">{}</p>{}",
        escape(app.name),
        escape(&platforms),
        gets(page, entry)
    );
    if !href.is_empty() {
        return format!(
            "{head}<a class=\"btn{}\" href=\"{}\">{} {}</a></div>",
            if first { " primary" } else { "" },
            escape(&href),
            page.t("Добавить в", "Add to"),
            escape(app.name)
        );
    }
    let downloads = app
        .downloads
        .iter()
        .map(|(label, address)| {
            format!(
                "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>",
                escape(address),
                escape(page.t(label, download_label(label)))
            )
        })
        .collect::<Vec<_>>()
        .join(" \u{b7} ");
    let paste = page.t(
        "Скопируйте ссылку подписки и вставьте в приложение.",
        "Copy the subscription link and paste it into the app.",
    );
    let label = format!("{} {}", page.t("Копировать ссылку для", "Copy the link for"), app.name);
    let copied = page.copy(&link, Some(&label), "");
    format!("{head}<p class=\"small\">{paste}</p>{copied}<p class=\"small\">{downloads}</p></div>")
}

/// `_quick_links(page, manifest, artifacts)`: for a client with no subscription protocol, the
/// links themselves, up front.
fn quick_links(page: &Page, manifest: &Manifest, artifacts: &Artifacts) -> String {
    let mut buttons = String::new();
    for grant in manifest.grants.iter().filter(|grant| grant.enabled) {
        for artifact in artifacts.get(&grant.grant_id).into_iter().flatten() {
            if artifact.media_type == "text/uri-list" && is_deep_link(&artifact.value) {
                buttons.push_str(&format!(
                    "<a class=\"btn primary\" href=\"{}\">{} \u{b7} {}</a>",
                    escape(&artifact.value),
                    page.t("Открыть", "Open"),
                    escape(protocol_title(&grant.protocol))
                ));
            }
        }
    }
    if buttons.is_empty() {
        return String::new();
    }
    format!(
        "<section class=\"card\"><h2>{}</h2><p>{}</p>{buttons}</section>",
        page.t("Подключиться", "Connect"),
        page.t("Нажмите на телефоне, где установлено приложение.", "Tap it on the phone where the app is installed.")
    )
}

/// `_auto_refresh(page, manifest, artifacts, url)`: add the link to an app once; a client with no
/// subscription protocol gets its links instead.
fn auto_refresh(page: &mut Page, manifest: &Manifest, artifacts: &Artifacts, url: &str) -> Result<String, RenderError> {
    let mut protocols: Vec<String> = Vec::new();
    for grant in &manifest.grants {
        let has = artifacts.get(&grant.grant_id).is_some_and(|items| !items.is_empty());
        if grant.enabled
            && has
            && SUBSCRIPTION_PROTOCOLS.contains(&grant.protocol.as_str())
            && !protocols.contains(&grant.protocol)
        {
            protocols.push(grant.protocol.clone());
        }
    }
    if protocols.is_empty() {
        return Ok(quick_links(page, manifest, artifacts));
    }
    let intro = page.t(
        "Добавьте ссылку в приложение один раз — новые доступы появятся в нём сами, без повторной настройки.",
        "Add the link to an app once — new accesses will show up in it by themselves, no need to set it up again.",
    );
    let mut body = String::new();
    // Without a public subscription address there is no link to copy or build buttons from.
    if !url.is_empty() {
        let found = apps_for(&protocols);
        let entries: Vec<String> =
            found.iter().enumerate().map(|(index, entry)| app_entry(page, manifest, entry, url, index == 0)).collect();
        let label = page.t("Копировать ссылку подписки", "Copy the subscription link").to_string();
        body = page.copy(url, Some(&label), "");
        body.push_str(&page.qr(url)?);
        if !entries.is_empty() {
            body.push_str(&format!(
                "<h3>{}</h3><p class=\"muted small\">{}</p>{}",
                page.t("Приложения", "Apps"),
                page.t(
                    "Кнопка работает на устройстве, где приложение уже установлено.",
                    "The button works on the device where the app is already installed."
                ),
                entries.concat()
            ));
        }
    }
    Ok(format!(
        "<section class=\"card\"><h2>{}</h2><p>{intro}</p>{body}</section>",
        page.t("Подписка обновляется сама", "The subscription updates itself")
    ))
}

/// `_footer(page, updated_at)`: no set number (the ETag does not move with it).
fn footer(page: &Page, updated_at: Option<i64>) -> String {
    match updated_at.filter(|stamp| *stamp != 0) {
        Some(stamp) => format!("<footer>{} {}</footer>", page.t("Обновлено", "Updated"), utc_minute(stamp)),
        None => String::new(),
    }
}

pub fn render(
    manifest: &Manifest,
    artifacts: &Artifacts,
    url: &str,
    lang: &str,
    updated_at: Option<i64>,
    max_bytes: usize,
) -> Result<Vec<u8>, RenderError> {
    check(manifest)?;
    let mut page = Page::new(lang);
    let name = escape(&manifest.client_name);
    let names = grant_names(manifest)?;
    let titles = titles(manifest, artifacts, &names);
    let mut sections = String::new();
    for grant in &manifest.grants {
        sections.push_str(&grant_section(
            &mut page,
            grant,
            artifacts,
            &names[&grant.grant_id],
            &titles[&grant.grant_id],
        )?);
    }
    let title = format!("{} \u{b7} {name}", page.t("Доступы", "Accesses"));
    let warning = page.t(
        "Ссылка на эту страницу — ваш личный ключ, не передавайте её другим.",
        "The link to this page is your personal key — do not share it.",
    );
    let refresh = auto_refresh(&mut page, manifest, artifacts, url)?;
    let body = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\">\
         <title>{title}</title><style>{STYLE}</style></head><body><main>\
         <h1>{title}</h1><p class=\"warn\">{warning}</p>\
         {refresh}\
         <h2>{}</h2>{sections}\
         {}<script>{SCRIPT}</script></main></body></html>",
        page.lang(),
        page.t("Все доступы", "All accesses"),
        footer(&page, updated_at),
    );
    finish(body.into_bytes(), max_bytes)
}
