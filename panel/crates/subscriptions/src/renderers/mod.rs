//! Subscription formats `manifest | singbox | clash | raw | html` (`subscriptions/renderers`).
//!
//! Every renderer is a pure function of a [`Manifest`] and the artifacts resolved for it; none
//! emits a link the target client is not known to parse.

pub mod base;
pub mod clash;
pub mod html;
pub mod manifest;
pub mod raw;
pub mod singbox;

use panel_model::subscriptions::Manifest;

pub use base::{resolve_artifacts, Artifacts, RenderError, MAX_BYTES, MAX_GRANTS, MEDIA_TYPE_MANIFEST, NO_CREDENTIAL};

/// One renderer of `RENDERERS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Manifest,
    Singbox,
    Clash,
    Raw,
    Html,
}

impl Format {
    /// `RENDERERS`, in its order.
    pub const ALL: [Format; 5] = [Format::Manifest, Format::Singbox, Format::Clash, Format::Raw, Format::Html];

    /// `RENDERERS.get(name)`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|format| format.name() == name)
    }

    /// `renderer.name`.
    pub fn name(self) -> &'static str {
        match self {
            Format::Manifest => "manifest",
            Format::Singbox => "singbox",
            Format::Clash => "clash",
            Format::Raw => "raw",
            Format::Html => "html",
        }
    }

    /// `renderer.media_type`.
    pub fn media_type(self) -> &'static str {
        match self {
            Format::Manifest => MEDIA_TYPE_MANIFEST,
            Format::Singbox => "application/json",
            Format::Clash => "text/yaml; charset=utf-8",
            Format::Raw => "text/plain; charset=utf-8",
            Format::Html => "text/html; charset=utf-8",
        }
    }

    /// `renderer.version` — part of the ETag.
    pub fn version(self) -> i64 {
        match self {
            Format::Manifest => 3,
            Format::Singbox => 4,
            Format::Clash => 2,
            Format::Raw => 2,
            Format::Html => 5,
        }
    }
}

/// The keyword arguments of `render`: the sing-box `client` (only that renderer takes one), the
/// page's `url`, `lang` and `updated_at`, and the byte limit (`MAX_BYTES`; tests lower it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOptions {
    pub client: Option<String>,
    pub url: String,
    pub lang: String,
    pub updated_at: Option<i64>,
    pub max_bytes: usize,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self { client: None, url: String::new(), lang: "ru".into(), updated_at: None, max_bytes: MAX_BYTES }
    }
}

impl RenderOptions {
    /// The sing-box cut for `client`.
    pub fn client(client: &str) -> Self {
        Self { client: Some(client.to_string()), ..Self::default() }
    }
}

/// `renderer.render(manifest, artifacts, **options)`.
pub fn render(
    format: Format,
    manifest: &Manifest,
    artifacts: &Artifacts,
    options: &RenderOptions,
) -> Result<Vec<u8>, RenderError> {
    let max = options.max_bytes;
    match format {
        Format::Manifest => manifest::render(manifest, artifacts, max),
        Format::Singbox => singbox::render(manifest, artifacts, options.client.as_deref().unwrap_or("karing"), max),
        Format::Clash => clash::render(manifest, artifacts, max),
        Format::Raw => raw::render(manifest, artifacts, max),
        Format::Html => html::render(manifest, artifacts, &options.url, &options.lang, options.updated_at, max),
    }
}

impl From<crate::names::NameCollision> for RenderError {
    fn from(error: crate::names::NameCollision) -> Self {
        RenderError(error.to_string())
    }
}
