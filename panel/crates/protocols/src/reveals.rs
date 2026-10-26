//! What a reveal hands out besides the link itself (`panel/reveals.py`): the QR code of a link and
//! the Karing import link of a sing-box config.

use panel_core::{pyjson, pytext};
use serde_json::{json, Value};

pub use crate::qr::DataOverflow;

/// `data:image/svg+xml;base64,…` of the QR code of `link`, byte-identical to python-qrcode's.
/// A payload over version 40-M (about 2.3 KB) is [`DataOverflow`].
pub fn qr_data(link: &str) -> Result<String, DataOverflow> {
    crate::qr::data_uri(link)
}

/// The QR code shown with a grant artifact, for what a phone can scan (`client_routes._qr_of`):
/// `text/uri-list` and the AmneziaWG `.conf`; a value too large for a code (an AmneziaWG config
/// with long `I1`…`I5`) simply has none.
///
/// python-qrcode 8.2 reports such an overflow as a `ValueError` (its version setter refuses 41
/// before `DataOverflowError` is reached), which `_qr_of` catches: Python answered `null` too.
pub fn artifact_qr(media_type: &str, value: &str) -> Option<String> {
    if !matches!(media_type, "text/uri-list" | crate::amneziawg::CONF_MEDIA_TYPE) {
        return None;
    }
    qr_data(value).ok()
}

/// The Karing client entry of a reveal: `karing://install-config?url=<config JSON>&name=<name>`
/// (`urlencode`, so spaces are `+`), the config, its file name and the QR of the import link.
pub fn karing_client(config: &Value, name: &str, filename: &str) -> Result<Value, DataOverflow> {
    let content = pyjson::compact_utf8(config);
    let import_url =
        format!("karing://install-config?{}", pytext::urlencode(&[("url", content.as_str()), ("name", name)]));
    let image = qr_data(&import_url)?;
    Ok(json!({
        "label": "Karing",
        "type": "link",
        "import_url": import_url,
        "config": config,
        "filename": filename,
        "qr": {"payload": import_url, "image": image},
    }))
}
