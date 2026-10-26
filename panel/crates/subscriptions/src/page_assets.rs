//! The stylesheet and the one small script of the subscription page, and the CSP that lets them run
//! (`subscriptions/page_assets.py`).
//!
//! Both are inlined (the subscription host answers only `/s/...`) and the policy admits exactly
//! these bytes by hash. The two files under `assets/` were written from the Python constants
//! byte for byte (`tests/fixtures/record_goldens.py`); [`csp`] recomputes the policy from them and a
//! test compares it with the recorded one.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// `STYLE`: the exact text between `<style>` and `</style>` (starts and ends with `\n`).
pub const STYLE: &str = include_str!("assets/style.css");

/// `SCRIPT`: the exact text between `<script>` and `</script>` (starts and ends with `\n`).
pub const SCRIPT: &str = include_str!("assets/script.js");

/// `'sha256-<base64>'` of a text's UTF-8 bytes.
fn hash(text: &str) -> String {
    format!("'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(text.as_bytes())))
}

/// `CSP`: the policy sent on every `/s/` response.
pub fn csp() -> String {
    format!(
        "default-src 'none'; style-src {}; script-src {}; img-src data:; object-src 'none'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'",
        hash(STYLE),
        hash(SCRIPT)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Python's `page_assets.CSP` is (recorded in `panel/tests/goldens/subscriptions`).
    const PYTHON_CSP: &str = "default-src 'none'; style-src 'sha256-7zrdh6FLXrs4+7ooaZeyFT55YBE79eotFOMQmu4tyvQ='; script-src 'sha256-prNdb/NLfe2hab7XNPF7XOM4DZuWYWGhoq4UthMMFQ0='; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    #[test]
    fn the_policy_pins_the_inline_assets_as_python_does() {
        assert_eq!(csp(), PYTHON_CSP);
        assert!(STYLE.starts_with('\n') && STYLE.ends_with('\n') && STYLE.contains("content:\"\\2212\""));
        assert!(SCRIPT.starts_with("\n(function () {") && SCRIPT.ends_with("})();\n"));
    }
}
