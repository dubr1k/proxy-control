//! The stylesheet and the one small script of the subscription page, and the CSP that lets them run
//! The page is self-contained on the subscription host.
//!
//! Both are inlined (the subscription host answers only `/s/...`) and the policy admits exactly
//! these bytes by hash. [`csp`] recomputes the policy from the files under `assets/`;
//! the HTTP boundary and browser tests verify that those exact bytes are admitted.

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

    /// Frozen expected policy; the HTTP boundary carries the same asset hashes.
    const EXPECTED_CSP: &str = "default-src 'none'; style-src 'sha256-1FowHbtXacpoU+atsvB/kHBga3uUhMjZGR5tGC4UXL4='; script-src 'sha256-prNdb/NLfe2hab7XNPF7XOM4DZuWYWGhoq4UthMMFQ0='; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    #[test]
    fn the_policy_pins_the_exact_inline_assets() {
        assert_eq!(csp(), EXPECTED_CSP);
        assert!(STYLE.starts_with('\n') && STYLE.ends_with('\n') && STYLE.contains("content:\"\\2212\""));
        assert!(SCRIPT.starts_with("\n(function () {") && SCRIPT.ends_with("})();\n"));
    }
}
