//! While the Python panel is still in the tree, every machine code it raises must be in
//! [`ErrorCode`]. The scan looks for `code="…"`, `"code": "…"` and `SomethingError(NNN, "…"` in
//! `panel/**/*.py` (tests excluded); it is skipped once the Python sources are gone.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use panel_core::errors::ErrorCode;

fn python_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(name.as_str(), "tests" | "crates" | "static" | "__pycache__") {
                python_sources(&path, out);
            }
        } else if name.ends_with(".py") {
            out.push(path);
        }
    }
}

fn is_code(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The quoted word starting right at `text`'s first byte (after optional spaces), if any.
fn quoted(text: &str) -> Option<&str> {
    let text = text.trim_start();
    let quote = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &text[1..];
    let end = rest.find(quote)?;
    Some(&rest[..end]).filter(|word| is_code(word))
}

fn codes_in(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (index, _) in source.match_indices("code=") {
        let before = source[..index].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        if let Some(word) = quoted(&source[index + 5..]) {
            found.insert(word.to_string());
        }
    }
    for marker in ["\"code\":", "'code':"] {
        for (index, _) in source.match_indices(marker) {
            if let Some(word) = quoted(&source[index + marker.len()..]) {
                found.insert(word.to_string());
            }
        }
    }
    for (index, _) in source.match_indices("Error(") {
        let rest = &source[index + 6..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() == 3 {
            if let Some(word) = rest[3..].trim_start().strip_prefix(',').and_then(quoted) {
                found.insert(word.to_string());
            }
        }
    }
    found
}

#[test]
fn every_python_code_is_in_the_enum() {
    let panel = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !panel.join("app.py").exists() {
        eprintln!("the Python panel is gone; nothing to compare");
        return;
    }
    let mut files = Vec::new();
    python_sources(&panel, &mut files);
    assert!(files.len() > 50, "found only {} Python files", files.len());
    let mut missing = BTreeSet::new();
    let mut seen = 0;
    for file in files {
        for code in codes_in(&std::fs::read_to_string(&file).unwrap()) {
            seen += 1;
            if ErrorCode::from_wire(&code).is_none() {
                missing.insert(format!("{code} ({})", file.display()));
            }
        }
    }
    assert!(seen > 40, "the scan found only {seen} codes");
    assert!(missing.is_empty(), "codes missing from ErrorCode: {missing:#?}");
}

#[test]
fn the_scanner_finds_each_pattern() {
    let codes = codes_in(
        r#"raise AdapterError("x", code="manager_unavailable")
           body = {"detail": d, "code": "node_unreachable"}
           raise RoutingError(409, "policy_conflict", "detail")
           LaneError(422, 'lanes_unsupported')
           encode(code="Not a code")"#,
    );
    assert_eq!(
        codes.into_iter().collect::<Vec<_>>(),
        ["lanes_unsupported", "manager_unavailable", "node_unreachable", "policy_conflict"]
    );
}
