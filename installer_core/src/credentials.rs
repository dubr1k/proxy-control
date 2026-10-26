//! Operator-chosen credentials kept beside the configuration, never in it
//! (`installer/credentials.py`): `<config>.credentials` (TOML, 0600) and the private staged copy
//! the adapters read while an installation runs.
//!
//! Difference from Python (DIFFERENCES.md): control characters other than tab are written as
//! `\uXXXX` escapes. Python wrote them raw, which made the file invalid TOML on the next read.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::pystr::{char_len, decode_utf8, strip, universal_newlines, with_suffix};
use crate::toml::{self, Value};

const MINIMUM_PASSWORD: usize = 12;
const MAXIMUM_PASSWORD: usize = 256;
const FIELDS: [&str; 4] = ["panel_username", "panel_password", "three_xui_username", "three_xui_password"];
const STAGED_ANCHOR: &str = "operator.toml";

/// `CredentialError`: a supplied credential cannot be used safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialError(pub String);

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CredentialError {}

type Result<T> = std::result::Result<T, CredentialError>;

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(CredentialError(message.into()))
}

/// What the operator typed, or `None` where a generated value was chosen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorCredentials {
    pub panel_username: Option<String>,
    pub panel_password: Option<String>,
    pub three_xui_username: Option<String>,
    pub three_xui_password: Option<String>,
}

impl OperatorCredentials {
    /// `OperatorCredentials(...)` with its checks.
    pub fn new(
        panel_username: Option<&str>,
        panel_password: Option<&str>,
        three_xui_username: Option<&str>,
        three_xui_password: Option<&str>,
    ) -> Result<Self> {
        let values = OperatorCredentials {
            panel_username: panel_username.map(str::to_string),
            panel_password: panel_password.map(str::to_string),
            three_xui_username: three_xui_username.map(str::to_string),
            three_xui_password: three_xui_password.map(str::to_string),
        };
        values.validate()?;
        Ok(values)
    }

    fn validate(&self) -> Result<()> {
        for (field, value) in
            [("panel_username", &self.panel_username), ("three_xui_username", &self.three_xui_username)]
        {
            if value.as_deref().is_some_and(|value| !crate::config::safe_name(value)) {
                return fail(format!("{field} must be a safe name"));
            }
        }
        for (field, value) in
            [("panel_password", &self.panel_password), ("three_xui_password", &self.three_xui_password)]
        {
            let Some(value) = value else { continue };
            if char_len(strip(value)) < MINIMUM_PASSWORD {
                return fail(format!("{field} must be at least {MINIMUM_PASSWORD} characters"));
            }
            if char_len(value) > MAXIMUM_PASSWORD || value.contains('\n') || value.contains('\r') {
                return fail(format!("{field} is not a usable password"));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.fields().iter().all(|(_, value)| value.is_none())
    }

    fn fields(&self) -> [(&'static str, &Option<String>); 4] {
        [
            (FIELDS[0], &self.panel_username),
            (FIELDS[1], &self.panel_password),
            (FIELDS[2], &self.three_xui_username),
            (FIELDS[3], &self.three_xui_password),
        ]
    }
}

/// `credentials_path(config)`: `install.toml` → `install.credentials`.
pub fn credentials_path(config_path: &Path) -> Result<PathBuf> {
    with_suffix(config_path, ".credentials").map_err(CredentialError)
}

/// `write_credentials(config, values)`: written in place (`O_NOFOLLOW`, 0600, fsync), replacing
/// any earlier file.
pub fn write_credentials(config_path: &Path, values: &OperatorCredentials) -> Result<PathBuf> {
    let path = credentials_path(config_path)?;
    let mut body = String::from(
        "# Written by the Proxy Control wizard. Anyone who can read this file\n\
         # can sign in to the panels it describes. Delete it once the\n\
         # installation has finished.\n",
    );
    for (field, value) in values.fields() {
        if let Some(value) = value {
            body.push_str(&format!("{field} = {}\n", toml_string(value)));
        }
    }
    let io_error = |err: std::io::Error| CredentialError(crate::pystr::os_error_message(&err, &path.to_string_lossy()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io_error)?;
    file.write_all(body.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    Ok(path)
}

/// `read_credentials(config)`: `None` when the operator chose none.
pub fn read_credentials(config_path: &Path) -> Result<Option<OperatorCredentials>> {
    let path = credentials_path(config_path)?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return fail("the credentials file cannot be read"),
    };
    if !metadata.file_type().is_file() {
        return fail("the credentials file is not a regular file");
    }
    if metadata.mode() & 0o077 != 0 {
        return fail("the credentials file is readable beyond its owner; run chmod 600 on it");
    }
    let invalid = || CredentialError("the credentials file is not valid TOML".into());
    let data = std::fs::read(&path).map_err(|_| invalid())?;
    let text = universal_newlines(&decode_utf8(&data).map_err(|_| invalid())?);
    let document = toml::loads(&text).map_err(|_| invalid())?;
    let mut unknown: Vec<&str> = document.keys().filter(|key| !FIELDS.contains(key)).collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return fail(format!("unknown credential key: {key}"));
    }
    let mut values: [Option<String>; 4] = Default::default();
    for (index, field) in FIELDS.iter().enumerate() {
        match document.get(field) {
            None => {}
            Some(Value::String(text)) => values[index] = Some(text.clone()),
            Some(_) => return fail(format!("{field} must be a string")),
        }
    }
    let [panel_username, panel_password, three_xui_username, three_xui_password] = values;
    let credentials = OperatorCredentials { panel_username, panel_password, three_xui_username, three_xui_password };
    credentials.validate()?;
    Ok(Some(credentials))
}

/// A TOML basic string: `\` and `"` escaped like Python, other control characters (except tab)
/// as `\uXXXX`.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push('\t'),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn anchor(root: &Path) -> Result<PathBuf> {
    let directory =
        pc_host::fs::root_path(root, pc_host::INSTALLER_PATH).map_err(|err| CredentialError(err.message()))?;
    Ok(directory.join(STAGED_ANCHOR))
}

/// The private file the adapters read while an installation runs.
pub fn staged_path(root: &Path) -> Result<PathBuf> {
    credentials_path(&anchor(root)?)
}

/// `stage_credentials(root, config)`: copies the operator's credentials where the adapters look;
/// `None` (nothing written) when the operator chose generated ones.
pub fn stage_credentials(root: &Path, config_path: &Path) -> Result<Option<PathBuf>> {
    stage_operator_credentials(root, read_credentials(config_path)?.as_ref())
}

/// `stage_operator_credentials(root, values)`: the wizard's in-memory credentials.
pub fn stage_operator_credentials(root: &Path, values: Option<&OperatorCredentials>) -> Result<Option<PathBuf>> {
    let Some(values) = values.filter(|values| !values.is_empty()) else { return Ok(None) };
    let anchor = anchor(root)?;
    let directory = anchor.parent().expect("the anchor has a directory").to_path_buf();
    let io_error =
        |err: std::io::Error| CredentialError(crate::pystr::os_error_message(&err, &directory.to_string_lossy()));
    std::fs::create_dir_all(&directory).map_err(io_error)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    write_credentials(&anchor, values).map(Some)
}

/// `staged_credentials(root)`.
pub fn staged_credentials(root: &Path) -> Result<Option<OperatorCredentials>> {
    read_credentials(&anchor(root)?)
}

/// `discard_staged_credentials(root)`: a password is needed while installing, never afterwards.
pub fn discard_staged_credentials(root: &Path) -> Result<()> {
    let path = staged_path(root)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => fail(crate::pystr::os_error_message(&err, &path.to_string_lossy())),
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
