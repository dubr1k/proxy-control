//! State files that survive a crash at any point: write a sibling, fsync, rename, fsync the
//! directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Replaces `path` with `data` atomically, created with `mode`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| {
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        // The umask may have narrowed the mode; state files need exactly the one asked for.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Serialises `value` as pretty JSON with sorted keys (serde_json's map order) and a trailing
/// newline, then writes it atomically.
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T, mode: u32) -> io::Result<()> {
    let mut data = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    data.push(b'\n');
    write_atomic(path, &data, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_file_with_exact_mode() {
        let dir = std::env::temp_dir().join(format!("pc-fsutil-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        write_atomic(&path, b"one", 0o600).unwrap();
        write_atomic(&path, b"two", 0o640).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
