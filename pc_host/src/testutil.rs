//! Throwaway directories for the unit tests.

use std::path::{Path, PathBuf};

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pc-host-{label}-{}", crate::fs::token_hex::<8>()));
        std::fs::create_dir(&path).expect("create a test directory");
        let canonical = std::fs::canonicalize(&path).expect("canonical test directory");
        TempDir(canonical)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = make_writable(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_writable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(path)? {
            let _ = make_writable(&entry?.path());
        }
    }
    Ok(())
}
