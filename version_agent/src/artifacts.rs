//! Pull one regular file out of a release archive the agent already verified by SHA-256
//! (`version_agent/artifacts.py`).

use std::fmt;
use std::io::{Cursor, Read};

/// The default member bound (256 MiB).
pub const MAX_MEMBER: u64 = 256 * 1024 * 1024;

/// `ArtifactError`: the archive does not hold the member the catalog names, or holds it unsafely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactError(pub String);

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ArtifactError {}

fn error(message: &str) -> ArtifactError {
    ArtifactError(message.into())
}

fn normalized(name: &str) -> &str {
    let mut name = name;
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    name
}

/// `extract_member(payload, {"format": format}, member, maximum=…)`.
pub fn extract_member(
    payload: &[u8],
    format: Option<&str>,
    member: &str,
    maximum: u64,
) -> Result<Vec<u8>, ArtifactError> {
    if member.is_empty() || member.starts_with('/') || member.split('/').any(|part| part == "..") {
        return Err(error("invalid archive member"));
    }
    match format {
        Some("zip") => from_zip(payload, member, maximum),
        Some("tar.gz") => from_tar(payload, member, maximum),
        _ => Err(error("unsupported archive format")),
    }
}

fn unreadable<E>(_: E) -> ArtifactError {
    error("archive is unreadable")
}

fn read_bounded(reader: &mut dyn Read, maximum: u64) -> Result<Vec<u8>, ArtifactError> {
    let mut data = Vec::new();
    reader.take(maximum + 1).read_to_end(&mut data).map_err(unreadable)?;
    if data.len() as u64 > maximum {
        return Err(error("archive member is too large"));
    }
    Ok(data)
}

fn from_zip(payload: &[u8], member: &str, maximum: u64) -> Result<Vec<u8>, ArtifactError> {
    let mut bundle = zip::ZipArchive::new(Cursor::new(payload)).map_err(unreadable)?;
    let mut found = None;
    for index in 0..bundle.len() {
        let file = bundle.by_index_raw(index).map_err(unreadable)?;
        let name = match file.name() {
            Ok(name) => name.to_string(),
            Err(_) => continue,
        };
        if normalized(&name) == member {
            let mode = (file.external_attributes() >> 16) & 0o170000;
            if file.is_dir() || (mode != 0 && mode != 0o100000) {
                return Err(error("archive member is not a regular file"));
            }
            if file.size() > maximum {
                return Err(error("archive member is too large"));
            }
            found = Some(index);
            break;
        }
    }
    let Some(index) = found else {
        return Err(error("archive member not found"));
    };
    let mut file = bundle.by_index(index).map_err(unreadable)?;
    read_bounded(&mut file, maximum)
}

fn from_tar(payload: &[u8], member: &str, maximum: u64) -> Result<Vec<u8>, ArtifactError> {
    let mut bundle = tar::Archive::new(flate2::read::GzDecoder::new(payload));
    for entry in bundle.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        if normalized(&name) != member {
            continue;
        }
        if !matches!(entry.header().entry_type(), tar::EntryType::Regular | tar::EntryType::Continuous) {
            return Err(error("archive member is not a regular file"));
        }
        if entry.size() > maximum {
            return Err(error("archive member is too large"));
        }
        return read_bounded(&mut entry, maximum);
    }
    Err(error("archive member not found"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `_zip(entries)` of the Python tests.
    pub(crate) fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            for (name, data) in entries {
                writer.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                std::io::Write::write_all(&mut writer, data).unwrap();
            }
            writer.finish().unwrap();
        }
        buffer.into_inner()
    }

    /// `_targz(entries, symlink=…)` of the Python tests.
    pub(crate) fn targz_of(entries: &[(&str, &[u8])], symlink: Option<&str>) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, data) in entries {
            // The name goes in verbatim (`set_path` would drop a leading `./`).
            let mut header = tar::Header::new_gnu();
            header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        if let Some(name) = symlink {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, name, "/etc/passwd").unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn zip_member_is_returned_by_exact_name() {
        let payload = zip_of(&[("xray", b"bin"), ("geoip.dat", b"geo")]);
        assert_eq!(extract_member(&payload, Some("zip"), "xray", MAX_MEMBER).unwrap(), b"bin");
    }

    #[test]
    fn tar_member_may_sit_under_a_directory() {
        let payload = targz_of(&[("mita_3.37.0_linux_amd64/mita", b"bin")], None);
        assert_eq!(
            extract_member(&payload, Some("tar.gz"), "mita_3.37.0_linux_amd64/mita", MAX_MEMBER).unwrap(),
            b"bin"
        );
    }

    #[test]
    fn tar_member_written_with_a_dot_slash_prefix_is_still_found() {
        let payload = targz_of(&[("./mita", b"bin")], None);
        assert_eq!(extract_member(&payload, Some("tar.gz"), "mita", MAX_MEMBER).unwrap(), b"bin");
    }

    #[test]
    fn missing_member_symlink_and_oversize_are_refused() {
        let message = |result: Result<Vec<u8>, ArtifactError>| result.unwrap_err().0;
        assert!(message(extract_member(&zip_of(&[("xray", b"bin")]), Some("zip"), "geoip.dat", MAX_MEMBER))
            .contains("member not found"));
        assert!(message(extract_member(&targz_of(&[], Some("mita")), Some("tar.gz"), "mita", MAX_MEMBER))
            .contains("not a regular file"));
        assert!(
            message(extract_member(&zip_of(&[("xray", &[b'x'; 32])]), Some("zip"), "xray", 16)).contains("too large")
        );
        assert!(message(extract_member(&targz_of(&[("mita", &[b'x'; 32])], None), Some("tar.gz"), "mita", 16))
            .contains("too large"));
    }

    #[test]
    fn escaping_members_unknown_formats_and_garbage_are_refused() {
        let payload = zip_of(&[("xray", b"bin")]);
        let message = |result: Result<Vec<u8>, ArtifactError>| result.unwrap_err().0;
        assert!(
            message(extract_member(&payload, Some("zip"), "../xray", MAX_MEMBER)).contains("invalid archive member")
        );
        assert!(message(extract_member(&payload, Some("zip"), "/xray", MAX_MEMBER)).contains("invalid archive member"));
        assert!(
            message(extract_member(&payload, Some("rar"), "xray", MAX_MEMBER)).contains("unsupported archive format")
        );
        assert!(message(extract_member(b"not an archive", Some("zip"), "xray", MAX_MEMBER)).contains("unreadable"));
        assert!(message(extract_member(b"not an archive", Some("tar.gz"), "mita", MAX_MEMBER)).contains("unreadable"));
    }
}
