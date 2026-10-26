//! Release archives and reviewed artifacts.
//!
//! - [`panel`]: [`PANEL_SYNC`] (the one list of synced release entries, also the handoff
//!   allow-list) and the panel archive preflight/extraction of a self-update.
//! - [`release`]: the external-artifact manifest ([`ReleaseManifest`]) and artifact digests.
//! - [`safe`]: dirfd-anchored extraction of reviewed tar and zip artifacts.
//! - [`identity`]: `release/release.json` and `release-manifest.json`.

pub(crate) mod dirfd;
pub mod identity;
pub mod panel;
pub mod release;
pub mod safe;

pub use identity::{verify_binaries, Builder, IdentityError, PublishedManifest, ReleaseIdentity};
pub use panel::{
    extract_panel_archive, handoff_allows, PanelArchive, PanelArchiveError, PanelMember, AGENT_ROOT, MAX_PANEL_TREE,
    PANEL_AGENT_DIR, PANEL_ARCHIVE_PREFIX, PANEL_SYNC, PROJECT_DIR, RUST_MANAGERS, RUST_SHARED,
};
pub use release::{
    normalize_archive_path, require_sha256, resolve_symlink_target, validate_release_url, verify_artifact, ArtifactPin,
    MemberPin, ReleaseError, ReleaseManifest, DEFAULT_MAX_MEMBER_SIZE, SUPPORTED_ARCHITECTURES,
    SUPPORTED_SPDX_LICENSES,
};
pub use safe::{safe_extract_tar, safe_extract_zip, safe_extract_zip_default, ArchiveEntry, ArchiveManifest};
