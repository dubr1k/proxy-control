//! `proxy-control-installer verify-release` (formerly `release/verify.py`): offline checks of
//! `release/external-artifacts.json` and of a downloaded artifact against its pin.
//!
//! ```text
//! verify-release manifest <manifest.json>                       → "manifest: ok"
//! verify-release artifact <manifest.json> <name> {amd64,arm64} <file>  → "artifact: ok"
//! ```
//!
//! Failures print `verification failed: <ReleaseError>` on stderr and exit 1; usage errors exit
//! 2. The texts come from `pc_host::archive` (the port of `installer/release.py`). Difference
//! from Python: argparse's `prog` is `proxy-control-installer verify-release`, not `verify.py`.

use std::path::{Path, PathBuf};

use crate::argparse::{Arg, Choices, Help, Namespace, Parser, SubCommand};
use crate::pystr::py_path_str;

pub const DESCRIPTION: &str = "Offline verification for pinned external release artifacts.";

/// What to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Manifest { manifest: PathBuf },
    Artifact { manifest: PathBuf, name: String, architecture: String, artifact: PathBuf },
}

/// The argparse parser of `verify.py`, under `prog`.
pub fn parser(prog: &str) -> Parser {
    let mut parser = Parser::new(prog, Some(DESCRIPTION));
    let mut manifest = Parser::new(&parser.sub_prog("manifest"), None);
    manifest.add_positional("manifest", Help::None, true, None);
    let mut artifact = Parser::new(&parser.sub_prog("artifact"), None);
    artifact.add_positional("manifest", Help::None, true, None);
    artifact.add_positional("name", Help::None, false, None);
    artifact.add_positional("architecture", Help::None, false, Some(Choices::strings(&["amd64", "arm64"])));
    artifact.add_positional("artifact", Help::None, true, None);
    parser.add_subparsers(
        "command",
        true,
        vec![
            SubCommand { name: "manifest".into(), help: Some("validate a release manifest".into()), parser: manifest },
            SubCommand {
                name: "artifact".into(),
                help: Some("verify an artifact against a manifest pin".into()),
                parser: artifact,
            },
        ],
    );
    parser
}

/// The request in a parsed namespace.
pub fn request(namespace: &Namespace) -> Request {
    let text = |key: &str| match namespace.get(key) {
        Some(Arg::Str(value)) => value.clone(),
        _ => String::new(),
    };
    match text("command").as_str() {
        "manifest" => Request::Manifest { manifest: PathBuf::from(text("manifest")) },
        _ => Request::Artifact {
            manifest: PathBuf::from(text("manifest")),
            name: text("name"),
            architecture: text("architecture"),
            artifact: PathBuf::from(text("artifact")),
        },
    }
}

/// Runs the request: `(exit status, stdout, stderr)`.
pub fn run(request: &Request) -> (i32, String, String) {
    let result = (|| -> Result<&'static str, pc_host::archive::ReleaseError> {
        let manifest_path = match request {
            Request::Manifest { manifest } | Request::Artifact { manifest, .. } => manifest,
        };
        let manifest = load_manifest(manifest_path)?;
        if let Request::Artifact { name, architecture, artifact, .. } = request {
            let pin = manifest.external_artifact(name, architecture)?;
            pc_host::archive::verify_artifact(artifact, &pin.sha256)?;
            return Ok("artifact: ok\n");
        }
        Ok("manifest: ok\n")
    })();
    match result {
        Ok(line) => (0, line.to_string(), String::new()),
        Err(err) => (1, String::new(), format!("verification failed: {err}\n")),
    }
}

fn load_manifest(path: &Path) -> Result<pc_host::archive::ReleaseManifest, pc_host::archive::ReleaseError> {
    let data = std::fs::read(path).map_err(|_| {
        pc_host::archive::ReleaseError(format!("could not read manifest: {}", py_path_str(&path.to_string_lossy())))
    })?;
    pc_host::archive::ReleaseManifest::from_bytes(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_release_manifest_verifies() {
        let manifest = repo().join("release/external-artifacts.json");
        let parsed = crate::cli::parse(&args(&["verify-release", "manifest", manifest.to_str().unwrap()]), 78).unwrap();
        let crate::cli::Command::VerifyRelease(request) = parsed.command else { panic!() };
        assert_eq!(run(&request), (0, "manifest: ok\n".into(), String::new()));
        let fixture = repo().join("tests/fixtures/releases/valid-manifest.json");
        assert_eq!(run(&Request::Manifest { manifest: fixture }).0, 0);
    }

    #[test]
    fn failures_exit_one_with_the_reason() {
        let missing = Request::Manifest { manifest: PathBuf::from("/nonexistent/./m.json") };
        assert_eq!(
            run(&missing),
            (1, String::new(), "verification failed: could not read manifest: /nonexistent/m.json\n".into())
        );
        let dir = std::env::temp_dir().join(format!("verify-release-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("blob");
        std::fs::write(&artifact, b"not the pinned bytes").unwrap();
        let request = Request::Artifact {
            manifest: repo().join("release/external-artifacts.json"),
            name: "xray".into(),
            architecture: "amd64".into(),
            artifact: artifact.clone(),
        };
        let (status, stdout, stderr) = run(&request);
        assert_eq!((status, stdout.as_str()), (1, ""));
        assert!(stderr.starts_with("verification failed: artifact digest mismatch"), "{stderr}");
        let unknown = Request::Artifact {
            manifest: repo().join("release/external-artifacts.json"),
            name: "nope".into(),
            architecture: "amd64".into(),
            artifact,
        };
        assert_eq!(run(&unknown).2, "verification failed: unknown artifact: nope\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn usage_errors_exit_two() {
        let exit =
            crate::cli::parse(&args(&["verify-release", "artifact", "m.json", "xray", "i386", "f"]), 78).unwrap_err();
        assert_eq!(exit.status, 2);
        assert!(exit.stderr.ends_with(
            "proxy-control-installer verify-release artifact: error: argument architecture: invalid choice: 'i386' (choose from 'amd64', 'arm64')\n"
        ), "{}", exit.stderr);
    }
}
