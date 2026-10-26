use super::AdapterContext;
use crate::error::Error;
use installer_core::planner::{Action, Evidence};
use pc_host::archive::{ArtifactPin, ReleaseManifest};
use pc_host::runner::{Capture, RunOptions};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub fn err(message: &str) -> Error {
    Error::other("XrayRouterError", message)
}
pub fn host(context: &AdapterContext, path: &str) -> Result<PathBuf, Error> {
    if !fs::symlink_metadata(&context.root)?.is_dir() {
        return Err(err("host root is not a plain directory"));
    }
    let path = pc_host::fs::root_path(&context.root, path)?;
    let mut parent = path.parent();
    while let Some(value) = parent {
        if value == context.root {
            break;
        }
        match fs::symlink_metadata(value) {
            Ok(metadata) if !metadata.is_dir() => return Err(err("host path parent is not a plain directory")),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        parent = value.parent();
    }
    Ok(path)
}
pub fn atomic(context: &AdapterContext, path: &str, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let path = host(context, path)?;
    if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
        return Err(err("owned path is not a regular file"));
    }
    let owner = if context.root == std::path::Path::new("/") { Some((0, 0)) } else { None };
    pc_host::fs::atomic_write(&path, bytes, mode, owner)?;
    Ok(())
}
pub fn run(context: &AdapterContext, argv: &[&str], stdin: Option<PathBuf>) -> Result<(), Error> {
    let result = context.runner.run(argv, &RunOptions { stdin_path: stdin, ..RunOptions::default() })?;
    if result.returncode != 0 {
        return Err(err(&format!("host command failed: {}", argv.first().unwrap_or(&"command"))));
    }
    Ok(())
}
pub fn capture(context: &AdapterContext, argv: &[&str]) -> String {
    context.runner.capture(argv, 65536, Capture { max_chars: 65536, timeout: Duration::from_secs(15) })
}
pub fn checked(context: &AdapterContext, argv: &[&str]) -> Result<String, Error> {
    context.runner.capture_checked(argv, Duration::from_secs(30)).map_err(|_| err("host runtime query failed"))
}
pub fn pin(context: &AdapterContext, name: &str) -> Result<ArtifactPin, Error> {
    let manifest = ReleaseManifest::from_bytes(&fs::read(context.tree.join("release/external-artifacts.json"))?)
        .map_err(|_| err("release manifest is invalid"))?;
    manifest.external_artifact(name, "amd64").cloned().map_err(|_| err("release artifact is not pinned"))
}
pub fn ensure_archive(context: &AdapterContext, path: &str, pin: &ArtifactPin) -> Result<PathBuf, Error> {
    let path = host(context, path)?;
    if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
        return Err(err("artifact must be a regular file"));
    }
    if !path.exists() {
        let client = pc_host::net::HttpsClient::new(pc_host::net::ClientOptions {
            user_agent: "proxy-control".into(),
            timeout: Duration::from_secs(120),
            ..Default::default()
        })
        .map_err(|_| err("artifact download failed"))?;
        use std::os::unix::fs::OpenOptionsExt;
        pc_host::fs::ensure_parent(&path)?;
        let temporary = path.with_file_name(format!(".artifact-{}.fetching", pc_host::fs::token_hex::<8>()));
        let mut created = false;
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            created = true;
            let response = client
                .download(&pin.url, pc_host::net::UPSTREAM_HOSTS, &[], 256 * 1024 * 1024, &mut file)
                .map_err(|_| err("artifact download failed"))?;
            if response.status != 200 {
                return Err(err("artifact download failed"));
            }
            file.sync_all()?;
            pc_host::archive::verify_artifact(&temporary, &pin.sha256).map_err(|_| err("artifact digest mismatch"))?;
            // Publish without ever replacing an operator-staged archive.
            match fs::hard_link(&temporary, &path) {
                Ok(()) => pc_host::fs::fsync_directory(path.parent().expect("absolute artifact parent"))?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            Ok::<(), Error>(())
        })();
        let cleanup = if created { pc_host::fs::durable_remove(&temporary, true) } else { Ok(()) };
        result?;
        cleanup?;
    }
    pc_host::archive::verify_artifact(&path, &pin.sha256).map_err(|_| err("artifact digest mismatch"))?;
    Ok(path)
}
pub fn selection(action: &Action, name: &str, owner: &str) -> Result<BTreeMap<String, String>, Error> {
    if action.adapter != name || action.owner != owner {
        return Err(err("adapter action is invalid"));
    }
    let mut values = BTreeMap::new();
    for mutation in &action.mutations {
        let (key, value) = mutation.split_once('=').ok_or_else(|| err("adapter action is invalid"))?;
        if values.insert(key.into(), value.into()).is_some() {
            return Err(err("adapter action is invalid"));
        }
    }
    Ok(values)
}
pub fn evidence(action: &Action, message: &str, details: Value) -> Result<Evidence, Error> {
    Evidence::new(&action.id, true, vec![message.into()], details.into()).map_err(Into::into)
}
pub fn ownership(context: &AdapterContext, paths: &[(&str, bool, bool)]) -> Result<Value, Error> {
    let mut map = serde_json::Map::new();
    for (path, preserve, mutable) in paths {
        let target = host(context, path)?;
        if target.is_file() {
            map.insert(
                (*path).into(),
                json!({"sha256":pc_host::fs::sha256_file(&target)?,"preserve":preserve,"mutable":mutable}),
            );
        }
    }
    Ok(Value::Object(map))
}
pub fn remove(context: &AdapterContext, path: &str) -> Result<(), Error> {
    pc_host::fs::durable_remove(&host(context, path)?, true)?;
    Ok(())
}
pub fn compose(context: &AdapterContext, args: &[&str]) -> Result<(), Error> {
    let project = "/opt/mtproxy-shared443";
    let mut env_files = vec![format!("{project}/.env")];
    let mut compose_files = vec![format!("{project}/compose.yaml")];
    for sibling in ["naive", "mieru", "amneziawg", "trusttunnel"] {
        let env = format!("{project}/.env.{sibling}");
        if host(context, &env)?.is_file() {
            env_files.push(env);
            compose_files.push(format!("{project}/compose.{sibling}.yaml"));
        }
    }
    env_files.push(format!("{project}/.env.xray-router"));
    compose_files.push(format!("{project}/compose.xray-router.yaml"));
    let overrides = format!("{project}/version-overrides/compose.versions.yaml");
    if host(context, &overrides)?.is_file() {
        compose_files.push(overrides);
    }
    let mut argv = vec!["docker".to_owned(), "compose".into(), "--project-directory".into(), project.into()];
    for path in env_files {
        argv.extend(["--env-file".into(), path]);
    }
    for path in compose_files {
        argv.extend(["-f".into(), path]);
    }
    argv.extend(args.iter().map(|s| (*s).into()));
    run(context, &argv.iter().map(String::as_str).collect::<Vec<_>>(), None)
}
