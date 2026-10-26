//! Host shell helpers sharing the installer's reviewed derivation and release parser.
use installer_core::{
    awg_ports::{machine_id, pick_ports},
    model::AWG_VERSIONS,
};
use pc_host::archive::ReleaseManifest;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub fn dispatch(arguments: &[String], tree: &Path) -> Option<Result<String, String>> {
    let command = arguments.first()?.as_str();
    if !["awg-ports", "release-pin"].contains(&command) {
        return None;
    }
    Some(run(command, &arguments[1..], tree))
}
fn run(command: &str, args: &[String], tree: &Path) -> Result<String, String> {
    if command == "release-pin" {
        let (args, path) = if args.len() == 4 && args[0] == "--manifest" {
            (&args[2..], PathBuf::from(&args[1]))
        } else {
            (args, tree.join("release/external-artifacts.json"))
        };
        if args.len() != 2 {
            return Err("usage: release-pin [--manifest PATH] ARTIFACT ARCHITECTURE".into());
        }
        let manifest =
            ReleaseManifest::from_bytes(&std::fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let pin = manifest.external_artifact(&args[0], &args[1]).map_err(|e| e.to_string())?;
        return Ok(format!("{} {}\n", pin.version, pin.sha256));
    }
    let (args, root) =
        if args.len() >= 2 && args[0] == "--root" { (&args[2..], Path::new(&args[1])) } else { (args, Path::new("/")) };
    let Some(separator) = args.iter().position(|s| s == "--") else {
        return Err("usage: awg-ports [--root ROOT] BOUND_PORTS [FIXED_PORT ...] -- VERSION ...".into());
    };
    if separator == 0 || separator + 1 == args.len() {
        return Err("awg-ports requires bound ports and at least one version".into());
    }
    let mut taken = BTreeSet::new();
    for text in args[0].split_whitespace().chain(args[1..separator].iter().map(String::as_str)) {
        let port = text.parse::<u16>().ok().filter(|p| *p > 0).ok_or("invalid awg-ports occupied port")?;
        taken.insert(i64::from(port));
    }
    let versions = &args[separator + 1..];
    if versions.iter().any(|v| !AWG_VERSIONS.contains(&v.as_str()))
        || versions.iter().collect::<BTreeSet<_>>().len() != versions.len()
    {
        return Err("invalid awg-ports versions".into());
    }
    let identity = machine_id(root).map_err(|e| e.to_string())?;
    let ports = pick_ports(versions, &identity, &taken, &[]).map_err(|e| e.to_string())?;
    Ok(versions.iter().zip(ports).map(|(v, p)| format!("{v}={p}\n")).collect())
}
