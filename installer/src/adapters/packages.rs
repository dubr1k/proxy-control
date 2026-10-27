//! Exact Debian package-selection ownership (`installer/adapters/packages.py`).
//!
//! Only packages absent during `prepare` become installer-owned. Package versions and all
//! pre-existing selections are checked again before and after every mutation; no host files are
//! declared as owned.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pc_host::runner::{Bounded, HostRunner};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::{HostMode, InstallerConfig};
use crate::planner::{Action, AuditFacts, Evidence};

pub const DEFAULT_PACKAGES: [&str; 7] =
    ["ca-certificates", "certbot", "curl", "docker-compose-v2", "docker.io", "nginx-full", "openssl"];
const QUERY_FORMAT: &str = "${Package}\t${db:Status-Abbrev}\t${Version}\\n";
const OWNER: &str = "proxy-control:packages";

pub struct PackagesAdapter {
    runner: Arc<dyn HostRunner>,
    packages: Vec<String>,
}

impl PackagesAdapter {
    pub fn new(context: &AdapterContext) -> PackagesAdapter {
        PackagesAdapter {
            runner: context.runner.clone(),
            packages: DEFAULT_PACKAGES.iter().map(|package| (*package).into()).collect(),
        }
    }

    #[cfg(test)]
    fn with_packages(context: &AdapterContext, packages: &[&str]) -> PackagesAdapter {
        let mut packages: Vec<String> = packages.iter().map(|package| (*package).into()).collect();
        packages.sort();
        packages.dedup();
        assert!(!packages.is_empty() && packages.iter().all(|package| valid_package(package)));
        PackagesAdapter { runner: context.runner.clone(), packages }
    }

    fn assert_selected(&self, packages: &[String]) -> Result<(), Error> {
        // Existing pre-4.0 plans keep their exact package ownership, including Python.
        // Only fresh plans use the native seven-package set; never discard an old journal's
        // pre-existing or installer-owned package record during resume/repair/uninstall.
        let legacy = self.packages.iter().map(String::as_str).eq(DEFAULT_PACKAGES)
            && packages.len() == DEFAULT_PACKAGES.len() + 1
            && packages.starts_with(&self.packages)
            && packages.last().is_some_and(|package| package == "python3");
        if packages != self.packages && !legacy {
            return Err(package_error("package action does not match this adapter"));
        }
        Ok(())
    }

    fn statuses(&self, packages: &[String]) -> Result<BTreeMap<String, Option<String>>, Error> {
        packages.iter().map(|package| Ok((package.clone(), self.status(package)?))).collect()
    }

    fn status(&self, package: &str) -> Result<Option<String>, Error> {
        let showformat = format!("--showformat={QUERY_FORMAT}");
        let result = self.runner.bounded(&["dpkg-query", "--show", &showformat, package], Bounded::PACKAGES)?;
        if result.returncode == 1 {
            return Ok(None);
        }
        if result.returncode != 0 {
            return Err(package_error("package status query failed"));
        }
        let lines = py_splitlines(&result.stdout);
        if lines.len() != 1 {
            return Err(package_error("package status response is malformed"));
        }
        let fields: Vec<&str> = lines[0].split('\t').collect();
        let status = if fields.len() == 3 { fields[1].as_bytes() } else { b"" };
        if fields.len() != 3
            || fields[0] != package
            || status.len() != 3
            || !matches!(status[0], b'u' | b'i' | b'h' | b'r' | b'p')
            || !matches!(status[1], b'n' | b'c' | b'H' | b'U' | b'F' | b'W' | b't' | b'i')
            || !matches!(status[2], b' ' | b'R')
        {
            return Err(package_error("package status response is malformed"));
        }
        if status[1] != b'i' {
            // Removed (`rc`) and purged (`un`) records are both absent selections.
            return Ok(None);
        }
        if !valid_version(fields[2]) {
            return Err(package_error("package status response is malformed"));
        }
        Ok(Some(fields[2].into()))
    }

    fn run_checked(&self, argv: &[&str], message: &str) -> Result<(), Error> {
        if self.runner.bounded(argv, Bounded::PACKAGES)?.returncode != 0 {
            return Err(package_error(message));
        }
        Ok(())
    }
}

impl Adapter for PackagesAdapter {
    fn name(&self) -> &str {
        "packages"
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        if config.host_mode != HostMode::Fresh {
            return Ok(Vec::new());
        }
        if has_hard_stops(facts) {
            return Err(package_error("host audit contains blocking findings"));
        }
        Ok(vec![Action::new(
            "packages.host",
            "packages",
            OWNER,
            self.packages.iter().map(|package| format!("package={package}")).collect(),
            vec!["supported package manager and package status are observed".into()],
            vec!["every exact requested package is installed".into()],
            vec![
                "remove only exact packages installed by this action; purge them only on uninstall --purge-data".into()
            ],
            false,
        )?])
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        let packages = action_packages(action)?;
        self.assert_selected(&packages)?;
        let statuses = self.statuses(&packages)?;
        let preexisting =
            statuses.into_iter().filter_map(|(package, version)| version.map(|version| (package, version))).collect();
        Ok(package_checkpoint(&action.owner, &preexisting, &BTreeMap::new()))
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let packages = action_packages(action)?;
        let (preexisting, recorded_added) = checkpoint_packages(&checkpoint, &packages)?;
        let current = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &current)?;
        assert_added_unchanged(&recorded_added, &current, false)?;
        let missing: Vec<&String> = packages.iter().filter(|package| current[*package].is_none()).collect();
        if !missing.is_empty() {
            let mut argv = vec![
                "apt-get".to_string(),
                "install".into(),
                "--yes".into(),
                "--no-install-recommends".into(),
                "--no-upgrade".into(),
            ];
            argv.extend(missing.into_iter().cloned());
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "package installation failed")?;
        }
        let observed = self.statuses(&packages)?;
        if packages.iter().any(|package| observed[package].is_none()) {
            return Err(package_error("requested package is not installed"));
        }
        assert_preexisting_unchanged(&preexisting, &observed)?;
        let installer_added: BTreeMap<String, String> = packages
            .iter()
            .filter(|package| !preexisting.contains_key(*package))
            .map(|package| {
                let version =
                    observed[package].clone().ok_or_else(|| package_error("requested package status is invalid"))?;
                if !valid_version(&version) {
                    return Err(package_error("requested package status is invalid"));
                }
                Ok((package.clone(), version))
            })
            .collect::<Result<_, Error>>()?;
        Ok(package_checkpoint(&action.owner, &preexisting, &installer_added))
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let packages = action_packages(action)?;
        let checked = (|| {
            self.assert_selected(&packages)?;
            let current = self.statuses(&packages)?;
            Ok(packages.iter().all(|package| current[package].is_some()))
        })();
        let success = match checked {
            Ok(success) => success,
            Err(error) if is_package_error(&error) => false,
            Err(error) => return Err(error),
        };
        let observation =
            if success { "exact package set is installed" } else { "exact package set is incomplete or invalid" };
        Ok(Evidence::with_details(
            &action.id,
            success,
            vec![observation.into()],
            Map::from_iter([("packages".into(), json!(packages))]),
        )?)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        // Maintainer-script purges also delete docker and certbot data. Only an explicit
        // uninstall --purge-data consents to that; even failed-install rollback uses remove.
        let purge = target == RollbackTarget::Uninstalled && purge_data;
        let packages = action_packages(action)?;
        let (preexisting, installer_added) = checkpoint_packages(&checkpoint, &packages)?;
        let current = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &current)?;
        assert_added_unchanged(&installer_added, &current, true)?;
        let present_owned: Vec<&String> = packages
            .iter()
            .filter(|package| installer_added.contains_key(*package) && current[*package].is_some())
            .collect();
        if !present_owned.is_empty() {
            let mut argv =
                vec!["apt-get".to_string(), if purge { "purge".into() } else { "remove".into() }, "--yes".into()];
            argv.extend(present_owned.into_iter().cloned());
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "package rollback failed")?;
        }
        let after = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &after)?;
        if installer_added.keys().any(|package| after[package].is_some()) {
            return Err(package_error("installer-owned package remains installed"));
        }
        let removed: Vec<&String> = installer_added.keys().collect();
        Ok(Evidence::with_details(
            &action.id,
            true,
            vec!["installer-owned packages were removed".into()],
            Map::from_iter([("removed".into(), json!(removed))]),
        )?)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        let packages = action_packages(action)?;
        let (preexisting, mut installer_added) = checkpoint_packages(&checkpoint, &packages)?;
        let current = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &current)?;
        for package in &packages {
            if !preexisting.contains_key(package) {
                if let Some(version) = &current[package] {
                    installer_added.insert(package.clone(), version.clone());
                }
            }
        }
        self.rollback(action, package_checkpoint(&action.owner, &preexisting, &installer_added), purge_data, target)
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let packages = action_packages(action)?;
        let (preexisting, installer_added) = checkpoint_packages(&checkpoint, &packages)?;
        let current = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &current)?;
        let mut missing = Vec::new();
        for (package, version) in &installer_added {
            match &current[package] {
                None => missing.push(format!("{package}={version}")),
                Some(observed) if observed != version => {
                    return Err(package_error("installer-owned package version drift"));
                }
                Some(_) => {}
            }
        }
        if !missing.is_empty() {
            let mut argv = vec![
                "apt-get".to_string(),
                "install".into(),
                "--yes".into(),
                "--no-install-recommends".into(),
                "--no-upgrade".into(),
            ];
            argv.extend(missing);
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "package repair failed")?;
        }
        let after = self.statuses(&packages)?;
        assert_preexisting_unchanged(&preexisting, &after)?;
        assert_added_unchanged(&installer_added, &after, false)?;
        Ok(package_checkpoint(&action.owner, &preexisting, &installer_added))
    }
}

fn package_error(message: &str) -> Error {
    Error::other("PackageError", message)
}

fn is_package_error(error: &Error) -> bool {
    matches!(error, Error::Other { class, .. } if class == "PackageError")
}

fn has_hard_stops(facts: &AuditFacts) -> bool {
    facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty())
}

fn valid_package(package: &str) -> bool {
    let bytes = package.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes[1..].iter().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'+' | b'.' | b'-'))
}

fn valid_version(version: &str) -> bool {
    let length = version.chars().count();
    (1..=256).contains(&length) && !version.chars().any(|ch| matches!(ch, '\t' | '\r' | '\n' | '\0'))
}

fn action_packages(action: &Action) -> Result<Vec<String>, Error> {
    if action.adapter != "packages" || action.id != "packages.host" {
        return Err(package_error("package action is invalid"));
    }
    let mut packages = Vec::new();
    for mutation in &action.mutations {
        let Some((key, value)) = mutation.split_once('=') else {
            return Err(package_error("package action is invalid"));
        };
        if key != "package" || !valid_package(value) {
            return Err(package_error("package action is invalid"));
        }
        packages.push(value.to_string());
    }
    let mut normalized = packages.clone();
    normalized.sort();
    normalized.dedup();
    if packages != normalized {
        return Err(package_error("package action is invalid"));
    }
    Ok(normalized)
}

fn package_checkpoint(
    owner: &str,
    preexisting: &BTreeMap<String, String>,
    installer_added: &BTreeMap<String, String>,
) -> CheckpointData {
    Map::from_iter([
        ("installer_added".into(), json!(installer_added)),
        ("owner".into(), json!(owner)),
        ("ownership".into(), json!({})),
        ("preexisting".into(), json!(preexisting)),
    ])
}

type PackageCheckpoint = (BTreeMap<String, String>, BTreeMap<String, String>);

fn checkpoint_packages(checkpoint: &CheckpointData, packages: &[String]) -> Result<PackageCheckpoint, Error> {
    const KEYS: [&str; 4] = ["installer_added", "owner", "ownership", "preexisting"];
    if checkpoint.len() != KEYS.len()
        || KEYS.iter().any(|key| !checkpoint.contains_key(*key))
        || checkpoint["owner"] != OWNER
        || checkpoint["ownership"] != json!({})
    {
        return Err(package_error("package checkpoint is invalid"));
    }
    let preexisting = version_mapping(&checkpoint["preexisting"], packages)?;
    let installer_added = version_mapping(&checkpoint["installer_added"], packages)?;
    if preexisting.keys().any(|package| installer_added.contains_key(package)) {
        return Err(package_error("package checkpoint is invalid"));
    }
    Ok((preexisting, installer_added))
}

fn version_mapping(value: &Value, packages: &[String]) -> Result<BTreeMap<String, String>, Error> {
    let Some(mapping) = value.as_object() else {
        return Err(package_error("package checkpoint is invalid"));
    };
    let selected: BTreeSet<&str> = packages.iter().map(String::as_str).collect();
    let mut parsed = BTreeMap::new();
    for (package, version) in mapping {
        let Some(version) = version.as_str() else {
            return Err(package_error("package checkpoint is invalid"));
        };
        if !selected.contains(package.as_str()) || !valid_version(version) {
            return Err(package_error("package checkpoint is invalid"));
        }
        parsed.insert(package.clone(), version.to_string());
    }
    Ok(parsed)
}

fn assert_preexisting_unchanged(
    expected: &BTreeMap<String, String>,
    current: &BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    if expected.iter().any(|(package, version)| current[package].as_ref() != Some(version)) {
        return Err(package_error("pre-existing package status changed"));
    }
    Ok(())
}

fn assert_added_unchanged(
    expected: &BTreeMap<String, String>,
    current: &BTreeMap<String, Option<String>>,
    allow_absent: bool,
) -> Result<(), Error> {
    for (package, version) in expected {
        let observed = &current[package];
        if allow_absent && observed.is_none() {
            continue;
        }
        if observed.as_ref() != Some(version) {
            return Err(package_error("installer-owned package version drift"));
        }
    }
    Ok(())
}

/// Python `str.splitlines()` without a trailing empty item (the status protocol is text, not a
/// Rust `lines()` iterator: form feeds and Unicode line separators are separators too).
fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if !is_line_break(ch) {
            continue;
        }
        lines.push(&text[start..index]);
        if ch == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
            chars.next();
        }
        start = chars.peek().map_or(text.len(), |(next, _)| *next);
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

fn is_line_break(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use pc_host::runner::{CallKind, RecordingRunner, Reply};

    use super::*;
    use crate::journal::Status;
    use crate::testkit::{engine_for, plan_with, TempDir};

    fn config() -> InstallerConfig {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core.toml");
        installer_core::config::load_config(&path).unwrap()
    }

    fn apt_runner(installed: BTreeMap<String, String>) -> (Arc<RecordingRunner>, Arc<Mutex<BTreeMap<String, String>>>) {
        let state = Arc::new(Mutex::new(installed));
        let responder_state = state.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let argv: Vec<&str> = call.argv.iter().map(String::as_str).collect();
            if argv.starts_with(&["dpkg-query", "--show"]) {
                let package = argv[3];
                let installed = responder_state.lock().unwrap();
                return Some(match installed.get(package) {
                    Some(version) => Reply::ok(&format!("{package}\tii \t{version}\n")),
                    None => Reply::exit(1, "", "not installed"),
                });
            }
            if argv.starts_with(&["apt-get", "install", "--yes", "--no-install-recommends", "--no-upgrade"]) {
                let mut installed = responder_state.lock().unwrap();
                for specification in &argv[5..] {
                    let (package, version) =
                        specification.split_once('=').map_or((*specification, "1.0"), |(p, v)| (p, v));
                    installed.entry(package.into()).or_insert_with(|| version.into());
                }
                return Some(Reply::ok("installed details"));
            }
            if argv.starts_with(&["apt-get", "remove", "--yes"]) || argv.starts_with(&["apt-get", "purge", "--yes"]) {
                let mut installed = responder_state.lock().unwrap();
                for package in &argv[3..] {
                    installed.remove(*package);
                }
                return Some(Reply::ok("removed details"));
            }
            panic!("unexpected command: {argv:?}")
        }));
        (runner, state)
    }

    #[test]
    fn package_status_parser_handles_installed_removed_purged_and_malformed() {
        let dir = TempDir::new("package-parser");
        let runner = Arc::new(RecordingRunner::new());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter = PackagesAdapter::with_packages(&context, &["curl"]);
        runner.reply_once(&["dpkg-query"], Reply::ok("curl\trc \t8.5.0\n"));
        assert_eq!(adapter.status("curl").unwrap(), None);
        runner.reply_once(&["dpkg-query"], Reply::ok("curl\tun \t\n"));
        assert_eq!(adapter.status("curl").unwrap(), None);
        runner.reply_once(&["dpkg-query"], Reply::ok("curl\thi \t8.5.0\n"));
        assert_eq!(adapter.status("curl").unwrap(), Some("8.5.0".into()));
        runner.reply_once(&["dpkg-query"], Reply::ok("different\tii \t8.5.0\n"));
        assert_eq!(adapter.status("curl").unwrap_err().message(), "package status response is malformed");
        runner.reply_once(&["dpkg-query"], Reply::ok("curl\tii \t\n"));
        assert!(adapter.status("curl").is_err());
    }

    #[test]
    fn real_engine_installs_repairs_and_rolls_back_only_owned_packages() {
        let dir = TempDir::new("packages-engine");
        let (runner, state) = apt_runner(BTreeMap::from([("curl".into(), "8.0".into())]));
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> = Arc::new(PackagesAdapter::with_packages(&context, &["curl", "nginx-full"]));
        let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
        assert_eq!(action.mutations, ["package=curl", "package=nginx-full"]);
        let plan = plan_with(vec![action], Map::new());
        let engine = engine_for(dir.path(), vec![adapter]);

        assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
        assert_eq!(state.lock().unwrap().get("nginx-full").map(String::as_str), Some("1.0"));
        state.lock().unwrap().remove("nginx-full");
        assert_eq!(engine.repair().unwrap().status, Status::Active);
        assert_eq!(state.lock().unwrap().get("nginx-full").map(String::as_str), Some("1.0"));
        assert!(runner.argvs().iter().any(|argv| argv.ends_with(&["nginx-full=1.0".into()])));
        assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
        assert_eq!(&*state.lock().unwrap(), &BTreeMap::from([("curl".into(), "8.0".into())]));
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.kind == CallKind::Bounded && call.timeout == Duration::from_secs(900)));
        assert!(!runner.argvs().iter().any(|argv| argv.starts_with(&["apt-get".into(), "update".into()])));
    }

    #[test]
    fn fresh_native_install_does_not_install_or_own_a_python_interpreter() {
        let dir = TempDir::new("native-packages");
        let (runner, installed) = apt_runner(BTreeMap::new());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner };
        let adapter = PackagesAdapter::new(&context);
        let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
        let checkpoint = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        assert!(!installed.lock().unwrap().contains_key("python3"));
        assert!(checkpoint["installer_added"].get("python3").is_none());
        assert!(adapter.verify(&action).unwrap().success);
    }

    #[test]
    fn legacy_package_plan_keeps_preexisting_python_during_repair_and_rollback() {
        let dir = TempDir::new("legacy-packages");
        let original = BTreeMap::from([("python3".into(), "3.12".into())]);
        let (runner, installed) = apt_runner(original.clone());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner };
        let adapter = PackagesAdapter::new(&context);
        let mut action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
        action.mutations.push("package=python3".into());
        let checkpoint = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        assert_eq!(checkpoint["preexisting"]["python3"], "3.12");
        assert!(checkpoint["installer_added"].get("python3").is_none());
        let repaired = adapter.repair(&action, checkpoint).unwrap();
        assert!(adapter.verify(&action).unwrap().success);
        adapter.rollback(&action, repaired, false, RollbackTarget::Uninstalled).unwrap();
        assert_eq!(*installed.lock().unwrap(), original);
    }

    #[test]
    fn explicit_uninstall_purge_is_the_only_package_purge() {
        let dir = TempDir::new("packages-purge");
        let (runner, _state) = apt_runner(BTreeMap::new());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter = PackagesAdapter::with_packages(&context, &["certbot", "docker.io"]);
        let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
        let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        adapter.rollback(&action, applied, true, RollbackTarget::RolledBack).unwrap();
        assert!(runner.argvs().iter().any(|argv| argv.starts_with(&["apt-get".into(), "remove".into()])));
        assert!(!runner.argvs().iter().any(|argv| argv.starts_with(&["apt-get".into(), "purge".into()])));

        let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        adapter.rollback(&action, applied, true, RollbackTarget::Uninstalled).unwrap();
        assert!(runner.argvs().iter().any(|argv| argv.starts_with(&["apt-get".into(), "purge".into()])));
    }

    #[test]
    fn interrupted_apply_and_rollback_claim_only_packages_absent_before_prepare() {
        for resume_apply in [false, true] {
            let dir = TempDir::new("packages-interrupted");
            let (runner, state) = apt_runner(BTreeMap::from([("curl".into(), "8.0".into())]));
            let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
            let adapter = PackagesAdapter::with_packages(&context, &["curl", "nginx-full"]);
            let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
            let prepared = adapter.prepare(&action).unwrap();
            adapter.apply(&action, prepared.clone()).unwrap();
            let checkpoint = if resume_apply {
                let applied = adapter.reconcile_apply(&action, prepared).unwrap();
                assert_eq!(applied["installer_added"], json!({"nginx-full": "1.0"}));
                assert_eq!(
                    runner.argvs().iter().filter(|a| a.starts_with(&["apt-get".into(), "install".into()])).count(),
                    1
                );
                applied
            } else {
                prepared
            };
            assert!(
                adapter.reconcile_rollback(&action, checkpoint, false, RollbackTarget::RolledBack).unwrap().success
            );
            assert_eq!(*state.lock().unwrap(), BTreeMap::from([("curl".into(), "8.0".into())]));
        }
    }

    #[test]
    fn package_version_drift_blocks_repair_and_rollback_without_removal() {
        for drifted in ["curl", "nginx-full"] {
            let dir = TempDir::new("packages-drift");
            let (runner, state) = apt_runner(BTreeMap::from([("curl".into(), "8.0".into())]));
            let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
            let adapter = PackagesAdapter::with_packages(&context, &["curl", "nginx-full"]);
            let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
            let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
            state.lock().unwrap().insert(drifted.into(), "operator-upgrade".into());
            let before = state.lock().unwrap().clone();
            assert!(adapter.repair(&action, applied.clone()).is_err());
            assert!(adapter.rollback(&action, applied, false, RollbackTarget::RolledBack).is_err());
            assert_eq!(*state.lock().unwrap(), before);
            assert!(!runner.argvs().iter().any(|a| a.starts_with(&["apt-get".into(), "remove".into()])));
        }
    }

    #[test]
    fn malformed_package_status_and_unbound_checkpoints_fail_before_mutation() {
        let dir = TempDir::new("packages-invalid");
        let runner = Arc::new(RecordingRunner::new());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter = PackagesAdapter::with_packages(&context, &["curl"]);
        for status in ["curl\tii \t\n", "other\tii \t1\n", "curl\tii \t1\ncurl\tii \t1\n", "curl\tzz \t1\n"] {
            runner.reply_once(&["dpkg-query"], Reply::ok(status));
            assert!(adapter.status("curl").is_err(), "{status:?}");
        }
        let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
        for invalid in [
            json!({"preexisting": {}, "installer_added": {"foreign": "1"}, "owner": OWNER, "ownership": {}}),
            json!({"preexisting": {"curl": "1"}, "installer_added": {"curl": "1"}, "owner": OWNER, "ownership": {}}),
            json!({"preexisting": [], "installer_added": {}, "owner": OWNER, "ownership": {}}),
        ] {
            assert!(adapter.apply(&action, invalid.as_object().unwrap().clone()).is_err());
        }
        assert!(!runner.argvs().iter().any(|a| a.first().is_some_and(|s| s == "apt-get")));
    }
}
