//! Plans recorded from Python (`tests/fixtures/host-golden/plans/`, `installs/*/journal/`,
//! `journals/**`): every `plan.json` is read back and re-rendered byte for byte with the same
//! digest, and every recorded plan is rebuilt from its TOML, its audit facts, the release
//! identity and the adapters' actions — bytes, digest, intent digest, `plan --json` and the text
//! output all equal.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use installer_core::awg_ports::resolve_awg_ports;
use installer_core::cli::{plan_summary_lines, render_plan_json, render_plan_text, validate_plan};
use installer_core::config::load_config;
use installer_core::model::InstallerConfig;
use installer_core::planner::{
    adapter_requires, adapters_for, build_plan, Action, AuditFacts, InstallPlan, PlanAdapter, PlanError,
    ReleaseIdentity,
};
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn golden() -> PathBuf {
    repo().join("tests/fixtures/host-golden")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn every_plan_json(directory: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            every_plan_json(&path, out);
        } else if path.file_name().is_some_and(|n| n == "plan.json") {
            out.push(path);
        }
    }
}

#[test]
fn every_python_written_plan_reads_back_byte_identical() {
    let mut plans = Vec::new();
    every_plan_json(&golden(), &mut plans);
    assert!(plans.len() >= 29, "found {}", plans.len());
    for path in plans {
        let bytes = read(&path);
        let plan = InstallPlan::from_json(&bytes).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        assert_eq!(plan.to_canonical_json().as_bytes(), &bytes[..], "{}", path.display());
        let state = path.with_file_name("state.json");
        if state.exists() {
            let state: Value = serde_json::from_slice(&read(&state)).unwrap();
            assert_eq!(plan.digest(), state["plan_digest"], "{}", path.display());
        }
    }
}

/// An adapter that plans exactly the actions the Python adapter planned.
struct Recorded {
    name: &'static str,
    actions: Vec<Action>,
}

impl PlanAdapter for Recorded {
    fn name(&self) -> &str {
        self.name
    }

    fn requires(&self) -> Vec<String> {
        adapter_requires(self.name).iter().map(|r| r.to_string()).collect()
    }

    fn plan(&self, _config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, PlanError> {
        Ok(self.actions.clone())
    }
}

#[test]
fn every_recorded_plan_is_rebuilt_from_its_inputs() {
    let index: Value = serde_json::from_slice(&read(&golden().join("plans/index.json"))).unwrap();
    let machine_id = index["host"]["machine_id"].as_str().unwrap();
    let tree_identity =
        pc_host::archive::ReleaseIdentity::from_bytes(&read(&golden().join("plans/release.json"))).unwrap();
    let release = ReleaseIdentity::from_tree(&tree_identity).unwrap();
    let empty_root = std::env::temp_dir().join(format!("installer-core-plans-{}", std::process::id()));
    std::fs::create_dir_all(&empty_root).unwrap();
    let plans = index["plans"].as_object().unwrap();
    assert_eq!(plans.len(), 10);
    for (name, entry) in plans {
        let directory = golden().join("plans").join(name);
        let bytes = read(&directory.join("plan.json"));
        let recorded = InstallPlan::from_json(&bytes).unwrap();
        let config_path = entry["config"].as_str().unwrap();
        let config_path =
            if config_path.starts_with("plans/") { golden().join(config_path) } else { repo().join(config_path) };
        let config = load_config(&config_path).unwrap();
        let config =
            resolve_awg_ports(&config, &empty_root, Some(&recorded.facts.listeners), Some(machine_id)).unwrap();
        assert_eq!(config.canonical_dict(), recorded.config, "{name}: canonical config");

        let names = adapters_for(&config).unwrap();
        assert_eq!(names, recorded.adapter_order, "{name}: adapter order");
        let adapters: Vec<Recorded> = names
            .iter()
            .map(|adapter| Recorded {
                name: adapter,
                actions: recorded.actions.iter().filter(|a| a.adapter == *adapter).cloned().collect(),
            })
            .collect();
        let refs: Vec<&dyn PlanAdapter> = adapters.iter().map(|a| a as &dyn PlanAdapter).collect();
        let plan = build_plan(&config, &recorded.facts, &refs, &release).unwrap();
        assert_eq!(plan.to_canonical_json().as_bytes(), &bytes[..], "{name}: plan bytes");

        let digest = String::from_utf8(read(&directory.join("digest"))).unwrap();
        assert_eq!(format!("{}\n", plan.digest()), digest, "{name}: digest");
        assert_eq!(plan.digest(), entry["digest"].as_str().unwrap());
        let digests: Value = serde_json::from_slice(&read(&directory.join("digests.json"))).unwrap();
        assert_eq!(plan.digest(), digests["plan_digest"]);
        assert_eq!(plan.digest(), digests["sha256_of_plan_json"]);
        assert_eq!(plan.intent_digest(), digests["intent_digest"], "{name}: intent digest");

        assert_eq!(
            render_plan_json(&plan).as_bytes(),
            &read(&directory.join("plan-cli.json"))[..],
            "{name}: plan --json"
        );
        assert_eq!(render_plan_text(&plan).as_bytes(), &read(&directory.join("plan-cli.txt"))[..], "{name}: plan text");
        let actions: Vec<&str> = plan.actions.iter().map(|a| a.id.as_str()).collect();
        let expected: Vec<&str> = entry["actions"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        assert_eq!(actions, expected);
        validate_plan(&config, &recorded.facts, &plan).unwrap();
        assert_eq!(plan_summary_lines(&plan).len(), 2 + 2 * plan.actions.len());
    }
    std::fs::remove_dir_all(&empty_root).unwrap();
}

#[test]
fn a_changed_fact_or_action_changes_the_digest() {
    let bytes = read(&golden().join("plans/core/plan.json"));
    let plan = InstallPlan::from_json(&bytes).unwrap();
    let mut changed = plan.clone();
    changed.facts.platform.insert("os".into(), Value::String("freebsd".into()));
    assert_ne!(changed.digest(), plan.digest());
    assert_eq!(plan.assert_fresh(&changed.facts).unwrap_err().message(), "platform facts changed");
    let mut reordered = plan.clone();
    reordered.actions.swap(0, 1);
    assert_ne!(reordered.digest(), plan.digest());
    let mut dependencies = BTreeMap::new();
    dependencies.insert("packages".to_string(), vec!["nginx".to_string()]);
    let mut other = plan.clone();
    other.adapter_dependencies.extend(dependencies);
    assert_ne!(other.digest(), plan.digest());
}
