//! The audits the Python recorder ran (`plans/*/audit-transcript.json`,
//! `installs/*/audit-transcript.json`): every command with its recorded output is replayed in
//! order, the resolver answers as the simulated host did, and the facts must equal the recorded
//! ones (stable groups and transient capacity) and the `audit_facts` of the recorded plan.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use installer_core::audit::{audit_host, AuditExecutor, CommandRunner, Family, Resolver};
use installer_core::config::load_config;
use pc_host::runner::{Bounded, BoundedError, BoundedOutput};
use serde_json::Value;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|err| panic!("{path:?}: {err}"))).unwrap()
}

struct Replay {
    commands: Vec<Value>,
    next: Mutex<usize>,
}

impl AuditExecutor for Replay {
    fn execute(&self, argv: &[&str], _limits: Bounded, _c_locale: bool) -> Result<BoundedOutput, BoundedError> {
        let mut next = self.next.lock().unwrap();
        let recorded = self.commands.get(*next).unwrap_or_else(|| panic!("unrecorded command {argv:?}"));
        let expected: Vec<&str> = recorded["argv"].as_array().unwrap().iter().map(|part| part.as_str().unwrap()).collect();
        assert_eq!(argv, expected.as_slice(), "command #{} differs", *next);
        *next += 1;
        Ok(BoundedOutput {
            returncode: recorded["returncode"].as_i64().unwrap() as i32,
            stdout: recorded["stdout"].as_str().unwrap().to_string(),
            stderr: recorded["stderr"].as_str().unwrap().to_string(),
        })
    }
}

struct SimResolver {
    a: Vec<String>,
    aaaa: Vec<String>,
}

impl Resolver for SimResolver {
    fn getaddrinfo(&self, _name: &str) -> Result<Vec<(Family, String)>, ()> {
        Ok(self
            .a
            .iter()
            .map(|address| (Family::Inet, address.clone()))
            .chain(self.aaaa.iter().map(|address| (Family::Inet6, address.clone())))
            .collect())
    }
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(|item| item.as_str().unwrap().to_string()).collect()
}

fn replay(transcript: &Path, config: &Path, plan: &Path) {
    let recorded = read_json(transcript);
    let config = load_config(config).unwrap();
    let executor = Replay { commands: recorded["commands"].as_array().unwrap().clone(), next: Mutex::new(0) };
    let resolver = SimResolver { a: strings(&recorded["resolver"]["a"]), aaaa: strings(&recorded["resolver"]["aaaa"]) };
    let runner = CommandRunner::new(&executor, &resolver).with_environment(&[]);
    let audit = audit_host(&config, &runner).unwrap_or_else(|err| panic!("{transcript:?}: {err}"));
    assert_eq!(*executor.next.lock().unwrap(), executor.commands.len(), "{transcript:?}: commands left over");
    let mut expected = recorded["facts"].clone();
    let transient = expected.as_object_mut().unwrap().remove("transient").unwrap();
    assert_eq!(audit.facts.stable_dict(), expected, "{transcript:?}");
    assert_eq!(Value::Object(audit.facts.transient.clone()), transient, "{transcript:?}");
    let plan = read_json(plan);
    assert_eq!(audit.facts.stable_dict(), plan["audit_facts"], "{transcript:?} vs its plan");
}

fn config_of(name: &str) -> PathBuf {
    let index = read_json(&golden().join("plans/index.json"));
    let relative = index["plans"][name]["config"].as_str().unwrap().to_string();
    let base = if relative.starts_with("plans/") { golden() } else { Path::new(env!("CARGO_MANIFEST_DIR")).join("..") };
    base.join(relative)
}

#[test]
fn recorded_plan_audits_are_reproduced() {
    let index = read_json(&golden().join("plans/index.json"));
    let names: Vec<&String> = index["plans"].as_object().unwrap().keys().collect();
    assert_eq!(names.len(), 10);
    for name in names {
        let base = golden().join("plans").join(name);
        replay(&base.join("audit-transcript.json"), &config_of(name), &base.join("plan.json"));
    }
}

#[test]
fn recorded_install_audits_are_reproduced() {
    let mut count = 0;
    for entry in std::fs::read_dir(golden().join("installs")).unwrap() {
        let base = entry.unwrap().path();
        let name = base.file_name().unwrap().to_str().unwrap().to_string();
        replay(&base.join("audit-transcript.json"), &config_of(&name), &base.join("journal/plan.json"));
        count += 1;
    }
    assert_eq!(count, 9);
}
