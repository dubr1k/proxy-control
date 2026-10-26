//! `status`, `install --json` and `report` outputs recorded from Python after each golden
//! install (`tests/fixtures/host-golden/installs/<name>/`), rebuilt from the journal.

use std::path::{Path, PathBuf};

use installer_core::cli::{render_report_written, StatusView};
use installer_core::config::load_config;
use installer_core::report::{
    evidence_from_checkpoint, operator_notes, AcceptanceReport, CredentialHandoff, ReportWriter,
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

fn json(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).unwrap()
}

fn installs() -> Vec<(String, PathBuf)> {
    let index = json(&golden().join("plans/index.json"));
    let mut out = Vec::new();
    for (name, entry) in index["plans"].as_object().unwrap() {
        let directory = golden().join("installs").join(name);
        if !directory.exists() {
            continue;
        }
        let config = entry["config"].as_str().unwrap();
        let config = if config.starts_with("plans/") { golden().join(config) } else { repo().join(config) };
        out.push((name.clone(), config));
    }
    out
}

#[test]
fn status_outputs_match_python() {
    let all = installs();
    assert_eq!(all.len(), 9);
    for (name, _) in all {
        let directory = golden().join("installs").join(&name);
        let state = json(&directory.join("journal/state.json"));
        let view = StatusView::from_state(&state).unwrap();
        assert_eq!(view.render(true).as_bytes(), &read(&directory.join("status.json"))[..], "{name}");
        assert_eq!(view.render(false).as_bytes(), &read(&directory.join("status.txt"))[..], "{name}");
        assert_eq!(view.render(true).as_bytes(), &read(&directory.join("install-stdout.json"))[..], "{name}");
    }
    for journal in ["rolled-back", "repaired", "uninstalled", "uninstalled-purged"] {
        let state = json(&golden().join("journals").join(journal).join("state.json"));
        let view = StatusView::from_state(&state).unwrap();
        let rendered: Value = serde_json::from_str(&view.render(true)).unwrap();
        assert_eq!(rendered["status"], state["status"], "{journal}");
        assert!(rendered.get("transaction_id").is_none() && rendered.get("accepted_digest").is_none());
    }
}

#[test]
fn reports_match_python() {
    for (name, config_path) in installs() {
        let directory = golden().join("installs").join(&name);
        let state = json(&directory.join("journal/state.json"));
        let plan = json(&directory.join("journal/plan.json"));
        let mut config = load_config(&config_path).unwrap();
        if let Some(awg) = config.amneziawg.as_mut() {
            // `report` resolves unassigned ports from the installed overlay; the journal's plan
            // carries the same resolved ports.
            awg.ports = plan["config"]["amneziawg"]["ports"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_u64().unwrap() as u16)
                .collect();
        }
        let mut evidence = Vec::new();
        for checkpoint in state["checkpoints"].as_array().unwrap() {
            if let Some(item) =
                evidence_from_checkpoint(checkpoint["action_id"].as_str().unwrap(), &checkpoint["evidence"]).unwrap()
            {
                evidence.push(item);
            }
        }
        // Python passed the transaction origin as the release tag (fixed in Rust: callers pass
        // the plan's tag); the writer itself is byte-identical.
        let report = AcceptanceReport::from_evidence(
            config.profile.value(),
            state["origin"].as_str().unwrap(),
            state["plan_digest"].as_str().unwrap(),
            &evidence,
            operator_notes(&config),
        );
        let output = std::env::temp_dir().join(format!("installer-core-report-{name}-{}", std::process::id()));
        let writer = ReportWriter::new(&output);
        let path = writer.write_public(&report).unwrap();
        assert_eq!(read(&path), read(&directory.join("report/report.json")), "{name}");
        let handoff = directory.join("report/credentials/handoff.json");
        if handoff.exists() {
            let document = json(&handoff);
            let entries = document["credentials"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let written = writer.write_credentials(&CredentialHandoff::new(entries).unwrap()).unwrap();
            assert_eq!(read(&written), read(&handoff), "{name}");
        }
        let stdout = render_report_written(&output.join("report.json"), true)
            .replace(&output.to_string_lossy().to_string(), "<output>");
        assert_eq!(stdout.as_bytes(), &read(&directory.join("report/stdout.json"))[..], "{name}");
        std::fs::remove_dir_all(&output).unwrap();
    }
}
