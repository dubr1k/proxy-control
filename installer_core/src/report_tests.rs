//! Ported from `tests/test_installer_reports.py`.

use std::os::unix::fs::PermissionsExt;

use super::*;

const PANEL_PASSWORD: &str = "operator-panel-password";
const MANAGER_TOKEN: &str = "0123456789abcdef0123456789abcdef";
const CLIENT_UUID: &str = "6f2c1d4e-6a2b-4c8f-9f0d-2a7b5c8e1d33";

fn fact_map(value: Value) -> Fact {
    Fact::from(value)
}

fn report_with_evidence() -> AcceptanceReport {
    AcceptanceReport::from_evidence(
        "full",
        "v2.0.0",
        &"a".repeat(64),
        &[
            Evidence::new(
                "core.runtime",
                true,
                vec!["Core acceptance passed".into()],
                fact_map(json!({
                    "healthy_services": 3, "expected_services": 3, "panel_login_ok": true,
                    "respq_verified": 2, "respq_expected": 2, "operator_handoff": PANEL_PASSWORD,
                })),
            )
            .unwrap(),
            Evidence::new(
                "naive.runtime",
                true,
                vec!["Naive acceptance passed".into()],
                fact_map(json!({
                    "connect_bytes": 4096, "recorded_bytes": 8192, "certificate_sans": ["naive.example.com"],
                    "listener_owner": "nginx", "response_status": 204,
                })),
            )
            .unwrap(),
        ],
        vec!["verify the cloud firewall allows UDP/443".into()],
    )
}

fn handoff_with_secrets() -> CredentialHandoff {
    CredentialHandoff::new(BTreeMap::from([
        ("panel_owner_password".into(), PANEL_PASSWORD.into()),
        ("naive_manager_token".into(), MANAGER_TOKEN.into()),
        ("three_xui_client_id".into(), CLIENT_UUID.into()),
    ]))
    .unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "installer-core-{label}-{}-{}",
            std::process::id(),
            pc_host::fs::uuid4_hex()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn public_values(root: &Path) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    out.push(key.clone());
                    walk(item, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            Value::String(text) => out.push(text.clone()),
            other => out.push(other.to_string()),
        }
    }
    let document: Value = serde_json::from_slice(&std::fs::read(root.join("report.json")).unwrap()).unwrap();
    let mut out = Vec::new();
    walk(&document, &mut out);
    out
}

#[test]
fn public_report_and_credential_handoff_are_schema_disjoint() {
    let dir = TempDir::new("reports");
    let writer = ReportWriter::new(&dir.0);
    writer.write_public(&report_with_evidence()).unwrap();
    writer.write_credentials(&handoff_with_secrets()).unwrap();
    let values = public_values(&dir.0);
    for secret in [PANEL_PASSWORD, MANAGER_TOKEN, CLIENT_UUID] {
        assert!(!values.iter().any(|v| v == secret));
    }
    assert_eq!(mode(&dir.0.join("credentials/handoff.json")), 0o600);
}

#[test]
fn public_report_is_world_readable_and_the_handoff_directory_is_not() {
    let dir = TempDir::new("reports");
    let writer = ReportWriter::new(&dir.0);
    writer.write_public(&report_with_evidence()).unwrap();
    writer.write_credentials(&handoff_with_secrets()).unwrap();
    assert_eq!(mode(&dir.0.join("report.json")), 0o644);
    assert_eq!(mode(&dir.0.join("credentials")), 0o700);
}

#[test]
fn public_report_keeps_only_named_acceptance_facts() {
    let dir = TempDir::new("reports");
    ReportWriter::new(&dir.0).write_public(&report_with_evidence()).unwrap();
    let document: Value = serde_json::from_slice(&std::fs::read(dir.0.join("report.json")).unwrap()).unwrap();
    let action =
        |id: &str| document["actions"].as_array().unwrap().iter().find(|a| a["action_id"] == id).unwrap().clone();
    assert_eq!(
        action("core.runtime")["facts"],
        json!({"expected_services": 3, "healthy_services": 3, "panel_login_ok": true, "respq_expected": 2, "respq_verified": 2})
    );
    assert_eq!(action("naive.runtime")["facts"]["certificate_sans"], json!(["naive.example.com"]));
    assert_eq!(action("naive.runtime")["facts"]["response_status"], json!(204));
    assert_eq!(document["release"], json!({"digest": "a".repeat(64), "tag": "v2.0.0"}));
}

#[test]
fn public_report_refuses_to_name_a_credential() {
    let report = AcceptanceReport::new(
        "core",
        "v2.0.0",
        &"a".repeat(64),
        vec!["the panel password is stored in the handoff".into()],
    );
    assert_eq!(
        report.public_document().unwrap_err().0,
        "public report must not describe a credential at report.operator_notes[0]"
    );
}

#[test]
fn credential_handoff_requires_named_string_entries() {
    let err = CredentialHandoff::new(BTreeMap::from([("panel_owner_password".into(), String::new())])).unwrap_err();
    assert!(err.0.contains("named strings"));
}

#[test]
fn reports_can_be_rewritten_in_place() {
    let dir = TempDir::new("reports");
    let writer = ReportWriter::new(&dir.0);
    writer.write_public(&report_with_evidence()).unwrap();
    writer.write_credentials(&handoff_with_secrets()).unwrap();
    writer.write_public(&report_with_evidence()).unwrap();
    writer
        .write_credentials(&CredentialHandoff::new(BTreeMap::from([("panel".into(), "second".into())])).unwrap())
        .unwrap();
    let handoff: Value =
        serde_json::from_slice(&std::fs::read(dir.0.join("credentials/handoff.json")).unwrap()).unwrap();
    assert_eq!(handoff["credentials"], json!({"panel": "second"}));
    assert_eq!(mode(&dir.0.join("credentials/handoff.json")), 0o600);
}

#[test]
fn evidence_from_a_checkpoint_keeps_python_defaults() {
    let evidence = evidence_from_checkpoint("core.runtime", &json!({"success": 1, "details": [1]})).unwrap().unwrap();
    assert!(evidence.success);
    assert_eq!(evidence.observations, vec!["no observation was recorded"]);
    assert!(evidence.details.is_empty());
    assert_eq!(evidence_from_checkpoint("x", &json!(null)).unwrap(), None);
}
