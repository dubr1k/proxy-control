//! Ported from the parsing and output parts of `tests/test_installer_cli.py`; the dispatch
//! parts (engine, wizard, audit fakes) belong to the `installer` binary.

use std::collections::BTreeMap;

use super::*;
use crate::planner::{build_plan, AuditFacts, Fact, PlanAdapter, ReleaseIdentity};

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn core_config() -> InstallerConfig {
    crate::config::load_config(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core.toml")).unwrap()
}

fn plan_for(config: &InstallerConfig) -> InstallPlan {
    let facts = AuditFacts::from_groups(
        Fact::Map(BTreeMap::from([("os".into(), Fact::Str("ubuntu".into()))])),
        Fact::Map(BTreeMap::new()),
        Fact::Map(BTreeMap::new()),
        Fact::Map(BTreeMap::new()),
        Fact::Map(BTreeMap::new()),
        Fact::Map(BTreeMap::new()),
    )
    .unwrap();
    let release =
        ReleaseIdentity::new("v0.1.0", &"c".repeat(40), &"d".repeat(64), BTreeMap::new(), BTreeMap::new()).unwrap();
    let adapters: Vec<&dyn PlanAdapter> = Vec::new();
    build_plan(config, &facts, &adapters, &release).unwrap()
}

#[test]
fn every_subcommand_parses_to_its_typed_command() {
    let parse = |items: &[&str]| parse_with(&python_parser(), &args(items), 78).unwrap();
    assert_eq!(
        parse(&["plan", "--config", "./x.toml", "--json"]),
        Args { root: "/".into(), command: Command::Plan { config: "x.toml".into(), json: true } }
    );
    assert_eq!(
        parse(&["--root", "/tmp/r/", "install", "--conf=a.toml", "--accept", "f00"]).command,
        Command::Install { config: "a.toml".into(), accept_plan: "f00".into(), json: false }
    );
    assert_eq!(parse(&["--root", "/tmp/r/", "status"]).root, PathBuf::from("/tmp/r"));
    assert_eq!(
        parse(&["wizard"]).command,
        Command::Wizard { lang: None, config_output: "proxy-control.toml".into(), json: false }
    );
    assert_eq!(
        parse(&["wizard", "--lang", "ru", "--config-o", "/etc/pc.toml"]).command,
        Command::Wizard { lang: Some("ru".into()), config_output: "/etc/pc.toml".into(), json: false }
    );
    assert_eq!(parse(&["uninstall", "--purge"]).command, Command::Uninstall { purge_data: true, json: false });
    assert_eq!(parse(&["resume", "--js"]).command, Command::Resume { json: true });
    assert_eq!(parse(&["repair"]).command, Command::Repair { json: false });
    assert_eq!(
        parse(&["report", "--config", "c.toml", "--output", "out"]).command,
        Command::Report { config: "c.toml".into(), output: "out".into(), json: false }
    );
    assert_eq!(
        parse(&["reconcile-panel-update", "--archive", "a.tgz", "--sha256", "ab"]).command,
        Command::ReconcilePanelUpdate { archive: "a.tgz".into(), sha256: "ab".into(), json: false }
    );
    assert_eq!(parse(&["plan", "--config", ""]).command, Command::Plan { config: ".".into(), json: false });
}

#[test]
fn usage_errors_exit_two_with_argparse_text() {
    let exit = parse_with(&python_parser(), &args(&["plan"]), 78).unwrap_err();
    assert_eq!(exit.status, 2);
    assert_eq!(
        exit.stderr,
        "usage: proxy-control-installer plan [-h] --config CONFIG [--json]\n\
         proxy-control-installer plan: error: the following arguments are required: --config\n"
    );
    let exit = parse_with(&python_parser(), &args(&["status", "--root", "/"]), 78).unwrap_err();
    assert!(
        exit.stderr.ends_with("proxy-control-installer: error: unrecognized arguments: --root /\n"),
        "{}",
        exit.stderr
    );
    let exit = parse_with(&python_parser(), &args(&["wizard", "--lang", "de"]), 78).unwrap_err();
    assert!(exit.stderr.ends_with(
        "error: argument --lang: invalid choice: 'de' (choose from <Locale.EN: 'en'>, <Locale.RU: 'ru'>)\n"
    ));
    let exit = parse_with(&python_parser(), &args(&["plan", "--json=1", "--config", "x"]), 78).unwrap_err();
    assert!(exit.stderr.ends_with("error: argument --json: ignored explicit argument '1'\n"), "{}", exit.stderr);
}

#[test]
fn help_exits_zero_on_stdout() {
    let exit = parse_with(&python_parser(), &args(&["status", "-h"]), 78).unwrap_err();
    assert_eq!(exit.status, 0);
    assert_eq!(
        exit.stdout,
        "usage: proxy-control-installer status [-h] [--json]\n\noptions:\n  -h, --help  show this help message and exit\n  --json\n"
    );
}

#[test]
fn the_binary_adds_verify_release_to_the_python_surface() {
    let python = python_parser();
    let rust = installer_parser();
    let names = |p: &crate::argparse::Parser| match &p.actions.last().unwrap().kind {
        crate::argparse::Kind::Subparsers(commands) => commands.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
        _ => panic!(),
    };
    let mut expected = names(&python);
    assert_eq!(expected, PYTHON_COMMANDS);
    expected.push("verify-release".into());
    assert_eq!(names(&rust), expected);
}

#[test]
fn automated_install_requires_complete_exact_digest() {
    let digest = plan_for(&core_config()).digest();
    assert_eq!(
        check_accepted_digest(&digest[..12], &digest).unwrap_err().0,
        "--accept-plan requires the complete plan digest"
    );
    assert_eq!(check_accepted_digest(&"0".repeat(64), &digest).unwrap_err().0, "accepted plan digest does not match");
    assert_eq!(
        check_accepted_digest(&digest.to_uppercase(), &digest).unwrap_err().0,
        "--accept-plan requires the complete plan digest"
    );
    check_accepted_digest(&digest, &digest).unwrap();
}

#[test]
fn interactive_confirmation_accepts_exactly_first_twelve_lowercase_hex() {
    let digest = plan_for(&core_config()).digest();
    assert!(confirmation_matches(&digest[..12], &digest));
    let upper = digest[..12].to_uppercase();
    for confirmation in ["000000000000", upper.as_str(), &digest[..11], &digest[..13]] {
        assert!(!confirmation_matches(confirmation, &digest) || confirmation == &digest[..12], "{confirmation}");
    }
}

#[test]
fn interactive_digest_rejects_surrounding_whitespace() {
    let digest = plan_for(&core_config()).digest();
    let prefix = &digest[..12];
    for raw in [format!(" {prefix}"), format!("{prefix} "), format!("\t{prefix}")] {
        assert!(!confirmation_matches(&raw, &digest));
    }
}

#[test]
fn interactive_wizard_rejects_a_plan_for_different_config() {
    let config = core_config();
    let mut other = config.clone();
    other.initial_user = "other".into();
    let plan = plan_for(&other);
    assert_eq!(
        validate_plan(&config, &plan.facts, &plan).unwrap_err().0,
        "planner returned a plan for a different configuration"
    );
    validate_plan(&other, &plan.facts, &plan).unwrap();
}

#[test]
fn toml_plan_uses_the_same_typed_config_and_canonical_plan() {
    let config = core_config();
    let plan = plan_for(&config);
    let payload: serde_json::Value = serde_json::from_str(&render_plan_json(&plan)).unwrap();
    assert_eq!(payload["config"], config.canonical_dict());
    assert_eq!(payload["digest"], plan.digest());
}

#[test]
fn status_json_is_deterministic_and_omits_legacy_payload() {
    let view = StatusView {
        schema: 1,
        status: "active".into(),
        plan_digest: "a".repeat(64),
        origin: "installer-v1".into(),
        error: Some("SafeError: password=hunter2".into()),
        checkpoints: Vec::new(),
    };
    let rendered = view.render(true);
    assert_eq!(rendered, view.render(true));
    let payload: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({
            "checkpoints": [], "error": "SafeError: password=[REDACTED]", "origin": "installer-v1",
            "plan_digest": "a".repeat(64), "schema": 1, "status": "active",
        })
    );
    assert!(!rendered.contains("hunter2"));
    assert_eq!(
        view.render(false),
        format!(
            "status: active\nplan_digest: {}\norigin: installer-v1\nerror: SafeError: password=[REDACTED]\n",
            "a".repeat(64)
        )
    );
}

#[test]
fn panel_recovery_rejects_wrong_archive_digest_before_mutation() {
    assert_eq!(
        check_archive_digest(&"0".repeat(64), b"not the approved archive").unwrap_err().0,
        "release archive SHA-256 mismatch"
    );
    assert_eq!(
        check_archive_digest("ABC", b"").unwrap_err().0,
        "release archive SHA-256 must be 64 lowercase hex digits"
    );
}

#[test]
fn the_ownership_journal_alone_marks_an_installed_host() {
    let root = std::env::temp_dir().join(format!("installer-core-installed-{}", pc_host::fs::uuid4_hex()));
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(installed_version(&root), None);
    std::fs::create_dir_all(root.join("var/lib/proxy-control")).unwrap();
    std::fs::write(root.join("var/lib/proxy-control/ownership.json"), "{}").unwrap();
    assert_eq!(installed_version(&root).as_deref(), Some(""));
    std::fs::create_dir_all(root.join("opt/mtproxy-shared443")).unwrap();
    std::fs::write(root.join("opt/mtproxy-shared443/VERSION"), "3.2.1\n").unwrap();
    assert_eq!(installed_version(&root).as_deref(), Some("3.2.1"));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn report_tells_how_amneziawg_reaches_warp() {
    let config = crate::config::load_config(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core-amneziawg.toml"),
    )
    .unwrap();
    let notes = crate::report::operator_notes(&config);
    assert!(notes.iter().any(|note| note.contains("send the whole tunnel through WARP")
        && note.contains("api.cloudflareclient.com:443")
        && note.contains("UDP 2408")));
}

#[test]
fn blocked_lines_are_bounded_and_redacted() {
    assert_eq!(blocked_line("a\u{0}b  \u{1c} token=abc"), "BLOCKED: ab token=[REDACTED]\n");
    assert_eq!(blocked_line(&"x".repeat(600)).len(), "BLOCKED: \n".len() + 500);
    assert_eq!(blocked_message("", "AuditError"), "AuditError");
    assert_eq!(render_report_written(Path::new("out/./report.json"), true), "{\"report\": \"out/report.json\"}\n");
    assert_eq!(
        render_report_written(Path::new("/r/report.json"), false),
        "Wrote the public acceptance report to /r/report.json\n"
    );
}
