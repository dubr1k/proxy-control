//! Replay every Python-recorded wizard transcript in both languages. The input, exact terminal
//! bytes, exit status, saved TOML/credentials and plan/apply boundaries must all match.

use std::path::{Path, PathBuf};

use installer_core::cli::StatusView;
use installer_core::credentials::{read_credentials, staged_credentials};
use installer_core::i18n::Locale;
use installer_core::model::InstallerConfig;
use installer_core::planner::{AuditFacts, InstallPlan};
use installer_core::wizard::{run_wizard_command, EngineError, TerminalIO, WizardCommand, WizardEngine};
use serde_json::Value;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/wizard")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|err| panic!("{path:?}: {err}"))).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("installer-wizard-golden-{}-{name}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ReplayEngine {
    root: PathBuf,
    initial: Result<AuditFacts, EngineError>,
    initial_calls: usize,
    plan: Option<InstallPlan>,
    plan_calls: usize,
    apply_calls: usize,
    staged: Option<installer_core::credentials::OperatorCredentials>,
    apply_error: Option<EngineError>,
}

impl WizardEngine for ReplayEngine {
    fn initial_facts(&mut self) -> Result<AuditFacts, EngineError> {
        self.initial_calls += 1;
        self.initial.clone()
    }

    fn plan(&mut self, config: &InstallerConfig) -> Result<InstallPlan, EngineError> {
        self.plan_calls += 1;
        let plan = self.plan.clone().expect("the recorded transcript has no planning step");
        assert_eq!(plan.config, config.canonical_dict(), "the wizard built a different configuration");
        Ok(plan)
    }

    fn apply(&mut self, plan: &InstallPlan) -> Result<StatusView, EngineError> {
        self.apply_calls += 1;
        self.staged = staged_credentials(&self.root).map_err(|err| EngineError::Blocked(err.0))?;
        if let Some(error) = &self.apply_error {
            return Err(error.clone());
        }
        Ok(StatusView {
            schema: 1,
            status: "active".into(),
            plan_digest: plan.digest(),
            origin: "installer-v1".into(),
            error: None,
            checkpoints: Vec::new(),
        })
    }
}

fn replay(locale: &str, name: &str) {
    let base = golden().join(locale);
    let recorded = read_json(&base.join(format!("{name}.json")));
    let work = TempDir::new(&format!("{locale}-{name}"));
    let root = work.0.join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/machine-id"), "0123456789abcdef0123456789abcdef\n").unwrap();
    if name.starts_with("already-installed") {
        let version = root.join("opt/mtproxy-shared443");
        std::fs::create_dir_all(&version).unwrap();
        std::fs::write(version.join("VERSION"), "3.2.1\n").unwrap();
    }
    let output = work.0.join("proxy-control.toml");
    let argv = recorded["argv"].as_array().unwrap().iter().filter_map(Value::as_str).collect::<Vec<_>>();
    let lang = argv.windows(2).find_map(|parts| {
        (parts == ["--lang", locale]).then_some(match locale {
            "ru" => Locale::Ru,
            _ => Locale::En,
        })
    });
    let environment = &recorded["environment"];
    let environment_locale = environment
        .get("LC_ALL")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| environment.get("LANG").and_then(Value::as_str))
        .map(str::to_string);
    let plan_path = base.join(format!("{name}.plan.json"));
    let plan = if plan_path.exists() {
        Some(InstallPlan::from_json(&std::fs::read(&plan_path).unwrap()).unwrap())
    } else {
        recorded.get("_plan").and_then(Value::as_str).map(|text| InstallPlan::from_json(text.as_bytes()).unwrap())
    };
    let expects_plan = plan.is_some();
    let mut engine = ReplayEngine {
        root: root.clone(),
        initial: Ok(AuditFacts::default()),
        initial_calls: 0,
        plan,
        plan_calls: 0,
        apply_calls: 0,
        staged: None,
        apply_error: None,
    };
    let input = recorded["stdin"].as_str().unwrap().as_bytes().to_vec();
    let mut io = TerminalIO::new(std::io::Cursor::new(input), Vec::new());
    let mut stderr = Vec::new();
    let code = run_wizard_command(
        &mut io,
        &mut stderr,
        &WizardCommand {
            root,
            lang,
            config_output: output.clone(),
            json: argv.contains(&"--json"),
            environment_locale,
            xray_version: "26.10.17".into(),
        },
        &mut engine,
    );
    let shown_work = work.0.to_string_lossy().into_owned();
    let expected = |key: &str| recorded[key].as_str().unwrap().replace("<work>", &shown_work);
    assert_eq!(code, recorded["exit"].as_i64().unwrap() as i32, "{locale}/{name}: exit");
    assert_eq!(String::from_utf8(io.into_output()).unwrap(), expected("stdout"), "{locale}/{name}: stdout");
    assert_eq!(String::from_utf8(stderr).unwrap(), expected("stderr"), "{locale}/{name}: stderr");
    assert_eq!(engine.initial_calls, 1, "{locale}/{name}: preliminary audit calls");
    assert_eq!(engine.plan_calls, usize::from(expects_plan), "{locale}/{name}: plan calls");
    assert_eq!(
        engine.apply_calls,
        usize::from(recorded.get("installed_status").is_some()),
        "{locale}/{name}: apply calls"
    );
    if recorded.get("installed_status").is_some() {
        assert!(engine.staged.is_none(), "{locale}/{name}: this scenario leaves credentials generated");
    }
    match recorded.get("config_output") {
        Some(expected) => {
            assert_eq!(std::fs::read_to_string(&output).unwrap(), expected.as_str().unwrap(), "{locale}/{name}: TOML")
        }
        None => assert!(!output.exists(), "{locale}/{name}: unexpected TOML"),
    }
    let credentials = installer_core::credentials::credentials_path(&output).unwrap();
    match recorded.get("credentials_output_keys") {
        Some(expected) => {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                format!("{:04o}", std::fs::metadata(&credentials).unwrap().permissions().mode() & 0o777),
                recorded["credentials_output_mode"].as_str().unwrap()
            );
            let parsed = read_credentials(&output).unwrap().unwrap();
            let mut keys = Vec::new();
            if parsed.panel_username.is_some() {
                keys.push("panel_username");
            }
            if parsed.panel_password.is_some() {
                keys.push("panel_password");
            }
            if parsed.three_xui_username.is_some() {
                keys.push("three_xui_username");
            }
            if parsed.three_xui_password.is_some() {
                keys.push("three_xui_password");
            }
            keys.sort_unstable();
            assert_eq!(
                keys,
                expected.as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect::<Vec<_>>()
            );
        }
        None => assert!(!credentials.exists(), "{locale}/{name}: unexpected credentials"),
    }
}

#[test]
fn python_wizard_transcripts_are_reproduced() {
    let mut count = 0;
    for locale in ["en", "ru"] {
        let mut names = std::fs::read_dir(golden().join(locale))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .strip_suffix(".json")
                    .is_some_and(|name| !name.ends_with(".plan"))
            })
            .collect::<Vec<_>>();
        names.sort();
        for path in names {
            let name = path.file_name().unwrap().to_str().unwrap().strip_suffix(".json").unwrap();
            replay(locale, name);
            count += 1;
        }
    }
    assert_eq!(count, 18);
}

#[test]
fn python_i18n_catalogue_is_reproduced_exactly() {
    let recorded = read_json(&golden().join("i18n-catalogue.json"));
    for (name, locale) in [("en", Locale::En), ("ru", Locale::Ru)] {
        let expected = recorded[name].as_object().unwrap();
        assert_eq!(expected.len(), 115);
        assert_eq!(installer_core::i18n::catalog(locale).len(), expected.len());
        for (key, message) in installer_core::i18n::catalog(locale) {
            assert_eq!(*message, expected[*key].as_str().unwrap(), "{name}/{key}");
        }
    }
}

#[test]
fn passwords_typed_in_the_wizard_reach_the_adapters_on_its_own_apply() {
    let work = TempDir::new("typed-apply");
    let root = work.0.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let plan =
        InstallPlan::from_json(&std::fs::read(golden().join("en/core-apply-install.plan.json")).unwrap()).unwrap();
    let digest = plan.digest();
    let answers = format!(
        "\ncore\n\npanel.example.com\nrelay.example.com\n\n\nn\nn\nadmin@example.com\nowner\ncorrect-horse-battery\ncorrect-horse-battery\n\napply\n{}\n",
        &digest[..12]
    );
    let mut engine = ReplayEngine {
        root: root.clone(),
        initial: Ok(AuditFacts::default()),
        initial_calls: 0,
        plan: Some(plan),
        plan_calls: 0,
        apply_calls: 0,
        staged: None,
        apply_error: None,
    };
    let mut io = TerminalIO::new(std::io::Cursor::new(answers.into_bytes()), Vec::new());
    let mut stderr = Vec::new();
    let code = run_wizard_command(
        &mut io,
        &mut stderr,
        &WizardCommand {
            root: root.clone(),
            lang: Some(Locale::En),
            config_output: work.0.join("unused.toml"),
            json: false,
            environment_locale: None,
            xray_version: "26.10.17".into(),
        },
        &mut engine,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(engine.apply_calls, 1);
    let staged = engine.staged.unwrap();
    assert_eq!(staged.panel_username.as_deref(), Some("owner"));
    assert_eq!(staged.panel_password.as_deref(), Some("correct-horse-battery"));
    assert!(!installer_core::credentials::staged_path(&root).unwrap().exists());
}

fn command(root: &Path) -> WizardCommand {
    WizardCommand {
        root: root.to_path_buf(),
        lang: Some(Locale::En),
        config_output: root.join("saved.toml"),
        json: false,
        environment_locale: None,
        xray_version: "26.10.17".into(),
    }
}

fn engine(root: &Path, facts: AuditFacts) -> ReplayEngine {
    ReplayEngine {
        root: root.to_path_buf(),
        initial: Ok(facts),
        initial_calls: 0,
        plan: None,
        plan_calls: 0,
        apply_calls: 0,
        staged: None,
        apply_error: None,
    }
}

#[test]
fn preliminary_audit_ownership_is_preserved_and_local_version_takes_precedence() {
    let work = TempDir::new("preliminary-ownership");
    for local_version in [None, Some("4.0.0")] {
        if let Some(version) = local_version {
            std::fs::create_dir_all(work.0.join("opt/mtproxy-shared443")).unwrap();
            std::fs::write(work.0.join("opt/mtproxy-shared443/VERSION"), version).unwrap();
        }
        let mut facts = AuditFacts::default();
        facts.ownership.insert("installed".into(), serde_json::json!({"version": "3.2.1"}));
        let mut engine = engine(&work.0, facts);
        let mut io = TerminalIO::new(std::io::Cursor::new(b"\n"), Vec::new());
        let mut stderr = Vec::new();
        assert_eq!(run_wizard_command(&mut io, &mut stderr, &command(&work.0), &mut engine), 0);
        let transcript = String::from_utf8(io.into_output()).unwrap();
        assert!(
            transcript.contains(&format!("Proxy Control {} is already installed", local_version.unwrap_or("3.2.1")))
        );
        assert!(transcript.contains("No changes were made."));
        assert!(stderr.is_empty());
        assert_eq!((engine.initial_calls, engine.plan_calls, engine.apply_calls), (1, 0, 0));
    }
}

#[test]
fn preliminary_audit_listeners_are_used_for_wizard_port_defaults() {
    let work = TempDir::new("preliminary-listeners");
    std::fs::create_dir_all(work.0.join("etc")).unwrap();
    std::fs::write(work.0.join("etc/machine-id"), "wizard-host\n").unwrap();
    let occupied = installer_core::awg_ports::derive_port("wizard-host", "1.5", 0);
    let mut facts = AuditFacts::default();
    facts.listeners.insert("tcp".into(), serde_json::json!([occupied]));
    let mut engine = engine(&work.0, facts);
    let answers = "fresh\ncore\nnone\npanel.example.com\nrelay.example.com\n\n\nyes\n1.5\n\n\nno\nadmin@example.com\nowner\n\nyes\nsave\n";
    let mut io = TerminalIO::new(std::io::Cursor::new(answers), Vec::new());
    let mut stderr = Vec::new();
    let cmd = command(&work.0);
    assert_eq!(run_wizard_command(&mut io, &mut stderr, &cmd, &mut engine), 0);
    assert!(stderr.is_empty());
    let saved = installer_core::config::load_config(&cmd.config_output).unwrap();
    let ports = saved.amneziawg.unwrap().ports;
    assert_eq!(ports.len(), 1);
    assert_ne!(ports[0], occupied);
    assert_eq!((engine.initial_calls, engine.plan_calls, engine.apply_calls), (1, 0, 0));
}

#[test]
fn preliminary_audit_errors_stop_before_questions() {
    let work = TempDir::new("preliminary-error");
    for (error, status, expected) in [
        (EngineError::Blocked("password=secret-value".into()), 2, "BLOCKED: password=[REDACTED]\n"),
        (EngineError::Interrupted, 130, ""),
        (
            EngineError::Fatal { class: "SystemExit".into(), message: "unsafe process state".into() },
            1,
            "unsafe process state\n",
        ),
    ] {
        let mut engine = engine(&work.0, AuditFacts::default());
        engine.initial = Err(error);
        let mut io = TerminalIO::new(std::io::Cursor::new(b""), Vec::new());
        let mut stderr = Vec::new();
        assert_eq!(run_wizard_command(&mut io, &mut stderr, &command(&work.0), &mut engine), status);
        assert_eq!(stderr, expected.as_bytes());
        assert!(io.into_output().is_empty());
        assert_eq!((engine.initial_calls, engine.plan_calls, engine.apply_calls), (1, 0, 0));
    }
}

#[test]
fn typed_credentials_are_discarded_after_every_apply_error() {
    let work = TempDir::new("typed-apply-error");
    let plan =
        InstallPlan::from_json(&std::fs::read(golden().join("en/core-apply-install.plan.json")).unwrap()).unwrap();
    for (error, status) in [
        (EngineError::Blocked("apply refused".into()), 2),
        (EngineError::Interrupted, 130),
        (EngineError::Fatal { class: "SystemExit".into(), message: "unsafe process state".into() }, 1),
    ] {
        let mut engine = engine(&work.0, AuditFacts::default());
        engine.plan = Some(plan.clone());
        engine.apply_error = Some(error);
        let answers = format!(
            "\ncore\n\npanel.example.com\nrelay.example.com\n\n\nn\nn\nadmin@example.com\nowner\ncorrect-horse-battery\ncorrect-horse-battery\n\napply\n{}\n",
            &plan.digest()[..12]
        );
        let mut io = TerminalIO::new(std::io::Cursor::new(answers), Vec::new());
        let mut stderr = Vec::new();
        assert_eq!(run_wizard_command(&mut io, &mut stderr, &command(&work.0), &mut engine), status);
        assert_eq!(engine.staged.unwrap().panel_password.as_deref(), Some("correct-horse-battery"));
        assert!(!installer_core::credentials::staged_path(&work.0).unwrap().exists());
        assert_eq!(engine.apply_calls, 1);
    }
}
