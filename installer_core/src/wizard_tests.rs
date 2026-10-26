use std::path::{Path, PathBuf};

use super::*;
use crate::config::load_config;
use crate::credentials::{credentials_path, read_credentials};
use crate::model::{HostMode, Profile, ThreeXuiMode};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("installer-wizard-test-{}", pc_host::fs::uuid4_hex()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn options(output: &Path, locale: Locale, root: &Path) -> WizardOptions {
    WizardOptions {
        locale: Some(locale),
        language_fixed: false,
        config_output: output.to_path_buf(),
        root: root.to_path_buf(),
        environment_locale: None,
        xray_version: "26.10.17".into(),
    }
}

fn scripted_with_facts(
    answers: &[&str],
    output: &Path,
    locale: Locale,
    root: &Path,
    facts: &AuditFacts,
) -> (String, String, InstallerConfig) {
    let input = format!("{}\n", answers.join("\n"));
    let mut io = TerminalIO::new(std::io::Cursor::new(input.into_bytes()), Vec::new());
    let mut wizard = Wizard::new(options(output, locale, root));
    let stopped = wizard.run(&mut io, facts);
    let transcript = String::from_utf8(io.into_output()).unwrap();
    let config = match stopped {
        Err(Stop::Saved { config, .. }) => *config,
        other => panic!("wizard did not save: {other:?}\n{transcript}"),
    };
    let written = std::fs::read_to_string(output).unwrap();
    assert_eq!(load_config(output).unwrap(), config);
    (transcript, written, config)
}

fn scripted(answers: &[&str], output: &Path, locale: Locale, root: &Path) -> (String, String, InstallerConfig) {
    scripted_with_facts(answers, output, locale, root, &AuditFacts::default())
}

fn awg_root(parent: &Path) -> PathBuf {
    let root = parent.join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/machine-id"), "wizard-host\n").unwrap();
    root
}

fn core_answers<'a>(awg: &'a [&'a str]) -> Vec<&'a str> {
    let mut answers = vec!["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", ""];
    answers.extend_from_slice(awg);
    answers.extend(["", "admin@example.com", "owner", "", "yes", "save"]);
    answers
}

fn tt_answers<'a>(tt: &'a [&'a str]) -> Vec<&'a str> {
    let mut answers = vec!["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "", "no"];
    answers.extend_from_slice(tt);
    if matches!(tt.first(), Some(&"yes" | &"да")) {
        answers.push("no");
    }
    answers.extend(["admin@example.com", "owner", "", "yes", "save"]);
    answers
}

#[test]
fn russian_integer_and_generic_string_feedback_hides_validator_details() {
    let mut terminal = TerminalIO::new(std::io::Cursor::new(b"abc\n70000\n46001\nbad\nok\n".to_vec()), Vec::new());
    terminal.set_locale(Locale::Ru);
    let port = terminal.integer("Порт", 1, 65535, None).unwrap();
    let value = terminal
        .validated(
            "Значение",
            &|value| if value == "ok" { Ok(value.to_string()) } else { Err(Refusal::Generic) },
            None,
            false,
        )
        .unwrap();
    assert_eq!(port, 46001);
    assert_eq!(value, "ok");
    let transcript = String::from_utf8(terminal.into_output()).unwrap();
    assert!(transcript.contains("Введите целое число."));
    assert!(transcript.contains("Введите число от 1 до 65535."));
    assert!(transcript.contains("Введите допустимое значение."));
}

#[test]
fn mismatched_passwords_are_rejected_and_asked_again() {
    let temp = TempDir::new();
    let output = temp.join("mismatch.toml");
    let (transcript, _, _) = scripted(
        &[
            "",
            "coexist",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "first-attempt-password",
            "second-attempt-password",
            "short",
            "short",
            "settled-panel-password",
            "settled-panel-password",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(transcript.contains("не совпадают"));
    assert_eq!(read_credentials(&output).unwrap().unwrap().panel_password.as_deref(), Some("settled-panel-password"));
}

#[test]
fn typed_panel_password_is_saved_privately_and_never_in_the_config() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new();
    let output = temp.join("typed.toml");
    let (_, written, _) = scripted(
        &[
            "",
            "coexist",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "correct-horse-battery",
            "correct-horse-battery",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(!written.contains("correct-horse-battery"));
    let stored = read_credentials(&output).unwrap().unwrap();
    assert_eq!(stored.panel_username.as_deref(), Some("owner"));
    assert_eq!(stored.panel_password.as_deref(), Some("correct-horse-battery"));
    assert_eq!(std::fs::metadata(credentials_path(&output).unwrap()).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn blank_passwords_leave_no_credentials_file_behind() {
    let temp = TempDir::new();
    let output = temp.join("generated.toml");
    scripted(
        &[
            "",
            "coexist",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(!credentials_path(&output).unwrap().exists());
}

#[test]
fn warp_domains_take_geosite_lists_and_refuse_a_blank_answer() {
    let temp = TempDir::new();
    let output = temp.join("warp.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core",
            "managed-new",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "xui.example.com",
            "vless.example.com",
            "xhttp.example.com",
            "hy2.example.com",
            "yes",
            "",
            "geosite:openai, domain:Claude.AI, chatgpt.com",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "xuiadmin",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert!(transcript.contains("at least one"));
    assert_eq!(transcript.matches("Enter one or more comma-separated domains or geosite:name lists.").count(), 1);
    assert_eq!(
        config.three_xui.warp_domains.into_iter().collect::<std::collections::BTreeSet<_>>(),
        ["geosite:openai", "domain:claude.ai", "chatgpt.com"].into_iter().map(str::to_string).collect()
    );
}

#[test]
fn wizard_offers_the_router_on_a_trusttunnel_only_node() {
    let temp = TempDir::new();
    let output = temp.join("tt-router.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "yes",
            "gate.example.com",
            "yes",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(config.trusttunnel.is_some());
    assert!(config.egress.as_ref().unwrap().router);
    assert!(transcript.contains("Xray-router"));
}

#[test]
fn enter_takes_the_explained_defaults_and_the_example_mieru_ports() {
    let temp = TempDir::new();
    let output = temp.join("defaults.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "",
            "",
            "",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "edge.example.com",
            "mieru.example.com",
            "",
            "",
            "no",
            "no",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    for line in [
        "fresh   — a clean server",
        "full       — the panel, MTProxy",
        "managed-new — the installer sets up its own 3x-ui",
    ] {
        assert!(transcript.contains(line), "{line}");
    }
    assert_eq!(
        (config.host_mode, config.profile, config.three_xui.mode),
        (HostMode::Fresh, Profile::Full, ThreeXuiMode::None)
    );
    let mieru = config.mieru.unwrap();
    assert_eq!((mieru.tcp_ports, mieru.udp_ports), (vec![46001], vec![46001]));
    let review = transcript.split("Configuration review").nth(1).unwrap();
    assert!(!review.contains("| None"));
    assert!(!review.contains("3x-ui through WARP"));
    assert!(review.contains("3x-ui mode | none"));
}

#[test]
fn amneziawg_defaults_are_all_versions_and_the_panel_domain() {
    let temp = TempDir::new();
    let output = temp.join("awg.toml");
    let root = awg_root(&temp.0);
    let (_, _, config) = scripted(&core_answers(&["yes", "", "", ""]), &output, Locale::En, &root);
    let awg = config.amneziawg.unwrap();
    assert_eq!(awg.versions, vec!["1.5", "2.0", "3.1"]);
    assert_eq!(awg.host, "panel.example.com");
}

#[test]
fn wizard_offers_the_router_whenever_a_service_could_feed_it() {
    let temp = TempDir::new();
    let output = temp.join("router.toml");
    let answers = [
        "",
        "fresh",
        "full",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",
        "",
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "yes",
        "yes",
        "yes",
        "no",
        "yes",
        "",
        "",
        "admin@example.com",
        "owner",
        "",
        "yes",
        "save",
    ];
    let (transcript, written, config) = scripted(&answers, &output, Locale::Ru, &temp.0);
    assert!(
        written.contains("router = true")
            && written.contains("naive = \"router\"")
            && written.contains("mieru = \"warp\"")
    );
    assert!(transcript.contains("Xray-router") && transcript.contains("скачивается сам"));
    assert!(!transcript.contains("Направлять весь трафик NaiveProxy через WARP"));
    let egress = config.egress.unwrap();
    assert_eq!((egress.naive, egress.mieru), (EgressChoice::Router, EgressChoice::Warp));

    let without = [
        "",
        "fresh",
        "full",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",
        "",
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "yes",
        "no",
        "yes",
        "yes",
        "",
        "",
        "admin@example.com",
        "owner",
        "",
        "yes",
        "save",
    ];
    let (transcript, written, _) = scripted(&without, &output, Locale::Ru, &temp.0);
    assert!(transcript.contains("Направлять весь трафик NaiveProxy через WARP"));
    assert!(!written.contains("router"));

    let core = temp.join("core.toml");
    let (transcript, _, _) = scripted(
        &[
            "",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &core,
        Locale::Ru,
        &temp.0,
    );
    assert!(!transcript.contains("Установить Xray-router"));
}

#[test]
fn wizard_writes_an_explicit_egress_section_per_service() {
    let temp = TempDir::new();
    let output = temp.join("egress.toml");
    let (transcript, written, config) = scripted(
        &[
            "",
            "fresh",
            "full",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "edge.example.com",
            "mieru.example.com",
            "46001",
            "46001",
            "yes",
            "no",
            "no",
            "yes",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(
        written.contains("[egress]") && written.contains("naive = \"direct\"") && written.contains("mieru = \"warp\"")
    );
    assert!(transcript.contains("Направлять весь трафик NaiveProxy через WARP"));
    let egress = config.egress.unwrap();
    assert!(egress.warp);
    assert_eq!((egress.naive, egress.mieru), (EgressChoice::Direct, EgressChoice::Warp));
    assert!(config.three_xui.warp);
}

#[test]
fn existing_xui_edit_can_clear_domain_and_back_preserves_absent_domain() {
    let temp = TempDir::new();
    let output = temp.join("existing.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "coexist",
            "core",
            "existing",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "vless.example.com",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "back",
            "",
            "edit",
            "three_xui.vless_tcp_domain",
            "tcp2.example.com",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert!(transcript.contains("At least one VLESS domain is needed"));
    assert!(!transcript.contains("3x-ui panel domain") && !transcript.contains("Hysteria2 domain"));
    assert!(!transcript.split("3x-ui mode").nth(1).unwrap().split(':').next().unwrap().contains("managed-new"));
    assert_eq!(config.three_xui.vless_tcp_domain.as_deref(), Some("tcp2.example.com"));
    assert_eq!(config.three_xui.vless_xhttp_domain, None);
    assert_eq!(config.three_xui.panel_domain, None);
    assert_eq!(config.three_xui.hysteria_domain, None);
}

#[test]
fn review_edit_and_back_change_typed_fields_before_save() {
    let temp = TempDir::new();
    let output = temp.join("edited.toml");
    let (_, _, config) = scripted(
        &[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "no",
            "edit",
            "domains.panel",
            "new-panel.example.com",
            "back",
            "yes",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert_eq!(config.domains.panel, "new-panel.example.com");
    assert!(config.firewall.manage_ufw);
}

#[test]
fn invalid_configuration_says_why() {
    let temp = TempDir::new();
    let output = temp.join("conflict.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core-mieru",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "mieru.example.com",
            "8443",
            "8443",
            "no",
            "no",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "mieru.tcp_ports",
            "46001",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    let reason = transcript.split("The configuration is invalid: ").nth(1).unwrap().lines().next().unwrap();
    assert!(reason.contains("8443 is taken by the panel's private TLS listener"));
    assert_eq!(config.mieru.unwrap().tcp_ports, vec![46001]);
}

#[test]
fn wizard_offers_amneziawg_with_versions_and_a_public_name() {
    let temp = TempDir::new();
    let output = temp.join("awg.toml");
    let root = awg_root(&temp.0);
    let (transcript, written, config) =
        scripted(&core_answers(&["yes", "3.1, 1.5", "vpn.example.com", ""]), &output, Locale::En, &root);
    let awg = config.amneziawg.unwrap();
    assert_eq!(awg.versions, vec!["1.5", "3.1"]);
    assert_eq!(awg.host, "vpn.example.com");
    assert_eq!(awg.port_map().len(), 2);
    assert!(awg.ports.iter().all(|port| (10240..=32000).contains(port)));
    assert!(written.contains("[amneziawg]") && written.contains("versions = [\"1.5\", \"3.1\"]"));
    assert!(transcript.contains("Install AmneziaWG") && transcript.contains("needs no new domain"));
    assert!(transcript.split("Configuration review").nth(1).unwrap().contains("AmneziaWG: versions | 1.5,3.1"));
}

#[test]
fn declining_amneziawg_writes_no_section() {
    let temp = TempDir::new();
    let output = temp.join("no-awg.toml");
    let (transcript, written, config) = scripted(&core_answers(&["no"]), &output, Locale::En, &temp.0);
    assert!(config.amneziawg.is_none());
    assert!(!written.contains("[amneziawg]"));
    assert!(!transcript.split("Configuration review").nth(1).unwrap().contains("amneziawg."));
}

#[test]
fn amneziawg_answers_are_validated_with_localized_feedback() {
    let temp = TempDir::new();
    let output = temp.join("awg-bad.toml");
    let root = awg_root(&temp.0);
    let (transcript, _, config) = scripted(
        &core_answers(&["yes", "4.0", "2.0, 2.0", "2.0", "bad_host", "198.51.100.4", ""]),
        &output,
        Locale::En,
        &root,
    );
    assert_eq!(transcript.matches("Enter one or more of 1.5, 2.0, 3.1").count(), 2);
    assert!(transcript.contains("Enter a DNS name or an IPv4 address."));
    let awg = config.amneziawg.unwrap();
    assert_eq!(awg.versions, vec!["2.0"]);
    assert_eq!(awg.host, "198.51.100.4");

    let ru_output = temp.join("awg-bad-ru.toml");
    let (transcript, _, config) =
        scripted(&core_answers(&["да", "9", "1.5", "x_y", "", ""]), &ru_output, Locale::Ru, &root);
    assert!(transcript.contains("Введите одну или несколько версий из 1.5, 2.0, 3.1"));
    assert!(transcript.contains("Введите DNS-имя или IPv4-адрес."));
    assert!(transcript.contains("новый домен не нужен"));
    assert_eq!(config.amneziawg.unwrap().host, "panel.example.com");
}

#[test]
fn review_can_edit_amneziawg() {
    let temp = TempDir::new();
    let output = temp.join("awg-edit.toml");
    let root = awg_root(&temp.0);
    let (_, _, config) = scripted(
        &[
            "",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "no",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "edit",
            "amneziawg",
            "yes",
            "2.0",
            "vpn.example.com",
            "",
            "save",
        ],
        &output,
        Locale::En,
        &root,
    );
    let awg = config.amneziawg.unwrap();
    assert_eq!(awg.versions, vec!["2.0"]);
    assert_eq!(awg.host, "vpn.example.com");
}

#[test]
fn amneziawg_port_that_collides_is_reported_by_the_review_loop() {
    let temp = TempDir::new();
    let output = temp.join("awg-collision.toml");
    let root = awg_root(&temp.0);
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core-mieru",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "mieru.example.com",
            "51820",
            "46001",
            "no",
            "no",
            "yes",
            "",
            "",
            "51820,23457,23458",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "mieru.tcp_ports",
            "46001",
            "save",
        ],
        &output,
        Locale::En,
        &root,
    );
    assert!(transcript.contains("amneziawg.ports.1.5: 51820 is taken by a Mieru"));
    assert_eq!(config.mieru.unwrap().tcp_ports, vec![46001]);
}

#[test]
fn amneziawg_ports_default_to_the_random_free_ones_and_enter_accepts_them() {
    let temp = TempDir::new();
    let output = temp.join("a.toml");
    let root = awg_root(&temp.0);
    let versions = vec!["1.5".to_string(), "2.0".to_string(), "3.1".to_string()];
    let expected = pick_ports(&versions, "wizard-host", &std::collections::BTreeSet::new(), &[]).unwrap();
    let (transcript, written, config) = scripted(&core_answers(&["yes", "", "", ""]), &output, Locale::En, &root);
    let awg = config.amneziawg.unwrap();
    assert_eq!(awg.ports, expected);
    let shown = expected.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    assert!(transcript.contains(&format!("[{shown}]")));
    assert!(transcript.contains("AmneziaWG UDP ports for versions 1.5, 2.0, 3.1"));
    assert!(transcript.contains("One UDP port per version, in this order"));
    assert!(transcript.split("Configuration review").nth(1).unwrap().contains(&shown));
    assert!(written.contains("[amneziawg]") && expected.iter().all(|port| written.contains(&port.to_string())));
}

#[test]
fn typed_amneziawg_port_list_overrides_the_default() {
    let temp = TempDir::new();
    let root = awg_root(&temp.0);
    let output = temp.join("t.toml");
    let (_, _, config) = scripted(&core_answers(&["yes", "", "", "23456, 24567,25678"]), &output, Locale::En, &root);
    assert_eq!(
        config.amneziawg.unwrap().port_map(),
        vec![("1.5".to_string(), 23456), ("2.0".to_string(), 24567), ("3.1".to_string(), 25678)]
    );
    let output = temp.join("o.toml");
    let (_, _, config) = scripted(&core_answers(&["yes", "3.1,1.5", "", "30001,30002"]), &output, Locale::En, &root);
    assert_eq!(config.amneziawg.unwrap().port_map(), vec![("1.5".to_string(), 30001), ("3.1".to_string(), 30002)]);
}

#[test]
fn bad_amneziawg_port_input_asks_again_in_both_languages() {
    let temp = TempDir::new();
    let root = awg_root(&temp.0);
    let output = temp.join("bad.toml");
    let (transcript, _, config) = scripted(
        &core_answers(&[
            "yes",
            "",
            "",
            "23456,24567",
            "1,2,3",
            "23456,23456,25678",
            "70000,24567,25678",
            "a,b,c",
            "23456,24567,25678",
        ]),
        &output,
        Locale::En,
        &root,
    );
    assert_eq!(
        transcript.matches("Enter distinct port numbers between 1024 and 65535, comma-separated, 3 in total").count(),
        5
    );
    assert_eq!(config.amneziawg.unwrap().ports, vec![23456, 24567, 25678]);

    let output = temp.join("bad-ru.toml");
    let (transcript, _, config) = scripted(&core_answers(&["да", "2.0", "", "x", ""]), &output, Locale::Ru, &root);
    assert!(transcript.contains("Введите разные номера портов от 1024 до 65535 через запятую, всего: 1"));
    assert!(transcript.contains("UDP-порты AmneziaWG для версий 2.0"));
    assert_eq!(config.amneziawg.unwrap().ports.len(), 1);
}

#[test]
fn editing_amneziawg_in_the_review_keeps_the_earlier_ports_as_the_default() {
    let temp = TempDir::new();
    let root = awg_root(&temp.0);
    let output = temp.join("e.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "yes",
            "",
            "",
            "23456,24567,25678",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "edit",
            "amneziawg",
            "yes",
            "",
            "",
            "",
            "save",
        ],
        &output,
        Locale::En,
        &root,
    );
    assert_eq!(config.amneziawg.unwrap().ports, vec![23456, 24567, 25678]);
    assert!(transcript.contains("[23456,24567,25678]"));
}

#[test]
fn wizard_offers_trusttunnel_with_its_own_domain_and_the_honest_hint() {
    let temp = TempDir::new();
    let output = temp.join("tt.toml");
    let (transcript, written, config) =
        scripted(&tt_answers(&["yes", "Gate.Example.org."]), &output, Locale::En, &temp.0);
    let trusttunnel = config.trusttunnel.unwrap();
    assert_eq!(trusttunnel.hostname, "gate.example.org");
    assert_eq!(trusttunnel.listen_port, 4453);
    assert_eq!(config.domains.trusttunnel.as_deref(), Some("gate.example.org"));
    assert!(written.contains("[trusttunnel]") && written.contains("trusttunnel = \"gate.example.org\""));
    for text in ["Install TrustTunnel", "A record to this server", "DNS only", "CDN", "TCP/443", "no UDP rule"] {
        assert!(transcript.contains(text), "{text}");
    }
    assert!(transcript.split("Configuration review").nth(1).unwrap().contains("TrustTunnel domain | gate.example.org"));
}

#[test]
fn trusttunnel_hint_is_honest_in_russian_too() {
    let temp = TempDir::new();
    let output = temp.join("tt-ru.toml");
    let (transcript, _, config) = scripted(&tt_answers(&["да", "gate.example.org"]), &output, Locale::Ru, &temp.0);
    for text in ["A-запись на этот сервер", "только DNS", "CDN", "TCP/443", "правило UDP не добавляются"]
    {
        assert!(transcript.contains(text), "{text}");
    }
    assert_eq!(config.trusttunnel.unwrap().hostname, "gate.example.org");
}

#[test]
fn declining_trusttunnel_writes_no_section_and_no_domain() {
    let temp = TempDir::new();
    let output = temp.join("no-tt.toml");
    let (transcript, written, config) = scripted(&tt_answers(&["no"]), &output, Locale::En, &temp.0);
    assert!(config.trusttunnel.is_none() && config.domains.trusttunnel.is_none());
    assert!(!written.contains("[trusttunnel]"));
    assert!(!transcript.split("Configuration review").nth(1).unwrap().contains("trusttunnel."));
}

#[test]
fn bad_trusttunnel_domain_is_asked_again_with_localized_feedback() {
    let temp = TempDir::new();
    let output = temp.join("bad.toml");
    let (transcript, _, _) =
        scripted(&tt_answers(&["yes", "not a domain", "gate.example.org"]), &output, Locale::En, &temp.0);
    assert_eq!(transcript.matches("Enter a fully-qualified domain name.").count(), 1);
    let output = temp.join("bad-ru.toml");
    let (transcript, _, _) = scripted(&tt_answers(&["да", "x_y", "gate.example.org"]), &output, Locale::Ru, &temp.0);
    assert_eq!(transcript.matches("Введите полное доменное имя.").count(), 1);
}

#[test]
fn review_can_add_trusttunnel_and_a_duplicate_name_sends_the_operator_back() {
    let temp = TempDir::new();
    let output = temp.join("tt-edit.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "no",
            "no",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "edit",
            "trusttunnel",
            "yes",
            "panel.example.com",
            "no",
            "trusttunnel",
            "yes",
            "gate.example.org",
            "no",
            "save",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert!(transcript.contains("domains.trusttunnel duplicates domains.panel"));
    assert_eq!(config.trusttunnel.unwrap().hostname, "gate.example.org");
}

#[test]
fn typed_trusttunnel_values_reach_the_adapters_on_apply_and_on_install_config() {
    let temp = TempDir::new();
    let mut answers = tt_answers(&["yes", "gate.example.org"]);
    *answers.last_mut().unwrap() = "apply";
    let input = format!("{}\n", answers.join("\n"));
    let mut io = TerminalIO::new(std::io::Cursor::new(input.into_bytes()), Vec::new());
    let mut wizard = Wizard::new(options(&temp.join("unused.toml"), Locale::En, &temp.0));
    let config = wizard.run(&mut io, &AuditFacts::default()).unwrap();
    assert_eq!(config.trusttunnel.as_ref().unwrap().hostname, "gate.example.org");
    assert!(crate::planner::ADAPTER_NAMES.contains(&"trusttunnel"));

    let saved = temp.join("saved.toml");
    scripted(&tt_answers(&["yes", "gate.example.org"]), &saved, Locale::En, &temp.0);
    let reread = load_config(&saved).unwrap();
    assert_eq!(reread.trusttunnel, config.trusttunnel);
    assert_eq!(reread.domains.trusttunnel, config.domains.trusttunnel);
}

#[test]
fn russian_full_wizard_exports_same_config_as_toml() {
    let temp = TempDir::new();
    let output = temp.join("proxy-control.toml");
    let (transcript, _, config) = scripted(
        &[
            "",
            "fresh",
            "full",
            "existing",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "edge.example.com",
            "mieru.example.com",
            "46001",
            "46001",
            "vless.example.com",
            "xhttp.example.com",
            "no",
            "no",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(transcript.contains("Ключи и пароли, оставленные пустыми, создаются при установке"));
    assert_eq!(
        (config.host_mode, config.profile, config.three_xui.mode),
        (HostMode::Fresh, Profile::Full, ThreeXuiMode::Existing)
    );
    assert_eq!(
        config.canonical_dict()["domains"],
        json!({
            "panel": "panel.example.com", "mtproxy": "relay.example.com", "naive": "edge.example.com",
            "mieru": "mieru.example.com", "subscription": null, "mcp": null, "trusttunnel": null
        })
    );
}

#[test]
fn russian_invalid_prompt_feedback_is_localized_in_pty() {
    let temp = TempDir::new();
    let output = temp.join("localized.toml");
    let (transcript, _, _) = scripted(
        &[
            "",
            "bogus",
            "fresh",
            "core-mieru",
            "none",
            "not a domain",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "mieru.example.com",
            "abc",
            "46001",
            "70000",
            "46001",
            "no",
            "no",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "maybe",
            "yes",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    for text in [
        "Выберите одно из: fresh/coexist.",
        "Введите полное доменное имя.",
        "Введите один или несколько портов через запятую.",
        "Введите да или нет.",
    ] {
        assert!(transcript.contains(text), "{text}");
    }
    for text in ["Invalid choice", "Invalid value", "ports must", "fully-qualified domain"] {
        assert!(!transcript.contains(text), "{text}");
    }
}

#[test]
fn russian_saved_toml_parses_to_the_wizard_result() {
    let temp = TempDir::new();
    let output = temp.join("saved.toml");
    let (_, _, config) = scripted(
        &[
            "",
            "fresh",
            "full",
            "existing",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "edge.example.com",
            "mieru.example.com",
            "46001",
            "46001",
            "vless.example.com",
            "xhttp.example.com",
            "no",
            "no",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert_eq!(load_config(&output).unwrap(), config);
}

#[test]
fn wizard_writes_the_subscription_domain_when_one_is_given() {
    let temp = TempDir::new();
    let output = temp.join("with-subscription.toml");
    let (transcript, written, config) = scripted(
        &[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "sub.example.com",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save-config",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert!(transcript.contains("Client subscription domain"));
    assert_eq!(config.domains.subscription.as_deref(), Some("sub.example.com"));
    assert!(written.contains("subscription = \"sub.example.com\""));
}

#[test]
fn wizard_writes_the_mcp_domain_when_one_is_given() {
    let temp = TempDir::new();
    let output = temp.join("with-mcp.toml");
    let (transcript, written, config) = scripted(
        &[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "mcp.example.com",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "yes",
            "save-config",
        ],
        &output,
        Locale::En,
        &temp.0,
    );
    assert!(transcript.contains("MCP server domain") && transcript.contains("central panel only"));
    assert!(transcript.find("Client subscription domain").unwrap() < transcript.find("MCP server domain").unwrap());
    assert_eq!(config.domains.mcp.as_deref(), Some("mcp.example.com"));
    assert!(written.contains("mcp = \"mcp.example.com\""));
}

#[test]
fn english_locale_can_be_selected_explicitly() {
    let temp = TempDir::new();
    let output = temp.join("proxy-control.toml");
    let (transcript, _, config) = scripted(
        &[
            "en",
            "coexist",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",
            "",
            "",
            "",
            "admin@example.com",
            "owner",
            "",
            "save-config",
        ],
        &output,
        Locale::Ru,
        &temp.0,
    );
    assert!(transcript.contains("Keys and every password left blank are generated during installation"));
    assert!(!transcript.contains("No changes were made."));
    assert_eq!(config.host_mode, HostMode::Coexist);
    assert_eq!(config.domains.subscription, None);
}

fn plain_answers(language: Option<&str>) -> Vec<&str> {
    let mut answers = Vec::new();
    if let Some(language) = language {
        answers.push(language);
    }
    answers.extend([
        "fresh",
        "core",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",
        "",
        "no",
        "",
        "admin@example.com",
        "owner",
        "",
        "yes",
        "save",
    ]);
    answers
}

#[test]
fn given_language_is_not_asked_again() {
    for locale in Locale::ALL {
        let temp = TempDir::new();
        let output = temp.join("l.toml");
        let input = format!("{}\n", plain_answers(None).join("\n"));
        let mut io = TerminalIO::new(std::io::Cursor::new(input.into_bytes()), Vec::new());
        let mut opts = options(&output, locale, &temp.0);
        opts.language_fixed = true;
        let mut wizard = Wizard::new(opts);
        assert!(matches!(wizard.run(&mut io, &AuditFacts::default()), Err(Stop::Saved { .. })));
        let transcript = String::from_utf8(io.into_output()).unwrap();
        assert!(!transcript.contains("Language / Язык"));
        assert_eq!(wizard.locale, Some(locale));
    }
}

#[test]
fn without_lang_the_language_is_still_asked() {
    let temp = TempDir::new();
    let output = temp.join("a.toml");
    let (transcript, _, _) = scripted(&plain_answers(Some("")), &output, Locale::En, &temp.0);
    assert!(transcript.contains("Language / Язык"));
}

#[test]
fn installed_host_is_told_about_update_and_quits_by_default() {
    for locale in Locale::ALL {
        let mut facts = AuditFacts::default();
        facts.ownership.insert("installed".into(), json!({"version": "3.2.1"}));
        let mut io = TerminalIO::new(std::io::Cursor::new(b"\n".to_vec()), Vec::new());
        let temp = TempDir::new();
        let mut opts = options(&temp.join("unused.toml"), locale, &temp.0);
        opts.language_fixed = true;
        let mut wizard = Wizard::new(opts);
        assert_eq!(wizard.run(&mut io, &facts), Err(Stop::Quit));
        let transcript = String::from_utf8(io.into_output()).unwrap();
        let notice = match locale {
            Locale::En => "Proxy Control 3.2.1 is already installed on this server. To update it: bash install-release.sh --update",
            Locale::Ru => "На этом сервере уже установлен Proxy Control 3.2.1. Для обновления: bash install-release.sh --update",
        };
        assert!(transcript.contains(notice));
        assert!(!transcript.contains("Language"));
    }
}

#[test]
fn installed_host_can_continue_with_a_reinstall() {
    let temp = TempDir::new();
    let output = temp.join("r.toml");
    let mut facts = AuditFacts::default();
    facts.ownership.insert("installed".into(), json!({"version": "3.2.1"}));
    let mut answers = vec!["", "continue"];
    answers.extend(plain_answers(None));
    let (transcript, _, _) = scripted_with_facts(&answers, &output, Locale::En, &temp.0, &facts);
    assert!(transcript.contains("bash install-release.sh --update"));
    assert!(output.exists());
}

#[test]
fn clean_host_gets_no_installed_warning() {
    let temp = TempDir::new();
    let output = temp.join("c.toml");
    let (transcript, _, _) = scripted(&plain_answers(Some("")), &output, Locale::En, &temp.0);
    assert!(!transcript.contains("is already installed on this server"));
}

#[test]
fn installer_audit_fact_alone_also_shows_the_notice() {
    let mut facts = AuditFacts::default();
    facts.ownership.insert("installer".into(), json!({"present": true}));
    let mut io = TerminalIO::new(std::io::Cursor::new(b"\n".to_vec()), Vec::new());
    let temp = TempDir::new();
    let mut opts = options(&temp.join("unused.toml"), Locale::En, &temp.0);
    opts.language_fixed = true;
    let mut wizard = Wizard::new(opts);
    assert_eq!(wizard.run(&mut io, &facts), Err(Stop::Quit));
    assert!(String::from_utf8(io.into_output())
        .unwrap()
        .contains("Proxy Control is already installed on this server. To update it"));
}

#[test]
fn profile_help_points_at_the_separate_awg_and_tt_questions() {
    let temp = TempDir::new();
    let (en, _, _) = scripted(&plain_answers(Some("")), &temp.join("p.toml"), Locale::En, &temp.0);
    let (ru, _, _) = scripted(&plain_answers(Some("ru")), &temp.join("p2.toml"), Locale::Ru, &temp.0);
    assert!(en.contains("AmneziaWG and TrustTunnel are not part of a profile"));
    assert!(ru.contains("AmneziaWG и TrustTunnel в профиль не входят"));
}

fn awg_tt_answers(language: &str) -> Vec<&'static str> {
    let language = if language == "ru" { "ru" } else { "en" };
    vec![
        language,
        "fresh",
        "core",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",
        "",
        "yes",
        "",
        "",
        "",
        "yes",
        "gate.example.org",
        "no",
        "admin@example.com",
        "owner",
        "",
        "yes",
        "save",
    ]
}

#[test]
fn awg_and_tt_prompts_are_short_with_the_explanation_as_a_help_line() {
    for locale in Locale::ALL {
        let temp = TempDir::new();
        let root = awg_root(&temp.0);
        let (transcript, _, _) = scripted(&awg_tt_answers(locale.value()), &temp.join("s.toml"), locale, &root);
        for key in ["amneziawg", "trusttunnel"] {
            assert!(text(locale, key, &[]).len() < 40);
            assert!(text(locale, &format!("{key}_help"), &[]).len() > 100);
            assert!(transcript.contains(text(locale, &format!("{key}_help"), &[]).lines().next().unwrap()));
        }
    }
}

#[test]
fn review_shows_labels_instead_of_raw_keys() {
    for locale in Locale::ALL {
        let temp = TempDir::new();
        let root = awg_root(&temp.0);
        let (transcript, _, _) = scripted(&awg_tt_answers(locale.value()), &temp.join("v.toml"), locale, &root);
        let review = transcript
            .split(if locale == Locale::En {
                "Configuration review"
            } else {
                "Проверка конфигурации"
            })
            .nth(1)
            .unwrap()
            .split(if locale == Locale::En { "Action" } else { "Действие" })
            .next()
            .unwrap();
        let rows = review.lines().filter(|line| line.contains(" | ")).skip(1).collect::<Vec<_>>();
        assert!(!rows.is_empty());
        for line in rows {
            let label = line.split(" | ").next().unwrap();
            assert!(!label.contains('.') && !label.contains('_'), "{line}");
        }
        for raw in ["schema", "relay_port", "lane_slots", "warp_port", "listen_port", "mtu"] {
            assert!(!review.contains(raw));
        }
        let expected = if locale == Locale::En {
            ["AmneziaWG: UDP ports", "TrustTunnel domain", "gate.example.org"]
        } else {
            ["AmneziaWG: UDP-порты", "Домен TrustTunnel", "gate.example.org"]
        };
        for item in expected {
            assert!(review.contains(item), "{item}");
        }
        assert!(review.contains(if locale == Locale::En { " | yes" } else { " | да" }));
        assert!(!review.contains(" | true") && !review.contains(" | false"));
    }
}

#[test]
fn every_review_key_of_the_examples_has_a_label_or_is_hidden() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer");
    let mut count = 0;
    for entry in std::fs::read_dir(examples).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "toml") {
            continue;
        }
        let config = load_config(&path).unwrap();
        for (key, value) in flatten(&config.canonical_dict(), "") {
            if value == "None" || REVIEW_HIDDEN.contains(&key.as_str()) {
                continue;
            }
            let label = format!("review_{}", key.replace('.', "_"));
            assert!(crate::i18n::message(Locale::En, &label).is_some(), "{path:?}: {key}");
        }
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn non_default_service_ports_are_labelled_in_the_review() {
    for locale in Locale::ALL {
        for key in ["egress.relay_port", "mieru.lane_slots", "egress.warp_port", "three_xui.warp_port"] {
            assert!(!text(locale, &format!("review_{}", key.replace('.', "_")), &[]).is_empty());
        }
    }
}

#[test]
fn router_question_names_the_pinned_xray_version() {
    let tree = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let expected = pinned_version(&tree, "xray");
    assert_eq!(expected, "26.10.17");
    for locale in Locale::ALL {
        assert!(text(locale, "router", &[("version", &expected)]).contains(&format!("Xray-core {expected}")));
    }
}

#[test]
fn managed_xui_help_names_the_pinned_version_in_both_languages() {
    let tree = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let expected = pinned_version(&tree, "three_xui");
    assert_eq!(expected, "3.10.2");
    for locale in Locale::ALL {
        assert!(text(locale, "three_xui_mode_help", &[]).contains(&format!("3x-ui {expected}")));
    }
}

#[test]
fn wizard_never_offers_a_mode_the_planner_will_refuse() {
    for mode in OFFERED_THREE_XUI_MODES {
        let mut three_xui = ThreeXuiConfig::new(mode);
        if mode != ThreeXuiMode::None {
            three_xui.vless_tcp_domain = Some("vless.example.com".into());
        }
        let config = InstallerConfig {
            schema: 1,
            host_mode: HostMode::Fresh,
            profile: Profile::Core,
            acme_email: "ops@example.com".into(),
            initial_user: "owner".into(),
            domains: crate::model::DomainConfig::new("panel.example.com", "proxy.example.com"),
            mieru: None,
            three_xui,
            firewall: crate::model::FirewallConfig { manage_ufw: true },
            egress: None,
            ingress: None,
            amneziawg: None,
            trusttunnel: None,
        };
        assert!(!crate::planner::adapters_for(&config).unwrap().is_empty());
    }
}

#[test]
fn wizard_quit_before_digest_confirmation_has_no_mutations() {
    let temp = TempDir::new();
    let marker = temp.join("etc/foreign.conf");
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, b"foreign bytes\n").unwrap();
    let output = temp.join("not-written.toml");
    let mut io = TerminalIO::new(std::io::Cursor::new(b"en\nquit\n".to_vec()), Vec::new());
    let mut wizard = Wizard::new(options(&output, Locale::En, &temp.0));
    assert_eq!(wizard.run(&mut io, &AuditFacts::default()), Err(Stop::Quit));
    assert!(!output.exists());
    assert_eq!(std::fs::read(&marker).unwrap(), b"foreign bytes\n");
}
