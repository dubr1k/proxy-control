from __future__ import annotations

import errno
import io
import os
import pty
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from installer.config import load_config
from installer.i18n import Locale
from installer.model import HostMode, Profile, ThreeXuiMode
from installer.planner import AuditFacts
from installer.wizard import TerminalIO, TerminalWizard, WizardSaved


ROOT = Path(__file__).parents[1]


def _tree(root: Path) -> dict[str, bytes | str]:
    result: dict[str, bytes | str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        result[relative] = "directory" if path.is_dir() else path.read_bytes()
    return result


def _run_cli_in_pty(
    tmp_path: Path,
    *,
    locale: str,
    answers: list[str],
    output: Path,
) -> tuple[subprocess.CompletedProcess[bytes], str]:
    master, slave = pty.openpty()
    env = {
        **os.environ,
        "LANG": locale,
        "LC_ALL": locale,
        "PYTHONPATH": str(ROOT),
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "installer.cli",
            "--root",
            str(tmp_path),
            "wizard",
            "--config-output",
            str(output),
        ],
        cwd=ROOT,
        env=env,
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )
    os.close(slave)
    os.write(master, ("\n".join(answers) + "\n").encode())
    chunks: list[bytes] = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
        if process.poll() is not None and not ready:
            break
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise AssertionError("wizard PTY did not exit") from None
    while True:
        try:
            chunk = os.read(master, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        chunks.append(chunk)
    os.close(master)
    completed = subprocess.CompletedProcess(process.args, process.returncode, b"".join(chunks), b"")
    return completed, completed.stdout.decode(errors="replace").replace("\r", "")


def test_russian_full_wizard_exports_same_config_as_toml(tmp_path: Path):
    output = tmp_path / "proxy-control.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="ru_RU.UTF-8",
        answers=[
            "",  # LANG default: Russian
            "fresh",
            "full",
            "existing",
            "panel.example.com",
            "relay.example.com",
            "",  # subscription domain: blank keeps subscriptions off
            "",  # MCP domain: blank keeps MCP off
            "edge.example.com",
            "mieru.example.com",
            "46001",
            "46001",
            # existing 3x-ui: only the two VLESS names are routed, so only they are asked
            "vless.example.com",
            "xhttp.example.com",
            "no",  # WARP: asked for Naive and Mieru profiles
            "no",  # Xray-router: offered whenever a proxy service could feed it (v0.5)
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "yes",
            "save",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Ключи и пароли, оставленные пустыми, создаются при установке" in transcript
    assert "Изменения не внесены." not in transcript
    assert "No changes were made." not in transcript
    config = load_config(output)
    assert config.host_mode is HostMode.FRESH
    assert config.profile is Profile.FULL
    assert config.three_xui.mode is ThreeXuiMode.EXISTING
    assert config.canonical_dict()["domains"] == {
        "panel": "panel.example.com",
        "mtproxy": "relay.example.com",
        "naive": "edge.example.com",
        "mieru": "mieru.example.com",
        "subscription": None,
        "mcp": None,
        "trusttunnel": None,
    }


def test_russian_invalid_prompt_feedback_is_localized_in_pty(tmp_path: Path):
    output = tmp_path / "localized.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="ru_RU.UTF-8",
        answers=[
            "",
            "bogus",
            "fresh",
            "core-mieru",
            "none",
            "not a domain",
            "panel.example.com",
            "relay.example.com",
            "",  # subscription domain: blank keeps subscriptions off
            "",  # MCP domain: blank keeps MCP off
            "mieru.example.com",
            "abc",
            "46001",
            "70000",
            "46001",
            "no",  # WARP: asked for the Mieru profile
            "no",  # Xray-router
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "maybe",
            "yes",
            "save",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Выберите одно из: fresh/coexist." in transcript
    assert "Введите полное доменное имя." in transcript
    assert "Введите один или несколько портов через запятую." in transcript
    assert "Введите да или нет." in transcript
    assert "Invalid choice" not in transcript
    assert "Invalid value" not in transcript
    assert "ports must" not in transcript
    assert "fully-qualified domain" not in transcript


def test_russian_integer_and_generic_string_feedback_hides_validator_details():
    transcript = io.StringIO()
    terminal = TerminalIO(
        io.StringIO("abc\n70000\n46001\nbad\nok\n"),
        transcript,
    )
    terminal.set_locale(Locale.RU)

    port = terminal.integer("Порт")

    def validator(value: str) -> str:
        if value != "ok":
            raise ValueError("internal English validator detail")
        return value

    value = terminal.validated("Значение", validator)

    assert port == 46001
    assert value == "ok"
    assert "Введите целое число." in transcript.getvalue()
    assert "Введите число от 1 до 65535." in transcript.getvalue()
    assert "Введите допустимое значение." in transcript.getvalue()
    assert "internal English validator detail" not in transcript.getvalue()


def test_russian_saved_toml_parses_to_the_wizard_result(tmp_path: Path):
    output = tmp_path / "saved.toml"
    answers = [
        "",
        "fresh",
        "full",
        "existing",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain: blank keeps subscriptions off
        "",  # MCP domain: blank keeps MCP off
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "xui.example.com",
        "vless.example.com",
        "xhttp.example.com",
        "hy2.example.com",
        "no",  # WARP: asked for Naive and Mieru profiles
        "no",  # Xray-router
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",  # panel password: blank keeps it generated
        "yes",
        "save",
    ]
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), io.StringIO())
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)

    with pytest.raises(WizardSaved) as caught:
        wizard.run(AuditFacts())

    assert load_config(output) == caught.value.config


def test_english_locale_can_be_selected_explicitly(tmp_path: Path):
    output = tmp_path / "proxy-control.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="ru_RU.UTF-8",
        answers=[
            "en",
            "coexist",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",  # subscription domain: blank keeps subscriptions off
            "",  # MCP domain: blank keeps MCP off
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "save-config",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Keys and every password left blank are generated during installation" in transcript
    assert "No changes were made." not in transcript
    assert load_config(output).host_mode is HostMode.COEXIST
    assert load_config(output).domains.subscription is None


def test_wizard_writes_the_subscription_domain_when_one_is_given(tmp_path: Path):
    output = tmp_path / "with-subscription.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="C.UTF-8",
        answers=[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "sub.example.com",
            "",  # MCP domain: blank keeps MCP off
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "yes",
            "save-config",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Client subscription domain" in transcript
    assert load_config(output).domains.subscription == "sub.example.com"
    assert 'subscription = "sub.example.com"' in output.read_text()


def test_wizard_writes_the_mcp_domain_when_one_is_given(tmp_path: Path):
    """The MCP prompt (v0.11 §9a) follows the subscription one and says it is for the
    central panel only; a name lands in the configuration, blank keeps MCP off."""
    output = tmp_path / "with-mcp.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="C.UTF-8",
        answers=[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",  # subscription domain
            "mcp.example.com",
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "yes",
            "save-config",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "MCP server domain" in transcript
    assert "central panel only" in transcript
    assert transcript.index("Client subscription domain") < transcript.index("MCP server domain")
    assert load_config(output).domains.mcp == "mcp.example.com"
    assert 'mcp = "mcp.example.com"' in output.read_text()


def test_wizard_writes_an_explicit_egress_section_per_service(tmp_path: Path):
    """[egress] (v0.4): with WARP on, each proxy service is asked; the answers land in
    the configuration as their own section, and the old keys mirror `warp`."""
    output = tmp_path / "egress.toml"
    answers = [
        "",
        "fresh",
        "full",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain
        "",  # MCP domain: blank keeps MCP off
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "yes",  # WARP
        "no",  # Xray-router
        "no",  # NaiveProxy through WARP? — direct
        "yes",  # Mieru through WARP
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",  # panel password
        "yes",
        "save",
    ]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    text = output.read_text()
    assert "[egress]" in text and 'naive = "direct"' in text and 'mieru = "warp"' in text
    assert "Направлять весь трафик NaiveProxy через WARP" in transcript.getvalue()
    config = load_config(output)
    assert config.egress is not None and config.egress.warp is True
    assert (config.egress.naive.value, config.egress.mieru.value) == ("direct", "warp")
    assert config.three_xui.warp is True


def test_review_edit_and_back_change_typed_fields_before_save(tmp_path: Path):
    output = tmp_path / "edited.toml"
    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="C.UTF-8",
        answers=[
            "en",
            "fresh",
            "core",
            "none",
            "panel.example.com",
            "relay.example.com",
            "",  # subscription domain: blank keeps subscriptions off
            "",  # MCP domain: blank keeps MCP off
            "",  # AmneziaWG: blank keeps it off
            "",  # TrustTunnel: blank keeps it off
            "admin@example.com",
            "owner",
            "",  # panel password: blank keeps it generated
            "no",
            "edit",
            "domains.panel",
            "new-panel.example.com",
            "back",
            "yes",
            "save",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    config = load_config(output)
    assert config.domains.panel == "new-panel.example.com"
    assert config.firewall.manage_ufw is True
    assert "Configuration saved" in transcript
    assert "No changes were made." not in transcript


def test_existing_xui_edit_can_clear_domain_and_back_preserves_absent_domain(
    tmp_path: Path,
):
    """An installed 3x-ui is asked only for the two VLESS names it gets routes for; both
    blank is refused (the planner would refuse it later), one is enough, and review
    «back»/«edit» change them without inventing the unused panel/Hysteria2 names."""
    output = tmp_path / "existing.toml"
    answers = [
        "",
        "coexist",
        "core",
        "existing",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain: blank keeps subscriptions off
        "",  # MCP domain: blank keeps MCP off
        "",  # VLESS TCP: blank
        "",  # VLESS XHTTP: blank — refused, both asked again
        "vless.example.com",
        "",
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",  # panel password: blank keeps it generated
        "back",  # the last editable field: VLESS XHTTP, still blank
        "",
        "edit",
        "three_xui.vless_tcp_domain",
        "tcp2.example.com",
        "save",
    ]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(
        terminal,
        locale=Locale.EN,
        config_output=output,
    )

    with pytest.raises(WizardSaved) as caught:
        wizard.run(AuditFacts())

    assert "At least one VLESS domain is needed" in transcript.getvalue()
    assert "3x-ui panel domain" not in transcript.getvalue() and "Hysteria2 domain" not in transcript.getvalue()
    assert "managed-new" not in transcript.getvalue().split("3x-ui mode", 1)[1].split(":", 1)[0]
    config = caught.value.config
    assert config.three_xui.vless_tcp_domain == "tcp2.example.com"
    assert config.three_xui.vless_xhttp_domain is None
    assert config.three_xui.panel_domain is None and config.three_xui.hysteria_domain is None
    assert load_config(output) == config


def test_wizard_quit_before_digest_confirmation_has_no_mutations(tmp_path: Path):
    marker = tmp_path / "etc" / "foreign.conf"
    marker.parent.mkdir()
    marker.write_bytes(b"foreign bytes\n")
    before = _tree(tmp_path)

    completed, transcript = _run_cli_in_pty(
        tmp_path,
        locale="C.UTF-8",
        answers=["en", "quit"],
        output=tmp_path / "not-written.toml",
    )

    assert completed.returncode == 0, transcript
    assert _tree(tmp_path) == before
    assert "No changes were made" in transcript


def test_the_wizard_never_offers_a_mode_the_planner_will_refuse():
    """An operator must not be able to answer several questions and only then
    be told the mode does not exist. Whatever the wizard offers, the planner
    has to accept."""
    from installer.planner import PlanError, adapters_for
    from installer.wizard import OFFERED_THREE_XUI_MODES

    for mode in OFFERED_THREE_XUI_MODES:
        config = _base_config(mode)
        try:
            adapters_for(config)
        except PlanError as exc:  # pragma: no cover - the assertion names it
            raise AssertionError(f"the wizard offers a refused mode: {mode}") from exc


def _base_config(mode: ThreeXuiMode):
    from installer.model import (
        DomainConfig,
        FirewallConfig,
        InstallerConfig,
        Profile,
        ThreeXuiConfig,
    )

    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com"),
        mieru=None,
        three_xui=(
            ThreeXuiConfig(mode=mode, vless_tcp_domain="vless.example.com")
            if mode is not ThreeXuiMode.NONE
            else ThreeXuiConfig(mode=mode)
        ),
        firewall=FirewallConfig(manage_ufw=True),
    )


def test_a_typed_panel_password_is_saved_privately_and_never_in_the_config(tmp_path: Path):
    """The configuration is read to build the plan, the plan is digested and
    shown, and reports derive from the same values, so a password in it would
    reach all three."""
    from installer.credentials import credentials_path, read_credentials

    output = tmp_path / "typed.toml"
    answers = [
        "",
        "coexist",
        "core",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain: blank keeps subscriptions off
        "",  # MCP domain: blank keeps MCP off
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "correct-horse-battery",
        "correct-horse-battery",
        "save",
    ]
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), io.StringIO())
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)

    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())

    assert "correct-horse-battery" not in output.read_text()
    stored = read_credentials(output)
    assert stored is not None
    assert stored.panel_username == "owner"
    assert stored.panel_password == "correct-horse-battery"
    assert stat.S_IMODE(os.stat(credentials_path(output)).st_mode) == 0o600


def test_blank_passwords_leave_no_credentials_file_behind(tmp_path: Path):
    from installer.credentials import credentials_path

    output = tmp_path / "generated.toml"
    answers = [
        "",
        "coexist",
        "core",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain: blank keeps subscriptions off
        "",  # MCP domain: blank keeps MCP off
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",
        "save",
    ]
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), io.StringIO())
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)

    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())

    assert not credentials_path(output).exists()


def test_mismatched_passwords_are_rejected_and_asked_again(tmp_path: Path):
    from installer.credentials import read_credentials

    output = tmp_path / "mismatch.toml"
    transcript = io.StringIO()
    answers = [
        "",
        "coexist",
        "core",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain: blank keeps subscriptions off
        "",  # MCP domain: blank keeps MCP off
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "first-attempt-password",
        "second-attempt-password",
        "short",
        "short",
        "settled-panel-password",
        "settled-panel-password",
        "save",
    ]
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)

    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())

    assert "не совпадают" in transcript.getvalue()
    stored = read_credentials(output)
    assert stored is not None and stored.panel_password == "settled-panel-password"


def test_wizard_offers_the_router_whenever_a_service_could_feed_it(tmp_path: Path):
    """[egress] router (v0.5): the Xray-router is offered to every profile with NaiveProxy
    or Mieru — the installer fetches the pinned archive itself, so the wizard never asks
    the operator to stage anything; a service handed to the router is not asked about WARP."""
    output = tmp_path / "router.toml"
    answers = [
        "",
        "fresh",
        "full",
        "none",
        "panel.example.com",
        "relay.example.com",
        "",  # subscription domain
        "",  # MCP domain: blank keeps MCP off
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "yes",  # WARP
        "yes",  # Xray-router
        "yes",  # NaiveProxy through the router
        "no",  # Mieru through the router
        "yes",  # Mieru through WARP (the only service still asked)
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",  # panel password
        "yes",
        "save",
    ]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    text = output.read_text()
    assert "router = true" in text and 'naive = "router"' in text and 'mieru = "warp"' in text
    assert "Xray-router" in transcript.getvalue() and "скачивается сам" in transcript.getvalue()
    assert "Направлять весь трафик NaiveProxy через WARP" not in transcript.getvalue()
    config = load_config(output)
    assert config.egress.router is True
    assert (config.egress.naive.value, config.egress.mieru.value) == ("router", "warp")

    # Declined, the v0.4 dialogue follows unchanged and no router key is written.
    answers_without = answers[:13] + ["no", "yes", "yes"] + answers[17:]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers_without) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    assert "Направлять весь трафик NaiveProxy через WARP" in transcript.getvalue()
    assert "router" not in output.read_text()

    # A core-only profile has nothing to feed a router: the question is not asked.
    core = tmp_path / "core.toml"
    answers_core = ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "", "", "", "admin@example.com",
                    "owner", "", "yes", "save"]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers_core) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=core)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    assert "Установить Xray-router" not in transcript.getvalue()


def test_wizard_offers_the_router_on_a_trusttunnel_only_node(tmp_path: Path):
    """v1.6: with TrustTunnel enabled the router can feed it even when the profile has neither
    NaiveProxy nor Mieru; the question follows the TrustTunnel answers."""
    output = tmp_path / "tt-router.toml"
    answers = ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "",
               "",  # AmneziaWG
               "yes", "gate.example.com",  # TrustTunnel and its name
               "yes",  # Xray-router
               "admin@example.com", "owner", "", "yes", "save"]
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.RU, config_output=output)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    config = load_config(output)
    assert config.trusttunnel is not None and config.egress.router is True
    assert "Xray-router" in transcript.getvalue()


def _scripted(
    answers: list[str], output: Path, locale: Locale = Locale.EN, root: Path | None = None
) -> tuple[str, str]:
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=locale, config_output=output, **({"root": root} if root else {}))
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    return transcript.getvalue(), output.read_text()


def test_enter_takes_the_explained_defaults_and_the_example_mieru_ports(tmp_path: Path):
    """v1.0.3: every choice is explained right before it is asked, Enter takes the common
    case (fresh, full, no 3x-ui) and the Mieru ports default to the examples' 46001."""
    output = tmp_path / "defaults.toml"
    answers = [
        "",  # language
        "",  # host mode → fresh
        "",  # profile → full
        "",  # 3x-ui → none
        "panel.example.com",
        "relay.example.com",
        "",
        "",
        "edge.example.com",
        "mieru.example.com",
        "",  # Mieru TCP → 46001
        "",  # Mieru UDP → 46001
        "no",  # WARP
        "no",  # router
        "",  # AmneziaWG: blank keeps it off
        "",  # TrustTunnel: blank keeps it off
        "admin@example.com",
        "owner",
        "",
        "yes",
        "save",
    ]
    transcript, written = _scripted(answers, output)
    for line in ("fresh   — a clean server", "full       — the panel, MTProxy", "managed-new — the installer sets up its own 3x-ui"):
        assert line in transcript, line
    config = load_config(output)
    assert (config.host_mode, config.profile, config.three_xui.mode) == (HostMode.FRESH, Profile.FULL, ThreeXuiMode.NONE)
    assert config.mieru.tcp_ports == (46001,) and config.mieru.udp_ports == (46001,)
    # The question says what the name is for: MTProxy and Mieru; the panel login is owner.
    assert "first MTProxy and Mieru user (the panel login is always owner)" in transcript
    # The review lists what this installation uses: no unset field, no 3x-ui block without 3x-ui.
    review = transcript.split("Configuration review", 1)[1]
    assert "| None" not in review and "3x-ui through WARP" not in review and "3x-ui mode | none" in review


def test_the_router_question_names_the_pinned_xray_version():
    import json

    from installer.wizard import pinned_version

    pins = json.loads((ROOT / "release" / "external-artifacts.json").read_text())
    expected = next(item["version"] for item in pins["artifacts"] if item["name"] == "xray")
    assert pinned_version("xray") == expected
    from installer.i18n import text

    assert f"Xray-core {expected}" in text(Locale.EN, "router", version=pinned_version("xray"))
    assert f"Xray-core {expected}" in text(Locale.RU, "router", version=pinned_version("xray"))


def test_the_managed_xui_help_names_the_pinned_version_in_both_languages():
    from installer.i18n import text
    from installer.wizard import pinned_version

    for locale in (Locale.EN, Locale.RU):
        assert f"3x-ui {pinned_version('three_xui')}" in text(locale, "three_xui_mode_help")


def test_warp_domains_take_geosite_lists_and_refuse_a_blank_answer(tmp_path: Path):
    """The managed 3x-ui routes a list through WARP and the plan refuses an empty one, so the
    question says «at least one» and keeps asking on a blank; `geosite:` and `domain:`
    selectors are accepted exactly as `three_xui.warp_domains` accepts them."""
    output = tmp_path / "warp.toml"
    answers = [
        "", "fresh", "core", "managed-new",
        "panel.example.com", "relay.example.com", "", "",
        "xui.example.com", "vless.example.com", "xhttp.example.com", "hy2.example.com",
        "yes",  # WARP for 3x-ui
        "",  # blank: refused, asked again
        "geosite:openai, domain:Claude.AI, chatgpt.com",
        "", "", "admin@example.com", "owner", "",
        "xuiadmin", "",  # 3x-ui username, generated password
        "yes", "save",
    ]
    transcript, written = _scripted(answers, output)
    assert "blank for none" not in transcript
    assert "at least one" in transcript
    assert transcript.count("Enter one or more comma-separated domains or geosite:name lists.") == 1
    config = load_config(output)
    assert set(config.three_xui.warp_domains) == {"geosite:openai", "domain:claude.ai", "chatgpt.com"}


def test_an_invalid_configuration_says_why(tmp_path: Path):
    """A refused configuration names the reason instead of «edit the highlighted fields»
    with nothing highlighted; the operator fixes the field and goes on."""
    output = tmp_path / "conflict.toml"
    answers = [
        "", "fresh", "core-mieru", "none",
        "panel.example.com", "relay.example.com", "", "",
        "mieru.example.com",
        "8443",  # the panel's private TLS listener: refused with the reason
        "8443",
        "no", "no",
        "", "", "admin@example.com", "owner", "", "yes",
        "mieru.tcp_ports", "46001",  # the field to fix and its new value
        "save",
    ]
    transcript, _ = _scripted(answers, output)
    reason = transcript.split("The configuration is invalid: ", 1)[1].splitlines()[0]
    assert "8443 is taken by the panel's private TLS listener" in reason
    assert load_config(output).mieru.tcp_ports == (46001,)


def _core_answers(*awg: str) -> list[str]:
    return ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "", *awg, "",  # TrustTunnel: blank keeps it off
            "admin@example.com", "owner", "", "yes", "save"]


def test_the_wizard_offers_amneziawg_with_versions_and_a_public_name(tmp_path: Path):
    """One yes/no, then the versions (default all three) and the name clients dial (default the
    panel domain); no new domain is asked, then the ports (Enter takes the random free ones).
    MTU and DNS stay in the TOML."""
    output = tmp_path / "awg.toml"
    transcript, written = _scripted(_core_answers("yes", "3.1, 1.5", "vpn.example.com", ""), output)
    awg = load_config(output).amneziawg
    assert awg is not None
    assert awg.versions == ("1.5", "3.1") and awg.host == "vpn.example.com"
    assert set(awg.port_map()) == {"1.5", "3.1"} and len(set(awg.ports)) == 2
    assert all(10240 <= port <= 32000 for port in awg.ports)
    assert "[amneziawg]" in written and 'versions = ["1.5", "3.1"]' in written
    assert "Install AmneziaWG" in transcript and "needs no new domain" in transcript
    assert "AmneziaWG: versions | 1.5,3.1" in transcript.split("Configuration review", 1)[1]


def test_amneziawg_defaults_are_all_versions_and_the_panel_domain(tmp_path: Path):
    output = tmp_path / "awg-defaults.toml"
    _scripted(_core_answers("yes", "", "", ""), output)
    awg = load_config(output).amneziawg
    assert awg.versions == ("1.5", "2.0", "3.1") and awg.host == "panel.example.com"


def test_declining_amneziawg_writes_no_section(tmp_path: Path):
    output = tmp_path / "no-awg.toml"
    transcript, written = _scripted(_core_answers("no"), output)
    assert load_config(output).amneziawg is None
    assert "[amneziawg]" not in written and "amneziawg." not in transcript.split("Configuration review", 1)[1]


def test_amneziawg_answers_are_validated_with_localized_feedback(tmp_path: Path):
    output = tmp_path / "awg-bad.toml"
    transcript, _ = _scripted(_core_answers("yes", "4.0", "2.0, 2.0", "2.0", "bad_host", "198.51.100.4", ""), output)
    assert transcript.count("Enter one or more of 1.5, 2.0, 3.1") == 2
    assert "Enter a DNS name or an IPv4 address." in transcript
    awg = load_config(output).amneziawg
    assert awg.versions == ("2.0",) and awg.host == "198.51.100.4"
    ru_output = tmp_path / "awg-bad-ru.toml"
    ru_transcript, _ = _scripted(_core_answers("да", "9", "1.5", "x_y", "", ""), ru_output, Locale.RU)
    assert "Введите одну или несколько версий из 1.5, 2.0, 3.1" in ru_transcript
    assert "Введите DNS-имя или IPv4-адрес." in ru_transcript
    assert "новый домен не нужен" in ru_transcript
    assert load_config(ru_output).amneziawg.host == "panel.example.com"


def test_the_review_can_edit_amneziawg(tmp_path: Path):
    output = tmp_path / "awg-edit.toml"
    answers = ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "",
               "no",  # AmneziaWG off at first
               "",  # TrustTunnel: blank keeps it off
               "admin@example.com", "owner", "", "yes",
               "edit", "amneziawg", "yes", "2.0", "vpn.example.com", "",
               "save"]
    _scripted(answers, output)
    awg = load_config(output).amneziawg
    assert awg.versions == ("2.0",) and awg.host == "vpn.example.com"


def test_an_amneziawg_port_that_collides_is_reported_by_the_review_loop(tmp_path: Path):
    """A typed AmneziaWG port that collides with a Mieru port is caught on the
    config round trip (`invalid_config`), so the operator is sent back to the field."""
    output = tmp_path / "awg-collision.toml"
    answers = ["", "fresh", "core-mieru", "none", "panel.example.com", "relay.example.com", "", "",
               "mieru.example.com", "51820", "46001", "no", "no",
               "yes", "", "", "51820,23457,23458",  # AmneziaWG: all versions, the panel name, the ports
               "",  # TrustTunnel: blank keeps it off
               "admin@example.com", "owner", "", "yes",
               "mieru.tcp_ports", "46001",
               "save"]
    transcript, _ = _scripted(answers, output)
    assert "amneziawg.ports.1.5: 51820 is taken by a Mieru" in transcript
    assert load_config(output).mieru.tcp_ports == (46001,)


def _awg_root(tmp_path: Path, identity: str = "wizard-host") -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc/machine-id").write_text(identity + "\n")
    return root


def test_amneziawg_ports_default_to_the_random_free_ones_and_enter_accepts_them(tmp_path: Path):
    from installer.awg_ports import pick_ports

    root = _awg_root(tmp_path)
    expected = pick_ports(("1.5", "2.0", "3.1"), identity="wizard-host", taken=())
    transcript, written = _scripted(_core_answers("yes", "", "", ""), tmp_path / "a.toml", root=root)
    awg = load_config(tmp_path / "a.toml").amneziawg
    assert awg.port_map() == expected
    shown = ",".join(str(port) for port in expected.values())
    assert f"[{shown}]" in transcript and "AmneziaWG UDP ports for versions 1.5, 2.0, 3.1" in transcript
    assert "One UDP port per version, in this order" in transcript
    assert not set(awg.ports) & {51820, 51821, 51822}
    assert f"AmneziaWG: UDP ports | {shown}" in transcript.split("Configuration review", 1)[1] or \
        all(str(port) in transcript.split("Configuration review", 1)[1] for port in expected.values())
    assert "[amneziawg]" in written and all(str(port) in written for port in expected.values())


def test_a_typed_amneziawg_port_list_overrides_the_default(tmp_path: Path):
    transcript, _ = _scripted(_core_answers("yes", "", "", "23456, 24567,25678"), tmp_path / "t.toml",
                              root=_awg_root(tmp_path))
    assert load_config(tmp_path / "t.toml").amneziawg.port_map() == {"1.5": 23456, "2.0": 24567, "3.1": 25678}
    # the order follows the selected versions
    _scripted(_core_answers("yes", "3.1,1.5", "", "30001,30002"), tmp_path / "o.toml", root=_awg_root(tmp_path))
    assert load_config(tmp_path / "o.toml").amneziawg.port_map() == {"1.5": 30001, "3.1": 30002}


def test_bad_amneziawg_port_input_asks_again_in_both_languages(tmp_path: Path):
    answers = _core_answers("yes", "", "", "23456,24567", "1,2,3", "23456,23456,25678", "70000,24567,25678",
                            "a,b,c", "23456,24567,25678")
    transcript, _ = _scripted(answers, tmp_path / "bad.toml", root=_awg_root(tmp_path))
    assert transcript.count("Enter distinct port numbers between 1024 and 65535, comma-separated, 3 in total") == 5
    assert load_config(tmp_path / "bad.toml").amneziawg.ports == (23456, 24567, 25678)
    ru_transcript, _ = _scripted(_core_answers("да", "2.0", "", "x", ""), tmp_path / "bad-ru.toml", Locale.RU,
                                 _awg_root(tmp_path))
    assert "Введите разные номера портов от 1024 до 65535 через запятую, всего: 1" in ru_transcript
    assert "UDP-порты AmneziaWG для версий 2.0" in ru_transcript
    assert len(load_config(tmp_path / "bad-ru.toml").amneziawg.ports) == 1


def test_editing_amneziawg_in_the_review_keeps_the_earlier_ports_as_the_default(tmp_path: Path):
    answers = ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "",
               "yes", "", "", "23456,24567,25678",
               "",  # TrustTunnel: blank keeps it off
               "admin@example.com", "owner", "", "yes",
               "edit", "amneziawg", "yes", "", "", "",  # versions, host, ports: Enter keeps all
               "save"]
    transcript, _ = _scripted(answers, tmp_path / "e.toml", root=_awg_root(tmp_path))
    assert load_config(tmp_path / "e.toml").amneziawg.ports == (23456, 24567, 25678)
    assert "[23456,24567,25678]" in transcript


def test_installer_catalog_has_the_same_keys_and_placeholders_in_both_languages():
    """Every wizard text exists in English and Russian with the same `{placeholders}`."""
    import string

    from installer.i18n import _CATALOG

    english, russian = _CATALOG[Locale.EN], _CATALOG[Locale.RU]
    assert set(english) == set(russian), sorted(set(english) ^ set(russian))

    def fields(message: str) -> set[str]:
        return {name for _, name, _, _ in string.Formatter().parse(message) if name}

    assert {key for key in english if fields(english[key]) != fields(russian[key])} == set()
    for key in ("amneziawg", "amneziawg_versions", "amneziawg_host", "invalid_awg_versions", "invalid_awg_host",
                "trusttunnel", "trusttunnel_domain"):
        assert key in english and key in russian


# -- TrustTunnel ------------------------------------------------------------------------


def _tt_answers(*tt: str, last: str = "save") -> list[str]:
    """A core wizard run: AmneziaWG declined, then the TrustTunnel answers."""
    # v1.6: with TrustTunnel on, a core profile is also asked about the Xray-router (declined here).
    router = ["no"] if tt and tt[0] in ("yes", "да") else []
    return ["", "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "", "no", *tt, *router,
            "admin@example.com", "owner", "", "yes", last]


def test_the_wizard_offers_trusttunnel_with_its_own_domain_and_the_honest_hint(tmp_path: Path):
    output = tmp_path / "tt.toml"
    transcript, written = _scripted(_tt_answers("yes", "Gate.Example.org."), output)
    config = load_config(output)
    assert config.trusttunnel is not None and config.trusttunnel.hostname == "gate.example.org"
    assert config.trusttunnel.listen_port == 4453 and config.domains.trusttunnel == "gate.example.org"
    assert "[trusttunnel]" in written and 'trusttunnel = "gate.example.org"' in written
    assert "Install TrustTunnel" in transcript and "A record to this server" in transcript
    assert "DNS only" in transcript and "CDN" in transcript and "TCP/443" in transcript and "no UDP rule" in transcript
    assert "TrustTunnel domain | gate.example.org" in transcript.split("Configuration review", 1)[1]


def test_the_trusttunnel_hint_is_honest_in_russian_too(tmp_path: Path):
    output = tmp_path / "tt-ru.toml"
    transcript, _ = _scripted(_tt_answers("да", "gate.example.org"), output, Locale.RU)
    assert "A-запись на этот сервер" in transcript and "только DNS" in transcript and "CDN" in transcript
    assert "TCP/443" in transcript and "правило UDP не добавляются" in transcript
    assert load_config(output).trusttunnel.hostname == "gate.example.org"


def test_declining_trusttunnel_writes_no_section_and_no_domain(tmp_path: Path):
    output = tmp_path / "no-tt.toml"
    transcript, written = _scripted(_tt_answers("no"), output)
    config = load_config(output)
    assert config.trusttunnel is None and config.domains.trusttunnel is None
    assert "[trusttunnel]" not in written and "trusttunnel." not in transcript.split("Configuration review", 1)[1]


def test_a_bad_trusttunnel_domain_is_asked_again_with_localized_feedback(tmp_path: Path):
    transcript, _ = _scripted(_tt_answers("yes", "not a domain", "gate.example.org"), tmp_path / "bad.toml")
    assert transcript.count("Enter a fully-qualified domain name.") == 1
    ru, _ = _scripted(_tt_answers("да", "x_y", "gate.example.org"), tmp_path / "bad-ru.toml", Locale.RU)
    assert ru.count("Введите полное доменное имя.") == 1


def test_the_review_can_add_trusttunnel_and_a_duplicate_name_sends_the_operator_back(tmp_path: Path):
    output = tmp_path / "tt-edit.toml"
    answers = _tt_answers("no")[:-1]  # up to «yes» (manage_ufw)
    answers += ["edit", "trusttunnel", "yes", "panel.example.com", "no",  # collides with the panel name; router declined
                "trusttunnel", "yes", "gate.example.org", "no",
                "save"]
    transcript, _ = _scripted(answers, output)
    assert "domains.trusttunnel duplicates domains.panel" in transcript
    assert load_config(output).trusttunnel.hostname == "gate.example.org"


def test_typed_trusttunnel_values_reach_the_adapters_on_apply_and_on_install_config(tmp_path: Path):
    """The «apply» path hands the config to the planner directly; `install --config` re-reads the
    saved TOML. Both must select the adapter and plan the typed name."""
    from installer.adapters.trusttunnel import TrustTunnelAdapter
    from installer.planner import adapters_for

    # apply
    transcript = io.StringIO()
    answers = _tt_answers("yes", "gate.example.org", last="apply")
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    config = TerminalWizard(terminal, locale=Locale.EN, config_output=tmp_path / "unused.toml").run(AuditFacts())
    assert config.trusttunnel is not None and config.trusttunnel.hostname == "gate.example.org"
    assert "trusttunnel" in [adapter.name for adapter in adapters_for(config)]
    (tmp_path / "dev").mkdir()
    (action,) = TrustTunnelAdapter(root=tmp_path, runner=object()).plan(config, AuditFacts())
    assert "hostname=gate.example.org" in action.mutations and "listen=127.0.0.1:4453" in action.mutations
    # install --config
    saved = tmp_path / "saved.toml"
    _scripted(_tt_answers("yes", "gate.example.org"), saved)
    reread = load_config(saved)
    assert reread.trusttunnel == config.trusttunnel and reread.domains.trusttunnel == config.domains.trusttunnel
    assert "trusttunnel" in [adapter.name for adapter in adapters_for(reread)]


# -- Task 10: installer usability ---------------------------------------------------------


def _plain_answers(*, language: list[str]) -> list[str]:
    return [*language, "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "", "no", "",
            "admin@example.com", "owner", "", "yes", "save"]


@pytest.mark.parametrize("locale", [Locale.EN, Locale.RU])
def test_a_given_language_is_not_asked_again(tmp_path: Path, locale: Locale):
    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n".join(_plain_answers(language=[])) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=locale, config_output=tmp_path / "l.toml", language_fixed=True)
    with pytest.raises(WizardSaved):
        wizard.run(AuditFacts())
    assert "Language / Язык" not in transcript.getvalue()
    assert wizard.locale is locale


def test_without_lang_the_language_is_still_asked(tmp_path: Path):
    transcript, _ = _scripted(_plain_answers(language=[""]), tmp_path / "a.toml")
    assert "Language / Язык" in transcript


_INSTALLED = AuditFacts(ownership={"installed": {"version": "3.2.1"}})


@pytest.mark.parametrize(
    ("locale", "notice"),
    [
        (Locale.EN, "Proxy Control 3.2.1 is already installed on this server. To update it: bash install-release.sh --update"),
        (Locale.RU, "На этом сервере уже установлен Proxy Control 3.2.1. Для обновления: bash install-release.sh --update"),
    ],
)
def test_an_installed_host_is_told_about_update_and_quits_by_default(locale: Locale, notice: str):
    from installer.wizard import WizardQuit

    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n"), transcript)
    wizard = TerminalWizard(terminal, locale=locale, language_fixed=True)
    with pytest.raises(WizardQuit):
        wizard.run(_INSTALLED)
    shown = transcript.getvalue()
    assert notice in shown
    # Nothing was asked before the warning, and nothing after the default answer.
    after = shown.split(notice, 1)[1]
    # Only the reinstall question follows the notice; no setup question was asked.
    assert "fresh" not in after.replace("quit", "") and "domain" not in after.lower() and "домен" not in after.lower()
    assert "Language" not in shown


def test_an_installed_host_can_continue_with_a_reinstall(tmp_path: Path):
    transcript = io.StringIO()
    answers = ["continue", *_plain_answers(language=[])]
    terminal = TerminalIO(io.StringIO("\n".join(answers) + "\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.EN, config_output=tmp_path / "r.toml", language_fixed=True)
    with pytest.raises(WizardSaved):
        wizard.run(_INSTALLED)
    assert "bash install-release.sh --update" in transcript.getvalue()
    assert (tmp_path / "r.toml").exists()


def test_a_clean_host_gets_no_installed_warning(tmp_path: Path):
    transcript, _ = _scripted(_plain_answers(language=[""]), tmp_path / "c.toml")
    assert "is already installed on this server" not in transcript


def test_the_profile_help_points_at_the_separate_awg_and_tt_questions(tmp_path: Path):
    en, _ = _scripted(_plain_answers(language=[""]), tmp_path / "p.toml")
    ru, _ = _scripted(_plain_answers(language=["ru"]), tmp_path / "p2.toml", locale=Locale.RU)
    assert "AmneziaWG and TrustTunnel are not part of a profile" in en
    assert "AmneziaWG и TrustTunnel в профиль не входят" in ru


def _awg_tt_answers(language: str) -> list[str]:
    return [language, "fresh", "core", "none", "panel.example.com", "relay.example.com", "", "",
            "yes", "", "", "",  # AmneziaWG: versions, host, ports default
            "yes", "gate.example.org", "no",  # TrustTunnel and its router question
            "admin@example.com", "owner", "", "yes", "save"]


@pytest.mark.parametrize("locale", [Locale.EN, Locale.RU])
def test_awg_and_tt_prompts_are_short_with_the_explanation_as_a_help_line(tmp_path: Path, locale: Locale):
    transcript, _ = _scripted(_awg_tt_answers(locale.value), tmp_path / "s.toml", locale=locale)
    from installer.i18n import text

    for key in ("amneziawg", "trusttunnel"):
        assert len(text(locale, key)) < 40 and len(text(locale, key + "_help")) > 100
    assert text(locale, "amneziawg_help").splitlines()[0] in transcript
    assert text(locale, "trusttunnel_help").splitlines()[0] in transcript


@pytest.mark.parametrize("locale", [Locale.EN, Locale.RU])
def test_the_review_shows_labels_instead_of_raw_keys(tmp_path: Path, locale: Locale):
    transcript, _ = _scripted(_awg_tt_answers(locale.value), tmp_path / "v.toml", locale=locale)
    review = transcript.split("Configuration review" if locale is Locale.EN else "Проверка конфигурации", 1)[1]
    review = review.split("Action" if locale is Locale.EN else "Действие", 1)[0]
    rows = [line for line in review.splitlines() if " | " in line][1:]
    assert rows
    for line in rows:
        label = line.split(" | ", 1)[0]
        assert "." not in label and "_" not in label, line
    for raw in ("schema", "relay_port", "lane_slots", "warp_port", "listen_port", "mtu"):
        assert raw not in review
    expected = ("AmneziaWG: UDP ports", "TrustTunnel domain", "gate.example.org") if locale is Locale.EN else (
        "AmneziaWG: UDP-порты", "Домен TrustTunnel", "gate.example.org")
    for item in expected:
        assert item in review, item
    assert (" | yes" if locale is Locale.EN else " | да") in review
    assert " | true" not in review and " | false" not in review


def test_every_review_key_of_the_examples_has_a_label_or_is_hidden():
    import glob

    from installer.config import parse_config
    from installer.i18n import _CATALOG
    from installer.wizard import _REVIEW_HIDDEN, _flatten

    known = set(_CATALOG[Locale.EN])
    missing: set[str] = set()
    for path in glob.glob(str(ROOT / "examples" / "installer" / "*.toml")):
        for key, value in _flatten(parse_config(Path(path).read_text()).canonical_dict()):
            if value == "None" or key in _REVIEW_HIDDEN:
                continue
            if "review_" + key.replace(".", "_") not in known:
                missing.add(key)
    assert missing == set()


def test_the_installer_audit_fact_alone_also_shows_the_notice():
    from installer.wizard import WizardQuit

    transcript = io.StringIO()
    terminal = TerminalIO(io.StringIO("\n"), transcript)
    wizard = TerminalWizard(terminal, locale=Locale.EN, language_fixed=True)
    with pytest.raises(WizardQuit):
        wizard.run(AuditFacts(ownership={"installer": {"present": True}}))
    assert "Proxy Control is already installed on this server. To update it" in transcript.getvalue()


def test_non_default_service_ports_are_labelled_in_the_review():
    from installer.i18n import text

    for locale in Locale:
        for key in ("egress.relay_port", "mieru.lane_slots", "egress.warp_port", "three_xui.warp_port"):
            assert text(locale, "review_" + key.replace(".", "_"))
