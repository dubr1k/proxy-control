from __future__ import annotations

import errno
import io
import os
import pty
import select
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
            "managed-new",
            "panel.example.com",
            "relay.example.com",
            "edge.example.com",
            "mieru.example.com",
            "46001",
            "46001",
            "xui.example.com",
            "vless.example.com",
            "xhttp.example.com",
            "hy2.example.com",
            "no",
            "admin@example.com",
            "owner",
            "yes",
            "save",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Пароли и ключи будут созданы только при установке" in transcript
    assert "Изменения не внесены." not in transcript
    assert "No changes were made." not in transcript
    config = load_config(output)
    assert config.host_mode is HostMode.FRESH
    assert config.profile is Profile.FULL
    assert config.three_xui.mode is ThreeXuiMode.MANAGED_NEW
    assert config.canonical_dict()["domains"] == {
        "panel": "panel.example.com",
        "mtproxy": "relay.example.com",
        "naive": "edge.example.com",
        "mieru": "mieru.example.com",
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
            "mieru.example.com",
            "abc",
            "46001",
            "70000",
            "46001",
            "admin@example.com",
            "owner",
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
        "managed-new",
        "panel.example.com",
        "relay.example.com",
        "edge.example.com",
        "mieru.example.com",
        "46001",
        "46001",
        "xui.example.com",
        "vless.example.com",
        "xhttp.example.com",
        "hy2.example.com",
        "no",
        "admin@example.com",
        "owner",
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
            "admin@example.com",
            "owner",
            "save-config",
        ],
        output=output,
    )

    assert completed.returncode == 0, transcript
    assert "Passwords and keys are generated only during installation" in transcript
    assert "No changes were made." not in transcript
    assert load_config(output).host_mode is HostMode.COEXIST


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
            "admin@example.com",
            "owner",
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
    output = tmp_path / "existing.toml"
    answers = [
        "",
        "coexist",
        "core",
        "existing",
        "panel.example.com",
        "relay.example.com",
        "xui.example.com",
        "",
        "",
        "",
        "admin@example.com",
        "owner",
        "back",
        "",
        "edit",
        "three_xui.panel_domain",
        "",
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

    assert caught.value.config.three_xui.panel_domain is None
    assert caught.value.config.three_xui.hysteria_domain is None
    assert load_config(output) == caught.value.config


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
